from __future__ import annotations

from datetime import datetime, timedelta, timezone
from threading import Event, Lock, Thread
import logging
import time
from typing import Any

from darkweb_collector.browser_process_pool import browser_process_pool_status, submit_browser_site
from darkweb_collector.code_monitoring import (
    github_code_search_status_payload,
    list_code_watchlists_payload,
    scan_code_watchlist_once,
)
from darkweb_collector.config import get_site_config, load_site_configs, set_site_enabled
from darkweb_collector.db import (
    get_active_crawl_job,
    get_db_connection,
    get_last_successful_crawl_job,
    get_latest_crawl_job,
    get_ransomware_live_sync_state,
    get_site_connectivity_probe_map,
    upsert_site_connectivity_probe,
)
from darkweb_collector.document_exposure import list_watchlists_payload, scan_watchlist_once
from darkweb_collector.changan_auto_login import changan_auto_login_available
from darkweb_collector.job_diagnostics import consecutive_failures, failure_cooldown_until
from darkweb_collector.orchestrator import dispatch_seed_job, is_site_due, mark_seed_dispatch_failed, run_site_once
from darkweb_collector.public_vulnerabilities import sync_public_vulnerability_feed
from darkweb_collector.queueing import (
    BROWSER_ACTIVE_QUEUES,
    BROWSER_QUEUES,
    browser_concurrency,
    browser_queue_concurrency,
    queue_for_seed,
)
from darkweb_collector.ransomware_live import (
    get_ransomware_live_api_key,
    get_ransomware_live_sync_config,
    get_ransomware_live_sync_status_snapshot,
    set_ransomware_live_sync_config,
)
from darkweb_collector.site_auth import site_auth_readiness
from darkweb_collector.tor_fetch import fetch_url, is_onion_url
from darkweb_collector.utils import utc_now_iso


STALE_RUNNING_MINUTES = 30
STALE_ENQUEUED_MINUTES = 10
STALE_ENQUEUED_BUSY_QUEUE_MINUTES = 60
CONTINUOUS_INTERVAL_SECONDS = 60
DEFAULT_VULNERABILITY_SYNC_INTERVAL_SECONDS = 3600
DEFAULT_VULNERABILITY_SYNC_LIMIT = 300
DEFAULT_RANSOMWARE_SYNC_INTERVAL_SECONDS = 3600
DEFAULT_RANSOMWARE_SYNC_LIMIT = 0
DEFAULT_CODE_MONITORING_INTERVAL_SECONDS = 3600
DEFAULT_CODE_MONITORING_CONTINUOUS_SEARCH_PAGE_LIMIT = 2
DEFAULT_CODE_MONITORING_CONTINUOUS_MAX_RESULTS_PER_TERM = 5
DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS = 3600
WORKER_QUEUE_CACHE_TTL_SECONDS = 5
WORKER_QUEUE_REFRESH_WAIT_SECONDS = 15
SITE_CONNECTIVITY_PROBE_INTERVAL_SECONDS = 24 * 60 * 60
SITE_CONNECTIVITY_MONITOR_POLL_SECONDS = 10 * 60


logger = logging.getLogger("darkweb_collector.api_actions")


_continuous_lock = Lock()
_continuous_enabled = False
_continuous_started_at = ""
_continuous_last_tick_at = ""
_continuous_mode = "queue"
_continuous_stop_event: Event | None = None
_continuous_thread: Thread | None = None

_vulnerability_sync_lock = Lock()
_vulnerability_sync_enabled = False
_vulnerability_sync_started_at = ""
_vulnerability_sync_last_tick_at = ""
_vulnerability_sync_last_success_at = ""
_vulnerability_sync_last_error = ""
_vulnerability_sync_last_mode = ""
_vulnerability_sync_last_source = ""
_vulnerability_sync_last_ingested = 0
_vulnerability_sync_interval_seconds = DEFAULT_VULNERABILITY_SYNC_INTERVAL_SECONDS
_vulnerability_sync_limit = DEFAULT_VULNERABILITY_SYNC_LIMIT
_vulnerability_sync_running = False
_vulnerability_sync_stop_event: Event | None = None
_vulnerability_sync_thread: Thread | None = None

_code_monitoring_lock = Lock()
_code_monitoring_enabled = False
_code_monitoring_started_at = ""
_code_monitoring_last_tick_at = ""
_code_monitoring_last_success_at = ""
_code_monitoring_last_error = ""
_code_monitoring_interval_seconds = DEFAULT_CODE_MONITORING_INTERVAL_SECONDS
_code_monitoring_running = False
_code_monitoring_last_watchlist_count = 0
_code_monitoring_last_candidate_count = 0
_code_monitoring_last_hit_count = 0
_code_monitoring_last_clue_hit_count = 0
_code_monitoring_last_sensitive_hit_count = 0
_code_monitoring_target_watchlist_id = 0
_code_monitoring_target_watchlist_name = ""
_code_monitoring_stop_event: Event | None = None
_code_monitoring_thread: Thread | None = None
_code_monitoring_tasks: dict[int, dict[str, Any]] = {}

_netdisk_monitoring_lock = Lock()
_netdisk_monitoring_once_running = False
_netdisk_monitoring_once_thread: Thread | None = None
_netdisk_monitoring_tasks: dict[int, dict[str, Any]] = {}

_worker_queue_cache_lock = Lock()
_worker_queue_cache_checked_at = 0.0
_worker_queue_cache_refresh_started_at = 0.0
_worker_queue_cache_available = False
_worker_queue_cache: set[str] = set()
_worker_queue_worker_counts: dict[str, int] = {}
_worker_queue_worker_names: dict[str, list[str]] = {}
_worker_queue_refresh_thread: Thread | None = None
_site_connectivity_monitor_lock = Lock()
_site_connectivity_monitor_thread: Thread | None = None


def _persist_site_connectivity_probe(payload: dict[str, Any]) -> None:
    with get_db_connection() as connection:
        upsert_site_connectivity_probe(connection, payload)


def probe_site_connectivity(site_name: str) -> dict[str, Any]:
    config = get_site_config(site_name)
    url = config.seed_urls[0]
    fetch_mode = "tor_http" if is_onion_url(url) else config.seed_fetch_mode
    started = time.perf_counter()
    try:
        html = fetch_url(
            url=url,
            mode=fetch_mode,
            timeout_seconds=min(max(config.fetch_timeout_seconds, 5), 30),
            render_wait_seconds=min(max(config.render_wait_seconds, 1), 5),
            retries=0,
        )
        available = True
        error = ""
    except Exception as exc:
        html = ""
        available = False
        error = str(exc).strip()[:500] or type(exc).__name__
    error_lower = error.lower()
    failure_reason = (
        ""
        if available
        else "route_unavailable"
        if any(marker in error_lower for marker in ("socks", "proxy", "tor connection"))
        else "timeout"
        if any(marker in error_lower for marker in ("timed out", "timeout"))
        else "fetch_failed"
    )
    latency_ms = max(0, round((time.perf_counter() - started) * 1000))
    payload = {
        "site_name": config.site_name,
        "url": url,
        "fetch_mode": fetch_mode,
        "available": available,
        "status": "available" if available else "unavailable",
        "latency_ms": latency_ms,
        "checked_at": utc_now_iso(),
        "response_bytes": len(html.encode("utf-8", errors="replace")),
        "failure_reason": failure_reason,
        "error": error,
    }
    _persist_site_connectivity_probe(payload)
    return payload


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _tor_route_ready_for_probe(url: str) -> bool:
    if not is_onion_url(url):
        return True
    try:
        from darkweb_collector.tor_bridge_control import get_tor_bridge_status, load_tor_bridge_settings

        settings = load_tor_bridge_settings()
        if not settings.get("enabled"):
            return True
        return bool(get_tor_bridge_status().get("connected"))
    except Exception:
        return True


def run_due_site_connectivity_probes(*, now: datetime | None = None) -> dict[str, list[str]]:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    with get_db_connection() as connection:
        latest = get_site_connectivity_probe_map(connection)

    result: dict[str, list[str]] = {
        "probed": [],
        "skipped_recent": [],
        "skipped_route": [],
        "errors": [],
    }
    for config in load_site_configs():
        if not config.enabled or not config.seed_urls:
            continue
        previous = latest.get(config.site_name) or {}
        checked_at = _parse_dt(str(previous.get("checked_at") or ""))
        if checked_at is not None and (current - checked_at).total_seconds() < SITE_CONNECTIVITY_PROBE_INTERVAL_SECONDS:
            result["skipped_recent"].append(config.site_name)
            continue
        if not _tor_route_ready_for_probe(config.seed_urls[0]):
            result["skipped_route"].append(config.site_name)
            continue
        try:
            probe_site_connectivity(config.site_name)
            result["probed"].append(config.site_name)
        except Exception as exc:
            result["errors"].append(config.site_name)
            logger.warning("daily site connectivity probe failed for %s: %s", config.site_name, exc)
    return result


def _site_connectivity_monitor_loop(stop_event: Event) -> None:
    while not stop_event.is_set():
        try:
            run_due_site_connectivity_probes()
        except Exception:
            logger.exception("daily site connectivity monitor failed")
        if stop_event.wait(SITE_CONNECTIVITY_MONITOR_POLL_SECONDS):
            break


def start_site_connectivity_monitor() -> None:
    global _site_connectivity_monitor_thread
    with _site_connectivity_monitor_lock:
        if _site_connectivity_monitor_thread and _site_connectivity_monitor_thread.is_alive():
            return
        stop_event = Event()
        thread = Thread(
            target=_site_connectivity_monitor_loop,
            args=(stop_event,),
            name="site-connectivity-monitor",
            daemon=True,
        )
        _site_connectivity_monitor_thread = thread
        thread.start()


def _has_recent_running_job_in_queue(connection, queue_name: str, *, exclude_job_id: str = "") -> bool:
    if not queue_name:
        return False
    rows = connection.execute(
        """
        SELECT job_id, started_at, finished_at
        FROM crawl_jobs
        WHERE queue_name = ? AND status = 'running'
        """,
        (queue_name,),
    ).fetchall()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=STALE_RUNNING_MINUTES)
    for row in rows:
        job_id = str(row["job_id"] or "")
        if exclude_job_id and job_id == exclude_job_id:
            continue
        if row["finished_at"]:
            continue
        started_at = _parse_dt(row["started_at"])
        if started_at is not None and started_at >= cutoff:
            return True
    return False


def _is_active_job_blocking(active_job: dict[str, Any] | None, *, queue_has_recent_running: bool = False) -> bool:
    if not active_job:
        return False
    status = active_job.get("status")
    if status == "enqueued":
        enqueued_at = _parse_dt(active_job.get("enqueued_at"))
        if enqueued_at is None:
            return False
        threshold_minutes = (
            STALE_ENQUEUED_BUSY_QUEUE_MINUTES if queue_has_recent_running else STALE_ENQUEUED_MINUTES
        )
        return enqueued_at >= datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)
    if status != "running":
        return False
    started_at = _parse_dt(active_job.get("started_at"))
    if started_at is None:
        return False
    return started_at >= datetime.now(timezone.utc) - timedelta(minutes=STALE_RUNNING_MINUTES)


def _mark_stale_active_job(site_name: str, active_job: dict[str, Any] | None) -> None:
    if not active_job:
        return
    if active_job.get("status") not in {"enqueued", "running"}:
        return

    marker = _parse_dt(active_job.get("started_at") or active_job.get("enqueued_at"))
    if marker is None:
        return

    with get_db_connection() as connection:
        connection.execute(
            """
            UPDATE crawl_jobs
            SET status = 'stale', finished_at = ?, error_message = 'stale seed task auto-cleared'
            WHERE job_id = ? AND site_name = ? AND job_type = 'seed' AND status = ?
                AND COALESCE(started_at, '') = ? AND COALESCE(enqueued_at, '') = ?
            """,
            (utc_now_iso(), str(active_job["job_id"]), site_name, active_job["status"],
             active_job.get("started_at") or "", active_job.get("enqueued_at") or ""),
        )
        connection.commit()


def _refresh_worker_queue_cache() -> tuple[set[str], dict[str, int], dict[str, list[str]]] | None:
    try:
        from darkweb_collector.celery_app import app as celery_app

        inspect = celery_app.control.inspect(timeout=0.8)
        active_queues = inspect.active_queues()
    except Exception:
        return None
    if not active_queues:
        return None
    queue_names: set[str] = set()
    worker_counts: dict[str, int] = {}
    worker_names: dict[str, list[str]] = {}
    for worker_name, worker_queues in active_queues.items():
        for queue in worker_queues or []:
            name = str((queue or {}).get("name") or "").strip()
            if name:
                queue_names.add(name)
                worker_counts[name] = worker_counts.get(name, 0) + 1
                worker_names.setdefault(name, []).append(str(worker_name))
    return queue_names, worker_counts, {name: sorted(names) for name, names in worker_names.items()}


def _refresh_worker_queue_cache_in_background() -> None:
    global _worker_queue_cache_checked_at, _worker_queue_cache, _worker_queue_worker_counts, _worker_queue_worker_names
    global _worker_queue_cache_available, _worker_queue_refresh_thread, _worker_queue_cache_refresh_started_at
    snapshot = None
    try:
        snapshot = _refresh_worker_queue_cache()
    finally:
        with _worker_queue_cache_lock:
            if snapshot is not None:
                _worker_queue_cache, _worker_queue_worker_counts, _worker_queue_worker_names = snapshot
            _worker_queue_cache_available = snapshot is not None
            _worker_queue_cache_checked_at = time.monotonic()
            _worker_queue_cache_refresh_started_at = 0.0
            _worker_queue_refresh_thread = None


def _schedule_worker_queue_cache_refresh() -> None:
    global _worker_queue_refresh_thread, _worker_queue_cache_refresh_started_at
    with _worker_queue_cache_lock:
        now = time.monotonic()
        cache_is_fresh = _worker_queue_cache_checked_at > 0 and (now - _worker_queue_cache_checked_at) <= WORKER_QUEUE_CACHE_TTL_SECONDS
        if cache_is_fresh or _worker_queue_refresh_thread is not None:
            return
        _worker_queue_refresh_thread = Thread(
            target=_refresh_worker_queue_cache_in_background,
            name="worker-queue-status-refresh",
            daemon=True,
        )
        _worker_queue_cache_refresh_started_at = now
        _worker_queue_refresh_thread.start()


def _has_queue_worker(queue_name: str) -> bool:
    _schedule_worker_queue_cache_refresh()
    with _worker_queue_cache_lock:
        # Unknown or refreshing state must not start a second local collector.
        if not _worker_queue_cache_available or _worker_queue_refresh_thread is not None:
            return True
        return queue_name in _worker_queue_cache


def _run_site_in_thread(site_name: str, job_id: str, force: bool) -> None:
    try:
        run_site_once(site_name, job_id=job_id, force=force)
    except Exception:
        try:
            mark_seed_dispatch_failed(job_id)
        except Exception:
            logger.warning("Could not record local seed startup failure for %s", site_name)
        return


def dispatch_run_site(site_name: str, force: bool = True) -> dict[str, Any]:
    config = get_site_config(site_name)
    auth = site_auth_readiness(config)
    if not auth["ready"] and not changan_auto_login_available(config):
        return {
            "site_name": site_name,
            "dispatch_mode": "skipped",
            "message": auth["auth_message"],
            "job_id": "",
            "reason": "auth_required",
            "auth_platform": auth["auth_platform"],
            "auth_status": auth["auth_status"],
        }
    with get_db_connection() as connection:
        active_job = get_active_crawl_job(connection, site_name=site_name, job_type="seed")
        last_success = get_last_successful_crawl_job(connection, site_name=site_name, job_type="seed")
        queue_has_recent_running = _has_recent_running_job_in_queue(
            connection,
            str((active_job or {}).get("queue_name") or ""),
            exclude_job_id=str((active_job or {}).get("job_id") or ""),
        )
        seed_rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT status, started_at, finished_at, enqueued_at, error_message
                FROM crawl_jobs
                WHERE site_name = ? AND job_type = 'seed'
                ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
                LIMIT 20
                """,
                (site_name,),
            ).fetchall()
        ]
    if _is_active_job_blocking(active_job, queue_has_recent_running=queue_has_recent_running):
        return {
            "site_name": site_name,
            "dispatch_mode": "skipped",
            "message": "该站点已有运行中的种子任务",
            "job_id": active_job.get("job_id") if active_job else "",
        }
    cooldown_until = failure_cooldown_until(config, seed_rows)
    if not force and cooldown_until is not None and datetime.now(timezone.utc) < cooldown_until:
        return {
            "site_name": site_name,
            "dispatch_mode": "skipped",
            "message": "该站点连续失败达到阈值，仍处于冷却期",
            "job_id": "",
            "reason": "failure_cooldown",
            "consecutive_failures": consecutive_failures(seed_rows),
            "failure_cooldown_until": cooldown_until.isoformat(),
        }
    if not force and not is_site_due(config, last_success["finished_at"] if last_success else None):
        return {
            "site_name": site_name,
            "dispatch_mode": "skipped",
            "message": "尚未到该站点的采集时间",
            "job_id": "",
            "reason": "interval_wait",
        }

    _mark_stale_active_job(site_name, active_job)

    queue_name = queue_for_seed(config)
    if not _has_queue_worker(queue_name):
        if config.uses_browser:
            job_id = dispatch_seed_job(
                config,
                lambda selected_id: submit_browser_site(site_name, selected_id, force=force),
            )
            return {
                "site_name": site_name,
                "dispatch_mode": "process",
                "message": "未检测到可消费浏览器队列的 worker，已提交到本地浏览器进程池",
                "job_id": job_id,
            }
        job_id = dispatch_seed_job(
            config,
            lambda selected_id: Thread(target=_run_site_in_thread, args=(site_name, selected_id, force), daemon=True).start(),
        )
        return {
            "site_name": site_name,
            "dispatch_mode": "thread",
            "message": "未检测到可消费该队列的 worker，已在本地线程触发单次运行",
            "job_id": job_id,
        }
    from darkweb_collector.tasks import crawl_seed

    job_id = dispatch_seed_job(
        config,
        lambda selected_id: crawl_seed.apply_async(
            kwargs={"site_name": site_name, "force": force},
            queue=queue_name,
            task_id=selected_id,
        ),
    )
    return {
        "site_name": site_name,
        "dispatch_mode": "queue",
        "message": "已提交到任务队列",
        "job_id": job_id,
    }


def dispatch_run_all_enabled_sites(force: bool = True) -> dict[str, Any]:
    results = []
    for config in load_site_configs():
        if not config.enabled:
            continue
        results.append(dispatch_run_site(config.site_name, force=force))
    return {
        "count": len(results),
        "results": results,
    }


def dispatch_run_all_enabled_sites_once(force: bool = True) -> dict[str, Any]:
    return dispatch_run_all_enabled_sites(force=force)


def _continuous_loop(stop_event: Event) -> None:
    global _continuous_last_tick_at, _continuous_enabled
    while not stop_event.is_set():
        _continuous_last_tick_at = utc_now_iso()
        try:
            configs = load_site_configs()
        except Exception:
            logger.warning("Could not load continuous crawl schedule; retrying next tick")
            configs = []
        for config in configs:
            if not config.enabled:
                continue
            try:
                dispatch_run_site(config.site_name, force=False)
            except Exception:
                logger.warning("Continuous seed dispatch failed for %s; retrying next tick", config.site_name)
        if stop_event.wait(CONTINUOUS_INTERVAL_SECONDS):
            break
    _continuous_enabled = False


def start_continuous_dispatch() -> dict[str, Any]:
    global _continuous_enabled, _continuous_started_at, _continuous_last_tick_at, _continuous_stop_event, _continuous_thread
    with _continuous_lock:
        if _continuous_enabled and _continuous_thread and _continuous_thread.is_alive():
            return {
                "enabled": True,
                "started_at": _continuous_started_at,
                "last_tick_at": _continuous_last_tick_at,
                "mode": _continuous_mode,
                "message": "持久运行已在运行",
            }

        stop_event = Event()
        thread = Thread(target=_continuous_loop, args=(stop_event,), daemon=True)
        _continuous_enabled = True
        _continuous_started_at = utc_now_iso()
        _continuous_last_tick_at = ""
        _continuous_stop_event = stop_event
        _continuous_thread = thread
        thread.start()

        return {
            "enabled": True,
            "started_at": _continuous_started_at,
            "last_tick_at": _continuous_last_tick_at,
            "mode": _continuous_mode,
            "message": "已开始持久运行",
        }


def stop_continuous_dispatch() -> dict[str, Any]:
    global _continuous_enabled, _continuous_stop_event, _continuous_thread
    with _continuous_lock:
        if not _continuous_enabled or _continuous_stop_event is None:
            return {
                "enabled": False,
                "started_at": _continuous_started_at,
                "last_tick_at": _continuous_last_tick_at,
                "mode": _continuous_mode,
                "message": "当前未运行持久调度",
            }

        _continuous_stop_event.set()
        _continuous_enabled = False
        return {
            "enabled": False,
            "started_at": _continuous_started_at,
            "last_tick_at": _continuous_last_tick_at,
            "mode": _continuous_mode,
            "message": "已停止持久运行",
        }


def get_continuous_dispatch_status() -> dict[str, Any]:
    thread_alive = bool(_continuous_thread and _continuous_thread.is_alive())
    enabled = bool(_continuous_enabled and thread_alive)
    return {
        "enabled": enabled,
        "started_at": _continuous_started_at,
        "last_tick_at": _continuous_last_tick_at,
        "mode": _continuous_mode,
    }


def get_browser_runtime_status() -> dict[str, Any]:
    _schedule_worker_queue_cache_refresh()
    with _worker_queue_cache_lock:
        worker_queues = sorted(_worker_queue_cache)
        worker_counts = dict(_worker_queue_worker_counts)
        worker_names = {name: list(names) for name, names in _worker_queue_worker_names.items()}
        worker_status = "ready" if _worker_queue_cache_available else "unknown"
        if _worker_queue_refresh_thread is not None:
            elapsed = time.monotonic() - _worker_queue_cache_refresh_started_at
            worker_status = "refreshing" if elapsed < WORKER_QUEUE_REFRESH_WAIT_SECONDS else "unknown"
    browser_worker_names = sorted(
        {
            worker_name
            for queue_name in BROWSER_QUEUES
            for worker_name in worker_names.get(queue_name, [])
        }
    )
    browser_worker_count = len(browser_worker_names)
    configured_concurrency = browser_concurrency()
    return {
        "browser_queue": ",".join(BROWSER_ACTIVE_QUEUES),
        "browser_queues": list(BROWSER_QUEUES),
        "queue_configured_concurrency": {
            queue_name: browser_queue_concurrency(queue_name)
            for queue_name in BROWSER_ACTIVE_QUEUES
        },
        "configured_concurrency": configured_concurrency,
        "browser_concurrency": configured_concurrency,
        "browser_worker_count": browser_worker_count,
        "browser_worker_names": browser_worker_names,
        "local_process_pool": browser_process_pool_status(),
        "worker_queues": worker_queues,
        "worker_counts": worker_counts,
        "worker_status": worker_status,
    }


def _run_vulnerability_sync(limit: int, prefer_live: bool = True) -> dict[str, Any]:
    global _vulnerability_sync_running
    global _vulnerability_sync_last_tick_at
    global _vulnerability_sync_last_success_at
    global _vulnerability_sync_last_error
    global _vulnerability_sync_last_mode
    global _vulnerability_sync_last_source
    global _vulnerability_sync_last_ingested
    with _vulnerability_sync_lock:
        _vulnerability_sync_running = True
        _vulnerability_sync_last_tick_at = utc_now_iso()
        _vulnerability_sync_last_error = ""
    try:
        result = sync_public_vulnerability_feed(
            limit=limit,
            prefer_live=prefer_live,
            refresh_normalized=False,
        )
        with _vulnerability_sync_lock:
            _vulnerability_sync_last_success_at = utc_now_iso()
            _vulnerability_sync_last_mode = str(result.get("mode") or "")
            _vulnerability_sync_last_source = str(result.get("source") or "")
            _vulnerability_sync_last_ingested = int(result.get("ingested") or 0)
            _vulnerability_sync_last_error = ""
        return result
    except Exception as exc:
        with _vulnerability_sync_lock:
            _vulnerability_sync_last_error = str(exc)
        raise
    finally:
        with _vulnerability_sync_lock:
            _vulnerability_sync_running = False


def _run_vulnerability_sync_once_in_thread(limit: int) -> None:
    try:
        _run_vulnerability_sync(limit=limit)
    except Exception:
        return


def dispatch_run_vulnerability_sync_once(limit: int = DEFAULT_VULNERABILITY_SYNC_LIMIT) -> dict[str, Any]:
    global _vulnerability_sync_thread
    with _vulnerability_sync_lock:
        if _vulnerability_sync_running:
            return {
                **get_vulnerability_sync_status(),
                "message": "漏洞同步任务已在运行中",
            }
        thread = Thread(target=_run_vulnerability_sync_once_in_thread, args=(limit,), daemon=True)
        _vulnerability_sync_thread = thread
        thread.start()
    return {
        **get_vulnerability_sync_status(),
        "message": "已触发一次漏洞同步",
    }


def _vulnerability_sync_loop(stop_event: Event) -> None:
    global _vulnerability_sync_enabled
    while not stop_event.is_set():
        try:
            _run_vulnerability_sync(limit=_vulnerability_sync_limit)
        except Exception:
            pass
        if stop_event.wait(_vulnerability_sync_interval_seconds):
            break
    _vulnerability_sync_enabled = False


def start_vulnerability_sync_dispatch(
    interval_seconds: int = DEFAULT_VULNERABILITY_SYNC_INTERVAL_SECONDS,
    limit: int = DEFAULT_VULNERABILITY_SYNC_LIMIT,
) -> dict[str, Any]:
    global _vulnerability_sync_enabled
    global _vulnerability_sync_started_at
    global _vulnerability_sync_stop_event
    global _vulnerability_sync_thread
    global _vulnerability_sync_interval_seconds
    global _vulnerability_sync_limit
    if interval_seconds <= 0:
        interval_seconds = DEFAULT_VULNERABILITY_SYNC_INTERVAL_SECONDS
    if limit <= 0:
        limit = DEFAULT_VULNERABILITY_SYNC_LIMIT
    with _vulnerability_sync_lock:
        if _vulnerability_sync_enabled and _vulnerability_sync_thread and _vulnerability_sync_thread.is_alive():
            return {
                **get_vulnerability_sync_status(),
                "message": "漏洞自动同步已在运行",
            }
        stop_event = Event()
        thread = Thread(target=_vulnerability_sync_loop, args=(stop_event,), daemon=True)
        _vulnerability_sync_enabled = True
        _vulnerability_sync_started_at = utc_now_iso()
        _vulnerability_sync_interval_seconds = interval_seconds
        _vulnerability_sync_limit = limit
        _vulnerability_sync_stop_event = stop_event
        _vulnerability_sync_thread = thread
        thread.start()
    return {
        **get_vulnerability_sync_status(),
        "message": "已开始漏洞自动同步",
    }


def stop_vulnerability_sync_dispatch() -> dict[str, Any]:
    global _vulnerability_sync_enabled
    with _vulnerability_sync_lock:
        if not _vulnerability_sync_enabled or _vulnerability_sync_stop_event is None:
            return {
                **get_vulnerability_sync_status(),
                "message": "漏洞自动同步当前未运行",
            }
        _vulnerability_sync_stop_event.set()
        _vulnerability_sync_enabled = False
    return {
        **get_vulnerability_sync_status(),
        "message": "已停止漏洞自动同步",
    }


def get_vulnerability_sync_status() -> dict[str, Any]:
    thread_alive = bool(_vulnerability_sync_thread and _vulnerability_sync_thread.is_alive())
    return {
        "enabled": bool(_vulnerability_sync_enabled and thread_alive),
        "running": bool(_vulnerability_sync_running),
        "started_at": _vulnerability_sync_started_at,
        "last_tick_at": _vulnerability_sync_last_tick_at,
        "last_success_at": _vulnerability_sync_last_success_at,
        "last_error": _vulnerability_sync_last_error,
        "last_mode": _vulnerability_sync_last_mode,
        "last_source": _vulnerability_sync_last_source,
        "last_ingested": _vulnerability_sync_last_ingested,
        "interval_seconds": _vulnerability_sync_interval_seconds,
        "limit": _vulnerability_sync_limit,
    }


def dispatch_run_ransomware_sync_once(limit: int = DEFAULT_RANSOMWARE_SYNC_LIMIT) -> dict[str, Any]:
    from darkweb_collector.tasks import enqueue_ransomware_live_sync

    job_id = enqueue_ransomware_live_sync(limit=max(0, int(limit)), force=True)
    if not job_id:
        return {
            **get_ransomware_sync_status(),
            "message": "ransomware.live 同步任务已在运行或等待执行",
        }
    return {
        **get_ransomware_sync_status(),
        "message": "已触发一次 ransomware.live 同步",
        "job_id": job_id,
    }


def start_ransomware_sync_dispatch(
    interval_seconds: int = DEFAULT_RANSOMWARE_SYNC_INTERVAL_SECONDS,
    limit: int = DEFAULT_RANSOMWARE_SYNC_LIMIT,
) -> dict[str, Any]:
    if not get_ransomware_live_api_key():
        raise RuntimeError("RANSOMWARE_LIVE_API_KEY is not set")
    sync_config = set_ransomware_live_sync_config(
        enabled=True,
        interval_seconds=interval_seconds,
        limit=limit,
    )
    from darkweb_collector.tasks import enqueue_ransomware_live_sync

    job_id = enqueue_ransomware_live_sync(limit=int(sync_config["limit"]), force=True)
    return {
        **get_ransomware_sync_status(),
        "message": "已开始 ransomware.live 自动同步",
        "job_id": job_id or "",
    }


def stop_ransomware_sync_dispatch() -> dict[str, Any]:
    sync_config = get_ransomware_live_sync_config()
    if not sync_config["enabled"]:
        return {
            **get_ransomware_sync_status(),
            "message": "ransomware.live 自动同步当前未开启",
        }
    set_ransomware_live_sync_config(
        enabled=False,
        interval_seconds=int(sync_config["interval_seconds"]),
        limit=int(sync_config["limit"]),
    )
    return {
        **get_ransomware_sync_status(),
        "message": "已停止 ransomware.live 后续自动同步；正在执行的任务不会被强制中断",
    }


def get_ransomware_sync_status() -> dict[str, Any]:
    sync_config = get_ransomware_live_sync_config()
    snapshot = get_ransomware_live_sync_status_snapshot()
    with get_db_connection() as connection:
        sync_state = get_ransomware_live_sync_state(connection)
        active_job = get_active_crawl_job(connection, "ransomware_live", "ransomware_sync")
        latest_job = get_latest_crawl_job(connection, "ransomware_live", "ransomware_sync")
        latest_success = get_last_successful_crawl_job(connection, "ransomware_live", "ransomware_sync")

    latest_status = str((latest_job or {}).get("status") or "")
    last_error = str(snapshot.get("last_error") or "")
    if latest_status == "failed":
        last_error = str((latest_job or {}).get("error_message") or last_error)
    elif latest_status == "succeeded":
        last_error = ""
    if get_ransomware_live_api_key() and "RANSOMWARE_LIVE_API_KEY" in last_error and "not set" in last_error.lower():
        last_error = ""
    last_tick_at = str(
        (active_job or {}).get("started_at")
        or (active_job or {}).get("enqueued_at")
        or snapshot.get("last_tick_at")
        or (latest_job or {}).get("started_at")
        or (latest_job or {}).get("enqueued_at")
        or ""
    )
    last_success_at = str((latest_success or {}).get("finished_at") or snapshot.get("last_success_at") or "")
    return {
        "enabled": bool(sync_config["enabled"]),
        "running": bool(active_job and active_job.get("status") == "running"),
        "pending": bool(active_job and active_job.get("status") == "enqueued"),
        "started_at": str(sync_config.get("started_at") or ""),
        "last_tick_at": last_tick_at,
        "last_success_at": last_success_at,
        "last_error": last_error,
        "last_source": str(snapshot.get("last_source") or ""),
        "last_fetched": int(snapshot.get("last_fetched") or 0),
        "last_ingested": int(snapshot.get("last_ingested") or 0),
        "last_new": int(snapshot.get("last_new") or 0),
        "last_updated": int(snapshot.get("last_updated") or 0),
        "last_unchanged": int(snapshot.get("last_unchanged") or 0),
        "interval_seconds": int(sync_config["interval_seconds"]),
        "limit": int(sync_config["limit"]),
        "last_job_id": str((latest_job or {}).get("job_id") or snapshot.get("last_job_id") or ""),
        "last_job_status": latest_status,
        "record_count": int(sync_state.get("count") or 0),
        "latest_disclosure_time": str(sync_state.get("latest_disclosure_time") or ""),
    }


def _run_code_monitoring_once() -> dict[str, Any]:
    return _run_code_monitoring_once_for_watchlist(None)


def _resolve_code_monitoring_watchlist_name(watchlist_id: int) -> str:
    if watchlist_id <= 0:
        return ""
    for item in list_code_watchlists_payload():
        if int(item.get("id") or 0) == int(watchlist_id):
            return str(item.get("name") or "")
    return ""


def _code_monitoring_task_snapshot(
    watchlist_id: int,
    *,
    watchlist_name: str = "",
    enabled: bool = False,
    running: bool = False,
    started_at: str = "",
    last_tick_at: str = "",
    last_success_at: str = "",
    last_error: str = "",
    interval_seconds: int = DEFAULT_CODE_MONITORING_INTERVAL_SECONDS,
    watchlist_count: int = 0,
    candidate_count: int = 0,
    hit_count: int = 0,
    clue_hit_count: int = 0,
    sensitive_hit_count: int = 0,
    new_primary_hit_count: int = 0,
    new_suppressed_hit_count: int = 0,
    updated_hit_count: int = 0,
    new_sensitive_hit_count: int = 0,
    new_clue_hit_count: int = 0,
    stop_event: Event | None = None,
    thread: Thread | None = None,
) -> dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "running": bool(running),
        "started_at": started_at,
        "last_tick_at": last_tick_at,
        "last_success_at": last_success_at,
        "last_error": last_error,
        "interval_seconds": int(interval_seconds or DEFAULT_CODE_MONITORING_INTERVAL_SECONDS),
        "watchlist_count": int(watchlist_count or 0),
        "candidate_count": int(candidate_count or 0),
        "hit_count": int(hit_count or 0),
        "clue_hit_count": int(clue_hit_count or 0),
        "sensitive_hit_count": int(sensitive_hit_count or 0),
        "new_primary_hit_count": int(new_primary_hit_count or 0),
        "new_suppressed_hit_count": int(new_suppressed_hit_count or 0),
        "updated_hit_count": int(updated_hit_count or 0),
        "new_sensitive_hit_count": int(new_sensitive_hit_count or 0),
        "new_clue_hit_count": int(new_clue_hit_count or 0),
        "target_watchlist_id": int(watchlist_id or 0),
        "target_watchlist_name": watchlist_name,
        "stop_event": stop_event,
        "thread": thread,
    }


def _active_code_monitoring_task_count() -> int:
    return sum(
        1
        for task in _code_monitoring_tasks.values()
        if bool(task.get("enabled")) and bool(task.get("thread")) and task["thread"].is_alive()
    )


def _code_monitoring_task_status_payload(watchlist_id: int, task: dict[str, Any] | None = None) -> dict[str, Any]:
    task = task or _code_monitoring_tasks.get(int(watchlist_id or 0)) or _code_monitoring_task_snapshot(
        int(watchlist_id or 0),
        watchlist_name=_resolve_code_monitoring_watchlist_name(int(watchlist_id or 0)),
    )
    thread_alive = bool(task.get("thread") and task["thread"].is_alive())
    return {
        "enabled": bool(task.get("enabled") and thread_alive),
        "running": bool(task.get("running")),
        "started_at": str(task.get("started_at") or ""),
        "last_tick_at": str(task.get("last_tick_at") or ""),
        "last_success_at": str(task.get("last_success_at") or ""),
        "last_error": str(task.get("last_error") or ""),
        "interval_seconds": int(task.get("interval_seconds") or DEFAULT_CODE_MONITORING_INTERVAL_SECONDS),
        "watchlist_count": int(task.get("watchlist_count") or 0),
        "candidate_count": int(task.get("candidate_count") or 0),
        "hit_count": int(task.get("hit_count") or 0),
        "clue_hit_count": int(task.get("clue_hit_count") or 0),
        "sensitive_hit_count": int(task.get("sensitive_hit_count") or 0),
        "new_primary_hit_count": int(task.get("new_primary_hit_count") or 0),
        "new_suppressed_hit_count": int(task.get("new_suppressed_hit_count") or 0),
        "updated_hit_count": int(task.get("updated_hit_count") or 0),
        "new_sensitive_hit_count": int(task.get("new_sensitive_hit_count") or 0),
        "new_clue_hit_count": int(task.get("new_clue_hit_count") or 0),
        "target_watchlist_id": int(task.get("target_watchlist_id") or 0),
        "target_watchlist_name": str(task.get("target_watchlist_name") or ""),
        "active_watchlist_count": _active_code_monitoring_task_count(),
        "github_search": github_code_search_status_payload(),
    }


def _positive_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _remaining_interval_seconds(interval_seconds: int, loop_started_at: float) -> float:
    elapsed_seconds = max(0.0, time.monotonic() - loop_started_at)
    return max(0.0, float(interval_seconds) - elapsed_seconds)


def _code_monitoring_continuous_scan_options(watchlist: dict[str, Any]) -> dict[str, Any]:
    search_page_limit = _positive_int(watchlist.get("search_page_limit"))
    max_results_per_term = _positive_int(watchlist.get("max_results_per_term"))
    return {
        "search_page_limit": search_page_limit if search_page_limit > 0 else DEFAULT_CODE_MONITORING_CONTINUOUS_SEARCH_PAGE_LIMIT,
        "max_results_per_term": max_results_per_term if max_results_per_term > 0 else DEFAULT_CODE_MONITORING_CONTINUOUS_MAX_RESULTS_PER_TERM,
        "detail_fetch": False,
        "browser_fallback": False,
    }


def _run_code_monitoring_once_for_watchlist(watchlist_id: int | None) -> dict[str, Any]:
    global _code_monitoring_running
    global _code_monitoring_last_tick_at
    global _code_monitoring_last_success_at
    global _code_monitoring_last_error
    global _code_monitoring_last_watchlist_count
    global _code_monitoring_last_candidate_count
    global _code_monitoring_last_hit_count
    global _code_monitoring_last_clue_hit_count
    global _code_monitoring_last_sensitive_hit_count
    selected_watchlist_id = int(watchlist_id or 0)
    with _code_monitoring_lock:
        if selected_watchlist_id > 0:
            existing_task = _code_monitoring_tasks.get(selected_watchlist_id)
            _code_monitoring_tasks[selected_watchlist_id] = {
                **(existing_task or _code_monitoring_task_snapshot(selected_watchlist_id, watchlist_name=_resolve_code_monitoring_watchlist_name(selected_watchlist_id))),
                "running": True,
                "last_tick_at": utc_now_iso(),
                "last_error": "",
            }
        else:
            _code_monitoring_running = True
            _code_monitoring_last_tick_at = utc_now_iso()
            _code_monitoring_last_error = ""
    try:
        watchlists = [item for item in list_code_watchlists_payload() if bool(item.get("enabled"))]
        if selected_watchlist_id:
            watchlists = [item for item in watchlists if int(item.get("id") or 0) == selected_watchlist_id]
            if not watchlists:
                raise ValueError(f"watchlist:{selected_watchlist_id}:not_found_or_disabled")
        aggregate = {
            "watchlist_count": len(watchlists),
            "candidate_count": 0,
            "hit_count": 0,
            "clue_hit_count": 0,
            "sensitive_hit_count": 0,
            "new_primary_hit_count": 0,
            "new_suppressed_hit_count": 0,
            "updated_hit_count": 0,
            "new_sensitive_hit_count": 0,
            "new_clue_hit_count": 0,
            "errors": [],
            "results": [],
        }
        for watchlist in watchlists:
            try:
                scan_options = _code_monitoring_continuous_scan_options(watchlist)
                result = scan_code_watchlist_once(
                    int(watchlist["id"]),
                    platforms=list(watchlist.get("platforms") or []),
                    file_extensions=list(watchlist.get("file_extensions") or []),
                    search_page_limit=scan_options["search_page_limit"],
                    max_results_per_term=scan_options["max_results_per_term"],
                    detail_fetch=scan_options["detail_fetch"],
                    browser_fallback=scan_options["browser_fallback"],
                    enabled_rule_keys=list(watchlist.get("enabled_rule_keys") or []),
                )
                aggregate["candidate_count"] += int(result.get("candidates") or 0)
                aggregate["hit_count"] += int(result.get("hits") or 0)
                aggregate["clue_hit_count"] += int(result.get("clue_hits") or 0)
                aggregate["sensitive_hit_count"] += int(result.get("sensitive_hits") or 0)
                aggregate["new_primary_hit_count"] += int(result.get("new_primary_hit_count") or 0)
                aggregate["new_suppressed_hit_count"] += int(result.get("new_suppressed_hit_count") or 0)
                aggregate["updated_hit_count"] += int(result.get("updated_hit_count") or 0)
                aggregate["new_sensitive_hit_count"] += int(result.get("new_sensitive_hit_count") or 0)
                aggregate["new_clue_hit_count"] += int(result.get("new_clue_hit_count") or 0)
                aggregate["errors"].extend(result.get("errors") or [])
                aggregate["results"].append(result)
            except Exception as exc:
                aggregate["errors"].append(f"watchlist:{watchlist.get('id')}:{exc}")
        if aggregate["errors"] and not aggregate["results"]:
            raise RuntimeError("；".join(str(item) for item in aggregate["errors"][:3]))
        with _code_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _code_monitoring_tasks.get(selected_watchlist_id) or _code_monitoring_task_snapshot(
                    selected_watchlist_id,
                    watchlist_name=_resolve_code_monitoring_watchlist_name(selected_watchlist_id),
                )
                _code_monitoring_tasks[selected_watchlist_id] = {
                    **existing_task,
                    "last_success_at": utc_now_iso(),
                    "last_error": "",
                    "watchlist_count": aggregate["watchlist_count"],
                    "candidate_count": aggregate["candidate_count"],
                    "hit_count": aggregate["hit_count"],
                    "clue_hit_count": aggregate["clue_hit_count"],
                    "sensitive_hit_count": aggregate["sensitive_hit_count"],
                    "new_primary_hit_count": aggregate["new_primary_hit_count"],
                    "new_suppressed_hit_count": aggregate["new_suppressed_hit_count"],
                    "updated_hit_count": aggregate["updated_hit_count"],
                    "new_sensitive_hit_count": aggregate["new_sensitive_hit_count"],
                    "new_clue_hit_count": aggregate["new_clue_hit_count"],
                }
            else:
                _code_monitoring_last_success_at = utc_now_iso()
                _code_monitoring_last_watchlist_count = aggregate["watchlist_count"]
                _code_monitoring_last_candidate_count = aggregate["candidate_count"]
                _code_monitoring_last_hit_count = aggregate["hit_count"]
                _code_monitoring_last_clue_hit_count = aggregate["clue_hit_count"]
                _code_monitoring_last_sensitive_hit_count = aggregate["sensitive_hit_count"]
                _code_monitoring_last_error = ""
        return aggregate
    except Exception as exc:
        with _code_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _code_monitoring_tasks.get(selected_watchlist_id) or _code_monitoring_task_snapshot(
                    selected_watchlist_id,
                    watchlist_name=_resolve_code_monitoring_watchlist_name(selected_watchlist_id),
                )
                _code_monitoring_tasks[selected_watchlist_id] = {
                    **existing_task,
                    "last_error": str(exc),
                }
            else:
                _code_monitoring_last_error = str(exc)
        raise
    finally:
        with _code_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _code_monitoring_tasks.get(selected_watchlist_id)
                if existing_task is not None:
                    _code_monitoring_tasks[selected_watchlist_id] = {**existing_task, "running": False}
            else:
                _code_monitoring_running = False


def _run_code_monitoring_once_in_thread(watchlist_id: int | None = None) -> None:
    try:
        _run_code_monitoring_once_for_watchlist(watchlist_id)
    except Exception:
        return


def dispatch_run_code_monitoring_once() -> dict[str, Any]:
    global _code_monitoring_thread
    with _code_monitoring_lock:
        if _code_monitoring_running:
            return {
                **get_code_monitoring_continuous_status(),
                "message": "代码监测任务已在运行中",
            }
        thread = Thread(target=_run_code_monitoring_once_in_thread, daemon=True)
        _code_monitoring_thread = thread
        thread.start()
    return {
        **get_code_monitoring_continuous_status(),
        "message": "已触发一次代码监测持续扫描",
    }


def _code_monitoring_loop(watchlist_id: int, stop_event: Event) -> None:
    while not stop_event.is_set():
        loop_started_at = time.monotonic()
        try:
            _run_code_monitoring_once_for_watchlist(watchlist_id)
        except Exception:
            pass
        with _code_monitoring_lock:
            task = _code_monitoring_tasks.get(watchlist_id) or {}
            interval_seconds = int(task.get("interval_seconds") or DEFAULT_CODE_MONITORING_INTERVAL_SECONDS)
        if stop_event.wait(_remaining_interval_seconds(interval_seconds, loop_started_at)):
            break
    with _code_monitoring_lock:
        task = _code_monitoring_tasks.get(watchlist_id)
        if task is not None:
            _code_monitoring_tasks[watchlist_id] = {**task, "enabled": False, "running": False, "stop_event": None}


def start_code_monitoring_dispatch(
    interval_seconds: int = DEFAULT_CODE_MONITORING_INTERVAL_SECONDS,
    *,
    watchlist_id: int | None = None,
) -> dict[str, Any]:
    if interval_seconds <= 0:
        interval_seconds = DEFAULT_CODE_MONITORING_INTERVAL_SECONDS
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id <= 0:
        raise ValueError("watchlist_id is required for code monitoring continuous scan")
    target_watchlist_name = ""
    enabled_watchlists = [item for item in list_code_watchlists_payload() if bool(item.get("enabled"))]
    target_watchlist = next((item for item in enabled_watchlists if int(item.get("id") or 0) == selected_watchlist_id), None)
    if target_watchlist is None:
        raise ValueError(f"watchlist not found or disabled: {selected_watchlist_id}")
    target_watchlist_name = str(target_watchlist.get("name") or "")
    with _code_monitoring_lock:
        existing_task = _code_monitoring_tasks.get(selected_watchlist_id)
        if existing_task and bool(existing_task.get("enabled")) and bool(existing_task.get("thread")) and existing_task["thread"].is_alive():
            _code_monitoring_tasks[selected_watchlist_id] = {
                **existing_task,
                "interval_seconds": interval_seconds,
                "target_watchlist_name": target_watchlist_name,
            }
            return {
                **_code_monitoring_task_status_payload(selected_watchlist_id),
                "message": "该监测对象的长期任务已在运行",
            }
        stop_event = Event()
        thread = Thread(target=_code_monitoring_loop, args=(selected_watchlist_id, stop_event), daemon=True)
        _code_monitoring_tasks[selected_watchlist_id] = {
            **(existing_task or _code_monitoring_task_snapshot(selected_watchlist_id, watchlist_name=target_watchlist_name)),
            "enabled": True,
            "running": False,
            "started_at": utc_now_iso(),
            "last_tick_at": "",
            "last_error": "",
            "interval_seconds": interval_seconds,
            "target_watchlist_id": selected_watchlist_id,
            "target_watchlist_name": target_watchlist_name,
            "stop_event": stop_event,
            "thread": thread,
        }
        thread.start()
    return {
        **_code_monitoring_task_status_payload(selected_watchlist_id),
        "message": "已开启该监测对象的代码长期后台扫描",
    }


def stop_code_monitoring_dispatch(*, watchlist_id: int | None = None) -> dict[str, Any]:
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id <= 0:
        raise ValueError("watchlist_id is required for code monitoring continuous stop")
    with _code_monitoring_lock:
        existing_task = _code_monitoring_tasks.get(selected_watchlist_id)
        if existing_task is None or not bool(existing_task.get("enabled")) or existing_task.get("stop_event") is None:
            return {
                **_code_monitoring_task_status_payload(selected_watchlist_id),
                "message": "该监测对象的长期任务当前未运行",
            }
        stop_event = existing_task.get("stop_event")
        if stop_event is not None:
            stop_event.set()
        _code_monitoring_tasks[selected_watchlist_id] = {
            **existing_task,
            "enabled": False,
        }
    return {
        **_code_monitoring_task_status_payload(selected_watchlist_id),
        "message": "已停止该监测对象的代码长期后台扫描",
    }


def get_code_monitoring_continuous_status(*, watchlist_id: int | None = None) -> dict[str, Any]:
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id > 0:
        with _code_monitoring_lock:
            task = _code_monitoring_tasks.get(selected_watchlist_id)
            return _code_monitoring_task_status_payload(selected_watchlist_id, task)
    with _code_monitoring_lock:
        active_tasks = [
            task for task in _code_monitoring_tasks.values()
            if bool(task.get("enabled")) and bool(task.get("thread")) and task["thread"].is_alive()
        ]
        if active_tasks:
            task = sorted(active_tasks, key=lambda item: str(item.get("started_at") or ""), reverse=True)[0]
            payload = _code_monitoring_task_status_payload(int(task.get("target_watchlist_id") or 0), task)
            payload["target_watchlist_name"] = task.get("target_watchlist_name") or "多个监测对象"
            return payload
    return _code_monitoring_task_status_payload(0)


def _run_netdisk_monitoring_once() -> dict[str, Any]:
    return _run_netdisk_monitoring_once_for_watchlist(None)


def _netdisk_watchlist_source_families(watchlist: dict[str, Any]) -> list[str]:
    families = watchlist.get("source_families")
    if not isinstance(families, list):
        return []
    return [str(item) for item in families if str(item)]


def _is_netdisk_monitoring_watchlist(watchlist: dict[str, Any]) -> bool:
    families = _netdisk_watchlist_source_families(watchlist)
    return not families or "netdisk_aggregator" in families


def _enabled_netdisk_monitoring_watchlists() -> list[dict[str, Any]]:
    return [
        item
        for item in list_watchlists_payload()
        if bool(item.get("enabled")) and _is_netdisk_monitoring_watchlist(item)
    ]


def _resolve_netdisk_monitoring_watchlist_name(watchlist_id: int) -> str:
    if watchlist_id <= 0:
        return ""
    for item in list_watchlists_payload():
        if int(item.get("id") or 0) == int(watchlist_id):
            return str(item.get("name") or "")
    return ""


def _netdisk_monitoring_task_snapshot(
    watchlist_id: int,
    *,
    watchlist_name: str = "",
    enabled: bool = False,
    running: bool = False,
    started_at: str = "",
    last_tick_at: str = "",
    last_success_at: str = "",
    last_error: str = "",
    interval_seconds: int = DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS,
    watchlist_count: int = 0,
    candidate_count: int = 0,
    hit_count: int = 0,
    error_count: int = 0,
    stop_event: Event | None = None,
    thread: Thread | None = None,
) -> dict[str, Any]:
    return {
        "enabled": bool(enabled),
        "running": bool(running),
        "started_at": started_at,
        "last_tick_at": last_tick_at,
        "last_success_at": last_success_at,
        "last_error": last_error,
        "interval_seconds": int(interval_seconds or DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS),
        "watchlist_count": int(watchlist_count or 0),
        "candidate_count": int(candidate_count or 0),
        "hit_count": int(hit_count or 0),
        "error_count": int(error_count or 0),
        "target_watchlist_id": int(watchlist_id or 0),
        "target_watchlist_name": watchlist_name,
        "stop_event": stop_event,
        "thread": thread,
    }


def _active_netdisk_monitoring_task_count() -> int:
    return sum(
        1
        for task in _netdisk_monitoring_tasks.values()
        if bool(task.get("enabled")) and bool(task.get("thread")) and task["thread"].is_alive()
    )


def _netdisk_monitoring_task_status_payload(watchlist_id: int, task: dict[str, Any] | None = None) -> dict[str, Any]:
    task = task or _netdisk_monitoring_tasks.get(int(watchlist_id or 0)) or _netdisk_monitoring_task_snapshot(
        int(watchlist_id or 0),
        watchlist_name=_resolve_netdisk_monitoring_watchlist_name(int(watchlist_id or 0)),
    )
    thread_alive = bool(task.get("thread") and task["thread"].is_alive())
    return {
        "enabled": bool(task.get("enabled") and thread_alive),
        "running": bool(task.get("running")),
        "started_at": str(task.get("started_at") or ""),
        "last_tick_at": str(task.get("last_tick_at") or ""),
        "last_success_at": str(task.get("last_success_at") or ""),
        "last_error": str(task.get("last_error") or ""),
        "interval_seconds": int(task.get("interval_seconds") or DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS),
        "watchlist_count": int(task.get("watchlist_count") or 0),
        "candidate_count": int(task.get("candidate_count") or 0),
        "hit_count": int(task.get("hit_count") or 0),
        "error_count": int(task.get("error_count") or 0),
        "target_watchlist_id": int(task.get("target_watchlist_id") or 0),
        "target_watchlist_name": str(task.get("target_watchlist_name") or ""),
        "active_watchlist_count": _active_netdisk_monitoring_task_count(),
    }


def _run_netdisk_monitoring_once_for_watchlist(watchlist_id: int | None) -> dict[str, Any]:
    global _netdisk_monitoring_once_running
    selected_watchlist_id = int(watchlist_id or 0)
    tick_at = utc_now_iso()
    with _netdisk_monitoring_lock:
        if selected_watchlist_id > 0:
            existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id)
            _netdisk_monitoring_tasks[selected_watchlist_id] = {
                **(
                    existing_task
                    or _netdisk_monitoring_task_snapshot(
                        selected_watchlist_id,
                        watchlist_name=_resolve_netdisk_monitoring_watchlist_name(selected_watchlist_id),
                    )
                ),
                "running": True,
                "last_tick_at": tick_at,
                "last_error": "",
            }
        else:
            _netdisk_monitoring_once_running = True
    try:
        watchlists = _enabled_netdisk_monitoring_watchlists()
        if selected_watchlist_id:
            watchlists = [item for item in watchlists if int(item.get("id") or 0) == selected_watchlist_id]
            if not watchlists:
                raise ValueError(f"watchlist:{selected_watchlist_id}:not_found_disabled_or_not_netdisk")
        aggregate = {
            "watchlist_count": len(watchlists),
            "candidate_count": 0,
            "hit_count": 0,
            "error_count": 0,
            "errors": [],
            "results": [],
        }
        for watchlist in watchlists:
            try:
                result = scan_watchlist_once(
                    int(watchlist["id"]),
                    source_families=["netdisk_aggregator"],
                )
                errors = list(result.get("errors") or [])
                aggregate["candidate_count"] += int(result.get("candidates") or 0)
                aggregate["hit_count"] += int(result.get("hits") or 0)
                aggregate["error_count"] += len(errors)
                aggregate["errors"].extend(errors)
                aggregate["results"].append(result)
            except Exception as exc:
                aggregate["error_count"] += 1
                aggregate["errors"].append(f"watchlist:{watchlist.get('id')}:{exc}")
        last_error = "；".join(str(item) for item in aggregate["errors"][:3])
        with _netdisk_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id) or _netdisk_monitoring_task_snapshot(
                    selected_watchlist_id,
                    watchlist_name=_resolve_netdisk_monitoring_watchlist_name(selected_watchlist_id),
                )
                _netdisk_monitoring_tasks[selected_watchlist_id] = {
                    **existing_task,
                    "last_success_at": utc_now_iso(),
                    "last_error": last_error,
                    "watchlist_count": aggregate["watchlist_count"],
                    "candidate_count": aggregate["candidate_count"],
                    "hit_count": aggregate["hit_count"],
                    "error_count": aggregate["error_count"],
                }
        return aggregate
    except Exception as exc:
        with _netdisk_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id) or _netdisk_monitoring_task_snapshot(
                    selected_watchlist_id,
                    watchlist_name=_resolve_netdisk_monitoring_watchlist_name(selected_watchlist_id),
                )
                _netdisk_monitoring_tasks[selected_watchlist_id] = {
                    **existing_task,
                    "last_error": str(exc),
                }
        raise
    finally:
        with _netdisk_monitoring_lock:
            if selected_watchlist_id > 0:
                existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id)
                if existing_task is not None:
                    _netdisk_monitoring_tasks[selected_watchlist_id] = {**existing_task, "running": False}
            else:
                _netdisk_monitoring_once_running = False


def _run_netdisk_monitoring_once_in_thread(watchlist_id: int | None = None) -> None:
    try:
        _run_netdisk_monitoring_once_for_watchlist(watchlist_id)
    except Exception:
        return


def dispatch_run_netdisk_monitoring_once() -> dict[str, Any]:
    global _netdisk_monitoring_once_running
    global _netdisk_monitoring_once_thread
    with _netdisk_monitoring_lock:
        if _netdisk_monitoring_once_running:
            return {
                **_netdisk_monitoring_task_status_payload(0),
                "message": "网盘监测任务已在运行中",
            }
        thread = Thread(target=_run_netdisk_monitoring_once_in_thread, daemon=True)
        _netdisk_monitoring_once_running = True
        _netdisk_monitoring_once_thread = thread
        thread.start()
        payload = _netdisk_monitoring_task_status_payload(0)
    return {
        **payload,
        "message": "已触发一次网盘监测持续扫描",
    }


def _netdisk_monitoring_loop(watchlist_id: int, stop_event: Event) -> None:
    while not stop_event.is_set():
        loop_started_at = time.monotonic()
        try:
            _run_netdisk_monitoring_once_for_watchlist(watchlist_id)
        except Exception:
            pass
        with _netdisk_monitoring_lock:
            task = _netdisk_monitoring_tasks.get(watchlist_id) or {}
            interval_seconds = int(task.get("interval_seconds") or DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS)
        if stop_event.wait(_remaining_interval_seconds(interval_seconds, loop_started_at)):
            break
    with _netdisk_monitoring_lock:
        task = _netdisk_monitoring_tasks.get(watchlist_id)
        if task is not None:
            _netdisk_monitoring_tasks[watchlist_id] = {**task, "enabled": False, "running": False, "stop_event": None}


def start_netdisk_monitoring_dispatch(
    interval_seconds: int = DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS,
    *,
    watchlist_id: int | None = None,
) -> dict[str, Any]:
    if interval_seconds <= 0:
        interval_seconds = DEFAULT_NETDISK_MONITORING_INTERVAL_SECONDS
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id <= 0:
        raise ValueError("watchlist_id is required for netdisk monitoring continuous scan")
    enabled_watchlists = _enabled_netdisk_monitoring_watchlists()
    target_watchlist = next((item for item in enabled_watchlists if int(item.get("id") or 0) == selected_watchlist_id), None)
    if target_watchlist is None:
        raise ValueError(f"watchlist not found, disabled, or not netdisk enabled: {selected_watchlist_id}")
    target_watchlist_name = str(target_watchlist.get("name") or "")
    with _netdisk_monitoring_lock:
        existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id)
        if existing_task and bool(existing_task.get("enabled")) and bool(existing_task.get("thread")) and existing_task["thread"].is_alive():
            _netdisk_monitoring_tasks[selected_watchlist_id] = {
                **existing_task,
                "interval_seconds": interval_seconds,
                "target_watchlist_name": target_watchlist_name,
            }
            return {
                **_netdisk_monitoring_task_status_payload(selected_watchlist_id),
                "message": "该监测对象的网盘长期任务已在运行",
            }
        stop_event = Event()
        thread = Thread(target=_netdisk_monitoring_loop, args=(selected_watchlist_id, stop_event), daemon=True)
        _netdisk_monitoring_tasks[selected_watchlist_id] = {
            **(existing_task or _netdisk_monitoring_task_snapshot(selected_watchlist_id, watchlist_name=target_watchlist_name)),
            "enabled": True,
            "running": False,
            "started_at": utc_now_iso(),
            "last_tick_at": "",
            "last_error": "",
            "interval_seconds": interval_seconds,
            "target_watchlist_id": selected_watchlist_id,
            "target_watchlist_name": target_watchlist_name,
            "stop_event": stop_event,
            "thread": thread,
        }
        thread.start()
        payload = _netdisk_monitoring_task_status_payload(selected_watchlist_id)
    return {
        **payload,
        "message": "已开启该监测对象的网盘长期后台扫描",
    }


def stop_netdisk_monitoring_dispatch(*, watchlist_id: int | None = None) -> dict[str, Any]:
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id <= 0:
        raise ValueError("watchlist_id is required for netdisk monitoring continuous stop")
    with _netdisk_monitoring_lock:
        existing_task = _netdisk_monitoring_tasks.get(selected_watchlist_id)
        if existing_task is None or not bool(existing_task.get("enabled")) or existing_task.get("stop_event") is None:
            return {
                **_netdisk_monitoring_task_status_payload(selected_watchlist_id),
                "message": "该监测对象的网盘长期任务当前未运行",
            }
        stop_event = existing_task.get("stop_event")
        if stop_event is not None:
            stop_event.set()
        _netdisk_monitoring_tasks[selected_watchlist_id] = {
            **existing_task,
            "enabled": False,
        }
        payload = _netdisk_monitoring_task_status_payload(selected_watchlist_id)
    return {
        **payload,
        "message": "已停止该监测对象的网盘长期后台扫描",
    }


def get_netdisk_monitoring_continuous_status(*, watchlist_id: int | None = None) -> dict[str, Any]:
    selected_watchlist_id = int(watchlist_id or 0)
    if selected_watchlist_id > 0:
        with _netdisk_monitoring_lock:
            task = _netdisk_monitoring_tasks.get(selected_watchlist_id)
            return _netdisk_monitoring_task_status_payload(selected_watchlist_id, task)
    with _netdisk_monitoring_lock:
        active_tasks = [
            task for task in _netdisk_monitoring_tasks.values()
            if bool(task.get("enabled")) and bool(task.get("thread")) and task["thread"].is_alive()
        ]
        if active_tasks:
            task = sorted(active_tasks, key=lambda item: str(item.get("started_at") or ""), reverse=True)[0]
            payload = _netdisk_monitoring_task_status_payload(int(task.get("target_watchlist_id") or 0), task)
            payload["target_watchlist_name"] = task.get("target_watchlist_name") or "多个监测对象"
            return payload
    return _netdisk_monitoring_task_status_payload(0)


def update_site_enabled(site_name: str, enabled: bool) -> dict[str, Any]:
    config = set_site_enabled(site_name=site_name, enabled=enabled)
    return {
        "site_name": config.site_name,
        "enabled": config.enabled,
        "message": "已启用站点采集" if config.enabled else "已停用站点采集",
    }
