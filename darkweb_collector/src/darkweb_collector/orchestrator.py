from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib
import logging
import time
import uuid
from typing import Callable

from darkweb_collector.adapters.registry import get_adapter
from darkweb_collector.changan_auto_login import changan_auto_login_available, recover_changan_session
from darkweb_collector.config import get_site_config, load_site_configs
from darkweb_collector.crawl_frontier import (
    DISPATCH_RESERVATION_SECONDS,
    begin_persist_frontier,
    claim_frontier,
    complete_frontier,
    fail_frontier,
    fail_frontier_dispatch,
    mark_frontier_queued,
    observe_frontier,
    save_page_cursor,
    start_frontier,
)
from darkweb_collector.db import (
    get_active_crawl_job,
    get_db_connection,
    get_last_successful_crawl_job,
    list_crawl_jobs,
    reconcile_stale_crawl_jobs,
    upsert_crawl_job,
)
from darkweb_collector.collection_errors import CollectionFailure, classify_failure, has_detail_body, request_budget
from darkweb_collector.detail_lifecycle import (
    claim_detail, complete_detail, consume_request, count_detail_writes, detail_timeout,
    eligible_detail_tasks, fail_detail, owns_detail, reconcile_detail_owners, release_detail, reset_site_failures, site_retry_at,
)
from darkweb_collector.worker_activity import track_task
from darkweb_collector.job_diagnostics import is_in_failure_cooldown
from darkweb_collector.models import DetailTask, RunContext, SiteConfig
from darkweb_collector.queueing import queue_for_detail, queue_for_seed
from darkweb_collector.site_auth import SiteAuthenticationRequired, site_auth_readiness
from darkweb_collector.state_store import StateStore
from darkweb_collector.utils import utc_now_iso


logger = logging.getLogger(__name__)


def new_job_id(job_type: str, site_name: str) -> str:
    return f"local-{job_type}-{site_name}-{uuid.uuid4().hex[:12]}"


def mark_job_running(job_id: str, site_name: str, job_type: str, queue_name: str, target: str) -> None:
    started_at = utc_now_iso()
    with get_db_connection() as connection:
        upsert_crawl_job(
            connection,
            job_id=job_id,
            site_name=site_name,
            job_type=job_type,
            queue_name=queue_name,
            target=target,
            status="running",
            started_at=started_at,
        )
        connection.commit()


def mark_job_enqueued(
    job_id: str,
    site_name: str,
    job_type: str,
    queue_name: str,
    target: str,
) -> str:
    enqueued_at = utc_now_iso()
    with get_db_connection() as connection:
        upsert_crawl_job(
            connection,
            job_id=job_id,
            site_name=site_name,
            job_type=job_type,
            queue_name=queue_name,
            target=target,
            status="enqueued",
            enqueued_at=enqueued_at,
        )
        connection.commit()
    return enqueued_at


def mark_seed_dispatch_failed(job_id: str, *, enqueued_at: str | None = None) -> None:
    statement = """
        UPDATE crawl_jobs
        SET status = 'failed', finished_at = ?, duration_ms = 0,
            error_message = '种子任务提交失败，请检查消息服务或本地运行环境'
        WHERE job_id = ? AND job_type = 'seed' AND status = 'enqueued'
            AND started_at IS NULL AND finished_at IS NULL
    """
    parameters = [utc_now_iso(), job_id]
    if enqueued_at is not None:
        statement += " AND enqueued_at = ?"
        parameters.append(enqueued_at)
    with get_db_connection() as connection:
        connection.execute(statement, parameters)
        connection.commit()


def dispatch_seed_job(config: SiteConfig, publisher: Callable[[str], object]) -> str:
    job_id = str(uuid.uuid4())
    enqueued_at = mark_job_enqueued(job_id, config.site_name, "seed", queue_for_seed(config), config.site_name)
    try:
        publisher(job_id)
    except Exception:
        try:
            mark_seed_dispatch_failed(job_id, enqueued_at=enqueued_at)
        except Exception:
            logger.warning("Could not record failed seed submission for %s", config.site_name)
        raise
    return job_id


def mark_job_finished(
    job_id: str,
    site_name: str,
    job_type: str,
    queue_name: str,
    target: str,
    status: str,
    duration_ms: int,
    error_message: str | None = None,
) -> None:
    with get_db_connection() as connection:
        upsert_crawl_job(
            connection,
            job_id=job_id,
            site_name=site_name,
            job_type=job_type,
            queue_name=queue_name,
            target=target,
            status=status,
            finished_at=utc_now_iso(),
            duration_ms=duration_ms,
            error_message=error_message,
        )
        connection.commit()


def is_site_due(config: SiteConfig, finished_at_utc: str | None) -> bool:
    if not finished_at_utc:
        return True
    finished_at = datetime.fromisoformat(finished_at_utc)
    if finished_at.tzinfo is None:
        finished_at = finished_at.replace(tzinfo=timezone.utc)
    next_due = finished_at + timedelta(seconds=config.effective_interval_seconds)
    return datetime.now(timezone.utc) >= next_due


def _dispatch_detail_jobs(
    config: SiteConfig,
    detail_tasks: list[DetailTask],
    state_store: StateStore,
    detail_dispatcher: Callable[[SiteConfig, DetailTask], str | None] | None,
) -> tuple[list[str], int]:
    dispatched: list[str] = []
    failed = 0
    if detail_dispatcher is None:
        return dispatched, failed

    with get_db_connection() as connection:
        eligible = eligible_detail_tasks(connection, config.site_name, detail_tasks)
    detail_ttl = max(config.dedupe_window_minutes * 60, 60)
    for detail_task in eligible:
        if not state_store.claim_detail(config.site_name, detail_task.target_url, detail_ttl):
            continue
        try:
            job_id = detail_dispatcher(config, detail_task)
        except Exception:
            failed += 1
            continue
        if job_id:
            dispatched.append(job_id)
    return dispatched, failed


def _dispatch_frontier_jobs(
    config: SiteConfig,
    detail_dispatcher: Callable[[SiteConfig, DetailTask], str | None] | None,
) -> tuple[list[str], int]:
    if detail_dispatcher is None or not config.enabled or config.max_detail_pages_per_run <= 0:
        return [], 0
    dispatched: list[str] = []
    failed = 0
    while len(dispatched) + failed < config.max_detail_pages_per_run:
        token = str(uuid.uuid4())
        with get_db_connection() as connection:
            task = claim_frontier(
                connection, config.site_name, None, token, DISPATCH_RESERVATION_SECONDS,
                max_active=config.frontier_dispatch_window,
            )
            connection.commit()
        if task is None:
            break
        try:
            job_id = detail_dispatcher(config, task)
            if not job_id:
                raise RuntimeError("detail dispatcher did not return a job id")
        except Exception:
            failed += 1
            with get_db_connection() as connection:
                fail_frontier_dispatch(
                    connection, config.site_name, task.target_url, token,
                    error_message="dispatch_failed",
                )
                connection.commit()
            continue
        with get_db_connection() as connection:
            mark_frontier_queued(connection, config.site_name, task.target_url, token)
            connection.commit()
        dispatched.append(str(job_id))
    return dispatched, failed


def execute_seed_job(
    site_name: str,
    queue_name: str,
    force: bool,
    state_store: StateStore,
    detail_dispatcher: Callable[[SiteConfig, DetailTask], str | None] | None,
    attempt: int = 0,
    job_id: str | None = None,
    config_path: Path | None = None,
) -> dict[str, object]:
    config = get_site_config(site_name, config_path)
    run_ctx = RunContext(
        job_id=job_id or new_job_id("seed", site_name),
        job_type="seed",
        queue_name=queue_name,
        target=site_name,
        started_at_utc=utc_now_iso(),
        force=force,
        attempt=attempt,
    )
    adapter = get_adapter(site_name)
    with get_db_connection() as connection:
        if force:
            reset_site_failures(connection, site_name)
            connection.commit()
        elif site_retry_at(connection, site_name) > time.time():
            return {"site_name": site_name, "seed_job_id": run_ctx.job_id, "reason": "source_cooldown",
                    "detail_job_ids": [], "detail_task_count": 0, "detail_dispatched_count": 0}
    seed_result = adapter.collect_seed(config, run_ctx)
    detail_tasks = adapter.plan_details(seed_result, config)
    uses_frontier = bool(getattr(adapter, "supports_frontier", False))
    if uses_frontier:
        with get_db_connection() as connection:
            observe_frontier(connection, site_name, detail_tasks)
            connection.commit()
    adapter.persist(config=config, run_ctx=run_ctx, seed_result=seed_result)
    pagination_errors = seed_result.metadata.get("pagination_errors", [])
    for error in pagination_errors:
        logger.warning(
            "%s listing page %s (%s) failed: %s; successful pages and retry position retained",
            site_name, error.get("page"), error.get("lane"), error.get("error_type"),
        )
    if uses_frontier:
        with get_db_connection() as connection:
            for cursor in seed_result.metadata.get("cursor_updates", []):
                save_page_cursor(
                    connection, site_name, cursor["source_url"],
                    next_page=cursor["next_page"],
                    last_signature=cursor.get("last_signature", ""),
                    completed_at=cursor.get("completed_at", ""),
                )
            connection.commit()
        dispatched_job_ids, failed_detail_jobs = _dispatch_frontier_jobs(config, detail_dispatcher)
    else:
        dispatched_job_ids, failed_detail_jobs = _dispatch_detail_jobs(
            config, detail_tasks, state_store, detail_dispatcher
        )
    return {
        "site_name": site_name,
        "seed_job_id": run_ctx.job_id,
        "detail_job_ids": dispatched_job_ids,
        "detail_task_count": len(detail_tasks),
        "detail_dispatched_count": len(dispatched_job_ids),
        "listing_pages_scanned": seed_result.metadata.get("pages_scanned", 0),
        "listing_error_count": len(pagination_errors),
        "detail_failed_count": failed_detail_jobs,
        "collected_at_utc": seed_result.collected_at_utc,
    }


def execute_detail_job(
    site_name: str,
    detail_task: DetailTask,
    queue_name: str,
    attempt: int = 0,
    job_id: str | None = None,
    config_path: Path | None = None,
    slot_owner: str = "",
) -> dict[str, object]:
    config = get_site_config(site_name, config_path)
    token = job_id or new_job_id("detail", site_name)
    frontier_token = str(detail_task.metadata.get("frontier_token") or "")
    run_ctx = RunContext(token, "detail", queue_name, detail_task.target_url, utc_now_iso(), attempt=attempt)
    adapter = get_adapter(site_name)
    result = {"site_name": site_name, "detail_job_id": token, "target_url": detail_task.target_url}

    def skip_stale(connection, reason):
        release_detail(connection, site_name, detail_task.target_url, token)
        connection.execute("""UPDATE crawl_jobs SET status = 'skipped', finished_at = ?, error_message = ?
            WHERE job_id = ? AND status IN ('enqueued', 'running') AND finished_at IS NULL""",
            (utc_now_iso(), reason, token))
        connection.commit()
        return {**result, "reason": reason}

    with get_db_connection() as connection:
        reconcile_detail_owners(connection)
        previous = connection.execute("SELECT status, finished_at FROM crawl_jobs WHERE job_id = ?", (token,)).fetchone()
        if previous and (previous["finished_at"] is not None or previous["status"] not in {"enqueued", "running"}):
            return {**result, "reason": "stale_delivery"}
        admission = claim_detail(connection, config, detail_task, token)
        if admission != "claimed":
            row = connection.execute("""SELECT next_retry, owner_token FROM crawl_detail_control
                WHERE site_name = ? AND target_url = ?""", (site_name, detail_task.target_url)).fetchone()
            if admission == "busy" and row and row["owner_token"] == token:
                connection.commit()
                return {**result, "reason": "duplicate_delivery"}
            retry_at = max(float(row[0] or 0), site_retry_at(connection, site_name)) if row else 0
            if frontier_token:
                fail_frontier(connection, site_name, detail_task.target_url, frontier_token,
                              retry_seconds=max(30, retry_at - time.time()), error_message=admission)
            upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                            queue_name=queue_name, target=detail_task.target_url, status="skipped",
                            finished_at=utc_now_iso(), duration_ms=0, error_message=admission)
            connection.commit()
            return {**result, "reason": admission}
        if frontier_token and not start_frontier(
            connection, site_name, detail_task.target_url, frontier_token, max(config.frontier_lease_seconds, detail_timeout(config) + 60),
        ):
            release_detail(connection, site_name, detail_task.target_url, token)
            upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                            queue_name=queue_name, target=detail_task.target_url, status="skipped",
                            finished_at=utc_now_iso(), duration_ms=0, error_message="stale_frontier")
            connection.commit()
            return {**result, "reason": "stale_frontier"}
        upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                        queue_name=queue_name, target=detail_task.target_url, status="running",
                        started_at=run_ctx.started_at_utc)
        connection.commit()

    def count_request():
        with get_db_connection() as connection:
            # Commit a budget reset even if the next request is refused.
            try:
                consume_request(connection, site_name, detail_task.target_url, token)
            finally:
                connection.commit()

    start_perf = time.perf_counter()
    failure = None
    try:
        with track_task(token, site_name, detail_task.target_url, slot_owner or token + ":local", detail_timeout(config)):
            try:
                with request_budget(count_request):
                    detail_result = adapter.collect_detail(detail_task, config, run_ctx)
                if detail_result is None or not detail_result.payload or not has_detail_body(detail_result.payload):
                    raise CollectionFailure("parse", "adapter returned no validated detail body")
                with get_db_connection() as connection:
                    if not owns_detail(connection, site_name, detail_task.target_url, token):
                        return skip_stale(connection, "stale_delivery")
                    if frontier_token and not begin_persist_frontier(
                        connection, site_name, detail_task.target_url, frontier_token,
                        max(config.frontier_lease_seconds, detail_timeout(config) + 60),
                    ):
                        return skip_stale(connection, "stale_frontier")
                    with count_detail_writes() as counts:
                        adapter.persist(config=config, run_ctx=run_ctx, detail_results=[detail_result], connection=connection)
                    if not sum(counts.values()):
                        raise CollectionFailure("infrastructure", "adapter did not persist a detail record")
                    artifacts_pending = not bool(detail_result.raw_html and detail_result.screenshot_png)
                    if frontier_token and not complete_frontier(
                        connection, site_name, detail_task.target_url, frontier_token,
                        artifacts_complete=not artifacts_pending, retry_seconds=3600,
                    ):
                        raise CollectionFailure("infrastructure", "detail ownership changed before persistence")
                    if not complete_detail(
                        connection, site_name, detail_task.target_url, token, counts,
                        detail_result.payload.get("content_hash") or hashlib.sha256(
                            str(detail_result.payload.get("content") or detail_result.payload.get("text_excerpt")).encode("utf-8")
                        ).hexdigest(), artifacts_pending=artifacts_pending,
                    ):
                        raise CollectionFailure("infrastructure", "detail ownership changed before completion")
                    upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                                    queue_name=queue_name, target=detail_task.target_url,
                                    status="partial" if artifacts_pending else "succeeded",
                                    finished_at=utc_now_iso(), duration_ms=int((time.perf_counter() - start_perf) * 1000))
                    connection.commit()
                    result.update(artifacts_pending=artifacts_pending, **counts)
            except Exception as error:
                failure = classify_failure(error)
                with get_db_connection() as connection:
                    retry_at = fail_detail(connection, site_name, detail_task.target_url, token, failure)
                    if frontier_token:
                        fail_frontier(connection, site_name, detail_task.target_url, frontier_token,
                                      retry_seconds=max(60, retry_at - time.time()), error_message=failure.kind)
                    upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                                    queue_name=queue_name, target=detail_task.target_url,
                                    status="skipped" if failure.kind in {"auth_required", "restricted", "unavailable"} else "failed",
                                    finished_at=utc_now_iso(), duration_ms=int((time.perf_counter() - start_perf) * 1000),
                                    error_message=f"{failure.kind}: {str(failure)[:500]}")
                    connection.commit()
    except Exception as error:
        # Journal creation can fail before entering the task context.
        # Keep a durable owner only when its journal can still be recovered.
        with get_db_connection() as connection:
            if owns_detail(connection, site_name, detail_task.target_url, token):
                entry_failure = classify_failure(error)
                retry_at = fail_detail(connection, site_name, detail_task.target_url, token, entry_failure)
                if frontier_token:
                    fail_frontier(connection, site_name, detail_task.target_url, frontier_token,
                                  retry_seconds=max(60, retry_at - time.time()), error_message=entry_failure.kind)
                upsert_crawl_job(connection, job_id=token, site_name=site_name, job_type="detail",
                                queue_name=queue_name, target=detail_task.target_url, status="failed",
                                finished_at=utc_now_iso(), duration_ms=int((time.perf_counter() - start_perf) * 1000),
                                error_message=entry_failure.kind + ": task finalization failed")
                connection.commit()
        raise
    if failure is not None:
        raise failure
    return result


def run_detail_job_once(site_name: str, detail_task: DetailTask, config_path: Path | None = None) -> str:
    config = get_site_config(site_name, config_path)
    job_id = str(detail_task.metadata.get("frontier_token") or new_job_id("detail", site_name))
    execute_detail_job(site_name, detail_task, queue_for_detail(config), job_id=job_id, config_path=config_path)
    return job_id


def run_site_once(
    site_name: str,
    config_path: Path | None = None,
    state_store: StateStore | None = None,
    job_id: str | None = None,
    force: bool = True,
) -> dict[str, object]:
    from darkweb_collector.state_store import InMemoryStateStore

    config = get_site_config(site_name, config_path)
    seed_queue = queue_for_seed(config)
    selected_job_id = job_id or new_job_id("seed", site_name)
    mark_job_running(
        job_id=selected_job_id,
        site_name=site_name,
        job_type="seed",
        queue_name=seed_queue,
        target=site_name,
    )
    start_perf = time.perf_counter()
    selected_state_store = state_store or InMemoryStateStore()

    def inline_dispatcher(dispatched_config: SiteConfig, detail_task: DetailTask) -> str | None:
        return run_detail_job_once(site_name=dispatched_config.site_name, detail_task=detail_task, config_path=config_path)

    try:
        result = execute_seed_job(
            site_name=site_name,
            queue_name=seed_queue,
            force=force,
            state_store=selected_state_store,
            detail_dispatcher=inline_dispatcher,
            job_id=selected_job_id,
            config_path=config_path,
        )
    except SiteAuthenticationRequired as exc:
        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        mark_job_finished(
            job_id=selected_job_id,
            site_name=site_name,
            job_type="seed",
            queue_name=seed_queue,
            target=site_name,
            status="skipped",
            duration_ms=duration_ms,
            error_message=str(exc),
        )
        return {
            "site_name": site_name,
            "seed_job_id": selected_job_id,
            "detail_job_ids": [],
            "detail_task_count": 0,
            "detail_failed_count": 0,
            "reason": "auth_required",
            "auth_platform": exc.platform,
        }
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        mark_job_finished(
            job_id=selected_job_id,
            site_name=site_name,
            job_type="seed",
            queue_name=seed_queue,
            target=site_name,
            status="failed",
            duration_ms=duration_ms,
            error_message=str(exc),
        )
        raise

    duration_ms = int((time.perf_counter() - start_perf) * 1000)
    mark_job_finished(
        job_id=selected_job_id,
        site_name=site_name,
        job_type="seed",
        queue_name=seed_queue,
        target=site_name,
        status="succeeded",
        duration_ms=duration_ms,
    )
    return result


def enqueue_due_sites(
    seed_dispatcher: Callable[[SiteConfig], str | None],
    state_store: StateStore,
    config_path: Path | None = None,
) -> list[dict[str, str]]:
    dispatched: list[dict[str, str]] = []
    configs = load_site_configs(config_path)
    for config in configs:
        if not config.enabled:
            continue
        auth = site_auth_readiness(config)
        if auth["ready"] or not changan_auto_login_available(config):
            continue
        recover_changan_session(config, str(auth.get("auth_message") or "session expired"))

    with get_db_connection() as connection:
        reconcile_stale_crawl_jobs(connection)
        connection.commit()
        for config in configs:
            if not config.enabled:
                continue
            if site_retry_at(connection, config.site_name) > time.time():
                continue
            if not site_auth_readiness(config)["ready"]:
                continue
            if get_active_crawl_job(connection, site_name=config.site_name, job_type="seed"):
                continue
            rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT status, started_at, finished_at
                    FROM crawl_jobs
                    WHERE site_name = ? AND job_type = 'seed'
                    ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
                    LIMIT 20
                    """,
                    (config.site_name,),
                ).fetchall()
            ]
            if is_in_failure_cooldown(config, rows):
                continue
            last_success = get_last_successful_crawl_job(connection, site_name=config.site_name, job_type="seed")
            last_finished = last_success["finished_at"] if last_success else None
            if not is_site_due(config, last_finished):
                continue
            if not state_store.claim_seed_slot(config.site_name, max(config.effective_interval_seconds, 300)):
                continue
            queue_name = queue_for_seed(config)
            job_id = seed_dispatcher(config)
            if not job_id:
                continue
            # The dispatcher commits its enqueue row before publishing the task.
            dispatched.append({"site_name": config.site_name, "job_id": job_id, "queue_name": queue_name})
        connection.commit()
    return dispatched


def show_runs(limit: int) -> list[dict[str, object]]:
    with get_db_connection() as connection:
        return list_crawl_jobs(connection, limit=limit)
