from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
import time
import uuid

from darkweb_collector.celery_app import app
from darkweb_collector.collection_errors import CollectionFailure, safe_failure_text
from darkweb_collector.detail_lifecycle import pause_site
from darkweb_collector.config import get_site_config
from darkweb_collector.crawl_frontier import (
    accept_frontier_delivery, fail_frontier, fail_frontier_dispatch,
)
from darkweb_collector.db import get_active_crawl_job, get_db_connection, get_latest_crawl_job
from darkweb_collector.models import DetailTask, SiteConfig
from darkweb_collector.orchestrator import (
    _dispatch_frontier_jobs,
    execute_detail_job,
    execute_seed_job,
    mark_job_enqueued,
    mark_job_finished,
    mark_job_running,
)
from darkweb_collector.queueing import MAX_RETRIES, SEED_HTTP_QUEUE, queue_for_detail, retry_backoff_seconds
from darkweb_collector.ransomware_live import (
    RANSOMWARE_LIVE_API_URL,
    get_ransomware_live_api_key,
    get_ransomware_live_sync_config,
    save_ransomware_live_sync_status,
    sync_ransomware_live_victims,
)
from darkweb_collector.site_auth import SiteAuthenticationRequired
from darkweb_collector.state_store import get_state_store
from darkweb_collector.utils import utc_now_iso


logger = logging.getLogger(__name__)

RANSOMWARE_LIVE_SITE_NAME = "ransomware_live"
RANSOMWARE_LIVE_JOB_TYPE = "ransomware_sync"


def _queue_name_from_request(task) -> str:
    delivery_info = getattr(task.request, "delivery_info", {}) or {}
    routing_key = delivery_info.get("routing_key")
    if routing_key:
        return str(routing_key)
    return "unknown"


def _enqueue_detail_task(config: SiteConfig, detail_task: DetailTask) -> str | None:
    queue_name = queue_for_detail(config)
    job_id = str(detail_task.metadata.get("frontier_token") or uuid.uuid4())
    mark_job_enqueued(
        job_id=job_id,
        site_name=config.site_name,
        job_type="detail",
        queue_name=queue_name,
        target=detail_task.target_url,
    )
    try:
        async_result = crawl_detail.apply_async(
            kwargs={
                "site_name": config.site_name,
                "detail_task_payload": detail_task.to_dict(),
                "fetch_attempt": 0,
            },
            queue=queue_name,
            task_id=job_id,
            priority=_detail_priority(detail_task),
        )
    except Exception as exc:
        if detail_task.metadata.get("frontier_token"):
            with get_db_connection() as connection:
                fail_frontier_dispatch(connection, config.site_name, detail_task.target_url, job_id)
                connection.commit()
        else:
            mark_job_finished(
                job_id=job_id, site_name=config.site_name, job_type="detail",
                queue_name=queue_name, target=detail_task.target_url,
                status="failed", duration_ms=0, error_message=str(exc),
            )
        raise
    return str(async_result.id)


def _detail_priority(detail_task: DetailTask) -> int:
    return 9 if detail_task.metadata.get("discovery_lane") == "backfill" else 0


def _mark_retry_enqueued(
    *,
    job_id: str,
    site_name: str,
    job_type: str,
    queue_name: str,
    target: str,
) -> None:
    try:
        mark_job_enqueued(
            job_id=job_id,
            site_name=site_name,
            job_type=job_type,
            queue_name=queue_name,
            target=target,
        )
    except Exception:
        logger.exception("failed to mark retrying %s job as enqueued", job_type)


def _save_ransomware_live_status(payload: dict[str, object]) -> None:
    try:
        save_ransomware_live_sync_status(payload)
    except Exception:
        logger.exception("failed to persist ransomware.live sync status")


def _parse_timestamp(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ransomware_live_sync_is_due(latest_job: dict | None, interval_seconds: int) -> bool:
    if not latest_job:
        return True
    latest_at = _parse_timestamp(
        latest_job.get("finished_at") or latest_job.get("started_at") or latest_job.get("enqueued_at")
    )
    if latest_at is None:
        return True
    return datetime.now(timezone.utc) >= latest_at + timedelta(seconds=max(60, interval_seconds))


def enqueue_ransomware_live_sync(*, limit: int | None = None, force: bool = False) -> str | None:
    sync_config = get_ransomware_live_sync_config()
    if not get_ransomware_live_api_key():
        if force:
            raise RuntimeError("RANSOMWARE_LIVE_API_KEY is not set")
        return None
    if not force and not sync_config["enabled"]:
        return None
    with get_db_connection() as connection:
        if get_active_crawl_job(connection, RANSOMWARE_LIVE_SITE_NAME, RANSOMWARE_LIVE_JOB_TYPE):
            return None
        latest_job = get_latest_crawl_job(connection, RANSOMWARE_LIVE_SITE_NAME, RANSOMWARE_LIVE_JOB_TYPE)
    if not force and not _ransomware_live_sync_is_due(latest_job, int(sync_config["interval_seconds"])):
        return None

    job_id = str(uuid.uuid4())
    selected_limit = int(sync_config["limit"]) if limit is None else max(0, int(limit))
    mark_job_enqueued(
        job_id=job_id,
        site_name=RANSOMWARE_LIVE_SITE_NAME,
        job_type=RANSOMWARE_LIVE_JOB_TYPE,
        queue_name=SEED_HTTP_QUEUE,
        target=RANSOMWARE_LIVE_API_URL,
    )
    try:
        async_result = sync_ransomware_live.apply_async(
            kwargs={"limit": selected_limit},
            queue=SEED_HTTP_QUEUE,
            task_id=job_id,
        )
    except Exception as exc:
        mark_job_finished(
            job_id=job_id,
            site_name=RANSOMWARE_LIVE_SITE_NAME,
            job_type=RANSOMWARE_LIVE_JOB_TYPE,
            queue_name=SEED_HTTP_QUEUE,
            target=RANSOMWARE_LIVE_API_URL,
            status="failed",
            duration_ms=0,
            error_message=str(exc),
        )
        raise
    return str(async_result.id)


@app.task(bind=True, name="darkweb_collector.tasks.sync_ransomware_live")
def sync_ransomware_live(self, limit: int = 0) -> dict[str, object]:
    started_at = utc_now_iso()
    start_perf = time.perf_counter()
    mark_job_running(
        job_id=self.request.id,
        site_name=RANSOMWARE_LIVE_SITE_NAME,
        job_type=RANSOMWARE_LIVE_JOB_TYPE,
        queue_name=_queue_name_from_request(self),
        target=RANSOMWARE_LIVE_API_URL,
    )
    _save_ransomware_live_status(
        {
            "last_job_id": self.request.id,
            "last_tick_at": started_at,
            "last_error": "",
        }
    )
    try:
        result = sync_ransomware_live_victims(limit=limit, refresh_normalized=False)
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        _save_ransomware_live_status(
            {
                "last_job_id": self.request.id,
                "last_tick_at": started_at,
                "last_error": str(exc),
            }
        )
        if self.request.retries < MAX_RETRIES:
            _mark_retry_enqueued(
                job_id=self.request.id,
                site_name=RANSOMWARE_LIVE_SITE_NAME,
                job_type=RANSOMWARE_LIVE_JOB_TYPE,
                queue_name=SEED_HTTP_QUEUE,
                target=RANSOMWARE_LIVE_API_URL,
            )
            raise self.retry(exc=exc, countdown=retry_backoff_seconds(self.request.retries))
        mark_job_finished(
            job_id=self.request.id,
            site_name=RANSOMWARE_LIVE_SITE_NAME,
            job_type=RANSOMWARE_LIVE_JOB_TYPE,
            queue_name=SEED_HTTP_QUEUE,
            target=RANSOMWARE_LIVE_API_URL,
            status="failed",
            duration_ms=duration_ms,
            error_message=str(exc),
        )
        logger.exception("ransomware.live sync failed")
        raise

    finished_at = utc_now_iso()
    duration_ms = int((time.perf_counter() - start_perf) * 1000)
    mark_job_finished(
        job_id=self.request.id,
        site_name=RANSOMWARE_LIVE_SITE_NAME,
        job_type=RANSOMWARE_LIVE_JOB_TYPE,
        queue_name=SEED_HTTP_QUEUE,
        target=RANSOMWARE_LIVE_API_URL,
        status="succeeded",
        duration_ms=duration_ms,
    )
    _save_ransomware_live_status(
        {
            "last_job_id": self.request.id,
            "last_tick_at": started_at,
            "last_success_at": finished_at,
            "last_error": "",
            "last_source": result.get("source"),
            "last_fetched": result.get("fetched"),
            "last_ingested": result.get("ingested"),
            "last_new": result.get("new_count"),
            "last_updated": result.get("updated_count"),
            "last_unchanged": result.get("unchanged_count"),
        }
    )
    return result


@app.task(bind=True, name="darkweb_collector.tasks.crawl_seed")
def crawl_seed(self, site_name: str, force: bool = False) -> dict[str, object]:
    queue_name = _queue_name_from_request(self)
    start_perf = time.perf_counter()
    try:
        mark_job_running(
            job_id=self.request.id,
            site_name=site_name,
            job_type="seed",
            queue_name=queue_name,
            target=site_name,
        )
        result = execute_seed_job(
            site_name=site_name,
            queue_name=queue_name,
            force=force,
            state_store=get_state_store(prefer_redis=True),
            detail_dispatcher=_enqueue_detail_task,
            attempt=self.request.retries,
            job_id=self.request.id,
        )
    except SiteAuthenticationRequired as exc:
        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        mark_job_finished(
            job_id=self.request.id,
            site_name=site_name,
            job_type="seed",
            queue_name=queue_name,
            target=site_name,
            status="skipped",
            duration_ms=duration_ms,
            error_message=f"auth_required: {safe_failure_text(str(exc), limit=3500)}",
        )
        return {
            "site_name": site_name,
            "seed_job_id": self.request.id,
            "reason": "auth_required",
            "auth_platform": exc.platform,
        }
    except Exception as exc:
        duration_ms = int((time.perf_counter() - start_perf) * 1000)
        failure = None
        if isinstance(exc, CollectionFailure):
            failure = CollectionFailure(
                exc.kind, safe_failure_text(str(exc), limit=3500), scope=exc.scope, retry_after=exc.retry_after,
            )
        if self.request.retries < MAX_RETRIES:
            _mark_retry_enqueued(
                job_id=self.request.id,
                site_name=site_name,
                job_type="seed",
                queue_name=queue_name,
                target=site_name,
            )
            countdown = retry_backoff_seconds(self.request.retries)
            if failure is not None:
                countdown = max(countdown, failure.retry_after)
            raise self.retry(exc=failure or exc, countdown=countdown)
        mark_job_finished(
            job_id=self.request.id,
            site_name=site_name,
            job_type="seed",
            queue_name=queue_name,
            target=site_name,
            status="failed",
            duration_ms=duration_ms,
            error_message=f"{failure.kind}: {failure}" if failure is not None else str(exc),
        )
        if failure is not None:
            raise failure from None
        raise
    duration_ms = int((time.perf_counter() - start_perf) * 1000)
    mark_job_finished(
        job_id=self.request.id,
        site_name=site_name,
        job_type="seed",
        queue_name=queue_name,
        target=site_name,
        status="skipped" if result.get("reason") == "source_cooldown" else "succeeded",
        duration_ms=duration_ms,
    )
    return result


@app.task(bind=True, name="darkweb_collector.tasks.crawl_detail")
def crawl_detail(self, site_name: str, detail_task_payload: dict[str, object], fetch_attempt: int = 0) -> dict[str, object]:
    # fetch_attempt stays accepted for messages published by older releases.
    detail_task = DetailTask.from_dict(detail_task_payload)
    config = get_site_config(site_name)
    queue_name = _queue_name_from_request(self)
    frontier_token = str(detail_task.metadata.get("frontier_token") or "")
    try:
        with get_db_connection() as connection:
            duplicate = connection.execute("SELECT owner_token FROM crawl_detail_control WHERE owner_token = ?",
                                           (self.request.id,)).fetchone()
            if duplicate:
                return {"site_name": site_name, "detail_job_id": self.request.id, "reason": "duplicate_delivery"}
    except Exception as error:
        # Storage outages must not turn into an immediate broker requeue loop.
        raise self.retry(exc=error, countdown=30, max_retries=MAX_RETRIES)
    if frontier_token:
        try:
            with get_db_connection() as connection:
                admission = accept_frontier_delivery(connection, site_name, detail_task.target_url, frontier_token)
                connection.commit()
        except Exception as error:
            raise self.retry(exc=error, countdown=30, max_retries=MAX_RETRIES)
        if admission in {"returned", "stale"}:
            if admission == "returned":
                _dispatch_frontier_jobs(config, _enqueue_detail_task)
            else:
                with get_db_connection() as connection:
                    connection.execute("""UPDATE crawl_jobs SET status = 'skipped', finished_at = ?,
                        error_message = 'stale_frontier' WHERE job_id = ?
                        AND status IN ('enqueued', 'running') AND finished_at IS NULL""",
                        (utc_now_iso(), self.request.id))
                    connection.commit()
            return {"site_name": site_name, "detail_job_id": self.request.id, "reason": "stale_frontier"}
    state_store = get_state_store(prefer_redis=True)
    slot_owner = f"{self.request.id}:{getattr(self.request, 'hostname', '') or 'worker'}"
    admission_reason = "detail_slot_wait"
    try:
        acquired = state_store.acquire_detail_slot(
            site_name, slot_owner, config.max_concurrent_details, config.detail_slot_ttl_seconds)
    except Exception as error:
        logger.warning("detail admission unavailable for %s (%s)", site_name, type(error).__name__)
        acquired = False
        admission_reason = "infrastructure"
    if not acquired:
        # Waiting for a site slot is admission control, not another fetch attempt.
        # The active collector refills this small window when it releases its slot.
        with get_db_connection() as connection:
            if admission_reason == "infrastructure":
                pause_site(connection, site_name, "infrastructure", 60)
            if frontier_token:
                fail_frontier(connection, site_name, detail_task.target_url, frontier_token,
                              retry_seconds=60 if admission_reason == "infrastructure" else 30,
                              error_message=admission_reason)
            connection.commit()
        mark_job_finished(job_id=self.request.id, site_name=site_name, job_type="detail",
                          queue_name=queue_name, target=detail_task.target_url,
                          status="failed" if admission_reason == "infrastructure" else "skipped",
                          duration_ms=0, error_message=admission_reason)
        return {"site_name": site_name, "detail_job_id": self.request.id, "reason": admission_reason}
    try:
        return execute_detail_job(site_name=site_name, detail_task=detail_task, queue_name=queue_name,
                                  job_id=self.request.id, slot_owner=slot_owner)
    finally:
        try:
            state_store.release_detail_slot(site_name, slot_owner)
        except Exception:
            logger.exception("failed to release detail slot for %s", site_name)
        if frontier_token:
            try:
                _dispatch_frontier_jobs(config, _enqueue_detail_task)
            except Exception:
                logger.exception("failed to refill detail window for %s", site_name)
