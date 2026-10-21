from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from threading import Event, Lock, Thread
import time
from typing import Any

from darkweb_collector.db import get_db_connection
from darkweb_collector.incremental_intelligence import refresh_incremental_intelligence
import darkweb_collector.normalized_intelligence as normalized_intelligence


logger = logging.getLogger("darkweb_collector.normalization_runtime")
DEFAULT_NORMALIZATION_INTERVAL_SECONDS = 30
_state_lock = Lock()
_worker_lock = Lock()
_stop_event: Event | None = None
_worker_thread: Thread | None = None
_state: dict[str, Any] = {
    "running": False,
    "last_started_at": "",
    "last_success_at": "",
    "last_published_at": "",
    "last_error": "",
    "pending": False,
    "last_duration_seconds": 0.0,
    "processed": 0,
    "published": 0,
    "removed": 0,
    "bootstrap_pending": 0,
}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalization_interval_seconds() -> int:
    try:
        configured = int(
            os.environ.get(
                "DARKWEB_NORMALIZATION_INTERVAL_SECONDS",
                DEFAULT_NORMALIZATION_INTERVAL_SECONDS,
            )
        )
    except (TypeError, ValueError):
        configured = DEFAULT_NORMALIZATION_INTERVAL_SECONDS
    return max(5, configured)


def get_normalization_runtime_status() -> dict[str, Any]:
    with _state_lock:
        state = dict(_state)
    state.update(
        {
            "enabled": bool(_worker_thread and _worker_thread.is_alive()),
            "interval_seconds": normalization_interval_seconds(),
        }
    )
    return state


def run_normalization_cycle() -> dict[str, Any]:
    started = time.perf_counter()
    already_running = False
    with _state_lock:
        if _state["running"]:
            already_running = True
        else:
            _state.update(running=True, last_started_at=_now_utc_iso(), last_error="",
                          processed=0, published=0, removed=0)
    if already_running:
        return get_normalization_runtime_status()
    release_local = False
    try:
        result = None
        with get_db_connection() as connection:
            if getattr(connection, "backend_name", "") == "postgresql":
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            acquired, release_local = normalized_intelligence._try_acquire_normalized_refresh_lock(connection)
            if acquired:
                result = refresh_incremental_intelligence(connection)
            connection.commit()
        with _state_lock:
            if result is None:
                _state["pending"] = True
            else:
                _state.update(
                    pending=bool(result["pending"]),
                    processed=result["processed"],
                    published=result["published"],
                    removed=result["removed"],
                    bootstrap_pending=result["bootstrap_pending"],
                    last_success_at=_now_utc_iso(),
                )
                if result["published"] or result["removed"]:
                    _state["last_published_at"] = _state["last_success_at"]
    except Exception as exc:
        logger.exception("background normalized intelligence refresh failed")
        with _state_lock:
            _state.update(pending=True, last_error=str(exc))
    finally:
        if release_local:
            normalized_intelligence._NORMALIZED_REFRESH_LOCK.release()
        with _state_lock:
            _state.update(
                running=False,
                last_duration_seconds=round(time.perf_counter() - started, 3),
            )
    return get_normalization_runtime_status()


def _normalization_loop(stop_event: Event) -> None:
    if stop_event.wait(min(5, normalization_interval_seconds())):
        return
    while not stop_event.is_set():
        status = run_normalization_cycle()
        delay = 1 if status["pending"] else normalization_interval_seconds()
        if stop_event.wait(delay):
            break


def start_normalization_worker() -> dict[str, Any]:
    global _stop_event, _worker_thread
    from darkweb_collector.normalization_notifications import start_notification_worker

    start_notification_worker()
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return get_normalization_runtime_status()
        stop_event = Event()
        thread = Thread(
            target=_normalization_loop,
            args=(stop_event,),
            name="normalized-intelligence-refresh",
            daemon=True,
        )
        _stop_event = stop_event
        _worker_thread = thread
        thread.start()
    logger.info(
        "normalized intelligence background refresh enabled at %ss intervals",
        normalization_interval_seconds(),
    )
    return get_normalization_runtime_status()


def stop_normalization_worker() -> dict[str, Any]:
    from darkweb_collector.normalization_notifications import stop_notification_worker

    stop_notification_worker()
    with _worker_lock:
        if _stop_event is not None:
            _stop_event.set()
    return get_normalization_runtime_status()
