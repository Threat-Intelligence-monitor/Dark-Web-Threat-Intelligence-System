from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from threading import Event, Lock, Thread
import time
from typing import Any

from darkweb_collector.db import get_db_connection
import darkweb_collector.normalized_intelligence as normalized_intelligence
from darkweb_collector.search_index import ensure_keyword_index_ready


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
    "last_error": "",
    "pending": False,
    "last_duration_seconds": 0.0,
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
            _state.update(running=True, last_started_at=_now_utc_iso(), last_error="")
    if already_running:
        return get_normalization_runtime_status()
    pending = False
    converged = False
    try:
        with get_db_connection() as connection:
            pending = normalized_intelligence.should_refresh_normalized_intelligence(connection)
            if pending:
                normalized_intelligence.ensure_normalized_intelligence(
                    connection,
                    force=False,
                    enrichment_budget=0,
                )
                pending = normalized_intelligence.should_refresh_normalized_intelligence(connection)
                converged = not pending
            if ensure_keyword_index_ready(connection):
                logger.info("keyword search index backfill completed")
            connection.commit()
        if converged:
            logger.info("normalized intelligence refresh converged in %.2fs", time.perf_counter() - started)
        with _state_lock:
            _state["pending"] = pending
            if converged:
                _state["last_success_at"] = _now_utc_iso()
    except Exception as exc:
        pending = True
        logger.exception("background normalized intelligence refresh failed")
        with _state_lock:
            _state.update(pending=True, last_error=str(exc))
    finally:
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
        run_normalization_cycle()
        if stop_event.wait(normalization_interval_seconds()):
            break


def start_normalization_worker() -> dict[str, Any]:
    global _stop_event, _worker_thread
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
    with _worker_lock:
        if _stop_event is not None:
            _stop_event.set()
    return get_normalization_runtime_status()
