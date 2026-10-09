from __future__ import annotations

import atexit
from concurrent.futures import Future, ProcessPoolExecutor
from threading import Lock
from typing import Any

from darkweb_collector.queueing import browser_concurrency


_POOL_LOCK = Lock()
_POOL: ProcessPoolExecutor | None = None
_POOL_SIZE = 0
_FUTURES: dict[str, Future] = {}


def _run_browser_site_once(site_name: str, job_id: str, force: bool = True) -> dict[str, object]:
    try:
        from darkweb_collector.orchestrator import run_site_once

        return run_site_once(site_name=site_name, job_id=job_id, force=force)
    finally:
        try:
            from darkweb_collector.browser_client import close_browser_client

            close_browser_client(all_threads=True)
        except Exception:
            pass


def _prune_locked() -> None:
    completed = [job_id for job_id, future in _FUTURES.items() if future.done()]
    for job_id in completed:
        _FUTURES.pop(job_id, None)


def _future_done(job_id: str, future: Future) -> None:
    try:
        future.result()
    except Exception:
        # Startup failures can occur before run_site_once records any result.
        try:
            from darkweb_collector.orchestrator import mark_seed_dispatch_failed

            mark_seed_dispatch_failed(job_id)
        except Exception:
            pass
    with _POOL_LOCK:
        _FUTURES.pop(job_id, None)


def _get_pool_locked() -> ProcessPoolExecutor:
    global _POOL, _POOL_SIZE
    desired_size = browser_concurrency()
    if _POOL is None or _POOL_SIZE != desired_size:
        if _POOL is not None:
            _POOL.shutdown(wait=False, cancel_futures=False)
        _POOL = ProcessPoolExecutor(max_workers=desired_size)
        _POOL_SIZE = desired_size
    return _POOL


def submit_browser_site(site_name: str, job_id: str, *, force: bool = True) -> None:
    with _POOL_LOCK:
        _prune_locked()
        pool = _get_pool_locked()
        future = pool.submit(_run_browser_site_once, site_name, job_id, force)
        _FUTURES[job_id] = future
    future.add_done_callback(lambda completed: _future_done(job_id, completed))


def browser_process_pool_status() -> dict[str, Any]:
    with _POOL_LOCK:
        _prune_locked()
        return {
            "max_workers": browser_concurrency(),
            "running_or_pending": len(_FUTURES),
            "job_ids": sorted(_FUTURES),
        }


def shutdown_browser_process_pool() -> None:
    global _POOL, _POOL_SIZE
    with _POOL_LOCK:
        if _POOL is not None:
            _POOL.shutdown(wait=False, cancel_futures=False)
            _POOL = None
            _POOL_SIZE = 0
        _FUTURES.clear()


atexit.register(shutdown_browser_process_pool)
