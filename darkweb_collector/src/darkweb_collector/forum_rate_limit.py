from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import time

from darkweb_collector.collection_errors import CollectionFailure, classify_failure


GUARDED_SITES = frozenset({"spear", "leakforum"})
NETWORK_FAILURES = frozenset({"rate_limited", "blocked", "auth_required"})
REQUEST_INTERVAL_SECONDS = 15
_source: ContextVar[str | None] = ContextVar("public_forum_source", default=None)


def scope_active() -> bool:
    return _source.get() in GUARDED_SITES


def reserve_source_request(connection, site_name: str, *, now: float | None = None) -> float:
    """Admit now, or return the next eligible time without reserving a future slot."""
    timestamp = time.time() if now is None else float(now)
    row = connection.execute("""INSERT INTO crawl_source_request_control(site_name, request_at)
        VALUES (?, ?) ON CONFLICT(site_name) DO UPDATE SET request_at = excluded.request_at
        WHERE crawl_source_request_control.request_at + ? <= excluded.request_at
        RETURNING request_at""",
        (site_name, timestamp, REQUEST_INTERVAL_SECONDS)).fetchone()
    if row is not None:
        return float(row[0])
    row = connection.execute(
        "SELECT request_at FROM crawl_source_request_control WHERE site_name = ?", (site_name,),
    ).fetchone()
    return float(row[0]) + REQUEST_INTERVAL_SECONDS


def _check_cooldown(connection, site_name: str) -> None:
    row = connection.execute(
        "SELECT failure_kind, next_retry FROM crawl_site_control WHERE site_name = ?", (site_name,),
    ).fetchone()
    remaining = float(row[1]) - time.time() if row else 0
    if remaining > 0:
        failure = CollectionFailure(str(row[0]), "source is in a persisted cooldown", scope="site", retry_after=remaining)
        failure._forum_backoff = (site_name, float(row[1]))
        raise failure


def before_source_request() -> None:
    site_name = _source.get()
    if site_name not in GUARDED_SITES:
        return
    from darkweb_collector.db import get_db_connection

    while True:
        with get_db_connection() as connection:
            # Recheck after each wait: another task may have received 429.
            _check_cooldown(connection, site_name)
            timestamp = time.time()
            request_at = reserve_source_request(connection, site_name, now=timestamp)
            connection.commit()
        if request_at <= timestamp:
            return
        delay = request_at - time.time()
        if delay > 0:
            time.sleep(delay)


def note_source_failure(site_name: str, error: Exception, *, now: float | None = None) -> float:
    failure = classify_failure(error)
    if site_name not in GUARDED_SITES or failure.kind not in NETWORK_FAILURES:
        return 0.0
    from darkweb_collector.db import get_db_connection
    from darkweb_collector.detail_lifecycle import pause_site, site_retry_at

    timestamp = time.time() if now is None else float(now)
    with get_db_connection() as connection:
        # Re-observing a cached cooldown must not extend it indefinitely.
        observed = getattr(failure, "_forum_backoff", None)
        deadline = observed[1] if observed and observed[0] == site_name else timestamp + max(1800, failure.retry_after)
        failure._forum_backoff = (site_name, deadline)
        delay = max(0, deadline - timestamp)
        pause_site(connection, site_name, failure.kind, delay, now=timestamp)
        retry_at = site_retry_at(connection, site_name, include_detail=False)
        connection.commit()
    return retry_at


@contextmanager
def source_request_scope(site_name: str):
    if site_name not in GUARDED_SITES:
        yield
        return
    token = _source.set(site_name)
    try:
        yield
    except CollectionFailure as failure:
        if failure.kind not in NETWORK_FAILURES:
            raise
        failure.scope = "site"
        note_source_failure(site_name, failure)
        raise
    finally:
        _source.reset(token)
