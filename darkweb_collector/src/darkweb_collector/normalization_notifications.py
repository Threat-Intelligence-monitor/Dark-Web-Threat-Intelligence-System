"""Deliver committed intelligence notifications outside the publication worker."""
from __future__ import annotations

import json
import logging
from threading import Event, Lock, Thread
import time

from darkweb_collector.db import get_db_connection
from darkweb_collector.normalized_intelligence import _hydrate_event_row


logger = logging.getLogger("darkweb_collector.normalization_notifications")
_worker_lock = Lock()
_stop_event: Event | None = None
_worker_thread: Thread | None = None
_LEASE_SECONDS = 600


def dispatch_notification_once(*, connection_factory=None, sender=None, now=None) -> dict:
    """Claim one durable item; failed delivery remains retryable after restart."""
    connection_factory = connection_factory or get_db_connection
    now = time.time() if now is None else float(now)
    lease_until = now + _LEASE_SECONDS
    with connection_factory() as connection:
        row = connection.execute("""SELECT event_id, payload, revision, attempts
            FROM normalized_notification_outbox WHERE next_retry <= ? AND lease_until <= ?
            ORDER BY enqueued_at, event_id LIMIT 1""", (now, now)).fetchone()
        if row is None:
            return {"claimed": False}
        row = dict(row)
        claimed = connection.execute("""UPDATE normalized_notification_outbox SET lease_until = ?
            WHERE event_id = ? AND revision = ? AND next_retry <= ? AND lease_until <= ?""",
            (lease_until, row["event_id"], row["revision"], now, now)).rowcount
        connection.commit()
        if claimed != 1:
            return {"claimed": False}

    failed = False
    try:
        if sender is None:
            from darkweb_collector.monitoring_notifications import notify_keyword_matches_for_watchlists

            sender = notify_keyword_matches_for_watchlists
        event = _hydrate_event_row(json.loads(row["payload"]))
        with connection_factory() as connection:
            result = sender(connection, [event])
            connection.commit()
        failed = bool(result and (result.get("failed") or result.get("errors")))
    except Exception as exc:
        failed = True
        logger.warning("intelligence notification delivery failed (%s)", type(exc).__name__)

    with connection_factory() as connection:
        fence = (row["event_id"], row["revision"], lease_until)
        if failed:
            attempts = int(row["attempts"]) + 1
            retry_at = now + min(3600, 5 * 2 ** min(attempts, 10))
            connection.execute("""UPDATE normalized_notification_outbox
                SET attempts = ?, next_retry = ?, lease_until = 0
                WHERE event_id = ? AND revision = ? AND lease_until = ?""", (attempts, retry_at, *fence))
        else:
            connection.execute("""DELETE FROM normalized_notification_outbox
                WHERE event_id = ? AND revision = ? AND lease_until = ?""", fence)
        connection.commit()
    return {"claimed": True, "failed": failed}


def _notification_loop(stop_event: Event) -> None:
    while not stop_event.wait(1):
        try:
            dispatch_notification_once()
        except Exception as exc:
            logger.warning("intelligence notification worker failed (%s)", type(exc).__name__)
            if stop_event.wait(5):
                break


def start_notification_worker() -> None:
    global _stop_event, _worker_thread
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return
        _stop_event = Event()
        _worker_thread = Thread(target=_notification_loop, args=(_stop_event,),
                                name="intelligence-notifications", daemon=True)
        _worker_thread.start()


def stop_notification_worker() -> None:
    with _worker_lock:
        if _stop_event is not None:
            _stop_event.set()
