from __future__ import annotations

import time

from darkweb_collector.collection_errors import CollectionFailure
from darkweb_collector.crawl_frontier import fail_frontier
from darkweb_collector.db import get_db_connection
from darkweb_collector.detail_lifecycle import fail_detail, worker_alive
from darkweb_collector.state_store import get_state_store
from darkweb_collector.utils import utc_now_iso


def recover_stopped_task(payload: dict, reason: str = "timeout") -> bool:
    """Called only after the supervisor confirms termination of its owned process tree."""
    job_id = str(payload.get("job_id") or "")
    site_name = str(payload.get("site_name") or "")
    slot_owner = str(payload.get("slot_owner") or "")
    if slot_owner and not slot_owner.startswith(job_id + ":"):
        raise RuntimeError("stopped task slot identity does not match its job")
    if not job_id or not site_name or worker_alive(payload.get("worker_pid", 0), payload.get("worker_started", 0)):
        raise RuntimeError("cannot recover a task without confirmed stopped ownership")
    with get_db_connection() as connection:
        job = connection.execute("SELECT site_name, target FROM crawl_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if job and job["site_name"] != site_name:
            raise RuntimeError("stopped task site does not match the stored job")
        if job:
            owner = connection.execute("""SELECT worker_pid, worker_started FROM crawl_detail_control
                WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
                (site_name, job["target"], job_id)).fetchone()
            if owner and (owner["worker_pid"] != int(payload["worker_pid"]) or
                          owner["worker_started"] != float(payload["worker_started"])):
                raise RuntimeError("stopped task worker identity does not match the stored owner")
            if owner:
                error = CollectionFailure("timeout", "task exceeded its deadline" if reason == "timeout" else "collector process stopped")
                retry_at = fail_detail(connection, site_name, job["target"], job_id, error)
                fail_frontier(connection, site_name, job["target"], job_id,
                              retry_seconds=max(60, retry_at - time.time()), error_message=reason)
                connection.execute("""UPDATE crawl_jobs SET status = 'failed', finished_at = ?, error_message = ?
                    WHERE job_id = ? AND status IN ('enqueued', 'running') AND finished_at IS NULL""",
                    (utc_now_iso(), reason + ": collector process stopped", job_id))
            connection.commit()
    if slot_owner:
        get_state_store(prefer_redis=True).release_detail_slot(site_name, slot_owner)
    return True
