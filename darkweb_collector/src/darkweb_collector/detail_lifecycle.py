from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
from pathlib import Path
import time

import psutil

from darkweb_collector.collection_errors import CollectionFailure, classify_failure


SCHEMA = """
CREATE TABLE IF NOT EXISTS crawl_detail_control (
    site_name TEXT NOT NULL, target_url TEXT NOT NULL, source_version TEXT NOT NULL DEFAULT '',
    request_count INTEGER NOT NULL DEFAULT 0, budget_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0, failure_kind TEXT NOT NULL DEFAULT '',
    next_retry DOUBLE PRECISION NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
    owner_token TEXT NOT NULL DEFAULT '', owner_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    worker_pid INTEGER NOT NULL DEFAULT 0, worker_started DOUBLE PRECISION NOT NULL DEFAULT 0,
    activity_path TEXT NOT NULL DEFAULT '',
    body_hash TEXT NOT NULL DEFAULT '', updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY(site_name, target_url)
);
CREATE INDEX IF NOT EXISTS idx_detail_control_owner ON crawl_detail_control(owner_token);
CREATE INDEX IF NOT EXISTS idx_detail_control_active ON crawl_detail_control(owner_token) WHERE owner_token <> '';
CREATE TABLE IF NOT EXISTS crawl_site_control (
    site_name TEXT PRIMARY KEY, failure_kind TEXT NOT NULL, next_retry DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS crawl_detail_results (
    job_id TEXT PRIMARY KEY, site_name TEXT NOT NULL, target_url TEXT NOT NULL,
    outcome TEXT NOT NULL, new_count INTEGER NOT NULL DEFAULT 0, updated_count INTEGER NOT NULL DEFAULT 0,
    unchanged_count INTEGER NOT NULL DEFAULT 0, finished_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_detail_results_finished ON crawl_detail_results(finished_at);
"""
REQUEST_LIMIT = 6
BUDGET_SECONDS = 3600
_write_counts: ContextVar[dict | None] = ContextVar("detail_write_counts", default=None)


def ensure_collection_schema(connection) -> None:
    for statement in SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)


def detail_timeout(config) -> int:
    return config.detail_task_timeout_seconds


def source_version(task) -> str:
    supplied = task.metadata.get("source_version") or task.metadata.get("content_hash")
    if supplied:
        return str(supplied)
    stable = {key: task.metadata[key] for key in ("name", "domain", "title", "status", "published_at")
              if key in task.metadata}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def worker_alive(pid: int, started: float) -> bool:
    if not pid:
        return False
    try:
        process = psutil.Process(int(pid))
        return process.create_time() == float(started) and process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied:
        return True


def reset_site_failures(connection, site_name: str) -> None:
    connection.execute("DELETE FROM crawl_site_control WHERE site_name = ?", (site_name,))
    connection.execute("""UPDATE crawl_detail_control SET failure_count = 0, failure_kind = '',
        next_retry = 0, request_count = 0, budget_until = 0, last_error = ''
        WHERE site_name = ? AND owner_token = ''""", (site_name,))
    connection.execute("""UPDATE crawl_frontier SET next_retry = 0, last_error = ''
        WHERE site_name = ? AND status = 'pending' AND NOT EXISTS (
            SELECT 1 FROM crawl_detail_control c WHERE c.site_name = crawl_frontier.site_name
                AND c.target_url = crawl_frontier.target_url AND c.owner_token <> '')""", (site_name,))


def site_retry_at(connection, site_name: str) -> float:
    row = connection.execute("SELECT next_retry FROM crawl_site_control WHERE site_name = ?", (site_name,)).fetchone()
    return float(row[0]) if row else 0.0


def eligible_detail_tasks(connection, site_name: str, tasks: list, *, now=None) -> list:
    timestamp = time.time() if now is None else float(now)
    if site_retry_at(connection, site_name) > timestamp:
        return []
    deferred = {}
    for offset in range(0, len(tasks), 200):
        urls = [task.target_url for task in tasks[offset:offset + 200]]
        placeholders = ",".join("?" for _ in urls)
        rows = connection.execute(f"""SELECT target_url, source_version FROM crawl_detail_control
            WHERE site_name = ? AND next_retry > ? AND target_url IN ({placeholders})""",
            (site_name, timestamp, *urls)).fetchall()
        deferred.update((row["target_url"], row["source_version"]) for row in rows)
    return [task for task in tasks if task.target_url not in deferred or source_version(task) != deferred[task.target_url]]


def pause_site(connection, site_name: str, kind: str, seconds: float, *, now=None) -> None:
    timestamp = time.time() if now is None else float(now)
    connection.execute("""INSERT INTO crawl_site_control(site_name, failure_kind, next_retry, updated_at)
        VALUES (?, ?, ?, ?) ON CONFLICT(site_name) DO UPDATE SET failure_kind = excluded.failure_kind,
        next_retry = CASE WHEN crawl_site_control.next_retry > excluded.next_retry
            THEN crawl_site_control.next_retry ELSE excluded.next_retry END, updated_at = excluded.updated_at""",
        (site_name, kind, timestamp + max(0, seconds), timestamp))


def claim_detail(connection, config, task, token: str, *, now=None) -> str:
    timestamp = time.time() if now is None else float(now)
    version = source_version(task)
    # Serialize site admission even if the broker slot expired during forced cleanup.
    connection.execute("""INSERT INTO crawl_frontier_admission(site_name, updated_at) VALUES (?, ?)
        ON CONFLICT(site_name) DO UPDATE SET updated_at = excluded.updated_at""", (config.site_name, timestamp))
    connection.execute("""INSERT INTO crawl_detail_control(site_name, target_url, source_version, updated_at)
        VALUES (?, ?, ?, ?) ON CONFLICT(site_name, target_url) DO UPDATE SET updated_at = excluded.updated_at""",
        (config.site_name, task.target_url, version, timestamp))
    row = connection.execute("""SELECT * FROM crawl_detail_control
        WHERE site_name = ? AND target_url = ?""", (config.site_name, task.target_url)).fetchone()
    if site_retry_at(connection, config.site_name) > timestamp:
        return "cooldown"
    if row["owner_token"]:
        # A passed clock deadline is not proof that a worker has stopped.
        if row["owner_until"] > timestamp or worker_alive(row["worker_pid"], row["worker_started"]):
            return "busy"
        return "owner_lost"
    changed = bool(row["source_version"] and version != row["source_version"])
    if row["next_retry"] > timestamp and not changed:
        return "cooldown"
    active = connection.execute("""SELECT COUNT(*) FROM crawl_detail_control
        WHERE site_name = ? AND owner_token <> ''""", (config.site_name,)).fetchone()[0]
    if int(active) >= config.max_concurrent_details:
        return "busy"
    process = psutil.Process()
    cursor = connection.execute("""UPDATE crawl_detail_control SET source_version = ?, owner_token = ?,
        owner_until = ?, worker_pid = ?, worker_started = ?, activity_path = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND (owner_token = '' OR owner_token = ?)""",
        (version, token, timestamp + detail_timeout(config) + 60, os.getpid(), process.create_time(),
         os.environ.get("DARKWEB_WORKER_ACTIVITY_FILE", ""), timestamp,
         config.site_name, task.target_url, token))
    return "claimed" if cursor.rowcount == 1 else "busy"


def consume_request(connection, site_name: str, target_url: str, token: str, *, now=None) -> None:
    timestamp = time.time() if now is None else float(now)
    row = connection.execute("""SELECT request_count, budget_until, failure_count FROM crawl_detail_control
        WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
        (site_name, target_url, token)).fetchone()
    if row is None:
        raise CollectionFailure("retry_budget", "task ownership no longer valid")
    if row["budget_until"] <= timestamp:
        connection.execute("""UPDATE crawl_detail_control SET request_count = 0, budget_until = ?
            WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
            (timestamp + BUDGET_SECONDS, site_name, target_url, token))
    # A recovery round may need direct/proxy/browser fallback; its requests still
    # share the persisted hourly limit. Failure cooldown bounds round frequency.
    limit = REQUEST_LIMIT
    cursor = connection.execute("""UPDATE crawl_detail_control SET request_count = request_count + 1
        WHERE site_name = ? AND target_url = ? AND owner_token = ? AND request_count < ?""",
        (site_name, target_url, token, limit))
    if cursor.rowcount != 1:
        raise CollectionFailure("retry_budget", "persistent source request budget exhausted", retry_after=BUDGET_SECONDS)


def owns_detail(connection, site_name: str, target_url: str, token: str) -> bool:
    row = connection.execute("""UPDATE crawl_detail_control SET updated_at = updated_at
        WHERE site_name = ? AND target_url = ? AND owner_token = ? RETURNING owner_token""",
        (site_name, target_url, token)).fetchone()
    return row is not None


def fail_detail(connection, site_name: str, target_url: str, token: str, error: Exception, *, now=None) -> float:
    timestamp = time.time() if now is None else float(now)
    failure = classify_failure(error)
    row = connection.execute("""SELECT failure_count FROM crawl_detail_control
        WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
        (site_name, target_url, token)).fetchone()
    if row is None:
        return 0.0
    count = int(row[0]) + 1
    if failure.kind in {"unavailable", "restricted"}:
        delay = 86400
    elif failure.kind in {"auth_required", "blocked", "rate_limited"}:
        delay = 1800
    elif failure.kind in {"parse", "unknown"}:
        delay = 900 if count == 1 else 3600
    elif failure.kind == "retry_budget":
        delay = BUDGET_SECONDS
    else:
        delay = (60, 300)[count - 1] if count < 3 else 3600
    delay = max(float(delay), failure.retry_after)
    retry_at = timestamp + delay
    connection.execute("""UPDATE crawl_detail_control SET failure_count = ?, failure_kind = ?,
        next_retry = ?, last_error = ?, owner_token = '', owner_until = 0, worker_pid = 0, worker_started = 0,
        updated_at = ? WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
        (count, failure.kind, retry_at, str(failure)[:500], timestamp, site_name, target_url, token))
    if failure.scope == "site":
        pause_site(connection, site_name, failure.kind, delay, now=timestamp)
    return retry_at


def release_detail(connection, site_name, target_url, token) -> None:
    connection.execute("""UPDATE crawl_detail_control SET owner_token = '', owner_until = 0, worker_pid = 0,
        worker_started = 0 WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
        (site_name, target_url, token))


@contextmanager
def count_detail_writes():
    counts = {"new_count": 0, "updated_count": 0, "unchanged_count": 0}
    token = _write_counts.set(counts)
    try:
        yield counts
    finally:
        _write_counts.reset(token)


def record_detail_write(previous_hash: str | None, new_hash: str) -> None:
    counts = _write_counts.get()
    if counts is not None:
        key = "new_count" if previous_hash is None else "unchanged_count" if previous_hash == new_hash else "updated_count"
        counts[key] += 1


def complete_detail(connection, site_name, target_url, token, counts, body_hash, *, artifacts_pending=False, now=None) -> bool:
    if not owns_detail(connection, site_name, target_url, token):
        return False
    timestamp = time.time() if now is None else float(now)
    outcome = "partial" if artifacts_pending else "succeeded"
    connection.execute("""INSERT INTO crawl_detail_results
        (job_id, site_name, target_url, outcome, new_count, updated_count, unchanged_count, finished_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(job_id) DO NOTHING""",
        (token, site_name, target_url, outcome, counts["new_count"], counts["updated_count"],
         counts["unchanged_count"], timestamp))
    connection.execute("""UPDATE crawl_detail_control SET failure_count = 0, failure_kind = '', last_error = '',
        next_retry = ?, request_count = 0, budget_until = 0, owner_token = '', owner_until = 0,
        worker_pid = 0, worker_started = 0, body_hash = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND owner_token = ?""",
        (timestamp + 3600 if artifacts_pending else 0, str(body_hash or ""), timestamp, site_name, target_url, token))
    return True


def reconcile_detail_owners(connection, *, now=None) -> int:
    timestamp = time.time() if now is None else float(now)
    rows = connection.execute("SELECT * FROM crawl_detail_control WHERE owner_token <> ''").fetchall()
    recovered = 0
    for row in rows:
        if worker_alive(row["worker_pid"], row["worker_started"]):
            continue
        if row["activity_path"]:
            try:
                if Path(row["activity_path"]).exists():
                    # Its supervisor must first confirm the entire process tree stopped.
                    continue
            except OSError:
                continue
        token = row["owner_token"]
        fail_detail(connection, row["site_name"], row["target_url"], token,
                    CollectionFailure("timeout", "previous collector process stopped"), now=timestamp)
        connection.execute("""UPDATE crawl_jobs SET status = 'failed', finished_at = ?, error_message = ?
            WHERE job_id = ? AND status IN ('enqueued', 'running') AND finished_at IS NULL""",
            (time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(timestamp)), "worker_lost: collector stopped", token))
        connection.execute("""UPDATE crawl_frontier SET status = 'pending', lease_token = '', lease_until = 0,
            claimed_version = '', next_retry = ?, last_error = 'worker_lost', updated_at = ?
            WHERE site_name = ? AND target_url = ? AND lease_token = ?""",
            (timestamp + 60, timestamp, row["site_name"], row["target_url"], token))
        recovered += 1
    return recovered
