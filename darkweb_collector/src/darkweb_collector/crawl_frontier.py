from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
import hashlib
import json
import time

from darkweb_collector.models import DetailTask


DISPATCH_RESERVATION_SECONDS = 60
_AVAILABLE = """(
    f.status = 'pending'
    OR (f.status IN ('dispatching', 'running') AND f.lease_until <= ?)
    OR (f.status = 'queued' AND f.lease_until > 0 AND f.lease_until <= ?
        AND NOT EXISTS (SELECT 1 FROM crawl_jobs j WHERE j.job_id = f.lease_token))
)"""
_ACTIVE = """(
    (f.status IN ('dispatching', 'running') AND f.lease_until > ?)
    OR (f.status = 'queued' AND (f.lease_until = 0 OR f.lease_until > ?
        OR EXISTS (SELECT 1 FROM crawl_jobs j WHERE j.job_id = f.lease_token)))
)"""


FRONTIER_SCHEMA = """
CREATE TABLE IF NOT EXISTS crawl_frontier (
    site_name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    section TEXT NOT NULL DEFAULT '',
    discovery_lane TEXT NOT NULL DEFAULT 'recent',
    metadata_json TEXT NOT NULL,
    observed_version TEXT NOT NULL,
    fetched_version TEXT NOT NULL DEFAULT '',
    claimed_version TEXT NOT NULL DEFAULT '',
    artifacts_complete INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    lease_token TEXT NOT NULL DEFAULT '',
    lease_until DOUBLE PRECISION NOT NULL DEFAULT 0,
    next_retry DOUBLE PRECISION NOT NULL DEFAULT 0,
    first_seen_at DOUBLE PRECISION NOT NULL,
    observed_at DOUBLE PRECISION NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL,
    last_claimed_at DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (site_name, target_url)
);
CREATE INDEX IF NOT EXISTS idx_crawl_frontier_pending
ON crawl_frontier(site_name, status, next_retry, lease_until);
CREATE INDEX IF NOT EXISTS idx_crawl_frontier_section
ON crawl_frontier(site_name, discovery_lane, section, last_claimed_at);
CREATE TABLE IF NOT EXISTS crawl_frontier_admission (
    site_name TEXT PRIMARY KEY,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS crawl_page_cursors (
    site_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    next_page INTEGER NOT NULL DEFAULT 2,
    last_signature TEXT NOT NULL DEFAULT '',
    completed_at TEXT NOT NULL DEFAULT '',
    updated_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (site_name, source_url)
);
"""


def ensure_frontier_schema(connection) -> None:
    """Called once during database initialization, never by frontier operations."""
    for statement in FRONTIER_SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)


def _timestamp(now: float | None) -> float:
    return time.time() if now is None else float(now)


def _task(row, *, claimed: bool = False) -> DetailTask:
    metadata = json.loads(row["metadata_json"])
    metadata["source_version"] = row["observed_version"]
    metadata["section"] = row["section"]
    metadata["discovery_lane"] = row["discovery_lane"]
    if claimed:
        metadata["frontier_token"] = row["lease_token"]
        metadata["frontier_version"] = row["claimed_version"]
        metadata["frontier_artifact_only"] = row["fetched_version"] == row["claimed_version"]
    return DetailTask(row["site_name"], row["target_url"], metadata)


def observe_frontier(connection, site_name: str, detail_tasks: Iterable[DetailTask], now=None) -> int:
    """Remember every discovered version without disturbing an in-flight owner."""
    timestamp = _timestamp(now)
    count = 0
    for task in detail_tasks:
        if task.site_name != site_name:
            raise ValueError("Frontier task site does not match observation site")
        metadata = {key: value for key, value in task.metadata.items() if not key.startswith("frontier_")}
        source_version = str(metadata.get("source_version") or metadata.get("content_hash") or "")
        if not source_version:
            version_metadata = {key: value for key, value in metadata.items() if key != "discovery_lane"}
            source_version = hashlib.sha256(json.dumps(version_metadata, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        metadata["source_version"] = source_version
        section = str(metadata.get("section") or "")
        lane = "backfill" if metadata.get("discovery_lane") == "backfill" else "recent"
        fetched_version = str(task.metadata.get("frontier_fetched_version") or "")
        artifacts_complete = int(bool(fetched_version and task.metadata.get("frontier_artifacts_complete", True)))
        status = "done" if fetched_version == source_version and artifacts_complete else "pending"
        connection.execute(
            """
            INSERT INTO crawl_frontier (
                site_name, target_url, section, discovery_lane, metadata_json,
                observed_version, fetched_version, artifacts_complete, status,
                first_seen_at, observed_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_name, target_url) DO UPDATE SET
                section = excluded.section,
                discovery_lane = CASE WHEN excluded.discovery_lane = 'recent'
                    THEN 'recent' ELSE crawl_frontier.discovery_lane END,
                metadata_json = excluded.metadata_json,
                observed_version = excluded.observed_version,
                observed_at = excluded.observed_at,
                updated_at = excluded.updated_at,
                next_retry = CASE WHEN excluded.observed_version <> crawl_frontier.observed_version
                    THEN 0 ELSE crawl_frontier.next_retry END,
                status = CASE
                    WHEN crawl_frontier.status = 'legacy_queued' THEN 'legacy_queued'
                    WHEN crawl_frontier.status = 'queued' AND (crawl_frontier.lease_until = 0
                        OR EXISTS (SELECT 1 FROM crawl_jobs j WHERE j.job_id = crawl_frontier.lease_token))
                        THEN 'queued'
                    WHEN crawl_frontier.lease_until > excluded.updated_at THEN crawl_frontier.status
                    WHEN excluded.observed_version = crawl_frontier.fetched_version
                        AND crawl_frontier.artifacts_complete = 1 THEN 'done'
                    ELSE 'pending' END
            """,
            (site_name, task.target_url, section, lane, json.dumps(metadata, ensure_ascii=False),
             source_version, fetched_version, artifacts_complete, status, timestamp, timestamp, timestamp),
        )
        count += 1
    return count


def list_frontier_candidates(connection, site_name: str, now=None, limit: int = 1000) -> list[DetailTask]:
    """Serve recent work first, rotating sections within each lane."""
    timestamp = _timestamp(now)
    rows = connection.execute(
        f"""
        WITH activity AS (
            SELECT section, discovery_lane, MAX(last_claimed_at) AS served_at
            FROM crawl_frontier WHERE site_name = ? GROUP BY section, discovery_lane
        ), candidates AS (
            SELECT f.*, a.served_at,
                CASE WHEN f.observed_version = f.fetched_version THEN 1 ELSE 0 END AS artifact_only,
                ROW_NUMBER() OVER (
                    PARTITION BY f.discovery_lane, f.section
                    ORDER BY CASE WHEN f.observed_version = f.fetched_version THEN 1 ELSE 0 END,
                        CASE WHEN f.discovery_lane = 'recent' THEN f.observed_at ELSE 0 END DESC,
                        CASE WHEN f.discovery_lane = 'recent' THEN f.first_seen_at ELSE 0 END DESC,
                        f.last_claimed_at, f.first_seen_at, f.target_url
                ) AS section_rank
            FROM crawl_frontier f
            JOIN activity a ON a.section = f.section AND a.discovery_lane = f.discovery_lane
            WHERE f.site_name = ? AND f.status <> 'done'
                AND f.next_retry <= ? AND {_AVAILABLE}
        )
        SELECT * FROM candidates
        ORDER BY CASE WHEN discovery_lane = 'recent' THEN 0 ELSE 1 END,
            CASE WHEN discovery_lane = 'recent' THEN observed_at ELSE 0 END DESC,
            CASE WHEN discovery_lane = 'recent' THEN first_seen_at ELSE 0 END DESC,
            section_rank, served_at, section
        LIMIT ?
        """,
        (site_name, site_name, timestamp, timestamp, timestamp, max(1, int(limit))),
    ).fetchall()
    return [_task(row) for row in rows]


def count_frontier_active(connection, site_name: str, now=None) -> int:
    timestamp = _timestamp(now)
    return int(connection.execute(
        f"SELECT COUNT(*) FROM crawl_frontier f WHERE f.site_name = ? AND {_ACTIVE}",
        (site_name, timestamp, timestamp),
    ).fetchone()[0])


def _lock_site_admission(connection, site_name, timestamp):
    connection.execute(
        """INSERT INTO crawl_frontier_admission(site_name, updated_at) VALUES (?, ?)
        ON CONFLICT(site_name) DO UPDATE SET updated_at = excluded.updated_at""",
        (site_name, timestamp),
    )
    # Keep already-published messages outside the new window until their first
    # delivery returns them to SQL pending without fetching.
    connection.execute(
        """UPDATE crawl_frontier AS f SET status = 'legacy_queued', lease_until = 0
        WHERE site_name = ? AND status = 'queued' AND lease_until > 0
            AND EXISTS (SELECT 1 FROM crawl_jobs j WHERE j.job_id = f.lease_token)""",
        (site_name,),
    )


def claim_frontier(connection, site_name: str, target_url: str | None, lease_token: str,
                   lease_seconds: float, now=None, *, max_active=2) -> DetailTask | None:
    """Reserve within a per-site transaction lock; None selects the next candidate."""
    if not lease_token:
        raise ValueError("A non-empty frontier lease token is required")
    timestamp = _timestamp(now)
    _lock_site_admission(connection, site_name, timestamp)
    if count_frontier_active(connection, site_name, timestamp) >= max(1, int(max_active)):
        return None
    if target_url is None:
        candidates = list_frontier_candidates(connection, site_name, timestamp, limit=1)
        if not candidates:
            return None
        target_url = candidates[0].target_url
    row = connection.execute(
        f"""
        UPDATE crawl_frontier AS f SET status = 'dispatching', lease_token = ?, lease_until = ?,
            claimed_version = observed_version, last_claimed_at = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND status <> 'done'
            AND next_retry <= ? AND {_AVAILABLE}
        RETURNING *
        """,
        (lease_token, timestamp + max(1, lease_seconds), timestamp, timestamp,
         site_name, target_url, timestamp, timestamp, timestamp),
    ).fetchone()
    return _task(row, claimed=True) if row is not None else None


def accept_frontier_delivery(connection, site_name, target_url, lease_token, *, now=None) -> str:
    """Seal a new delivery, or durably return old published work to pending."""
    timestamp = _timestamp(now)
    _lock_site_admission(connection, site_name, timestamp)
    row = connection.execute(
        "SELECT status FROM crawl_frontier WHERE site_name = ? AND target_url = ? AND lease_token = ?",
        (site_name, target_url, lease_token),
    ).fetchone()
    if row is None:
        return 'stale'
    if row['status'] == 'legacy_queued':
        connection.execute(
            """UPDATE crawl_frontier SET status = 'pending',
                discovery_lane = CASE WHEN observed_version <> claimed_version THEN 'recent' ELSE 'backfill' END,
                lease_token = '', lease_until = 0, claimed_version = '', next_retry = 0, updated_at = ?
            WHERE site_name = ? AND target_url = ? AND lease_token = ? AND status = 'legacy_queued'""",
            (timestamp, site_name, target_url, lease_token),
        )
        connection.execute(
            """UPDATE crawl_jobs SET status = 'skipped', finished_at = ?, duration_ms = 0,
                error_message = 'legacy_returned_to_frontier' WHERE job_id = ?""",
            (datetime.fromtimestamp(timestamp, timezone.utc).isoformat(), lease_token),
        )
        return 'returned'
    return 'accepted' if renew_frontier(connection, site_name, target_url, lease_token, now=timestamp) else 'stale'


def mark_frontier_queued(connection, site_name, target_url, lease_token, now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        """UPDATE crawl_frontier SET status = 'queued', lease_until = 0, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ?
            AND status = 'dispatching' AND lease_until > ?""",
        (timestamp, site_name, target_url, lease_token, timestamp),
    )
    return cursor.rowcount == 1


def fail_frontier_dispatch(connection, site_name, target_url, lease_token, *, error_message='dispatch_failed', now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        """UPDATE crawl_frontier SET status = 'pending', lease_token = '', lease_until = 0,
            claimed_version = '', next_retry = ?, last_error = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ? AND status = 'dispatching'""",
        (timestamp + 60, str(error_message)[:1000], timestamp, site_name, target_url, lease_token),
    )
    if cursor.rowcount != 1:
        return False
    connection.execute(
        """UPDATE crawl_jobs SET status = 'failed', finished_at = ?, duration_ms = 0, error_message = ?
        WHERE job_id = ? AND status = 'enqueued' AND finished_at IS NULL""",
        (datetime.fromtimestamp(timestamp, timezone.utc).isoformat(), str(error_message)[:1000], lease_token),
    )
    return True


def start_frontier(connection, site_name, target_url, lease_token, lease_seconds=300, now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        f"""UPDATE crawl_frontier AS f SET status = 'running', lease_until = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ?
            AND status IN ('dispatching', 'queued') AND {_ACTIVE}""",
        (timestamp + max(1, lease_seconds), timestamp, site_name, target_url, lease_token, timestamp, timestamp),
    )
    return cursor.rowcount == 1


def renew_frontier(connection, site_name, target_url, lease_token, now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        f"""UPDATE crawl_frontier AS f SET
            lease_until = 0,
            status = CASE WHEN status = 'dispatching' THEN 'queued' ELSE status END, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ?
            AND status IN ('dispatching', 'queued') AND {_ACTIVE}""",
        (timestamp, site_name, target_url, lease_token, timestamp, timestamp),
    )
    return cursor.rowcount == 1


def retry_frontier(connection, site_name, target_url, lease_token, now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        f"""UPDATE crawl_frontier AS f SET
            lease_until = ?, status = 'dispatching', updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ? AND {_ACTIVE}""",
        (timestamp + DISPATCH_RESERVATION_SECONDS, timestamp, site_name, target_url, lease_token, timestamp, timestamp),
    )
    return cursor.rowcount == 1


def begin_persist_frontier(connection, site_name, target_url, lease_token, lease_seconds=300, now=None) -> bool:
    """Hold the owner row lock until the caller commits detail persistence + completion."""
    timestamp = _timestamp(now)
    expires_at = timestamp + max(1, lease_seconds)
    cursor = connection.execute(
        """UPDATE crawl_frontier SET
            lease_until = CASE WHEN lease_until > ? THEN lease_until ELSE ? END, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ? AND status = 'running' AND lease_until > ?""",
        (expires_at, expires_at, timestamp, site_name, target_url, lease_token, timestamp),
    )
    return cursor.rowcount == 1


def complete_frontier(connection, site_name, target_url, lease_token, *, artifacts_complete=True, retry_seconds=300, now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        """
        UPDATE crawl_frontier SET fetched_version = claimed_version, artifacts_complete = ?,
            status = CASE WHEN observed_version = claimed_version AND ? = 1 THEN 'done' ELSE 'pending' END,
            next_retry = CASE WHEN observed_version <> claimed_version OR ? = 1 THEN 0 ELSE ? END,
            lease_token = '', lease_until = 0, claimed_version = '', last_error = '', updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ?
            AND lease_until > ? AND status = 'running'
        """,
        (int(bool(artifacts_complete)), int(bool(artifacts_complete)), int(bool(artifacts_complete)),
         timestamp + max(0, retry_seconds), timestamp, site_name, target_url, lease_token, timestamp),
    )
    return cursor.rowcount == 1


def fail_frontier(connection, site_name, target_url, lease_token, *, retry_seconds=60, error_message='', now=None) -> bool:
    timestamp = _timestamp(now)
    cursor = connection.execute(
        """
        UPDATE crawl_frontier SET status = 'pending', lease_token = '', lease_until = 0,
            claimed_version = '', next_retry = ?, last_error = ?, updated_at = ?
        WHERE site_name = ? AND target_url = ? AND lease_token = ?
            AND status IN ('queued', 'running')
        """,
        (timestamp + max(0, retry_seconds), str(error_message)[:1000], timestamp, site_name, target_url, lease_token),
    )
    return cursor.rowcount == 1


def count_frontier_pending(connection, site_name: str) -> int:
    row = connection.execute(
        "SELECT COUNT(*) FROM crawl_frontier WHERE site_name = ? AND status <> 'done'", (site_name,),
    ).fetchone()
    return int(row[0])


def _sites_filter(site_names, column="site_name"):
    names = list(dict.fromkeys(site_names)) if site_names is not None else None
    if names is None:
        return names, "", []
    if not names:
        return names, " WHERE 1 = 0", []
    return names, f" WHERE {column} IN ({', '.join('?' for _ in names)})", names


def frontier_counts(connection, site_names=None, now=None) -> dict[str, dict[str, int]]:
    names, where, parameters = _sites_filter(site_names, column="f.site_name")
    timestamp = _timestamp(now)
    rows = connection.execute(
        f"""
        WITH inventory AS (
            SELECT f.*, CASE WHEN {_ACTIVE} THEN 1 ELSE 0 END AS active
            FROM crawl_frontier f {where}
        )
        SELECT site_name, COUNT(*) AS total,
            SUM(CASE WHEN status NOT IN ('done', 'legacy_queued') AND active = 0 THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN status = 'legacy_queued' THEN 1 ELSE active END) AS inflight,
            SUM(CASE WHEN status = 'legacy_queued' THEN 1 ELSE 0 END) AS legacy_queued,
            SUM(CASE WHEN active = 1 AND status = 'dispatching' THEN 1 ELSE 0 END) AS dispatching,
            SUM(CASE WHEN active = 1 AND status = 'queued' THEN 1 ELSE 0 END) AS queued,
            SUM(CASE WHEN active = 1 AND status = 'running' THEN 1 ELSE 0 END) AS running,
            SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) AS completed,
            SUM(CASE WHEN status <> 'done' AND fetched_version = observed_version
                AND artifacts_complete = 0 THEN 1 ELSE 0 END) AS artifacts_pending
        FROM inventory GROUP BY site_name
        """,
        [timestamp, timestamp, *parameters],
    ).fetchall()
    empty = {key: 0 for key in ("total", "pending", "inflight", "dispatching", "queued", "legacy_queued", "running", "completed", "artifacts_pending")}
    result = {name: dict(empty) for name in names or []}
    for row in rows:
        result[row["site_name"]] = {key: int(row[key]) for key in empty}
    return result


def load_page_cursor(connection, site_name: str, source_url: str) -> dict:
    row = connection.execute(
        "SELECT next_page, last_signature, completed_at, updated_at FROM crawl_page_cursors WHERE site_name = ? AND source_url = ?",
        (site_name, source_url),
    ).fetchone()
    return dict(row) if row is not None else {"next_page": 2, "last_signature": "", "completed_at": "", "updated_at": 0.0}


def save_page_cursor(connection, site_name: str, source_url: str, *, next_page: int, last_signature='', completed_at='', now=None) -> None:
    connection.execute(
        """
        INSERT INTO crawl_page_cursors (site_name, source_url, next_page, last_signature, completed_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(site_name, source_url) DO UPDATE SET next_page = excluded.next_page,
            last_signature = excluded.last_signature, completed_at = excluded.completed_at,
            updated_at = excluded.updated_at
        """,
        (site_name, source_url, max(2, int(next_page)), str(last_signature or ''), str(completed_at or ''), _timestamp(now)),
    )


def list_page_cursors(connection, site_names=None) -> dict[str, list[dict]]:
    names, where, parameters = _sites_filter(site_names)
    rows = connection.execute(
        "SELECT site_name, source_url, next_page, last_signature, completed_at, updated_at FROM crawl_page_cursors"
        + where + " ORDER BY site_name, source_url", parameters,
    ).fetchall()
    result = {name: [] for name in names or []}
    for row in rows:
        result.setdefault(row["site_name"], []).append({key: row[key] for key in row.keys() if key != "site_name"})
    return result
