from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import os
import sqlite3
from threading import Lock
import time

from darkweb_collector.crawl_frontier import ensure_frontier_schema
from darkweb_collector.postgres_backend import connect_postgres
from darkweb_collector.search_schema import REPORT_TIME, SEARCH_ORDER, SEVERITY_RANK, ensure_search_indexes
from darkweb_collector.search_index import (
    SEARCH_EXPRESSION,
    ensure_keyword_index_schema,
    mark_search_index_revision,
    search_indexed_events,
    sync_search_documents,
)
from darkweb_collector.runtime import (
    active_release_config,
    configured_database_schema,
    configured_database_url,
    default_db_path,
)


class ManagedConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            return super().__exit__(exc_type, exc_val, exc_tb)
        finally:
            self.close()


_SCHEMA_INIT_LOCK = Lock()
_SCHEMA_INIT_FINGERPRINTS: set[str] = set()


def _has_core_schema(connection: sqlite3.Connection) -> bool:
    required_tables = ("collection_runs", "victims", "victim_details", "normalized_intelligence_events")
    for table_name in required_tables:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        if row is None:
            return False
    return True


def _should_skip_wal(db_path: Path) -> bool:
    resolved = db_path.resolve()
    path_text = resolved.as_posix().lower()
    return os.name != "nt" and path_text.startswith("/mnt/")


def _is_transient_open_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return "unable to open database file" in message or "disk i/o error" in message


SCHEMA = """
CREATE TABLE IF NOT EXISTS collection_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    collected_at_utc TEXT NOT NULL,
    victim_count INTEGER NOT NULL,
    run_metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    detail_url TEXT,
    name TEXT NOT NULL,
    display_label TEXT NOT NULL,
    domain TEXT,
    status TEXT NOT NULL,
    published_at_utc TEXT,
    claimed_size TEXT,
    claimed_size_gb REAL,
    content_hash TEXT NOT NULL,
    first_seen_run_id INTEGER NOT NULL,
    last_seen_run_id INTEGER NOT NULL,
    last_detail_fetch_status TEXT,
    raw_json TEXT NOT NULL,
    UNIQUE(site_name, source_url, name, domain, status)
);

CREATE TABLE IF NOT EXISTS victim_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id INTEGER NOT NULL,
    fetched_at_utc TEXT NOT NULL,
    fetch_status TEXT NOT NULL,
    page_title TEXT,
    text_excerpt TEXT,
    outbound_link_count INTEGER,
    raw_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS forum_topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    section TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT NOT NULL,
    author TEXT,
    replies TEXT,
    views TEXT,
    published_at TEXT,
    last_reply_at TEXT,
    content_hash TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    UNIQUE(site_name, section, url)
);

CREATE TABLE IF NOT EXISTS forum_details (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    section TEXT NOT NULL,
    topic_url TEXT NOT NULL,
    content TEXT,
    authors TEXT,
    timestamps TEXT,
    attachments TEXT,
    victims TEXT,
    attackers TEXT,
    content_hash TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    UNIQUE(site_name, section, topic_url)
);

CREATE TABLE IF NOT EXISTS forum_victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    forum_detail_id INTEGER NOT NULL,
    victim_name TEXT NOT NULL,
    industry TEXT,
    region TEXT,
    FOREIGN KEY (forum_detail_id) REFERENCES forum_details(id)
);

CREATE TABLE IF NOT EXISTS crawl_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL UNIQUE,
    site_name TEXT NOT NULL,
    job_type TEXT NOT NULL,
    queue_name TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    enqueued_at TEXT,
    started_at TEXT,
    finished_at TEXT,
    duration_ms INTEGER,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_crawl_jobs_site_type_status
ON crawl_jobs(site_name, job_type, status);

CREATE INDEX IF NOT EXISTS idx_crawl_jobs_finished_at
ON crawl_jobs(finished_at);

CREATE TABLE IF NOT EXISTS site_connectivity_probes (
    site_name TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    available INTEGER NOT NULL,
    status TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    last_success_at TEXT,
    failure_reason TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulnerability_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    title TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    vulnerability_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL,
    is_exploited INTEGER NOT NULL DEFAULT 0,
    has_poc INTEGER NOT NULL DEFAULT 0,
    patch_available INTEGER NOT NULL DEFAULT 0,
    wide_impact INTEGER NOT NULL DEFAULT 0,
    disclosure_time TEXT NOT NULL,
    affected_versions TEXT NOT NULL,
    summary TEXT NOT NULL,
    advisory_url TEXT NOT NULL,
    reference_urls_json TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE(source_name, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_records_cve
ON vulnerability_records(cve_id);

CREATE INDEX IF NOT EXISTS idx_vulnerability_records_time
ON vulnerability_records(disclosure_time);

CREATE TABLE IF NOT EXISTS ransomware_live_victims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_id TEXT NOT NULL UNIQUE,
    group_name TEXT NOT NULL,
    victim_name TEXT NOT NULL,
    website TEXT NOT NULL,
    country_code TEXT NOT NULL,
    activity TEXT NOT NULL,
    discovered_at TEXT NOT NULL,
    attacked_at TEXT NOT NULL,
    post_url TEXT NOT NULL,
    permalink TEXT NOT NULL,
    screenshot_url TEXT NOT NULL,
    description TEXT NOT NULL,
    press_url TEXT NOT NULL,
    raw_json TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ransomware_live_victims_attacked_at
ON ransomware_live_victims(attacked_at);

CREATE INDEX IF NOT EXISTS idx_ransomware_live_victims_discovered_at
ON ransomware_live_victims(discovered_at);

CREATE INDEX IF NOT EXISTS idx_ransomware_live_victims_last_seen_at
ON ransomware_live_victims(last_seen_at);

CREATE TABLE IF NOT EXISTS platform_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL UNIQUE,
    account_label TEXT NOT NULL,
    login_url TEXT NOT NULL,
    homepage_url TEXT NOT NULL,
    requires_login INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    storage_state_path TEXT NOT NULL,
    last_verified_at TEXT,
    expires_hint TEXT,
    last_error TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposure_watchlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    organization_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exposure_watch_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    term TEXT NOT NULL,
    term_type TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 10,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(watchlist_id, term, term_type),
    FOREIGN KEY (watchlist_id) REFERENCES exposure_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_exposure_watch_terms_watchlist
ON exposure_watch_terms(watchlist_id, enabled);

CREATE TABLE IF NOT EXISTS document_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    platform_type TEXT NOT NULL,
    discovery_source TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    normalized_title TEXT NOT NULL,
    resource_fingerprint TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    access_state TEXT NOT NULL,
    confidence_score INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'low',
    review_status TEXT NOT NULL DEFAULT 'new',
    matched_terms_json TEXT NOT NULL DEFAULT '[]',
    file_count INTEGER NOT NULL DEFAULT 0,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    share_owner TEXT NOT NULL DEFAULT '',
    disclosure_time TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_snapshot_id INTEGER,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(watchlist_id, platform, canonical_url, normalized_title),
    FOREIGN KEY (watchlist_id) REFERENCES exposure_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_document_hits_watchlist
ON document_hits(watchlist_id, risk_score, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_document_hits_review_status
ON document_hits(review_status, access_state);

CREATE UNIQUE INDEX IF NOT EXISTS idx_document_hits_resource_fingerprint
ON document_hits(watchlist_id, platform, resource_fingerprint)
WHERE resource_fingerprint <> '';

CREATE TABLE IF NOT EXISTS document_hit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER NOT NULL,
    fetched_at TEXT NOT NULL,
    source_query TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    page_url TEXT NOT NULL,
    page_title TEXT NOT NULL,
    html_path TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    ocr_text TEXT NOT NULL DEFAULT '',
    preview_text TEXT NOT NULL DEFAULT '',
    file_list_json TEXT NOT NULL DEFAULT '[]',
    access_state TEXT NOT NULL,
    matched_terms_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (hit_id) REFERENCES document_hits(id)
);

CREATE INDEX IF NOT EXISTS idx_document_hit_snapshots_hit
ON document_hit_snapshots(hit_id, fetched_at);

CREATE TABLE IF NOT EXISTS document_hit_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (hit_id) REFERENCES document_hits(id)
);

CREATE INDEX IF NOT EXISTS idx_document_hit_reviews_hit
ON document_hit_reviews(hit_id, created_at);

CREATE TABLE IF NOT EXISTS exposure_scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    source_families_json TEXT NOT NULL DEFAULT '[]',
    requested_terms_json TEXT NOT NULL DEFAULT '[]',
    candidate_count INTEGER NOT NULL DEFAULT 0,
    hit_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    scan_stats_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    errors_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    FOREIGN KEY (watchlist_id) REFERENCES exposure_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_exposure_scan_runs_watchlist
ON exposure_scan_runs(watchlist_id, finished_at);

CREATE TABLE IF NOT EXISTS netdisk_source_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    source_key TEXT NOT NULL,
    term TEXT NOT NULL,
    source_family TEXT NOT NULL DEFAULT 'netdisk_aggregator',
    next_page INTEGER NOT NULL DEFAULT 1,
    last_scanned_page INTEGER NOT NULL DEFAULT 0,
    page_window_size INTEGER NOT NULL DEFAULT 4,
    consecutive_empty_pages INTEGER NOT NULL DEFAULT 0,
    consecutive_repeated_pages INTEGER NOT NULL DEFAULT 0,
    last_candidate_signature TEXT NOT NULL DEFAULT '',
    last_success_at TEXT NOT NULL DEFAULT '',
    last_error_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    backoff_until TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(watchlist_id, source_key, term, source_family),
    FOREIGN KEY (watchlist_id) REFERENCES exposure_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_netdisk_source_states_watchlist
ON netdisk_source_states(watchlist_id, source_key, term);

CREATE TABLE IF NOT EXISTS netdisk_source_health (
    source_key TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'healthy',
    success_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    login_required_count INTEGER NOT NULL DEFAULT 0,
    captcha_count INTEGER NOT NULL DEFAULT 0,
    rate_limited_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_success_at TEXT NOT NULL DEFAULT '',
    last_error_at TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    backoff_until TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS code_watchlists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    organization_name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notes TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS code_watch_terms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    term TEXT NOT NULL,
    term_type TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 10,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(watchlist_id, term, term_type),
    FOREIGN KEY (watchlist_id) REFERENCES code_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_code_watch_terms_watchlist
ON code_watch_terms(watchlist_id, enabled);

CREATE TABLE IF NOT EXISTS code_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    repository_name TEXT NOT NULL,
    repository_owner TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    file_path TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT '',
    file_url TEXT NOT NULL,
    visibility TEXT NOT NULL DEFAULT 'public',
    language TEXT NOT NULL DEFAULT '',
    sensitive_type TEXT NOT NULL,
    matched_rule TEXT NOT NULL DEFAULT '',
    matched_term TEXT NOT NULL DEFAULT '',
    result_layer TEXT NOT NULL DEFAULT 'sensitive',
    risk_score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'low',
    review_status TEXT NOT NULL DEFAULT 'new',
    evidence_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    last_snapshot_id INTEGER,
    raw_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(watchlist_id, platform, file_url, sensitive_type, matched_term),
    FOREIGN KEY (watchlist_id) REFERENCES code_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_code_hits_watchlist
ON code_hits(watchlist_id, risk_score, last_seen_at);

CREATE INDEX IF NOT EXISTS idx_code_hits_review_status
ON code_hits(review_status, platform);

CREATE TABLE IF NOT EXISTS code_hit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER NOT NULL,
    fetched_at TEXT NOT NULL,
    search_url TEXT NOT NULL DEFAULT '',
    page_url TEXT NOT NULL DEFAULT '',
    html_path TEXT NOT NULL DEFAULT '',
    screenshot_path TEXT NOT NULL DEFAULT '',
    code_fragment TEXT NOT NULL DEFAULT '',
    masked_fragment TEXT NOT NULL DEFAULT '',
    raw_artifact_path TEXT NOT NULL DEFAULT '',
    line_start INTEGER NOT NULL DEFAULT 0,
    line_end INTEGER NOT NULL DEFAULT 0,
    language TEXT NOT NULL DEFAULT '',
    findings_json TEXT NOT NULL DEFAULT '[]',
    raw_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (hit_id) REFERENCES code_hits(id)
);

CREATE INDEX IF NOT EXISTS idx_code_hit_snapshots_hit
ON code_hit_snapshots(hit_id, fetched_at);

CREATE TABLE IF NOT EXISTS code_hit_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hit_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (hit_id) REFERENCES code_hits(id)
);

CREATE INDEX IF NOT EXISTS idx_code_hit_reviews_hit
ON code_hit_reviews(hit_id, created_at);

CREATE TABLE IF NOT EXISTS code_scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    platforms_json TEXT NOT NULL DEFAULT '[]',
    requested_terms_json TEXT NOT NULL DEFAULT '[]',
    candidate_count INTEGER NOT NULL DEFAULT 0,
    hit_count INTEGER NOT NULL DEFAULT 0,
    clue_hit_count INTEGER NOT NULL DEFAULT 0,
    sensitive_hit_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    errors_json TEXT NOT NULL DEFAULT '[]',
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    FOREIGN KEY (watchlist_id) REFERENCES code_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_code_scan_runs_watchlist
ON code_scan_runs(watchlist_id, finished_at);

CREATE TABLE IF NOT EXISTS code_search_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL,
    platform TEXT NOT NULL,
    term TEXT NOT NULL,
    query_key TEXT NOT NULL DEFAULT 'base',
    last_page_scanned INTEGER NOT NULL DEFAULT 0,
    last_candidate_signature TEXT NOT NULL DEFAULT '',
    last_candidate_keys_json TEXT NOT NULL DEFAULT '[]',
    last_repository_urls_json TEXT NOT NULL DEFAULT '[]',
    last_run_started_at TEXT NOT NULL DEFAULT '',
    last_run_finished_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT '',
    UNIQUE(watchlist_id, platform, term, query_key),
    FOREIGN KEY (watchlist_id) REFERENCES code_watchlists(id)
);

CREATE INDEX IF NOT EXISTS idx_code_search_states_lookup
ON code_search_states(watchlist_id, platform, term, query_key);

CREATE TABLE IF NOT EXISTS normalized_intelligence_events (
    event_id TEXT PRIMARY KEY,
    source_kind TEXT NOT NULL,
    raw_source_type TEXT NOT NULL,
    source_site_name TEXT NOT NULL,
    source_record_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    category TEXT NOT NULL,
    leak_type TEXT NOT NULL,
    title TEXT NOT NULL,
    attacker TEXT NOT NULL,
    victim TEXT NOT NULL,
    victim_key TEXT NOT NULL,
    industry TEXT NOT NULL,
    region TEXT NOT NULL,
    disclosure_time TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    detail_text TEXT NOT NULL,
    mirror_resources_json TEXT NOT NULL,
    screenshot_resources_json TEXT NOT NULL,
    json_preview_url TEXT NOT NULL,
    risk_reasons_json TEXT NOT NULL,
    event_metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_normalized_intelligence_type_time
ON normalized_intelligence_events(event_type, disclosure_time);

CREATE INDEX IF NOT EXISTS idx_normalized_intelligence_attacker
ON normalized_intelligence_events(attacker);

CREATE INDEX IF NOT EXISTS idx_normalized_intelligence_victim_key
ON normalized_intelligence_events(victim_key);

CREATE TABLE IF NOT EXISTS normalized_intelligence_cache_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    source_signature TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    refreshed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS monitoring_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL,
    category TEXT NOT NULL,
    weight INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    match_mode TEXT NOT NULL DEFAULT 'contains',
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_monitoring_keywords_unique
ON monitoring_keywords(keyword, category);

CREATE TABLE IF NOT EXISTS monitoring_keyword_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    event_key TEXT NOT NULL DEFAULT '',
    match_signature TEXT NOT NULL,
    match_keywords_json TEXT NOT NULL,
    status TEXT NOT NULL,
    dry_run INTEGER NOT NULL DEFAULT 0,
    response_json TEXT NOT NULL,
    error_message TEXT NOT NULL,
    sent_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(event_id, match_signature)
);

CREATE INDEX IF NOT EXISTS idx_monitoring_keyword_notifications_event
ON monitoring_keyword_notifications(event_id);

CREATE INDEX IF NOT EXISTS idx_monitoring_keyword_notifications_status
ON monitoring_keyword_notifications(status, updated_at);

CREATE INDEX IF NOT EXISTS idx_monitoring_keyword_notifications_event_key
ON monitoring_keyword_notifications(event_key, status, dry_run);
"""


LEGACY_COLUMN_ADDITIONS: dict[str, dict[str, str]] = {
    "exposure_watchlists": {
        "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
    },
    "monitoring_keyword_notifications": {
        "event_key": "TEXT NOT NULL DEFAULT ''",
    },
    "document_hits": {
        "resource_fingerprint": "TEXT NOT NULL DEFAULT ''",
    },
    "code_hits": {
        "result_layer": "TEXT NOT NULL DEFAULT 'sensitive'",
    },
    "code_scan_runs": {
        "clue_hit_count": "INTEGER NOT NULL DEFAULT 0",
        "sensitive_hit_count": "INTEGER NOT NULL DEFAULT 0",
    },
    "exposure_scan_runs": {
        "scan_stats_json": "TEXT NOT NULL DEFAULT '[]'",
    },
}


def _list_table_columns(connection: sqlite3.Connection, table_name: str) -> set[str]:
    try:
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    except sqlite3.OperationalError:
        return set()
    return {str(row[1]) for row in rows}


def _ensure_legacy_columns(connection: sqlite3.Connection) -> None:
    for table_name, columns in LEGACY_COLUMN_ADDITIONS.items():
        existing_columns = _list_table_columns(connection, table_name)
        if not existing_columns:
            continue
        for column_name, column_sql in columns.items():
            if column_name in existing_columns:
                continue
            connection.execute(
                f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}"
            )
            existing_columns.add(column_name)


def _ensure_schema(connection: sqlite3.Connection) -> None:
    for statement in [item.strip() for item in SCHEMA.split(";") if item.strip()]:
        try:
            connection.execute(statement)
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            # Older databases in the workspace may have pre-existing tables with
            # narrower schemas. Ignore index-creation failures that only stem from
            # missing legacy columns so we can still create newly added tables.
            if "no such column" in message:
                continue
            raise
    ensure_frontier_schema(connection)
    _ensure_legacy_columns(connection)
    ensure_search_indexes(connection)
    ensure_keyword_index_schema(connection)
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_monitoring_keyword_notifications_event_key
        ON monitoring_keyword_notifications(event_key, status, dry_run)
        """
    )
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_document_hits_resource_fingerprint
        ON document_hits(watchlist_id, platform, resource_fingerprint)
        WHERE resource_fingerprint <> ''
        """
    )


def connect(db_path: Path) -> sqlite3.Connection:
    database_url = configured_database_url()
    if database_url:
        if not database_url.lower().startswith(("postgres://", "postgresql://")):
            raise ValueError("configured database URL must use PostgreSQL")
        active = active_release_config()
        return connect_postgres(
            database_url,
            schema=configured_database_schema(),
            expected_fingerprint=str(active.get("schema_fingerprint") or "").strip(),
            expected_version=str(active.get("schema_version") or "0002_sqlite_compat").strip(),
        )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    resolved = db_path.resolve()
    last_error: Exception | None = None
    for attempt in range(1, 6):
        connection = sqlite3.connect(db_path, factory=ManagedConnection, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.cache_identity = ("sqlite", str(resolved))
        try:
            connection.execute("PRAGMA busy_timeout=30000")
            skip_wsl_checks = _should_skip_wal(resolved)
            if not skip_wsl_checks:
                try:
                    connection.execute("PRAGMA journal_mode=WAL")
                except sqlite3.OperationalError:
                    # On WSL drvfs mounts, switching journal mode can fail even though the
                    # database itself is readable and writable. Keep SQLite's existing
                    # journal mode in that case so the shared workspace DB remains usable.
                    pass
            stat = resolved.stat()
            schema_key = str(resolved)
            if schema_key not in _SCHEMA_INIT_FINGERPRINTS:
                with _SCHEMA_INIT_LOCK:
                    if schema_key not in _SCHEMA_INIT_FINGERPRINTS:
                        if skip_wsl_checks and stat.st_size > 0:
                            ensure_frontier_schema(connection)
                            ensure_search_indexes(connection)
                            ensure_keyword_index_schema(connection)
                        else:
                            _ensure_schema(connection)
                        connection.commit()
                        _SCHEMA_INIT_FINGERPRINTS.add(schema_key)
            return connection
        except (sqlite3.OperationalError, sqlite3.DatabaseError) as exc:
            last_error = exc
            connection.close()
            if not _is_transient_open_error(exc) or attempt == 5:
                raise
            time.sleep(0.2 * attempt)
    assert last_error is not None
    raise last_error


def get_db_connection() -> sqlite3.Connection:
    """Get database connection"""
    return connect(default_db_path())


def get_site_connectivity_probe_map(connection: sqlite3.Connection) -> dict[str, dict]:
    rows = connection.execute(
        """
        SELECT site_name, url, available, status, checked_at, last_success_at, failure_reason, error
        FROM site_connectivity_probes
        """
    ).fetchall()
    return {
        str(row["site_name"]): {
            **dict(row),
            "available": bool(row["available"]),
        }
        for row in rows
    }


def upsert_site_connectivity_probe(connection: sqlite3.Connection, payload: dict) -> None:
    site_name = str(payload.get("site_name") or "").strip()
    checked_at = str(payload.get("checked_at") or "").strip()
    if not site_name or not checked_at:
        raise ValueError("site connectivity probe requires site_name and checked_at")
    available = bool(payload.get("available"))
    connection.execute(
        """
        INSERT INTO site_connectivity_probes (
            site_name, url, available, status, checked_at, last_success_at, failure_reason, error
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(site_name) DO UPDATE SET
            url = excluded.url,
            available = excluded.available,
            status = excluded.status,
            checked_at = excluded.checked_at,
            last_success_at = CASE
                WHEN excluded.available = 1 THEN excluded.checked_at
                ELSE site_connectivity_probes.last_success_at
            END,
            failure_reason = excluded.failure_reason,
            error = excluded.error
        """,
        (
            site_name,
            str(payload.get("url") or ""),
            int(available),
            str(payload.get("status") or ("available" if available else "unavailable")),
            checked_at,
            checked_at if available else None,
            str(payload.get("failure_reason") or ""),
            str(payload.get("error") or ""),
        ),
    )


def insert_collection_run(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO collection_runs (
            site_name, source_url, collected_at_utc, victim_count, run_metadata_json
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            payload["site_name"],
            payload["source_url"],
            payload["collected_at_utc"],
            payload["victim_count"],
            json.dumps(payload, ensure_ascii=False),
        ),
    )
    return int(cursor.lastrowid)


def upsert_victim(connection: sqlite3.Connection, run_id: int, payload: dict) -> int:
    cursor = connection.execute(
        """
        SELECT id
        FROM victims
        WHERE site_name = ? AND source_url = ? AND name = ? AND ifnull(domain, '') = ifnull(?, '') AND status = ?
        """,
        (
            payload["site_name"],
            payload["source_url"],
            payload["name"],
            payload.get("domain"),
            payload["status"],
        ),
    )
    row = cursor.fetchone()
    raw_json = json.dumps(payload, ensure_ascii=False)
    if row:
        victim_id = int(row[0])
        connection.execute(
            """
            UPDATE victims
            SET detail_url = ?, display_label = ?, published_at_utc = ?, claimed_size = ?,
                claimed_size_gb = ?, content_hash = ?, last_seen_run_id = ?,
                last_detail_fetch_status = COALESCE(?, last_detail_fetch_status), raw_json = ?
            WHERE id = ?
            """,
            (
                payload.get("detail_url"),
                payload["display_label"],
                payload.get("published_at_utc"),
                payload.get("claimed_size"),
                payload.get("claimed_size_gb"),
                payload["content_hash"],
                run_id,
                payload.get("last_detail_fetch_status"),
                raw_json,
                victim_id,
            ),
        )
        return victim_id

    cursor = connection.execute(
        """
        INSERT INTO victims (
            site_name, source_url, detail_url, name, display_label, domain, status, published_at_utc,
            claimed_size, claimed_size_gb, content_hash, first_seen_run_id, last_seen_run_id,
            last_detail_fetch_status, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["site_name"],
            payload["source_url"],
            payload.get("detail_url"),
            payload["name"],
            payload["display_label"],
            payload.get("domain"),
            payload["status"],
            payload.get("published_at_utc"),
            payload.get("claimed_size"),
            payload.get("claimed_size_gb"),
            payload["content_hash"],
            run_id,
            run_id,
            payload.get("last_detail_fetch_status"),
            raw_json,
        ),
    )
    return int(cursor.lastrowid)


def insert_victim_detail(connection: sqlite3.Connection, victim_id: int, payload: dict) -> None:
    connection.execute(
        """
        INSERT INTO victim_details (
            victim_id, fetched_at_utc, fetch_status, page_title, text_excerpt, outbound_link_count, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            victim_id,
            payload["fetched_at_utc"],
            payload["fetch_status"],
            payload.get("page_title"),
            payload.get("text_excerpt"),
            payload.get("outbound_link_count"),
            json.dumps(payload, ensure_ascii=False),
        ),
    )


def get_victim_snapshot(
    connection: sqlite3.Connection,
    site_name: str,
    source_url: str,
    name: str,
    domain: str | None,
    status: str,
) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, content_hash, last_detail_fetch_status
        FROM victims
        WHERE site_name = ? AND source_url = ? AND name = ? AND ifnull(domain, '') = ifnull(?, '') AND status = ?
        """,
        (site_name, source_url, name, domain, status),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def record_victim_detail(
    connection: sqlite3.Connection,
    site_name: str,
    source_url: str,
    name: str,
    domain: str | None,
    status: str,
    detail_payload: dict,
) -> None:
    snapshot = get_victim_snapshot(
        connection,
        site_name=site_name,
        source_url=source_url,
        name=name,
        domain=domain,
        status=status,
    )
    if snapshot is None:
        raise ValueError(f"victim not found for detail persistence: {site_name} {source_url} {name}")

    connection.execute(
        "UPDATE victims SET last_detail_fetch_status = ? WHERE id = ?",
        (detail_payload["fetch_status"], snapshot["id"]),
    )
    insert_victim_detail(connection, int(snapshot["id"]), detail_payload)

def upsert_forum_topic(connection: sqlite3.Connection, **kwargs) -> int:
    """Upsert forum topic"""
    cursor = connection.execute(
        """
        SELECT id
        FROM forum_topics
        WHERE site_name = ? AND section = ? AND url = ?
        """,
        (
            kwargs["site_name"],
            kwargs["section"],
            kwargs["url"],
        ),
    )
    row = cursor.fetchone()
    now = kwargs.get("collected_at_utc", "") or ""
    
    payload = {
        "site_name": kwargs["site_name"],
        "section": kwargs["section"],
        "title": kwargs["title"],
        "url": kwargs["url"],
        "author": kwargs.get("author", ""),
        "replies": kwargs.get("replies", ""),
        "views": kwargs.get("views", ""),
        "published_at": kwargs.get("published_at", ""),
        "last_reply_at": kwargs.get("last_reply_at", ""),
        "content_hash": kwargs["content_hash"]
    }
    
    raw_json = json.dumps(payload, ensure_ascii=False)
    
    if row:
        topic_id = int(row[0])
        connection.execute(
            """
            UPDATE forum_topics
            SET title = ?, author = ?, replies = ?, views = ?, published_at = ?, last_reply_at = ?,
                content_hash = ?, last_seen_at = ?, raw_json = ?
            WHERE id = ?
            """,
            (
                kwargs["title"],
                kwargs.get("author", ""),
                kwargs.get("replies", ""),
                kwargs.get("views", ""),
                kwargs.get("published_at", ""),
                kwargs.get("last_reply_at", ""),
                kwargs["content_hash"],
                now,
                raw_json,
                topic_id,
            ),
        )
        return topic_id

    cursor = connection.execute(
        """
        INSERT INTO forum_topics (
            site_name, section, title, url, author, replies, views, published_at, last_reply_at, content_hash,
            first_seen_at, last_seen_at, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            kwargs["site_name"],
            kwargs["section"],
            kwargs["title"],
            kwargs["url"],
            kwargs.get("author", ""),
            kwargs.get("replies", ""),
            kwargs.get("views", ""),
            kwargs.get("published_at", ""),
            kwargs.get("last_reply_at", ""),
            kwargs["content_hash"],
            now,
            now,
            raw_json,
        ),
    )
    return int(cursor.lastrowid)


def get_forum_topic_snapshot(connection: sqlite3.Connection, site_name: str, section: str, url: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, content_hash, last_seen_at
        FROM forum_topics
        WHERE site_name = ? AND section = ? AND url = ?
        """,
        (site_name, section, url),
    )
    row = cursor.fetchone()
    return dict(row) if row else None

def upsert_forum_detail(connection: sqlite3.Connection, **kwargs) -> int:
    """Upsert forum detail"""
    cursor = connection.execute(
        """
        SELECT id
        FROM forum_details
        WHERE site_name = ? AND section = ? AND topic_url = ?
        """,
        (
            kwargs["site_name"],
            kwargs["section"],
            kwargs["topic_url"],
        ),
    )
    row = cursor.fetchone()
    now = kwargs.get("collected_at_utc", "") or ""
    
    # Get victims and attackers
    victims = kwargs.get("victims", [])
    attackers = kwargs.get("attackers", [])
    
    # Convert to string for storage
    victims_str = ", ".join([v['name'] for v in victims]) if victims else ""
    attackers_str = ", ".join(attackers) if attackers else ""
    
    payload = {
        "site_name": kwargs["site_name"],
        "section": kwargs["section"],
        "topic_url": kwargs["topic_url"],
        "content": kwargs.get("content", ""),
        "authors": kwargs.get("authors", ""),
        "timestamps": kwargs.get("timestamps", ""),
        "published_at_utc": kwargs.get("published_at_utc", ""),
        "attachments": kwargs.get("attachments", ""),
        "victims": victims_str,
        "attackers": attackers_str,
        "content_hash": kwargs["content_hash"]
    }
    
    raw_json = json.dumps(payload, ensure_ascii=False)
    
    if row:
        detail_id = int(row[0])
        connection.execute(
            """
            UPDATE forum_details
            SET content = ?, authors = ?, timestamps = ?, attachments = ?, victims = ?, attackers = ?, content_hash = ?, fetched_at = ?, raw_json = ?
            WHERE id = ?
            """,
            (
                kwargs.get("content", ""),
                kwargs.get("authors", ""),
                kwargs.get("timestamps", ""),
                kwargs.get("attachments", ""),
                victims_str,
                attackers_str,
                kwargs["content_hash"],
                now,
                raw_json,
                detail_id,
            ),
        )
        
        # Update victim details
        connection.execute("DELETE FROM forum_victims WHERE forum_detail_id = ?", (detail_id,))
        for victim in victims:
            connection.execute(
                """
                INSERT INTO forum_victims (forum_detail_id, victim_name, industry, region)
                VALUES (?, ?, ?, ?)
                """,
                (detail_id, victim['name'], victim.get('industry'), victim.get('region'))
            )
        
        return detail_id

    cursor = connection.execute(
        """
        INSERT INTO forum_details (
            site_name, section, topic_url, content, authors, timestamps, attachments, victims, attackers, content_hash, fetched_at, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            kwargs["site_name"],
            kwargs["section"],
            kwargs["topic_url"],
            kwargs.get("content", ""),
            kwargs.get("authors", ""),
            kwargs.get("timestamps", ""),
            kwargs.get("attachments", ""),
            victims_str,
            attackers_str,
            kwargs["content_hash"],
            now,
            raw_json,
        ),
    )
    
    detail_id = int(cursor.lastrowid)
    
    # Insert victim details
    for victim in victims:
        connection.execute(
            """
            INSERT INTO forum_victims (forum_detail_id, victim_name, industry, region)
            VALUES (?, ?, ?, ?)
            """,
            (detail_id, victim['name'], victim.get('industry'), victim.get('region'))
        )
    
    return detail_id


def get_forum_detail_snapshot(connection: sqlite3.Connection, site_name: str, section: str, topic_url: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, content_hash, fetched_at
        FROM forum_details
        WHERE site_name = ? AND section = ? AND topic_url = ?
        """,
        (site_name, section, topic_url),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def upsert_crawl_job(connection: sqlite3.Connection, **kwargs) -> None:
    connection.execute(
        """
        INSERT INTO crawl_jobs (
            job_id, site_name, job_type, queue_name, target, status,
            enqueued_at, started_at, finished_at, duration_ms, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(job_id) DO UPDATE SET
            site_name = excluded.site_name,
            job_type = excluded.job_type,
            queue_name = excluded.queue_name,
            target = excluded.target,
            status = excluded.status,
            enqueued_at = COALESCE(excluded.enqueued_at, crawl_jobs.enqueued_at),
            started_at = COALESCE(excluded.started_at, crawl_jobs.started_at),
            finished_at = COALESCE(excluded.finished_at, crawl_jobs.finished_at),
            duration_ms = COALESCE(excluded.duration_ms, crawl_jobs.duration_ms),
            error_message = excluded.error_message
        """,
        (
            kwargs["job_id"],
            kwargs["site_name"],
            kwargs["job_type"],
            kwargs["queue_name"],
            kwargs["target"],
            kwargs["status"],
            kwargs.get("enqueued_at"),
            kwargs.get("started_at"),
            kwargs.get("finished_at"),
            kwargs.get("duration_ms"),
            kwargs.get("error_message"),
        ),
    )


def upsert_vulnerability_record(connection: sqlite3.Connection, payload: dict) -> int:
    raw_json = json.dumps(payload, ensure_ascii=False)
    reference_urls_json = json.dumps(payload.get("reference_urls") or [], ensure_ascii=False)
    affected_versions = payload.get("affected_versions") or []
    if isinstance(affected_versions, list):
        affected_versions_text = json.dumps(affected_versions, ensure_ascii=False)
    else:
        affected_versions_text = str(affected_versions)

    cursor = connection.execute(
        """
        SELECT id
        FROM vulnerability_records
        WHERE source_name = ? AND cve_id = ?
        """,
        (
            payload["source_name"],
            payload["cve_id"],
        ),
    )
    row = cursor.fetchone()
    if row:
        record_id = int(row[0])
        connection.execute(
            """
            UPDATE vulnerability_records
            SET source_type = ?, title = ?, vendor = ?, product = ?, vulnerability_type = ?, severity = ?,
                cvss = ?, is_exploited = ?, has_poc = ?, patch_available = ?, wide_impact = ?,
                disclosure_time = ?, affected_versions = ?, summary = ?, advisory_url = ?,
                reference_urls_json = ?, raw_json = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (
                payload.get("source_type", "public"),
                payload.get("title", ""),
                payload.get("vendor", ""),
                payload.get("product", ""),
                payload.get("vulnerability_type", ""),
                payload.get("severity", ""),
                payload.get("cvss"),
                int(bool(payload.get("is_exploited"))),
                int(bool(payload.get("has_poc"))),
                int(bool(payload.get("patch_available"))),
                int(bool(payload.get("wide_impact"))),
                payload.get("disclosure_time", ""),
                affected_versions_text,
                payload.get("summary", ""),
                payload.get("advisory_url", ""),
                reference_urls_json,
                raw_json,
                payload.get("last_seen_at") or payload.get("disclosure_time") or "",
                record_id,
            ),
        )
        return record_id

    cursor = connection.execute(
        """
        INSERT INTO vulnerability_records (
            source_name, source_type, cve_id, title, vendor, product, vulnerability_type, severity,
            cvss, is_exploited, has_poc, patch_available, wide_impact, disclosure_time,
            affected_versions, summary, advisory_url, reference_urls_json, raw_json, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["source_name"],
            payload.get("source_type", "public"),
            payload["cve_id"],
            payload.get("title", ""),
            payload.get("vendor", ""),
            payload.get("product", ""),
            payload.get("vulnerability_type", ""),
            payload.get("severity", ""),
            payload.get("cvss"),
            int(bool(payload.get("is_exploited"))),
            int(bool(payload.get("has_poc"))),
            int(bool(payload.get("patch_available"))),
            int(bool(payload.get("wide_impact"))),
            payload.get("disclosure_time", ""),
            affected_versions_text,
            payload.get("summary", ""),
            payload.get("advisory_url", ""),
            reference_urls_json,
            raw_json,
            payload.get("last_seen_at") or payload.get("disclosure_time") or "",
        ),
    )
    return int(cursor.lastrowid)


def list_vulnerability_records(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, source_name, source_type, cve_id, title, vendor, product, vulnerability_type,
               severity, cvss, is_exploited, has_poc, patch_available, wide_impact,
               disclosure_time, affected_versions, summary, advisory_url, reference_urls_json,
               raw_json, last_seen_at
        FROM vulnerability_records
        ORDER BY datetime(disclosure_time) DESC, id DESC
        """
    )
    return [dict(row) for row in cursor.fetchall()]


def replace_vulnerability_records(connection: sqlite3.Connection, rows: list[dict]) -> None:
    connection.execute("DELETE FROM vulnerability_records")
    for row in rows:
        upsert_vulnerability_record(connection, row)


def upsert_ransomware_live_victim(
    connection: sqlite3.Connection,
    payload: dict,
    *,
    return_outcome: bool = False,
) -> int | tuple[int, str]:
    raw_json = payload.get("raw_json")
    if isinstance(raw_json, str):
        raw_json_text = raw_json
    else:
        raw_json_text = json.dumps(raw_json if raw_json is not None else payload, ensure_ascii=False)

    cursor = connection.execute(
        """
        SELECT id, raw_json
        FROM ransomware_live_victims
        WHERE victim_id = ?
        """,
        (payload["victim_id"],),
    )
    row = cursor.fetchone()
    if row:
        record_id = int(row[0])
        existing_raw_json = str(row["raw_json"] or "")
        try:
            unchanged = json.loads(existing_raw_json) == json.loads(raw_json_text)
        except (TypeError, ValueError):
            unchanged = existing_raw_json == raw_json_text
        outcome = "unchanged" if unchanged else "updated"
        connection.execute(
            """
            UPDATE ransomware_live_victims
            SET group_name = ?, victim_name = ?, website = ?, country_code = ?, activity = ?,
                discovered_at = ?, attacked_at = ?, post_url = ?, permalink = ?, screenshot_url = ?,
                description = ?, press_url = ?, raw_json = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (
                payload.get("group_name", ""),
                payload.get("victim_name", ""),
                payload.get("website", ""),
                payload.get("country_code", ""),
                payload.get("activity", ""),
                payload.get("discovered_at", ""),
                payload.get("attacked_at", ""),
                payload.get("post_url", ""),
                payload.get("permalink", ""),
                payload.get("screenshot_url", ""),
                payload.get("description", ""),
                payload.get("press_url", ""),
                raw_json_text,
                payload.get("last_seen_at", ""),
                record_id,
            ),
        )
        return (record_id, outcome) if return_outcome else record_id

    cursor = connection.execute(
        """
        INSERT INTO ransomware_live_victims (
            victim_id, group_name, victim_name, website, country_code, activity,
            discovered_at, attacked_at, post_url, permalink, screenshot_url,
            description, press_url, raw_json, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            payload["victim_id"],
            payload.get("group_name", ""),
            payload.get("victim_name", ""),
            payload.get("website", ""),
            payload.get("country_code", ""),
            payload.get("activity", ""),
            payload.get("discovered_at", ""),
            payload.get("attacked_at", ""),
            payload.get("post_url", ""),
            payload.get("permalink", ""),
            payload.get("screenshot_url", ""),
            payload.get("description", ""),
            payload.get("press_url", ""),
            raw_json_text,
            payload.get("last_seen_at", ""),
        ),
    )
    record_id = int(cursor.lastrowid)
    return (record_id, "new") if return_outcome else record_id


def list_ransomware_live_victims(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, victim_id, group_name, victim_name, website, country_code, activity,
               discovered_at, attacked_at, post_url, permalink, screenshot_url,
               description, press_url, raw_json, last_seen_at
        FROM ransomware_live_victims
        ORDER BY datetime(COALESCE(attacked_at, discovered_at)) DESC, id DESC
        """
    )
    return [dict(row) for row in cursor.fetchall()]


def get_ransomware_live_sync_state(connection: sqlite3.Connection) -> dict[str, object]:
    row = connection.execute(
        """
        SELECT COUNT(*) AS count,
               MAX(last_seen_at) AS latest_seen_at,
               MAX(COALESCE(attacked_at, discovered_at)) AS latest_disclosure_time
        FROM ransomware_live_victims
        """
    ).fetchone()
    if row is None:
        return {
            "count": 0,
            "latest_seen_at": "",
            "latest_disclosure_time": "",
        }
    return dict(row)


def get_last_successful_crawl_job(connection: sqlite3.Connection, site_name: str, job_type: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT job_id, status, finished_at
        FROM crawl_jobs
        WHERE site_name = ? AND job_type = ? AND status = 'succeeded'
        ORDER BY datetime(finished_at) DESC
        LIMIT 1
        """,
        (site_name, job_type),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def get_latest_crawl_job(connection: sqlite3.Connection, site_name: str, job_type: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT job_id, status, queue_name, target, enqueued_at, started_at, finished_at,
               duration_ms, error_message
        FROM crawl_jobs
        WHERE site_name = ? AND job_type = ?
        ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
        LIMIT 1
        """,
        (site_name, job_type),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def _parse_crawl_job_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def reconcile_stale_crawl_jobs(
    connection: sqlite3.Connection,
    *,
    now: datetime | None = None,
    running_timeout_minutes: int = 30,
    enqueued_timeout_minutes: int = 60,
) -> int:
    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    observed_at = observed_at.astimezone(timezone.utc)

    rows = connection.execute(
        """
        SELECT job_id, job_type, status, enqueued_at, started_at
        FROM crawl_jobs
        WHERE status IN ('enqueued', 'running') AND finished_at IS NULL
        """
    ).fetchall()
    stale_jobs: list[tuple[str, str, str]] = []
    for row in rows:
        status = str(row["status"] or "")
        timestamp = _parse_crawl_job_timestamp(row["started_at"] if status == "running" else row["enqueued_at"])
        timeout_minutes = running_timeout_minutes if status == "running" else enqueued_timeout_minutes
        if timestamp is None or timestamp >= observed_at - timedelta(minutes=timeout_minutes):
            continue
        job_type = str(row["job_type"] or "").strip()
        task_label = f"{job_type} task" if job_type else "task"
        stale_jobs.append(
            (observed_at.isoformat(), f"stale {task_label} auto-cleared", str(row["job_id"]))
        )

    connection.executemany(
        """
        UPDATE crawl_jobs
        SET status = 'stale', finished_at = ?, error_message = ?
        WHERE job_id = ? AND status IN ('enqueued', 'running') AND finished_at IS NULL
        """,
        stale_jobs,
    )
    return len(stale_jobs)


def get_active_crawl_job(connection: sqlite3.Connection, site_name: str, job_type: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT job_id, status, queue_name, target, started_at, enqueued_at, finished_at, error_message
        FROM crawl_jobs
        WHERE site_name = ? AND job_type = ? AND status IN ('enqueued', 'running')
        ORDER BY COALESCE(started_at, enqueued_at) DESC
        LIMIT 1
        """,
        (site_name, job_type),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def list_crawl_jobs(connection: sqlite3.Connection, limit: int = 20) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT job_id, site_name, job_type, queue_name, target, status,
               enqueued_at, started_at, finished_at, duration_ms, error_message
        FROM crawl_jobs
        ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
        LIMIT ?
        """,
        (limit,),
    )
    return [dict(row) for row in cursor.fetchall()]


def replace_normalized_intelligence_events(
    connection: sqlite3.Connection,
    rows: list[dict],
) -> None:
    connection.execute("DELETE FROM normalized_intelligence_events")
    connection.executemany(
        """
        INSERT INTO normalized_intelligence_events (
            event_id, source_kind, raw_source_type, source_site_name, source_record_id,
            event_type, category, leak_type, title, attacker, victim, victim_key,
            industry, region, disclosure_time, severity, risk_score, source_url,
            detail_text, mirror_resources_json, screenshot_resources_json,
            json_preview_url, risk_reasons_json, event_metadata_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                row["event_id"],
                row["source_kind"],
                row["raw_source_type"],
                row["source_site_name"],
                row["source_record_id"],
                row["event_type"],
                row["category"],
                row["leak_type"],
                row["title"],
                row["attacker"],
                row["victim"],
                row["victim_key"],
                row["industry"],
                row["region"],
                row.get("disclosure_time"),
                row["severity"],
                row["risk_score"],
                row["source_url"],
                row["detail_text"],
                row["mirror_resources_json"],
                row["screenshot_resources_json"],
                row["json_preview_url"],
                row["risk_reasons_json"],
                row["event_metadata_json"],
                row["updated_at"],
            )
            for row in rows
        ],
    )
    sync_search_documents(connection, rows)


_NORMALIZED_INTELLIGENCE_SEARCH_EXPRESSION = SEARCH_EXPRESSION


def _normalized_intelligence_filters(event_type: str = "", query: str = "") -> tuple[str, list[object]]:
    conditions = []
    parameters: list[object] = []
    if event_type:
        conditions.append("event_type = ?")
        parameters.append(event_type)
    for term in str(query or "").casefold().split():
        conditions.append(f"{_NORMALIZED_INTELLIGENCE_SEARCH_EXPRESSION} LIKE ?")
        parameters.append(f"%{term}%")
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    return where, parameters


def list_normalized_intelligence_events(
    connection: sqlite3.Connection,
    *,
    event_type: str = "",
    limit: int | None = None,
    offset: int = 0,
    query: str = "",
    sort: str = "latest",
) -> list[dict]:
    order_by = SEARCH_ORDER.get(sort)
    if order_by is None:
        raise ValueError(f"unsupported normalized intelligence sort: {sort}")
    if offset < 0:
        raise ValueError("offset must not be negative")
    if offset and limit is None:
        raise ValueError("offset requires limit")
    where, parameters = _normalized_intelligence_filters(event_type, query)
    limit_sql = " LIMIT ? OFFSET ?" if limit is not None else ""
    if limit is not None:
        parameters.extend((int(limit), int(offset)))
    cursor = connection.execute(
        f"""
        SELECT event_id, source_kind, raw_source_type, source_site_name, source_record_id,
               event_type, category, leak_type, title, attacker, victim, victim_key,
               industry, region, disclosure_time, severity, risk_score, source_url,
               detail_text, mirror_resources_json, screenshot_resources_json,
               json_preview_url, risk_reasons_json, event_metadata_json, updated_at
        FROM normalized_intelligence_events
        {where}
        ORDER BY {order_by}
        {limit_sql}
        """,
        tuple(parameters),
    )
    return [dict(row) for row in cursor.fetchall()]


def search_normalized_intelligence_events(
    connection: sqlite3.Connection,
    *,
    event_type: str = "",
    query: str = "",
    sort: str = "latest",
    limit: int = 20,
    page: int = 1,
    counts: dict[str, int] | None = None,
) -> dict:
    """Share an uncached substring scan between counts and a narrow page sort."""
    if sort not in SEARCH_ORDER:
        raise ValueError(f"unsupported normalized intelligence sort: {sort}")
    limit = int(limit)
    if limit < 1:
        raise ValueError("limit must be positive")
    page = max(1, int(page))
    indexed = search_indexed_events(
        connection, query=query, event_type=event_type, sort=sort,
        limit=limit, page=page, counts=counts,
    ) if str(query or "").strip() else None
    if indexed is not None:
        return indexed
    if (counts is not None or not str(query or "").strip()
            or getattr(connection, "backend_name", "sqlite") != "postgresql"):
        if counts is None:
            counts = count_normalized_intelligence_events_by_type(connection, query=query)
        total = counts.get(event_type, 0) if event_type else sum(counts.values())
        page = min(page, max(1, (total + limit - 1) // limit))
        rows = list_normalized_intelligence_events(
            connection, event_type=event_type, query=query, sort=sort,
            limit=limit, offset=(page - 1) * limit,
        ) if total else []
        return {"rows": rows, "counts": counts, "page": page}

    where, parameters = _normalized_intelligence_filters(query=query)
    order = {
        "latest": "report_time DESC, event_id DESC",
        "oldest": "report_time ASC, event_id ASC",
        "severity": "severity_rank DESC, risk_score DESC, report_time DESC, event_id DESC",
    }[sort]
    # Materialize only identifiers and small sort keys, not article bodies or JSON.
    # The LEFT JOIN retains the count row even when the selected category is empty.
    records = connection.execute(
        f"""
        WITH matches AS MATERIALIZED (
            SELECT event_id, event_type, {REPORT_TIME} AS report_time,
                   {SEVERITY_RANK} AS severity_rank, risk_score
            FROM normalized_intelligence_events {where}
        ), totals AS (
            SELECT COUNT(CASE WHEN event_type = 'data_leak' THEN 1 END) AS search_data_leak,
                   COUNT(CASE WHEN event_type = 'ransomware' THEN 1 END) AS search_ransomware,
                   COUNT(CASE WHEN event_type = 'vulnerability' THEN 1 END) AS search_vulnerability,
                   COUNT(CASE WHEN ? = '' OR event_type = ? THEN 1 END) AS search_total
            FROM matches
        ), bounds AS (
            SELECT totals.*,
                   CASE WHEN search_total = 0 THEN 1
                        WHEN ? > (search_total + ? - 1) / ?
                        THEN (search_total + ? - 1) / ? ELSE ? END AS search_page
            FROM totals
        ), selected AS (
            SELECT * FROM matches WHERE ? = '' OR event_type = ?
            ORDER BY {order} LIMIT ? OFFSET (SELECT (search_page - 1) * ? FROM bounds)
        )
        SELECT n.*, bounds.search_data_leak, bounds.search_ransomware,
               bounds.search_vulnerability, bounds.search_page
        FROM bounds LEFT JOIN selected s ON 1 = 1
        LEFT JOIN normalized_intelligence_events n ON n.event_id = s.event_id
        ORDER BY {', '.join('s.' + item.strip() for item in order.split(','))}
        """,
        tuple(parameters + [event_type, event_type, page, limit, limit, limit, limit,
                            page, event_type, event_type, limit, limit]),
    ).fetchall()
    first = records[0]
    result_counts = {kind: int(first[f"search_{kind}"]) for kind in
                     ("data_leak", "ransomware", "vulnerability")}
    rows = []
    for record in records:
        if record["event_id"] is not None:
            rows.append({key: value for key, value in dict(record).items()
                         if not key.startswith("search_")})
    return {"rows": rows, "counts": result_counts, "page": int(first["search_page"])}


def count_normalized_intelligence_events(
    connection: sqlite3.Connection,
    event_type: str = "",
    query: str = "",
) -> int:
    where, parameters = _normalized_intelligence_filters(event_type, query)
    row = connection.execute(
        f"SELECT COUNT(*) FROM normalized_intelligence_events{where}",
        tuple(parameters),
    ).fetchone()
    return int(row[0])


def count_normalized_intelligence_events_by_type(
    connection: sqlite3.Connection,
    query: str = "",
) -> dict[str, int]:
    where, parameters = _normalized_intelligence_filters(query=query)
    rows = connection.execute(
        f"""
        SELECT event_type, COUNT(*) AS event_count
        FROM normalized_intelligence_events
        {where}
        GROUP BY event_type
        """,
        tuple(parameters),
    ).fetchall()
    return {str(row[0]): int(row[1]) for row in rows}


def get_normalized_intelligence_event(
    connection: sqlite3.Connection,
    event_id: str,
) -> dict | None:
    cursor = connection.execute(
        """
        SELECT event_id, source_kind, raw_source_type, source_site_name, source_record_id,
               event_type, category, leak_type, title, attacker, victim, victim_key,
               industry, region, disclosure_time, severity, risk_score, source_url,
               detail_text, mirror_resources_json, screenshot_resources_json,
               json_preview_url, risk_reasons_json, event_metadata_json, updated_at
        FROM normalized_intelligence_events
        WHERE event_id = ?
        """,
        (event_id,),
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def get_normalized_intelligence_cache_state(connection: sqlite3.Connection) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, source_signature, event_count, refreshed_at
        FROM normalized_intelligence_cache_state
        WHERE id = 1
        """
    )
    row = cursor.fetchone()
    return dict(row) if row else None


def upsert_normalized_intelligence_cache_state(
    connection: sqlite3.Connection,
    *,
    source_signature: str,
    event_count: int,
    refreshed_at: str,
) -> None:
    connection.execute(
        """
        INSERT INTO normalized_intelligence_cache_state (id, source_signature, event_count, refreshed_at)
        VALUES (1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            source_signature = excluded.source_signature,
            event_count = excluded.event_count,
            refreshed_at = excluded.refreshed_at
        """,
        (source_signature, event_count, refreshed_at),
    )
    mark_search_index_revision(connection, source_signature, event_count, refreshed_at)


def list_monitoring_keywords(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, keyword, category, weight, enabled, match_mode, updated_at
        FROM monitoring_keywords
        ORDER BY category, keyword
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        rows.append(payload)
    return rows


def replace_monitoring_keywords(connection: sqlite3.Connection, rows: list[dict]) -> None:
    connection.execute("DELETE FROM monitoring_keywords")
    if not rows:
        return
    connection.executemany(
        """
        INSERT INTO monitoring_keywords (
            keyword, category, weight, enabled, match_mode, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                str(row.get("keyword") or "").strip(),
                str(row.get("category") or "").strip(),
                int(row.get("weight") or 0),
                int(bool(row.get("enabled", True))),
                str(row.get("match_mode") or "contains").strip() or "contains",
                str(row.get("updated_at") or ""),
            )
            for row in rows
            if str(row.get("keyword") or "").strip()
        ],
    )


def get_monitoring_keyword_notification(
    connection: sqlite3.Connection,
    event_id: str,
    match_signature: str,
) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, event_id, event_key, match_signature, match_keywords_json, status, dry_run,
               response_json, error_message, sent_at, created_at, updated_at
        FROM monitoring_keyword_notifications
        WHERE event_id = ? AND match_signature = ?
        """,
        (event_id, match_signature),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["dry_run"] = bool(payload.get("dry_run"))
    return payload


def get_monitoring_keyword_notification_by_event_key(
    connection: sqlite3.Connection,
    event_key: str,
) -> dict | None:
    normalized_key = str(event_key or "").strip()
    if not normalized_key:
        return None
    cursor = connection.execute(
        """
        SELECT id, event_id, event_key, match_signature, match_keywords_json, status, dry_run,
               response_json, error_message, sent_at, created_at, updated_at
        FROM monitoring_keyword_notifications
        WHERE event_key = ? AND status = 'sent' AND dry_run = 0
        ORDER BY datetime(updated_at) DESC, id DESC
        LIMIT 1
        """,
        (normalized_key,),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["dry_run"] = bool(payload.get("dry_run"))
    return payload


def list_monitoring_keyword_notifications(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, event_id, event_key, match_signature, match_keywords_json, status, dry_run,
               response_json, error_message, sent_at, created_at, updated_at
        FROM monitoring_keyword_notifications
        ORDER BY datetime(updated_at) DESC, id DESC
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["dry_run"] = bool(payload.get("dry_run"))
        rows.append(payload)
    return rows


def upsert_monitoring_keyword_notification(connection: sqlite3.Connection, payload: dict) -> None:
    connection.execute(
        """
        INSERT INTO monitoring_keyword_notifications (
            event_id, event_key, match_signature, match_keywords_json, status, dry_run,
            response_json, error_message, sent_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(event_id, match_signature) DO UPDATE SET
            event_key = excluded.event_key,
            match_keywords_json = excluded.match_keywords_json,
            status = excluded.status,
            dry_run = excluded.dry_run,
            response_json = excluded.response_json,
            error_message = excluded.error_message,
            sent_at = excluded.sent_at,
            updated_at = excluded.updated_at
        """,
        (
            str(payload.get("event_id") or "").strip(),
            str(payload.get("event_key") or "").strip(),
            str(payload.get("match_signature") or "").strip(),
            str(payload.get("match_keywords_json") or "[]"),
            str(payload.get("status") or "").strip(),
            int(bool(payload.get("dry_run"))),
            str(payload.get("response_json") or "{}"),
            str(payload.get("error_message") or ""),
            payload.get("sent_at"),
            str(payload.get("created_at") or ""),
            str(payload.get("updated_at") or ""),
        ),
    )


def list_platform_sessions(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, platform, account_label, login_url, homepage_url, requires_login, status,
               storage_state_path, last_verified_at, expires_hint, last_error, metadata_json, updated_at
        FROM platform_sessions
        ORDER BY platform
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["requires_login"] = bool(payload.get("requires_login"))
        rows.append(payload)
    return rows


def get_platform_session(connection: sqlite3.Connection, platform: str) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, platform, account_label, login_url, homepage_url, requires_login, status,
               storage_state_path, last_verified_at, expires_hint, last_error, metadata_json, updated_at
        FROM platform_sessions
        WHERE platform = ?
        """,
        (str(platform or "").strip(),),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["requires_login"] = bool(payload.get("requires_login"))
    return payload


def upsert_platform_session(connection: sqlite3.Connection, payload: dict) -> int:
    platform = str(payload.get("platform") or "").strip()
    if not platform:
        raise ValueError("platform is required")
    existing = get_platform_session(connection, platform)
    values = (
        str(payload.get("account_label") or "").strip(),
        str(payload.get("login_url") or "").strip(),
        str(payload.get("homepage_url") or "").strip(),
        int(bool(payload.get("requires_login"))),
        str(payload.get("status") or "").strip() or "unknown",
        str(payload.get("storage_state_path") or "").strip(),
        payload.get("last_verified_at"),
        str(payload.get("expires_hint") or "").strip(),
        str(payload.get("last_error") or "").strip(),
        str(payload.get("metadata_json") or "{}"),
        str(payload.get("updated_at") or "").strip(),
    )
    if existing is not None:
        connection.execute(
            """
            UPDATE platform_sessions
            SET account_label = ?, login_url = ?, homepage_url = ?, requires_login = ?, status = ?,
                storage_state_path = ?, last_verified_at = ?, expires_hint = ?, last_error = ?,
                metadata_json = ?, updated_at = ?
            WHERE platform = ?
            """,
            (*values, platform),
        )
        return int(existing["id"])
    cursor = connection.execute(
        """
        INSERT INTO platform_sessions (
            platform, account_label, login_url, homepage_url, requires_login, status,
            storage_state_path, last_verified_at, expires_hint, last_error, metadata_json, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (platform, *values),
    )
    return int(cursor.lastrowid)


def delete_platform_session(connection: sqlite3.Connection, platform: str) -> None:
    connection.execute("DELETE FROM platform_sessions WHERE platform = ?", (str(platform or "").strip(),))


def list_exposure_watchlists(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        FROM exposure_watchlists
        ORDER BY updated_at DESC, id DESC
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        payload["metadata_json"] = str(payload.get("metadata_json") or "{}")
        rows.append(payload)
    return rows


def get_exposure_watchlist(connection: sqlite3.Connection, watchlist_id: int) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        FROM exposure_watchlists
        WHERE id = ?
        """,
        (int(watchlist_id),),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["enabled"] = bool(payload.get("enabled"))
    payload["metadata_json"] = str(payload.get("metadata_json") or "{}")
    return payload


def upsert_exposure_watchlist(connection: sqlite3.Connection, payload: dict) -> int:
    watchlist_id = payload.get("id")
    values = (
        str(payload.get("name") or "").strip(),
        str(payload.get("organization_name") or "").strip(),
        int(bool(payload.get("enabled", True))),
        str(payload.get("notes") or "").strip(),
        str(payload.get("metadata_json") or "{}"),
        str(payload.get("created_at") or "").strip(),
        str(payload.get("updated_at") or "").strip(),
    )
    if not values[0]:
        raise ValueError("watchlist name is required")
    if not values[1]:
        raise ValueError("organization_name is required")
    if watchlist_id:
        connection.execute(
            """
            UPDATE exposure_watchlists
            SET name = ?, organization_name = ?, enabled = ?, notes = ?, metadata_json = ?, updated_at = ?
            WHERE id = ?
            """,
            (values[0], values[1], values[2], values[3], values[4], values[6], int(watchlist_id)),
        )
        return int(watchlist_id)
    cursor = connection.execute(
        """
        INSERT INTO exposure_watchlists (
            name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        values,
    )
    return int(cursor.lastrowid)


def delete_exposure_watchlist(connection: sqlite3.Connection, watchlist_id: int) -> None:
    target_id = int(watchlist_id)
    connection.execute(
        """
        DELETE FROM document_hit_reviews
        WHERE hit_id IN (
            SELECT id FROM document_hits WHERE watchlist_id = ?
        )
        """,
        (target_id,),
    )
    connection.execute(
        """
        DELETE FROM document_hit_snapshots
        WHERE hit_id IN (
            SELECT id FROM document_hits WHERE watchlist_id = ?
        )
        """,
        (target_id,),
    )
    connection.execute("DELETE FROM document_hits WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM exposure_scan_runs WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM netdisk_source_states WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM exposure_watch_terms WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM exposure_watchlists WHERE id = ?", (target_id,))


def list_exposure_watch_terms(connection: sqlite3.Connection, watchlist_id: int | None = None) -> list[dict]:
    if watchlist_id is None:
        cursor = connection.execute(
            """
            SELECT id, watchlist_id, term, term_type, weight, enabled, created_at, updated_at
            FROM exposure_watch_terms
            ORDER BY watchlist_id, weight DESC, term
            """
        )
    else:
        cursor = connection.execute(
            """
            SELECT id, watchlist_id, term, term_type, weight, enabled, created_at, updated_at
            FROM exposure_watch_terms
            WHERE watchlist_id = ?
            ORDER BY weight DESC, term
            """,
            (int(watchlist_id),),
        )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        rows.append(payload)
    return rows


def replace_exposure_watch_terms(connection: sqlite3.Connection, watchlist_id: int, rows: list[dict]) -> None:
    connection.execute("DELETE FROM exposure_watch_terms WHERE watchlist_id = ?", (int(watchlist_id),))
    if not rows:
        return
    connection.executemany(
        """
        INSERT INTO exposure_watch_terms (
            watchlist_id, term, term_type, weight, enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                int(watchlist_id),
                str(row.get("term") or "").strip(),
                str(row.get("term_type") or "").strip() or "custom",
                int(row.get("weight") or 0),
                int(bool(row.get("enabled", True))),
                str(row.get("created_at") or ""),
                str(row.get("updated_at") or ""),
            )
            for row in rows
            if str(row.get("term") or "").strip()
        ],
    )


def get_document_hit(connection: sqlite3.Connection, hit_id: int) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, platform, platform_type, discovery_source, canonical_url, normalized_title,
               resource_fingerprint, title, access_state, confidence_score, risk_score, severity, review_status,
               matched_terms_json, file_count, evidence_count, share_owner, disclosure_time,
               first_seen_at, last_seen_at, last_snapshot_id, raw_json
        FROM document_hits
        WHERE id = ?
        """,
        (int(hit_id),),
    )
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def list_document_hits(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    platform_type: str | None = None,
    access_state: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    where_parts = []
    params: list[object] = []
    if watchlist_id is not None:
        where_parts.append("h.watchlist_id = ?")
        params.append(int(watchlist_id))
    if review_status:
        where_parts.append("h.review_status = ?")
        params.append(str(review_status).strip())
    if platform:
        where_parts.append("h.platform = ?")
        params.append(str(platform).strip())
    if platform_type:
        where_parts.append("h.platform_type = ?")
        params.append(str(platform_type).strip())
    if access_state:
        where_parts.append("h.access_state = ?")
        params.append(str(access_state).strip())
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    cursor = connection.execute(
        f"""
        SELECT h.id, h.watchlist_id, h.platform, h.platform_type, h.discovery_source, h.canonical_url,
               h.normalized_title, h.resource_fingerprint, h.title, h.access_state, h.confidence_score, h.risk_score,
               h.severity, h.review_status, h.matched_terms_json, h.file_count, h.evidence_count,
               h.share_owner, h.disclosure_time, h.first_seen_at, h.last_seen_at, h.last_snapshot_id,
               h.raw_json, w.name AS watchlist_name, w.organization_name
        FROM document_hits h
        JOIN exposure_watchlists w
          ON w.id = h.watchlist_id
        {where_clause}
        ORDER BY h.risk_score DESC, datetime(h.last_seen_at) DESC, h.id DESC
        {limit_clause}
        """,
        tuple(params),
    )
    return [dict(row) for row in cursor.fetchall()]


def upsert_document_hit(connection: sqlite3.Connection, payload: dict) -> int:
    resource_fingerprint = str(payload.get("resource_fingerprint") or "").strip()
    signature = (
        int(payload.get("watchlist_id") or 0),
        str(payload.get("platform") or "").strip(),
        str(payload.get("canonical_url") or "").strip(),
        str(payload.get("normalized_title") or "").strip(),
    )
    if not signature[0] or not signature[1] or not signature[2] or not signature[3]:
        raise ValueError("watchlist_id, platform, canonical_url, and normalized_title are required")
    row = None
    if resource_fingerprint:
        cursor = connection.execute(
            """
            SELECT id, first_seen_at
            FROM document_hits
            WHERE watchlist_id = ? AND platform = ? AND resource_fingerprint = ?
            """,
            (signature[0], signature[1], resource_fingerprint),
        )
        row = cursor.fetchone()
    if row is None:
        cursor = connection.execute(
            """
            SELECT id, first_seen_at
            FROM document_hits
            WHERE watchlist_id = ? AND platform = ? AND canonical_url = ? AND normalized_title = ?
            """,
            signature,
        )
        row = cursor.fetchone()
    values = (
        str(payload.get("platform_type") or "").strip() or "document_library",
        str(payload.get("discovery_source") or "").strip(),
        resource_fingerprint,
        str(payload.get("title") or "").strip(),
        str(payload.get("access_state") or "").strip() or "unknown",
        int(payload.get("confidence_score") or 0),
        int(payload.get("risk_score") or 0),
        str(payload.get("severity") or "").strip() or "low",
        str(payload.get("review_status") or "").strip() or "new",
        str(payload.get("matched_terms_json") or "[]"),
        int(payload.get("file_count") or 0),
        int(payload.get("evidence_count") or 0),
        str(payload.get("share_owner") or "").strip(),
        payload.get("disclosure_time"),
        str(payload.get("last_seen_at") or ""),
        payload.get("last_snapshot_id"),
        str(payload.get("raw_json") or "{}"),
    )
    if row is not None:
        connection.execute(
            """
            UPDATE document_hits
            SET platform_type = ?, discovery_source = ?,
                resource_fingerprint = CASE WHEN ? <> '' THEN ? ELSE resource_fingerprint END,
                title = ?, access_state = ?, confidence_score = ?,
                risk_score = ?, severity = ?, review_status = ?, matched_terms_json = ?, file_count = ?,
                evidence_count = ?, share_owner = ?, disclosure_time = ?, last_seen_at = ?,
                last_snapshot_id = ?, raw_json = ?
            WHERE id = ?
            """,
            (values[0], values[1], values[2], values[2], *values[3:], int(row["id"])),
        )
        return int(row["id"])
    cursor = connection.execute(
        """
        INSERT INTO document_hits (
            watchlist_id, platform, platform_type, discovery_source, canonical_url, normalized_title, resource_fingerprint, title,
            access_state, confidence_score, risk_score, severity, review_status, matched_terms_json,
            file_count, evidence_count, share_owner, disclosure_time, first_seen_at, last_seen_at,
            last_snapshot_id, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature[0],
            signature[1],
            values[0],
            values[1],
            signature[2],
            signature[3],
            values[2],
            values[3],
            values[4],
            values[5],
            values[6],
            values[7],
            values[8],
            values[9],
            values[10],
            values[11],
            values[12],
            values[13],
            str(payload.get("first_seen_at") or values[14]),
            values[14],
            values[15],
            values[16],
        ),
    )
    return int(cursor.lastrowid)


def insert_document_hit_snapshot(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO document_hit_snapshots (
            hit_id, fetched_at, source_query, source_url, page_url, page_title, html_path, screenshot_path,
            ocr_text, preview_text, file_list_json, access_state, matched_terms_json, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("hit_id") or 0),
            str(payload.get("fetched_at") or ""),
            str(payload.get("source_query") or ""),
            str(payload.get("source_url") or ""),
            str(payload.get("page_url") or ""),
            str(payload.get("page_title") or ""),
            str(payload.get("html_path") or ""),
            str(payload.get("screenshot_path") or ""),
            str(payload.get("ocr_text") or ""),
            str(payload.get("preview_text") or ""),
            str(payload.get("file_list_json") or "[]"),
            str(payload.get("access_state") or "").strip() or "unknown",
            str(payload.get("matched_terms_json") or "[]"),
            str(payload.get("raw_json") or "{}"),
        ),
    )
    return int(cursor.lastrowid)


def list_document_hit_snapshots(connection: sqlite3.Connection, hit_id: int) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, hit_id, fetched_at, source_query, source_url, page_url, page_title, html_path, screenshot_path,
               ocr_text, preview_text, file_list_json, access_state, matched_terms_json, raw_json
        FROM document_hit_snapshots
        WHERE hit_id = ?
        ORDER BY datetime(fetched_at) DESC, id DESC
        """,
        (int(hit_id),),
    )
    return [dict(row) for row in cursor.fetchall()]


def update_document_hit_snapshot_files(connection: sqlite3.Connection, snapshot_id: int, *, html_path: str = "", screenshot_path: str = "") -> None:
    connection.execute(
        """
        UPDATE document_hit_snapshots
        SET html_path = ?, screenshot_path = ?
        WHERE id = ?
        """,
        (str(html_path or ""), str(screenshot_path or ""), int(snapshot_id)),
    )


def update_document_hit_last_snapshot(connection: sqlite3.Connection, hit_id: int, snapshot_id: int) -> None:
    connection.execute(
        "UPDATE document_hits SET last_snapshot_id = ?, evidence_count = evidence_count + 1 WHERE id = ?",
        (int(snapshot_id), int(hit_id)),
    )


def add_document_hit_review(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO document_hit_reviews (hit_id, status, reviewer, note, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("hit_id") or 0),
            str(payload.get("status") or "").strip() or "triaged",
            str(payload.get("reviewer") or "").strip(),
            str(payload.get("note") or ""),
            str(payload.get("created_at") or ""),
        ),
    )
    connection.execute(
        "UPDATE document_hits SET review_status = ? WHERE id = ?",
        (str(payload.get("status") or "").strip() or "triaged", int(payload.get("hit_id") or 0)),
    )
    return int(cursor.lastrowid)


def list_document_hit_reviews(connection: sqlite3.Connection, hit_id: int) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, hit_id, status, reviewer, note, created_at
        FROM document_hit_reviews
        WHERE hit_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        """,
        (int(hit_id),),
    )
    return [dict(row) for row in cursor.fetchall()]


def insert_exposure_scan_run(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO exposure_scan_runs (
            watchlist_id, source_families_json, requested_terms_json, candidate_count,
            hit_count, error_count, scan_stats_json, status, errors_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("watchlist_id") or 0),
            str(payload.get("source_families_json") or "[]"),
            str(payload.get("requested_terms_json") or "[]"),
            int(payload.get("candidate_count") or 0),
            int(payload.get("hit_count") or 0),
            int(payload.get("error_count") or 0),
            str(payload.get("scan_stats_json") or "[]"),
            str(payload.get("status") or "").strip() or "succeeded",
            str(payload.get("errors_json") or "[]"),
            str(payload.get("started_at") or ""),
            str(payload.get("finished_at") or ""),
        ),
    )
    return int(cursor.lastrowid)


def list_exposure_scan_runs(connection: sqlite3.Connection, watchlist_id: int | None = None, limit: int | None = 100) -> list[dict]:
    params: list[object] = []
    where_clause = ""
    if watchlist_id is not None:
        where_clause = "WHERE r.watchlist_id = ?"
        params.append(int(watchlist_id))
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    cursor = connection.execute(
        f"""
        SELECT r.id, r.watchlist_id, r.source_families_json, r.requested_terms_json,
               r.candidate_count, r.hit_count, r.error_count, r.scan_stats_json, r.status, r.errors_json,
               r.started_at, r.finished_at, w.name AS watchlist_name, w.organization_name
        FROM exposure_scan_runs r
        JOIN exposure_watchlists w
          ON w.id = r.watchlist_id
        {where_clause}
        ORDER BY datetime(r.finished_at) DESC, r.id DESC
        {limit_clause}
        """,
        tuple(params),
    )
    return [dict(row) for row in cursor.fetchall()]


def list_netdisk_source_states(connection: sqlite3.Connection, watchlist_id: int | None = None) -> list[dict]:
    params: list[object] = []
    where_clause = ""
    if watchlist_id is not None:
        where_clause = "WHERE s.watchlist_id = ?"
        params.append(int(watchlist_id))
    cursor = connection.execute(
        f"""
        SELECT s.id, s.watchlist_id, s.source_key, s.term, s.source_family, s.next_page,
               s.last_scanned_page, s.page_window_size, s.consecutive_empty_pages,
               s.consecutive_repeated_pages, s.last_candidate_signature, s.last_success_at,
               s.last_error_at, s.last_error, s.backoff_until, s.created_at, s.updated_at,
               w.name AS watchlist_name, w.organization_name
        FROM netdisk_source_states s
        JOIN exposure_watchlists w
          ON w.id = s.watchlist_id
        {where_clause}
        ORDER BY s.watchlist_id, s.source_key, s.term
        """,
        tuple(params),
    )
    return [dict(row) for row in cursor.fetchall()]


def get_netdisk_source_state(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int,
    source_key: str,
    term: str,
    source_family: str = "netdisk_aggregator",
) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, source_key, term, source_family, next_page,
               last_scanned_page, page_window_size, consecutive_empty_pages,
               consecutive_repeated_pages, last_candidate_signature, last_success_at,
               last_error_at, last_error, backoff_until, created_at, updated_at
        FROM netdisk_source_states
        WHERE watchlist_id = ? AND source_key = ? AND term = ? AND source_family = ?
        """,
        (
            int(watchlist_id),
            str(source_key).strip(),
            str(term).strip(),
            str(source_family).strip() or "netdisk_aggregator",
        ),
    )
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def upsert_netdisk_source_state(connection: sqlite3.Connection, payload: dict) -> int:
    signature = (
        int(payload.get("watchlist_id") or 0),
        str(payload.get("source_key") or "").strip(),
        str(payload.get("term") or "").strip(),
        str(payload.get("source_family") or "").strip() or "netdisk_aggregator",
    )
    if not all(signature):
        raise ValueError("watchlist_id, source_key, term, and source_family are required")
    now = str(payload.get("updated_at") or "")
    cursor = connection.execute(
        """
        SELECT id, created_at
        FROM netdisk_source_states
        WHERE watchlist_id = ? AND source_key = ? AND term = ? AND source_family = ?
        """,
        signature,
    )
    row = cursor.fetchone()
    values = (
        max(1, int(payload.get("next_page") or 1)),
        max(0, int(payload.get("last_scanned_page") or 0)),
        max(1, int(payload.get("page_window_size") or 4)),
        max(0, int(payload.get("consecutive_empty_pages") or 0)),
        max(0, int(payload.get("consecutive_repeated_pages") or 0)),
        str(payload.get("last_candidate_signature") or ""),
        str(payload.get("last_success_at") or ""),
        str(payload.get("last_error_at") or ""),
        str(payload.get("last_error") or ""),
        str(payload.get("backoff_until") or ""),
        now,
    )
    if row is not None:
        connection.execute(
            """
            UPDATE netdisk_source_states
            SET next_page = ?, last_scanned_page = ?, page_window_size = ?,
                consecutive_empty_pages = ?, consecutive_repeated_pages = ?,
                last_candidate_signature = ?, last_success_at = ?, last_error_at = ?,
                last_error = ?, backoff_until = ?, updated_at = ?
            WHERE id = ?
            """,
            (*values, int(row["id"])),
        )
        return int(row["id"])
    cursor = connection.execute(
        """
        INSERT INTO netdisk_source_states (
            watchlist_id, source_key, term, source_family, next_page, last_scanned_page,
            page_window_size, consecutive_empty_pages, consecutive_repeated_pages,
            last_candidate_signature, last_success_at, last_error_at, last_error,
            backoff_until, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature[0],
            signature[1],
            signature[2],
            signature[3],
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            values[5],
            values[6],
            values[7],
            values[8],
            values[9],
            str(payload.get("created_at") or now),
            values[10],
        ),
    )
    return int(cursor.lastrowid)


def reset_netdisk_source_states(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int | None = None,
    source_key: str | None = None,
    term: str | None = None,
) -> int:
    where_parts: list[str] = []
    params: list[object] = []
    if watchlist_id is not None:
        where_parts.append("watchlist_id = ?")
        params.append(int(watchlist_id))
    if source_key:
        where_parts.append("source_key = ?")
        params.append(str(source_key).strip())
    if term:
        where_parts.append("term = ?")
        params.append(str(term).strip())
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    cursor = connection.execute(f"DELETE FROM netdisk_source_states {where_clause}", tuple(params))
    return int(cursor.rowcount if cursor.rowcount is not None else 0)


def list_netdisk_source_health(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT source_key, enabled, status, success_count, error_count, login_required_count,
               captcha_count, rate_limited_count, consecutive_failures, last_success_at,
               last_error_at, last_error, backoff_until, updated_at
        FROM netdisk_source_health
        ORDER BY source_key
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        rows.append(payload)
    return rows


def ensure_netdisk_source_health_records(connection: sqlite3.Connection, source_keys: list[dict] | list[str], updated_at: str) -> None:
    for item in source_keys:
        source_key = str(item.get("source_key") if isinstance(item, dict) else item).strip()
        if not source_key:
            continue
        connection.execute(
            """
            INSERT OR IGNORE INTO netdisk_source_health (source_key, updated_at)
            VALUES (?, ?)
            """,
            (source_key, updated_at),
        )


def upsert_netdisk_source_health(connection: sqlite3.Connection, payload: dict) -> None:
    source_key = str(payload.get("source_key") or "").strip()
    if not source_key:
        raise ValueError("source_key is required")
    updated_at = str(payload.get("updated_at") or "")
    cursor = connection.execute(
        """
        SELECT source_key, enabled, status, success_count, error_count, login_required_count,
               captcha_count, rate_limited_count, consecutive_failures, last_success_at,
               last_error_at, last_error, backoff_until, updated_at
        FROM netdisk_source_health
        WHERE source_key = ?
        """,
        (source_key,),
    )
    row = cursor.fetchone()
    success_delta = max(0, int(payload.get("success_delta") or 0))
    error_delta = max(0, int(payload.get("error_delta") or 0))
    login_delta = max(0, int(payload.get("login_required_delta") or 0))
    captcha_delta = max(0, int(payload.get("captcha_delta") or 0))
    rate_limited_delta = max(0, int(payload.get("rate_limited_delta") or 0))
    if row is None:
        base = {
            "enabled": True,
            "status": "healthy",
            "success_count": 0,
            "error_count": 0,
            "login_required_count": 0,
            "captcha_count": 0,
            "rate_limited_count": 0,
            "consecutive_failures": 0,
            "last_success_at": "",
            "last_error_at": "",
            "last_error": "",
            "backoff_until": "",
        }
    else:
        base = dict(row)
    status = str(payload.get("status") or base.get("status") or "healthy")
    if success_delta and not error_delta:
        status = "healthy"
    consecutive_failures = 0 if success_delta and not error_delta else int(base.get("consecutive_failures") or 0) + error_delta
    values = (
        1 if payload.get("enabled", base.get("enabled", True)) else 0,
        status,
        int(base.get("success_count") or 0) + success_delta,
        int(base.get("error_count") or 0) + error_delta,
        int(base.get("login_required_count") or 0) + login_delta,
        int(base.get("captcha_count") or 0) + captcha_delta,
        int(base.get("rate_limited_count") or 0) + rate_limited_delta,
        consecutive_failures,
        str(payload.get("last_success_at") or base.get("last_success_at") or ""),
        str(payload.get("last_error_at") or base.get("last_error_at") or ""),
        str(payload.get("last_error") or base.get("last_error") or ""),
        str(payload.get("backoff_until") or base.get("backoff_until") or ""),
        updated_at,
    )
    if row is None:
        connection.execute(
            """
            INSERT INTO netdisk_source_health (
                source_key, enabled, status, success_count, error_count, login_required_count,
                captcha_count, rate_limited_count, consecutive_failures, last_success_at,
                last_error_at, last_error, backoff_until, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (source_key, *values),
        )
        return
    connection.execute(
        """
        UPDATE netdisk_source_health
        SET enabled = ?, status = ?, success_count = ?, error_count = ?,
            login_required_count = ?, captcha_count = ?, rate_limited_count = ?,
            consecutive_failures = ?, last_success_at = ?, last_error_at = ?,
            last_error = ?, backoff_until = ?, updated_at = ?
        WHERE source_key = ?
        """,
        (*values, source_key),
    )


def list_code_watchlists(connection: sqlite3.Connection) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        FROM code_watchlists
        ORDER BY updated_at DESC, id DESC
        """
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        payload["metadata_json"] = str(payload.get("metadata_json") or "{}")
        rows.append(payload)
    return rows


def get_code_watchlist(connection: sqlite3.Connection, watchlist_id: int) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        FROM code_watchlists
        WHERE id = ?
        """,
        (int(watchlist_id),),
    )
    row = cursor.fetchone()
    if row is None:
        return None
    payload = dict(row)
    payload["enabled"] = bool(payload.get("enabled"))
    payload["metadata_json"] = str(payload.get("metadata_json") or "{}")
    return payload


def upsert_code_watchlist(connection: sqlite3.Connection, payload: dict) -> int:
    watchlist_id = payload.get("id")
    values = (
        str(payload.get("name") or "").strip(),
        str(payload.get("organization_name") or "").strip(),
        int(bool(payload.get("enabled", True))),
        str(payload.get("notes") or ""),
        str(payload.get("metadata_json") or "{}"),
        str(payload.get("created_at") or ""),
        str(payload.get("updated_at") or ""),
    )
    if watchlist_id:
        connection.execute(
            """
            UPDATE code_watchlists
            SET name = ?, organization_name = ?, enabled = ?, notes = ?, metadata_json = ?, created_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (*values, int(watchlist_id)),
        )
        return int(watchlist_id)
    cursor = connection.execute(
        """
        INSERT INTO code_watchlists (
            name, organization_name, enabled, notes, metadata_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        values,
    )
    return int(cursor.lastrowid)


def delete_code_watchlist(connection: sqlite3.Connection, watchlist_id: int) -> None:
    target_id = int(watchlist_id)
    connection.execute(
        """
        DELETE FROM code_hit_reviews
        WHERE hit_id IN (
            SELECT id FROM code_hits WHERE watchlist_id = ?
        )
        """,
        (target_id,),
    )
    connection.execute(
        """
        DELETE FROM code_hit_snapshots
        WHERE hit_id IN (
            SELECT id FROM code_hits WHERE watchlist_id = ?
        )
        """,
        (target_id,),
    )
    connection.execute("DELETE FROM code_hits WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM code_scan_runs WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM code_search_states WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM code_watch_terms WHERE watchlist_id = ?", (target_id,))
    connection.execute("DELETE FROM code_watchlists WHERE id = ?", (target_id,))


def list_code_watch_terms(connection: sqlite3.Connection, watchlist_id: int) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, term, term_type, weight, enabled, created_at, updated_at
        FROM code_watch_terms
        WHERE watchlist_id = ?
        ORDER BY enabled DESC, term
        """,
        (int(watchlist_id),),
    )
    rows = []
    for row in cursor.fetchall():
        payload = dict(row)
        payload["enabled"] = bool(payload.get("enabled"))
        rows.append(payload)
    return rows


def replace_code_watch_terms(connection: sqlite3.Connection, watchlist_id: int, rows: list[dict]) -> None:
    connection.execute("DELETE FROM code_watch_terms WHERE watchlist_id = ?", (int(watchlist_id),))
    if not rows:
        return
    connection.executemany(
        """
        INSERT INTO code_watch_terms (
            watchlist_id, term, term_type, weight, enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                int(watchlist_id),
                str(row.get("term") or "").strip(),
                str(row.get("term_type") or "").strip() or "custom",
                int(row.get("weight") or 0),
                int(bool(row.get("enabled", True))),
                str(row.get("created_at") or ""),
                str(row.get("updated_at") or ""),
            )
            for row in rows
            if str(row.get("term") or "").strip()
        ],
    )


def get_code_hit(connection: sqlite3.Connection, hit_id: int) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, platform, repository_name, repository_owner, repository_url, file_path,
               branch, file_url, visibility, language, sensitive_type, matched_rule, matched_term, result_layer,
               risk_score, severity, review_status, evidence_count, first_seen_at, last_seen_at,
               last_snapshot_id, raw_json
        FROM code_hits
        WHERE id = ?
        """,
        (int(hit_id),),
    )
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def list_code_hits(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    sensitive_type: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    where_parts = []
    params: list[object] = []
    if watchlist_id is not None:
        where_parts.append("h.watchlist_id = ?")
        params.append(int(watchlist_id))
    if review_status:
        where_parts.append("h.review_status = ?")
        params.append(str(review_status).strip())
    if platform:
        where_parts.append("h.platform = ?")
        params.append(str(platform).strip())
    if sensitive_type:
        where_parts.append("h.sensitive_type = ?")
        params.append(str(sensitive_type).strip())
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    cursor = connection.execute(
        f"""
        SELECT h.id, h.watchlist_id, h.platform, h.repository_name, h.repository_owner, h.repository_url,
               h.file_path, h.branch, h.file_url, h.visibility, h.language, h.sensitive_type, h.matched_rule,
               h.matched_term, h.result_layer, h.risk_score, h.severity, h.review_status, h.evidence_count, h.first_seen_at,
               h.last_seen_at, h.last_snapshot_id, h.raw_json, w.name AS watchlist_name, w.organization_name, w.metadata_json AS watchlist_metadata_json
        FROM code_hits h
        JOIN code_watchlists w
          ON w.id = h.watchlist_id
        {where_clause}
        ORDER BY h.risk_score DESC, datetime(h.last_seen_at) DESC, h.id DESC
        {limit_clause}
        """,
        tuple(params),
    )
    return [dict(row) for row in cursor.fetchall()]


def upsert_code_hit_with_state(connection: sqlite3.Connection, payload: dict) -> tuple[int, bool]:
    signature = (
        int(payload.get("watchlist_id") or 0),
        str(payload.get("platform") or "").strip(),
        str(payload.get("file_url") or "").strip(),
        str(payload.get("sensitive_type") or "").strip(),
        str(payload.get("matched_term") or "").strip(),
    )
    if not all(signature):
        raise ValueError("watchlist_id, platform, file_url, sensitive_type, and matched_term are required")
    cursor = connection.execute(
        """
        SELECT id
        FROM code_hits
        WHERE watchlist_id = ? AND platform = ? AND file_url = ? AND sensitive_type = ? AND matched_term = ?
        """,
        signature,
    )
    row = cursor.fetchone()
    values = (
        str(payload.get("repository_name") or "").strip(),
        str(payload.get("repository_owner") or "").strip(),
        str(payload.get("repository_url") or "").strip(),
        str(payload.get("file_path") or "").strip(),
        str(payload.get("branch") or "").strip(),
        str(payload.get("visibility") or "").strip() or "public",
        str(payload.get("language") or "").strip(),
        str(payload.get("matched_rule") or "").strip(),
        str(payload.get("result_layer") or "").strip() or "sensitive",
        int(payload.get("risk_score") or 0),
        str(payload.get("severity") or "").strip() or "low",
        str(payload.get("review_status") or "").strip() or "new",
        int(payload.get("evidence_count") or 0),
        str(payload.get("last_seen_at") or ""),
        payload.get("last_snapshot_id"),
        str(payload.get("raw_json") or "{}"),
    )
    if row is not None:
        connection.execute(
            """
            UPDATE code_hits
            SET repository_name = ?, repository_owner = ?, repository_url = ?, file_path = ?, branch = ?,
                visibility = ?, language = ?, matched_rule = ?, result_layer = ?, risk_score = ?, severity = ?, review_status = ?,
                evidence_count = ?, last_seen_at = ?, last_snapshot_id = ?, raw_json = ?
            WHERE id = ?
            """,
            (*values, int(row["id"])),
        )
        return int(row["id"]), False
    cursor = connection.execute(
        """
        INSERT INTO code_hits (
            watchlist_id, platform, repository_name, repository_owner, repository_url, file_path, branch,
            file_url, visibility, language, sensitive_type, matched_rule, matched_term, result_layer, risk_score, severity,
            review_status, evidence_count, first_seen_at, last_seen_at, last_snapshot_id, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature[0],
            signature[1],
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            signature[2],
            values[5],
            values[6],
            signature[3],
            values[7],
            signature[4],
            values[8],
            values[9],
            values[10],
            values[11],
            values[12],
            str(payload.get("first_seen_at") or values[13]),
            values[13],
            values[14],
            values[15],
        ),
    )
    return int(cursor.lastrowid), True


def upsert_code_hit(connection: sqlite3.Connection, payload: dict) -> int:
    return upsert_code_hit_with_state(connection, payload)[0]


def insert_code_hit_snapshot(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO code_hit_snapshots (
            hit_id, fetched_at, search_url, page_url, html_path, screenshot_path, code_fragment, masked_fragment,
            raw_artifact_path, line_start, line_end, language, findings_json, raw_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("hit_id") or 0),
            str(payload.get("fetched_at") or ""),
            str(payload.get("search_url") or ""),
            str(payload.get("page_url") or ""),
            str(payload.get("html_path") or ""),
            str(payload.get("screenshot_path") or ""),
            str(payload.get("code_fragment") or ""),
            str(payload.get("masked_fragment") or ""),
            str(payload.get("raw_artifact_path") or ""),
            int(payload.get("line_start") or 0),
            int(payload.get("line_end") or 0),
            str(payload.get("language") or ""),
            str(payload.get("findings_json") or "[]"),
            str(payload.get("raw_json") or "{}"),
        ),
    )
    return int(cursor.lastrowid)


def list_code_hit_snapshots(connection: sqlite3.Connection, hit_id: int) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, hit_id, fetched_at, search_url, page_url, html_path, screenshot_path, code_fragment,
               masked_fragment, raw_artifact_path, line_start, line_end, language, findings_json, raw_json
        FROM code_hit_snapshots
        WHERE hit_id = ?
        ORDER BY datetime(fetched_at) DESC, id DESC
        """,
        (int(hit_id),),
    )
    return [dict(row) for row in cursor.fetchall()]


def update_code_hit_last_snapshot(connection: sqlite3.Connection, hit_id: int, snapshot_id: int) -> None:
    connection.execute(
        "UPDATE code_hits SET last_snapshot_id = ?, evidence_count = evidence_count + 1 WHERE id = ?",
        (int(snapshot_id), int(hit_id)),
    )


def add_code_hit_review(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO code_hit_reviews (hit_id, status, reviewer, note, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("hit_id") or 0),
            str(payload.get("status") or "").strip() or "triaged",
            str(payload.get("reviewer") or "").strip(),
            str(payload.get("note") or ""),
            str(payload.get("created_at") or ""),
        ),
    )
    connection.execute(
        "UPDATE code_hits SET review_status = ? WHERE id = ?",
        (str(payload.get("status") or "").strip() or "triaged", int(payload.get("hit_id") or 0)),
    )
    return int(cursor.lastrowid)


def list_code_hit_reviews(connection: sqlite3.Connection, hit_id: int) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, hit_id, status, reviewer, note, created_at
        FROM code_hit_reviews
        WHERE hit_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        """,
        (int(hit_id),),
    )
    return [dict(row) for row in cursor.fetchall()]


def insert_code_scan_run(connection: sqlite3.Connection, payload: dict) -> int:
    cursor = connection.execute(
        """
        INSERT INTO code_scan_runs (
            watchlist_id, platforms_json, requested_terms_json, candidate_count, hit_count,
            clue_hit_count, sensitive_hit_count, error_count, status, errors_json, started_at, finished_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(payload.get("watchlist_id") or 0),
            str(payload.get("platforms_json") or "[]"),
            str(payload.get("requested_terms_json") or "[]"),
            int(payload.get("candidate_count") or 0),
            int(payload.get("hit_count") or 0),
            int(payload.get("clue_hit_count") or 0),
            int(payload.get("sensitive_hit_count") or 0),
            int(payload.get("error_count") or 0),
            str(payload.get("status") or "").strip() or "succeeded",
            str(payload.get("errors_json") or "[]"),
            str(payload.get("started_at") or ""),
            str(payload.get("finished_at") or ""),
        ),
    )
    return int(cursor.lastrowid)


def update_code_scan_run(connection: sqlite3.Connection, scan_run_id: int, payload: dict) -> int:
    cursor = connection.execute(
        """
        UPDATE code_scan_runs
           SET platforms_json = ?,
               requested_terms_json = ?,
               candidate_count = ?,
               hit_count = ?,
               clue_hit_count = ?,
               sensitive_hit_count = ?,
               error_count = ?,
               status = ?,
               errors_json = ?,
               finished_at = ?
         WHERE id = ?
        """,
        (
            str(payload.get("platforms_json") or "[]"),
            str(payload.get("requested_terms_json") or "[]"),
            int(payload.get("candidate_count") or 0),
            int(payload.get("hit_count") or 0),
            int(payload.get("clue_hit_count") or 0),
            int(payload.get("sensitive_hit_count") or 0),
            int(payload.get("error_count") or 0),
            str(payload.get("status") or "").strip() or "succeeded",
            str(payload.get("errors_json") or "[]"),
            str(payload.get("finished_at") or ""),
            int(scan_run_id),
        ),
    )
    return int(cursor.rowcount)


def list_code_scan_runs(connection: sqlite3.Connection, watchlist_id: int | None = None, limit: int | None = 100) -> list[dict]:
    params: list[object] = []
    where_clause = ""
    if watchlist_id is not None:
        where_clause = "WHERE r.watchlist_id = ?"
        params.append(int(watchlist_id))
    limit_clause = f"LIMIT {int(limit)}" if limit else ""
    cursor = connection.execute(
        f"""
        SELECT r.id, r.watchlist_id, r.platforms_json, r.requested_terms_json, r.candidate_count,
               r.hit_count, r.clue_hit_count, r.sensitive_hit_count, r.error_count, r.status, r.errors_json, r.started_at, r.finished_at,
               w.name AS watchlist_name, w.organization_name
        FROM code_scan_runs r
        JOIN code_watchlists w
          ON w.id = r.watchlist_id
        {where_clause}
        ORDER BY datetime(COALESCE(NULLIF(r.finished_at, ''), r.started_at)) DESC, r.id DESC
        {limit_clause}
        """,
        tuple(params),
    )
    return [dict(row) for row in cursor.fetchall()]


def list_code_search_states(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int,
    platform: str,
    term: str,
) -> list[dict]:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, platform, term, query_key, last_page_scanned,
               last_candidate_signature, last_candidate_keys_json, last_repository_urls_json,
               last_run_started_at, last_run_finished_at, updated_at
        FROM code_search_states
        WHERE watchlist_id = ? AND platform = ? AND term = ?
        ORDER BY query_key ASC, id ASC
        """,
        (int(watchlist_id), str(platform).strip(), str(term).strip()),
    )
    return [dict(row) for row in cursor.fetchall()]


def get_code_search_state(
    connection: sqlite3.Connection,
    *,
    watchlist_id: int,
    platform: str,
    term: str,
    query_key: str = "base",
) -> dict | None:
    cursor = connection.execute(
        """
        SELECT id, watchlist_id, platform, term, query_key, last_page_scanned,
               last_candidate_signature, last_candidate_keys_json, last_repository_urls_json,
               last_run_started_at, last_run_finished_at, updated_at
        FROM code_search_states
        WHERE watchlist_id = ? AND platform = ? AND term = ? AND query_key = ?
        """,
        (int(watchlist_id), str(platform).strip(), str(term).strip(), str(query_key).strip() or "base"),
    )
    row = cursor.fetchone()
    return dict(row) if row is not None else None


def upsert_code_search_state(connection: sqlite3.Connection, payload: dict) -> int:
    signature = (
        int(payload.get("watchlist_id") or 0),
        str(payload.get("platform") or "").strip(),
        str(payload.get("term") or "").strip(),
        str(payload.get("query_key") or "").strip() or "base",
    )
    if not all(signature):
        raise ValueError("watchlist_id, platform, term, and query_key are required")
    cursor = connection.execute(
        """
        SELECT id
        FROM code_search_states
        WHERE watchlist_id = ? AND platform = ? AND term = ? AND query_key = ?
        """,
        signature,
    )
    row = cursor.fetchone()
    values = (
        int(payload.get("last_page_scanned") or 0),
        str(payload.get("last_candidate_signature") or ""),
        str(payload.get("last_candidate_keys_json") or "[]"),
        str(payload.get("last_repository_urls_json") or "[]"),
        str(payload.get("last_run_started_at") or ""),
        str(payload.get("last_run_finished_at") or ""),
        str(payload.get("updated_at") or ""),
    )
    if row is not None:
        connection.execute(
            """
            UPDATE code_search_states
            SET last_page_scanned = ?, last_candidate_signature = ?, last_candidate_keys_json = ?,
                last_repository_urls_json = ?, last_run_started_at = ?, last_run_finished_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (*values, int(row["id"])),
        )
        return int(row["id"])
    cursor = connection.execute(
        """
        INSERT INTO code_search_states (
            watchlist_id, platform, term, query_key, last_page_scanned, last_candidate_signature,
            last_candidate_keys_json, last_repository_urls_json, last_run_started_at, last_run_finished_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            signature[0],
            signature[1],
            signature[2],
            signature[3],
            values[0],
            values[1],
            values[2],
            values[3],
            values[4],
            values[5],
            values[6],
        ),
    )
    return int(cursor.lastrowid)
