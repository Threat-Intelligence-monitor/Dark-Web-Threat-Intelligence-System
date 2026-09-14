from __future__ import annotations

import json
from datetime import datetime, timezone


def event_report_time(row: dict) -> str:
    """Use the displayed source update time, in a sortable UTC representation."""
    metadata = row.get("metadata")
    if not isinstance(metadata, dict):
        try:
            metadata = json.loads(row.get("event_metadata_json") or "{}")
        except (ValueError, TypeError):
            metadata = {}
    if not isinstance(metadata, dict):
        metadata = {}
    candidates = [metadata.get("updated_time"), row.get("disclosure_time")]
    if row.get("event_type") == "vulnerability":
        candidates.append(row.get("updated_at"))
    for value in candidates:
        if not value:
            continue
        raw = str(value).strip().replace(" UTC", "+00:00").replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            parsed = None
            for fmt in ("%d/%m/%Y", "%d %B %Y", "%d %b %Y"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
            if parsed is None:
                continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return ""


REPORT_TIME = "report_time"
MISSING_TIME = "CASE WHEN report_time IS NULL OR report_time = '' THEN 1 ELSE 0 END"
SEVERITY_RANK = (
    "CASE LOWER(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)
SEARCH_ORDER = {
    "latest": f"{MISSING_TIME} ASC, {REPORT_TIME} DESC, event_id DESC",
    "oldest": f"{MISSING_TIME} ASC, {REPORT_TIME} ASC, event_id ASC",
    "severity": f"{SEVERITY_RANK} DESC, risk_score DESC, {MISSING_TIME} ASC, {REPORT_TIME} DESC, event_id DESC",
}


def ensure_search_indexes(connection) -> None:
    """Keep the column, backfill and indexes atomic, including SQLite DDL."""
    connection.execute("SAVEPOINT intelligence_report_time_migration")
    try:
        _ensure_search_indexes(connection)
    except Exception:
        connection.execute("ROLLBACK TO SAVEPOINT intelligence_report_time_migration")
        connection.execute("RELEASE SAVEPOINT intelligence_report_time_migration")
        raise
    connection.execute("RELEASE SAVEPOINT intelligence_report_time_migration")


def _ensure_search_indexes(connection) -> None:
    """Migrate the display-time sort key once, then ensure its indexes."""
    # PostgreSQL initialization passes a raw psycopg cursor; SQLite a connection.
    postgres = type(connection).__module__.startswith("psycopg")
    if postgres:
        connection.execute("SELECT column_name FROM information_schema.columns "
                           "WHERE table_schema=current_schema() "
                           "AND table_name='normalized_intelligence_events'")
        columns = {row[0] for row in connection.fetchall()}
    else:
        columns = {row[1] for row in connection.execute(
            "PRAGMA table_info(normalized_intelligence_events)").fetchall()}
    if "report_time" not in columns:
        connection.execute("ALTER TABLE normalized_intelligence_events "
                           "ADD COLUMN report_time TEXT NOT NULL DEFAULT ''")
        # Existing keyword postings keep their text; update their time keys as well.
        if postgres:
            connection.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() "
                               "AND table_name='intelligence_search_documents'")
            has_documents = connection.fetchone() is not None
        else:
            has_documents = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                               "AND name='intelligence_search_documents'").fetchone() is not None
        placeholder = "%s" if postgres else "?"
        names = ("event_id", "event_type", "disclosure_time", "updated_at", "event_metadata_json")
        after = None
        while True:
            where = "" if after is None else f" WHERE event_id > {placeholder}"
            result = connection.execute("SELECT event_id, event_type, disclosure_time, "
                                        "updated_at, event_metadata_json FROM normalized_intelligence_events"
                                        + where + " ORDER BY event_id LIMIT 500",
                                        () if after is None else (after,))
            records = connection.fetchall() if postgres else result.fetchall()
            if not records:
                break
            updates = [(event_report_time(dict(zip(names, row))), row[0]) for row in records]
            connection.executemany(f"UPDATE normalized_intelligence_events SET report_time={placeholder} "
                                   f"WHERE event_id={placeholder}", updates)
            if has_documents:
                connection.executemany(f"UPDATE intelligence_search_documents SET report_time={placeholder} "
                                       f"WHERE event_id={placeholder}", updates)
            after = records[-1][0]
        for suffix in ("", "_type"):
            connection.execute(f"DROP INDEX IF EXISTS idx_intelligence_report_order{suffix}")
            connection.execute(f"DROP INDEX IF EXISTS idx_intelligence_severity_order{suffix}")
    for suffix, prefix in (("", ""), ("_type", "event_type, ")):
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS idx_intelligence_report_order{suffix} "
            f"ON normalized_intelligence_events ({prefix}({MISSING_TIME}) ASC, ({REPORT_TIME}) DESC, event_id DESC)"
        )
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS idx_intelligence_severity_order{suffix} "
            f"ON normalized_intelligence_events ({prefix}({SEVERITY_RANK}) DESC, "
            f"risk_score DESC, ({MISSING_TIME}) ASC, ({REPORT_TIME}) DESC, event_id DESC)"
        )
