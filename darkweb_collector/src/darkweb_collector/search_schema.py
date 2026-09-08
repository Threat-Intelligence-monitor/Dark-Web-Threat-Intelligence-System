from __future__ import annotations


REPORT_TIME = "COALESCE(NULLIF(disclosure_time, ''), updated_at)"
SEVERITY_RANK = (
    "CASE LOWER(severity) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END"
)
SEARCH_ORDER = {
    "latest": f"{REPORT_TIME} DESC, event_id DESC",
    "oldest": f"{REPORT_TIME} ASC, event_id ASC",
    "severity": f"{SEVERITY_RANK} DESC, risk_score DESC, {REPORT_TIME} DESC, event_id DESC",
}


def ensure_search_indexes(connection) -> None:
    """Add indexes at database initialization without changing baseline schema."""
    for suffix, prefix in (("", ""), ("_type", "event_type, ")):
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS idx_intelligence_report_order{suffix} "
            f"ON normalized_intelligence_events ({prefix}({REPORT_TIME}) DESC, event_id DESC)"
        )
        connection.execute(
            f"CREATE INDEX IF NOT EXISTS idx_intelligence_severity_order{suffix} "
            f"ON normalized_intelligence_events ({prefix}({SEVERITY_RANK}) DESC, "
            f"risk_score DESC, ({REPORT_TIME}) DESC, event_id DESC)"
        )
