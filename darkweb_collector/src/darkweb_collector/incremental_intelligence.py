"""Bounded, durable projection from collected records to visible intelligence.

The caller holds the normalizer lock and owns the transaction.  Source changes,
canonical winners, search postings and the notification outbox commit together.
Historical context and risk changes use the same bounded queues as bootstrap;
they never require rebuilding every historical body before publishing a new one.
"""
from __future__ import annotations

from datetime import timedelta
from hashlib import sha256
import json
import time

from darkweb_collector import intelligence_changes as changes
from darkweb_collector import normalized_intelligence as n
from darkweb_collector import search_index
from darkweb_collector.db import upsert_normalized_intelligence_cache_state
from darkweb_collector.search_schema import event_report_time


SOURCE_TYPES = ("forum_details", "victims", "ransomware_live_victims", "vulnerability_records")
_COLUMNS = (
    "event_id", "source_kind", "raw_source_type", "source_site_name", "source_record_id",
    "event_type", "category", "leak_type", "title", "attacker", "victim", "victim_key",
    "industry", "region", "disclosure_time", "severity", "risk_score", "source_url",
    "detail_text", "mirror_resources_json", "screenshot_resources_json", "json_preview_url",
    "risk_reasons_json", "event_metadata_json", "updated_at", "report_time",
)


def ensure_incremental_projection_schema(connection, postgres=False):
    # Use portable, explicit keys: no serial/rowid allocation or migration-time
    # body scans are needed on either database backend.
    statements = (
        "CREATE TABLE IF NOT EXISTS intelligence_projection_state (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS intelligence_projection_candidates (
            source_type TEXT NOT NULL, source_id BIGINT NOT NULL, event_id TEXT NOT NULL,
            payload TEXT NOT NULL, payload_bytes BIGINT NOT NULL, summary TEXT NOT NULL,
            source_rank INTEGER NOT NULL, order_time TEXT NOT NULL,
            victim_key TEXT NOT NULL, country_known INTEGER NOT NULL, country_score INTEGER NOT NULL,
            industry_known INTEGER NOT NULL, industry_score INTEGER NOT NULL, confidence INTEGER NOT NULL,
            actor TEXT NOT NULL, site TEXT NOT NULL, industry TEXT NOT NULL, region TEXT NOT NULL,
            disclosure_at TEXT NOT NULL, time_window INTEGER NOT NULL, next_expiry TEXT NOT NULL,
            PRIMARY KEY(source_type, source_id))""",
        """CREATE TABLE IF NOT EXISTS intelligence_projection_identities (
            event_id TEXT PRIMARY KEY, group_key TEXT NOT NULL, payload TEXT NOT NULL, payload_bytes BIGINT NOT NULL,
            source_rank INTEGER NOT NULL, order_time TEXT NOT NULL, source_id BIGINT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS intelligence_projection_work (
            kind TEXT NOT NULL, work_key TEXT NOT NULL, priority INTEGER NOT NULL, revision BIGINT NOT NULL,
            cursor_json TEXT NOT NULL DEFAULT '', payload TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(kind, work_key))""",
        """CREATE TABLE IF NOT EXISTS intelligence_projection_dependencies (
            kind TEXT NOT NULL, label TEXT NOT NULL, priority INTEGER NOT NULL,
            cursor_type TEXT NOT NULL DEFAULT '', cursor_id BIGINT NOT NULL DEFAULT 0, repeat INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(kind, label))""",
        """CREATE TABLE IF NOT EXISTS intelligence_projection_publications (
            event_id TEXT PRIMARY KEY, group_key TEXT NOT NULL, source_type TEXT NOT NULL,
            source_id BIGINT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS normalized_notification_outbox (
            event_id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision BIGINT NOT NULL,
            enqueued_at DOUBLE PRECISION NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_retry DOUBLE PRECISION NOT NULL DEFAULT 0, lease_until DOUBLE PRECISION NOT NULL DEFAULT 0)""",
        "CREATE INDEX IF NOT EXISTS idx_projection_candidate_identity ON intelligence_projection_candidates(event_id, source_rank, order_time DESC, source_id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_projection_country ON intelligence_projection_candidates(victim_key, country_known DESC, country_score DESC, confidence DESC, source_rank, order_time DESC, source_id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_projection_industry_context ON intelligence_projection_candidates(victim_key, industry_known DESC, industry_score DESC, confidence DESC, source_rank, order_time DESC, source_id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_projection_actor ON intelligence_projection_candidates(actor, source_type, source_id, site)",
        "CREATE INDEX IF NOT EXISTS idx_projection_victim ON intelligence_projection_candidates(victim_key, source_type, source_id)",
        "CREATE INDEX IF NOT EXISTS idx_projection_industry ON intelligence_projection_candidates(industry, source_type, source_id, time_window)",
        "CREATE INDEX IF NOT EXISTS idx_projection_region ON intelligence_projection_candidates(region, source_type, source_id, time_window)",
        "CREATE INDEX IF NOT EXISTS idx_projection_expiry ON intelligence_projection_candidates(next_expiry)",
        "CREATE INDEX IF NOT EXISTS idx_projection_identity_group ON intelligence_projection_identities(group_key, source_rank, order_time DESC, source_id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_projection_work_priority ON intelligence_projection_work(kind, priority DESC, work_key)",
        "CREATE INDEX IF NOT EXISTS idx_projection_publication_group ON intelligence_projection_publications(group_key, event_id)",
        "CREATE INDEX IF NOT EXISTS idx_projection_publication_source ON intelligence_projection_publications(source_type, source_id)",
        "CREATE INDEX IF NOT EXISTS idx_projection_legacy_source ON normalized_intelligence_events(raw_source_type, source_record_id)",
        "CREATE INDEX IF NOT EXISTS idx_projection_legacy_title ON normalized_intelligence_events(source_site_name, event_type, title)",
        "CREATE INDEX IF NOT EXISTS idx_normalized_outbox_ready ON normalized_notification_outbox(next_retry, lease_until, enqueued_at)",
    )
    for statement in statements:
        connection.execute(statement)


def _state(connection, name, default=""):
    row = connection.execute("SELECT value FROM intelligence_projection_state WHERE name = ?", (name,)).fetchone()
    return row["value"] if row else default


def _set_state(connection, name, value):
    connection.execute("INSERT INTO intelligence_projection_state(name, value) VALUES (?, ?) "
                       "ON CONFLICT(name) DO UPDATE SET value = excluded.value", (name, str(value)))


def _group(event):
    key = [event.get("source_site_name") or "", event.get("event_type") or "", n._canonical_key(event.get("title") or "")]
    return sha256(n._json_dumps(key).encode("utf-8")).hexdigest()


def _enqueue(connection, kind, key, priority=0):
    if key:
        connection.execute("""INSERT INTO intelligence_projection_work(kind, work_key, priority, revision)
            VALUES (?, ?, ?, 1) ON CONFLICT(kind, work_key) DO UPDATE SET
            priority = CASE WHEN intelligence_projection_work.priority > excluded.priority
                THEN intelligence_projection_work.priority ELSE excluded.priority END,
            revision = intelligence_projection_work.revision + 1, cursor_json = '', payload = ''""", (kind, key, priority))


def _dependency(connection, kind, label, priority=0):
    if not label or label in {"unknown", "未知"}:
        return
    connection.execute("""INSERT INTO intelligence_projection_dependencies(kind, label, priority)
        VALUES (?, ?, ?) ON CONFLICT(kind, label) DO UPDATE SET
        priority = CASE WHEN intelligence_projection_dependencies.priority > excluded.priority
            THEN intelligence_projection_dependencies.priority ELSE excluded.priority END,
        repeat = 1""", (kind, label, priority))


def _summary(event):
    result = {key: event.get(key) for key in ("victim_key", "country", "country_code", "region", "industry", "confidence_score", "completeness_score")}
    result["metadata"] = {key: (event.get("metadata") or {}).get(key) for key in
                          ("country_score", "country_source", "industry_score", "industry_source")}
    return result


def _context(connection, event):
    victim = event.get("victim_key") or "unknown"
    if victim == "unknown":
        return event
    peers = []
    for prefix in ("country", "industry"):
        row = connection.execute(f"""SELECT summary, source_rank, order_time, source_id
            FROM intelligence_projection_candidates WHERE victim_key = ?
            ORDER BY {prefix}_known DESC, {prefix}_score DESC, confidence DESC,
                source_rank, order_time DESC, source_id DESC LIMIT 1""", (victim,)).fetchone()
        if row:
            peers.append((dict(row), json.loads(row["summary"])))
    # The two selected maxima contain exactly the context used by a full pass.
    # An event is appended last so an equal context never replaces an earlier
    # source's tie-breaking choice.  The summaries contain no bodies/raw JSON.
    peers.sort(key=lambda item: (item[0]["source_rank"],
        -(n._parse_dt(item[0]["order_time"]).timestamp() if item[0]["order_time"] else 0), -int(item[0]["source_id"])))
    n._propagate_entity_context([summary for _, summary in peers] + [event])
    return event


def _clock_fields(event, now):
    disclosed = n._parse_dt(str(event.get("disclosure_time") or ""))
    if not disclosed:
        return "", 0, ""
    stamp = disclosed.isoformat(timespec="microseconds")
    window = 1 if disclosed >= now - timedelta(days=n.SPIKE_WINDOW_DAYS) else 2 if disclosed >= now - timedelta(days=n.SPIKE_WINDOW_DAYS * 2) else 0
    boundaries = [disclosed + timedelta(hours=n.RECENT_EVENT_HOURS), disclosed + timedelta(days=n.SPIKE_WINDOW_DAYS),
                  disclosed + timedelta(days=n.SPIKE_WINDOW_DAYS * 2)]
    future = [item for item in boundaries if item >= now]
    expiry = (min(future) + timedelta(microseconds=1)).isoformat(timespec="microseconds") if future else ""
    return stamp, window, expiry


def _read_raw(connection, source_type, source_id):
    if source_type == "forum_details":
        statement = """SELECT d.*, COALESCE(t.title, d.topic_url) AS title,
            GROUP_CONCAT(fv.victim_name, '||') AS victim_names,
            GROUP_CONCAT(COALESCE(fv.industry, ''), '||') AS industries,
            GROUP_CONCAT(COALESCE(fv.region, ''), '||') AS regions
            FROM forum_details d LEFT JOIN forum_topics t ON t.site_name = d.site_name
                AND t.section = d.section AND t.url = d.topic_url
            LEFT JOIN forum_victims fv ON fv.forum_detail_id = d.id WHERE d.id = ? GROUP BY d.id, t.title"""
    elif source_type == "victims":
        statement = """SELECT v.*, vd.text_excerpt, vd.page_title, vd.fetched_at_utc,
            cr.collected_at_utc AS last_seen_at_utc, vd.raw_json AS detail_raw_json
            FROM victims v LEFT JOIN collection_runs cr ON cr.id = v.last_seen_run_id
            LEFT JOIN victim_details vd ON vd.id = (SELECT vd2.id FROM victim_details vd2
                WHERE vd2.victim_id = v.id ORDER BY datetime(vd2.fetched_at_utc) DESC, vd2.id DESC LIMIT 1)
            WHERE v.id = ?"""
    else:
        statement = f"SELECT * FROM {source_type} WHERE id = ?"
    row = connection.execute(statement, (source_id,)).fetchone()
    return dict(row) if row else None


def _raw_size(connection, source_type, source_id):
    columns = {
        "forum_details": ("content", "raw_json", "attachments", "victims", "attackers", "timestamps"),
        "victims": ("raw_json", "name", "display_label"),
        "ransomware_live_victims": ("description", "raw_json", "victim_name", "website"),
        "vulnerability_records": ("summary", "raw_json", "reference_urls_json", "affected_versions", "title"),
    }[source_type]
    expression = " + ".join("COALESCE(LENGTH(" + column + "), 0)" for column in columns)
    row = connection.execute(f"SELECT {expression} AS characters FROM {source_type} WHERE id = ?", (source_id,)).fetchone()
    size = int(row["characters"] or 0) * 4 if row else 0
    if source_type == "victims":
        detail = connection.execute("""SELECT COALESCE(LENGTH(raw_json), 0) + COALESCE(LENGTH(text_excerpt), 0) +
            COALESCE(LENGTH(page_title), 0) AS characters FROM victim_details WHERE victim_id = ?
            ORDER BY datetime(fetched_at_utc) DESC, id DESC LIMIT 1""", (source_id,)).fetchone()
        size += int(detail["characters"] or 0) * 4 if detail else 0
    # UTF-8 needs at most four bytes/character.  Small joined labels, JSON syntax
    # and compact metadata have headroom without fetching a batch of bodies.
    return size + 8192


def _remember_publication(connection, event):
    connection.execute("""INSERT INTO intelligence_projection_publications(event_id, group_key, source_type, source_id)
        VALUES (?, ?, ?, ?) ON CONFLICT(event_id) DO UPDATE SET group_key = excluded.group_key,
        source_type = excluded.source_type, source_id = excluded.source_id""",
        (event["event_id"], _group(event), event["raw_source_type"], event["source_record_id"]))


def _catalog(connection, limit):
    if _state(connection, "catalog_complete") == "1":
        return
    # This one-time compact catalog permits indexed canonical lookups during an
    # upgrade.  It pages metadata only; no source body, raw JSON, artifact tree or
    # historical inference is read before fresh changes can publish.
    after = _state(connection, "catalog_after")
    while True:
        rows = connection.execute("""SELECT event_id, source_site_name, event_type, title, raw_source_type,
            source_record_id FROM normalized_intelligence_events WHERE event_id > ? ORDER BY event_id LIMIT 1000""", (after,)).fetchall()
        values = [(row["event_id"], _group(dict(row)), row["raw_source_type"], row["source_record_id"]) for row in rows]
        statement = """INSERT INTO intelligence_projection_publications(event_id, group_key, source_type, source_id)
            VALUES {} ON CONFLICT(event_id) DO UPDATE SET group_key = excluded.group_key,
            source_type = excluded.source_type, source_id = excluded.source_id"""
        if values and getattr(connection, "backend_name", "") == "postgresql":
            from psycopg2.extras import execute_values
            with connection._raw.cursor() as cursor:
                execute_values(cursor, statement.format("%s"), values, page_size=1000)
        elif values:
            connection.executemany(statement.format("(?, ?, ?, ?)"), values)
        if rows:
            after = rows[-1]["event_id"]
            _set_state(connection, "catalog_after", after)
        if len(rows) < 1000:
            _set_state(connection, "catalog_complete", 1)
            return


def _legacy_for_change(connection, source_type, source_id, event, priority):
    rows = connection.execute("""SELECT event_id, source_site_name, event_type, title, raw_source_type,
        source_record_id FROM normalized_intelligence_events WHERE raw_source_type = ? AND source_record_id = ?""",
        (source_type, source_id)).fetchall()
    if event:
        rows += connection.execute("""SELECT event_id, source_site_name, event_type, title, raw_source_type,
            source_record_id FROM normalized_intelligence_events WHERE event_id = ? OR
                (source_site_name = ? AND event_type = ? AND title = ?)""",
            (event["event_id"], event["source_site_name"], event["event_type"], event["title"])).fetchall()
    for row in rows:
        _remember_publication(connection, dict(row))
        _enqueue(connection, "group", _group(dict(row)), priority)


def _put_candidate(connection, source_type, source_id, event, raw, domain_cache, priority, now):
    existing = connection.execute("SELECT event_id, victim_key, actor, industry, region FROM intelligence_projection_candidates "
                                  "WHERE source_type = ? AND source_id = ?", (source_type, source_id)).fetchone()
    _legacy_for_change(connection, source_type, source_id, event, priority)
    if existing:
        _enqueue(connection, "identity", existing["event_id"], priority)
        for kind, column in (("victim", "victim_key"), ("actor", "actor"), ("industry", "industry"), ("region", "region")):
            _dependency(connection, kind, existing[column])
    if event is None:
        connection.execute("DELETE FROM intelligence_projection_candidates WHERE source_type = ? AND source_id = ?", (source_type, source_id))
        return
    summary = _summary(event)
    payload = n._json_dumps(event)
    metadata = event.get("metadata") or {}
    rank = SOURCE_TYPES.index(source_type)
    ordered = (raw.get("attacked_at") or raw.get("discovered_at")) if rank == 2 else raw.get("disclosure_time") if rank == 3 else ""
    ordered_dt = n._parse_dt(str(ordered or ""))
    ordered = ordered_dt.isoformat(timespec="microseconds") if ordered_dt else ""
    disclosed, window, expiry = _clock_fields(event, now)
    # First make the new source's own context available, then derive its compact
    # effective counters.  Other affected sources are reconciled by dependency.
    values = (source_type, source_id, event["event_id"], payload, len(payload.encode("utf-8")), n._json_dumps(summary), rank, ordered,
              event.get("victim_key") or "unknown", int(event.get("country") not in {None, "", "未知"}), int(metadata.get("country_score") or 0),
              int(event.get("industry") not in {None, "", "未知"}), int(metadata.get("industry_score") or 0), int(event.get("confidence_score") or 0),
              event["attacker"], event["source_site_name"], n._normalize_label(event["industry"]), n._normalize_label(event["region"]),
              disclosed, window, expiry)
    columns = ("source_type", "source_id", "event_id", "payload", "payload_bytes", "summary", "source_rank", "order_time", "victim_key",
               "country_known", "country_score", "industry_known", "industry_score", "confidence", "actor", "site", "industry", "region",
               "disclosure_at", "time_window", "next_expiry")
    connection.execute("INSERT INTO intelligence_projection_candidates(" + ",".join(columns) + ") VALUES (" + ",".join("?" for _ in columns) + ") "
                       "ON CONFLICT(source_type, source_id) DO UPDATE SET " + ",".join(column + "=excluded." + column for column in columns[2:]), values)
    effective = _context(connection, event)
    n._apply_domain_enrichment([effective], domain_cache)
    connection.execute("UPDATE intelligence_projection_candidates SET industry = ?, region = ? WHERE source_type = ? AND source_id = ?",
                       (n._normalize_label(effective["industry"]), n._normalize_label(effective["region"]), source_type, source_id))
    _enqueue(connection, "identity", event["event_id"], priority)
    for kind, label in (("victim", event.get("victim_key")), ("actor", event.get("attacker")),
                        ("industry", effective.get("industry")), ("region", effective.get("region"))):
        _dependency(connection, kind, label)


def _statistic(connection, kind, label):
    column = {"actor": "actor", "victim": "victim_key", "industry": "industry", "region": "region"}[kind]
    if kind in {"industry", "region"}:
        row = connection.execute(f"SELECT SUM(CASE WHEN time_window = 1 THEN 1 ELSE 0 END) AS recent, "
                                 f"SUM(CASE WHEN time_window = 2 THEN 1 ELSE 0 END) AS previous "
                                 f"FROM intelligence_projection_candidates WHERE {column} = ?", (label,)).fetchone()
        return int(row["recent"] or 0), int(row["previous"] or 0)
    if label in {"", "未知", "unknown"}:
        return 0, 0
    row = connection.execute(f"SELECT COUNT(*) AS total, COUNT(DISTINCT site) AS sites "
                             f"FROM intelligence_projection_candidates WHERE {column} = ?", (label,)).fetchone()
    return int(row["total"] or 0), int(row["sites"] or 0)


def _score(connection, event, domain_cache):
    _context(connection, event)
    n._apply_domain_enrichment([event], domain_cache)
    actor, victim = event["attacker"], event["victim_key"]
    industry, region = n._normalize_label(event["industry"]), n._normalize_label(event["region"])
    # Candidates/context counters are stable throughout this scoring stage.
    # Sharing a label must not cause the same compact historical index range
    # to be counted fifty times in one publication cycle.
    statistics = domain_cache.setdefault("__projection_statistics__", {})
    def statistic(kind, label):
        key = (kind, label)
        if key not in statistics:
            statistics[key] = _statistic(connection, kind, label)
        return statistics[key]
    actor_count, sites = statistic("actor", actor)
    victim_count, _ = statistic("victim", victim)
    industry_recent, industry_previous = statistic("industry", industry)
    region_recent, region_previous = statistic("region", region)
    n._score_events([event], statistics=({actor: actor_count}, {victim: victim_count}, {actor: sites},
        {industry: industry_recent}, {industry: industry_previous}, {region: region_recent}, {region: region_previous}), recent_cutoff=n._recent_cutoff())
    return event


def _dependencies(connection, limit, domain_cache):
    budget = limit
    for work in connection.execute("SELECT * FROM intelligence_projection_dependencies ORDER BY priority DESC, kind, label LIMIT ?", (limit,)).fetchall():
        if budget <= 0:
            break
        column = {"actor": "actor", "victim": "victim_key", "industry": "industry", "region": "region"}[work["kind"]]
        rows = connection.execute(f"""SELECT source_type, source_id, event_id, summary, industry, region
            FROM intelligence_projection_candidates WHERE {column} = ? AND
                (source_type > ? OR (source_type = ? AND source_id > ?))
            ORDER BY source_type, source_id LIMIT ?""", (work["label"], work["cursor_type"], work["cursor_type"], work["cursor_id"], budget)).fetchall()
        for row in rows:
            if work["kind"] == "victim":
                summary = _context(connection, json.loads(row["summary"]))
                # Enrichment already present in the persisted base summary is
                # sufficient here; no historical body or network fetch occurs.
                industry, region = n._normalize_label(summary["industry"]), n._normalize_label(summary["region"])
                if (industry, region) != (row["industry"], row["region"]):
                    connection.execute("UPDATE intelligence_projection_candidates SET industry = ?, region = ? WHERE source_type = ? AND source_id = ?",
                                       (industry, region, row["source_type"], row["source_id"]))
                    for kind, before, after in (("industry", row["industry"], industry), ("region", row["region"], region)):
                        _dependency(connection, kind, before)
                        _dependency(connection, kind, after)
            _enqueue(connection, "identity", row["event_id"], int(work["priority"]))
        budget -= len(rows)
        if len(rows) < max(1, budget + len(rows)):
            if work["repeat"]:
                connection.execute("UPDATE intelligence_projection_dependencies SET cursor_type = '', cursor_id = 0, repeat = 0 WHERE kind = ? AND label = ?",
                                   (work["kind"], work["label"]))
            else:
                connection.execute("DELETE FROM intelligence_projection_dependencies WHERE kind = ? AND label = ?", (work["kind"], work["label"]))
        elif rows:
            connection.execute("UPDATE intelligence_projection_dependencies SET cursor_type = ?, cursor_id = ? WHERE kind = ? AND label = ?",
                               (rows[-1]["source_type"], rows[-1]["source_id"], work["kind"], work["label"]))


def _expire(connection, limit, now):
    stamp = now.isoformat(timespec="microseconds")
    rows = connection.execute("""SELECT source_type, source_id, event_id, industry, region, disclosure_at, time_window
        FROM intelligence_projection_candidates WHERE next_expiry > '' AND next_expiry <= ?
        ORDER BY next_expiry LIMIT ?""", (stamp, limit)).fetchall()
    for row in rows:
        _, window, expiry = _clock_fields({"disclosure_time": row["disclosure_at"]}, now)
        connection.execute("UPDATE intelligence_projection_candidates SET time_window = ?, next_expiry = ? WHERE source_type = ? AND source_id = ?",
                           (window, expiry, row["source_type"], row["source_id"]))
        _enqueue(connection, "identity", row["event_id"])
        if window != row["time_window"]:
            _dependency(connection, "industry", row["industry"])
            _dependency(connection, "region", row["region"])


def _after_cursor(cursor):
    if not cursor:
        return "", []
    rank, ordered, source_id = json.loads(cursor)
    return (" AND (source_rank > ? OR (source_rank = ? AND order_time < ?) OR "
            "(source_rank = ? AND order_time = ? AND source_id < ?))", [rank, rank, ordered, rank, ordered, source_id])


def _work_rows(connection, table, column, key, cursor, limit, max_bytes):
    after, parameters = _after_cursor(cursor)
    rows = connection.execute(f"SELECT source_rank, order_time, source_id, payload_bytes FROM {table} WHERE {column} = ?"
                              + after + " ORDER BY source_rank, order_time DESC, source_id DESC LIMIT ?", [key, *parameters, limit]).fetchall()
    selected, size = [], 0
    for row in rows:
        if selected and size + int(row["payload_bytes"]) > max_bytes:
            break
        selected.append(dict(row))
        size += int(row["payload_bytes"])
    return selected, size


def _merge_work(connection, kind, limit, max_bytes, domain_cache, publish):
    table, column = (("intelligence_projection_candidates", "event_id") if kind == "identity"
                     else ("intelligence_projection_identities", "group_key"))
    remaining, byte_budget = limit, max_bytes
    tasks = connection.execute("""SELECT kind, work_key, priority, revision, cursor_json,
        LENGTH(payload) AS payload_characters FROM intelligence_projection_work WHERE kind = ?
        ORDER BY priority DESC, work_key LIMIT ?""", (kind, limit)).fetchall()
    for task in tasks:
        if remaining <= 0 or byte_budget <= 0:
            break
        carry_size = int(task["payload_characters"] or 0) * 4
        if remaining < limit and carry_size > byte_budget:
            break
        carried = connection.execute("SELECT payload FROM intelligence_projection_work WHERE kind = ? AND work_key = ?",
                                     (kind, task["work_key"])).fetchone()["payload"]
        rows, size = _work_rows(connection, table, column, task["work_key"], task["cursor_json"], remaining, max(1, byte_budget - carry_size))
        merged = json.loads(carried) if carried else None
        first = None
        if merged:
            first = merged.pop("__projection_order__", None)
        for row in rows:
            # Unique ordering keys identify at most one candidate within a raw
            # family and at most one identity within a canonical group.
            result = connection.execute(f"SELECT payload FROM {table} WHERE {column} = ? AND source_rank = ? AND order_time = ? AND source_id = ?",
                                        (task["work_key"], row["source_rank"], row["order_time"], row["source_id"])).fetchone()
            event = json.loads(result["payload"])
            if kind == "identity":
                _score(connection, event, domain_cache)
            first = first or [row["source_rank"], row["order_time"], row["source_id"]]
            merged = n._merge_duplicate_events(merged, event) if merged else event
        remaining -= len(rows)
        byte_budget -= size + carry_size
        cursor = n._json_dumps([rows[-1]["source_rank"], rows[-1]["order_time"], rows[-1]["source_id"]]) if rows else task["cursor_json"]
        after, parameters = _after_cursor(cursor)
        more = connection.execute(f"SELECT 1 FROM {table} WHERE {column} = ?" + after + " LIMIT 1", [task["work_key"], *parameters]).fetchone() if cursor else None
        if more:
            if merged:
                merged["__projection_order__"] = first
            connection.execute("UPDATE intelligence_projection_work SET cursor_json = ?, payload = ? WHERE kind = ? AND work_key = ? AND revision = ?",
                               (cursor, n._json_dumps(merged) if merged else "", kind, task["work_key"], task["revision"]))
            continue
        connection.execute("DELETE FROM intelligence_projection_work WHERE kind = ? AND work_key = ? AND revision = ?", (kind, task["work_key"], task["revision"]))
        if kind == "identity":
            old = connection.execute("SELECT group_key FROM intelligence_projection_identities WHERE event_id = ?", (task["work_key"],)).fetchone()
            if old:
                _enqueue(connection, "group", old["group_key"], int(task["priority"]))
            if merged:
                payload, group = n._json_dumps(merged), _group(merged)
                connection.execute("""INSERT INTO intelligence_projection_identities(event_id, group_key, payload, payload_bytes, source_rank, order_time, source_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(event_id) DO UPDATE SET group_key = excluded.group_key, payload = excluded.payload,
                    payload_bytes = excluded.payload_bytes, source_rank = excluded.source_rank, order_time = excluded.order_time, source_id = excluded.source_id""",
                    (merged["event_id"], group, payload, len(payload.encode("utf-8")), *first))
                # Keep the currently published row (and its retained evidence)
                # attached to this identity while its canonical title changes.
                # Otherwise processing the old group first could delete it
                # before the new group gets a chance to retain its resources.
                connection.execute("UPDATE intelligence_projection_publications SET group_key = ? WHERE event_id = ?",
                                   (group, merged["event_id"]))
                _enqueue(connection, "group", group, int(task["priority"]))
            else:
                connection.execute("DELETE FROM intelligence_projection_identities WHERE event_id = ?", (task["work_key"],))
        else:
            publish(task["work_key"], merged, int(task["priority"]))


def _serialize(event, previous, updated_at):
    mirrors = n._merge_unique_resources(n._coerce_resource_list(n._parse_json((previous or {}).get("mirror_resources_json"))), event.get("mirror_resources") or [])
    screenshots = n._merge_unique_resources(n._coerce_resource_list(n._parse_json((previous or {}).get("screenshot_resources_json"))), event.get("screenshot_resources") or [])
    metadata = {**event["metadata"], "country": event.get("country") or "未知", "country_code": event.get("country_code") or "",
        "macro_region": event.get("region") or "未知", "confidence_score": int(event.get("confidence_score") or 0),
        "completeness_score": int(event.get("completeness_score") or 0), "resource_count": len(mirrors)}
    row = {key: event[key] for key in _COLUMNS[:18]}
    row.update(detail_text=event.get("detail_text") or "", disclosure_time=event.get("disclosure_time") or "",
        source_url=event.get("source_url") or "", mirror_resources_json=n._json_dumps(mirrors), screenshot_resources_json=n._json_dumps(screenshots),
        json_preview_url=str(event.get("json_preview_url") or (previous or {}).get("json_preview_url") or ""),
        risk_reasons_json=n._json_dumps(event["metadata"].get("risk_reasons") or []), event_metadata_json=n._json_dumps(metadata), updated_at=updated_at)
    row["report_time"] = event_report_time(row)
    return row


def _bootstrap_complete(connection):
    return all(bool(row and row["complete"]) for row in (
        connection.execute("SELECT complete FROM intelligence_source_bootstrap WHERE source_type = ?", (source,)).fetchone() for source in SOURCE_TYPES))


def _publication(connection, group, event, priority, updated_at, revision, complete, result):
    previous_rows = connection.execute("""SELECT n.event_id, n.raw_source_type, n.source_record_id FROM normalized_intelligence_events n
        JOIN intelligence_projection_publications p ON p.event_id = n.event_id WHERE p.group_key = ?""", (group,)).fetchall()
    # During upgrade an old canonical winner remains visible until all possible
    # historical contributors have been indexed.  A changed/new winner may still
    # publish immediately; unrelated rows are never cleared wholesale.
    if event is None and not complete:
        return
    previous = {row["event_id"]: dict(row) for row in previous_rows}
    if event and not complete:
        for legacy in previous.values():
            indexed = connection.execute("""SELECT 1 FROM intelligence_projection_candidates
                WHERE source_type = ? AND source_id = ?""", (legacy["raw_source_type"], legacy["source_record_id"])).fetchone()
            acknowledged = connection.execute("""SELECT 1 FROM intelligence_source_changes WHERE source_type = ?
                AND source_id = ? AND published_revision > 0""", (legacy["raw_source_type"], legacy["source_record_id"])).fetchone()
            if indexed is None and acknowledged is None:
                legacy_row = connection.execute("SELECT * FROM normalized_intelligence_events WHERE event_id = ?", (legacy["event_id"],)).fetchone()
                event = n._merge_duplicate_events(n._hydrate_event_row(dict(legacy_row)), event)
    if event:
        existing = connection.execute("SELECT * FROM normalized_intelligence_events WHERE event_id = ?", (event["event_id"],)).fetchone()
        current = dict(existing) if existing else None
        row = _serialize(event, current, updated_at)
        # Context dependencies often converge without changing any public field.
        # Avoid revision churn and duplicate outbox work for those no-op passes.
        same = current is not None and all(current.get(column) == row[column] for column in _COLUMNS if column != "updated_at")
        if not same:
            connection.execute("INSERT INTO normalized_intelligence_events(" + ",".join(_COLUMNS) + ") VALUES (" + ",".join("?" for _ in _COLUMNS) + ") "
                "ON CONFLICT(event_id) DO UPDATE SET " + ",".join(column + "=excluded." + column for column in _COLUMNS[1:]), tuple(row[column] for column in _COLUMNS))
            search_index.sync_search_document_delta(connection, [row])
            if priority > 0:
                connection.execute("""INSERT INTO normalized_notification_outbox(event_id, payload, revision, enqueued_at)
                    VALUES (?, ?, ?, ?) ON CONFLICT(event_id) DO UPDATE SET payload = excluded.payload,
                    revision = excluded.revision, enqueued_at = excluded.enqueued_at, attempts = 0, next_retry = 0, lease_until = 0""",
                    (row["event_id"], n._json_dumps(row), revision, time.time()))
            result["published"] += 1
        _remember_publication(connection, event)
    removed = [event_id for event_id in previous if not event or event_id != event["event_id"]]
    for event_id in removed:
        connection.execute("DELETE FROM normalized_intelligence_events WHERE event_id = ?", (event_id,))
        connection.execute("DELETE FROM intelligence_projection_publications WHERE event_id = ? AND group_key = ?", (event_id, group))
        connection.execute("DELETE FROM normalized_notification_outbox WHERE event_id = ?", (event_id,))
    if removed:
        search_index.sync_search_document_delta(connection, [], removed)
        result["removed"] += len(removed)


def _cleanup(connection, limit):
    if _state(connection, "catalog_complete") != "1" or not _bootstrap_complete(connection):
        return
    pending = connection.execute("SELECT 1 FROM intelligence_projection_work WHERE kind = 'identity' LIMIT 1").fetchone()
    pending = pending or connection.execute("SELECT 1 FROM intelligence_source_changes WHERE revision > published_revision LIMIT 1").fetchone()
    if pending or _state(connection, "cleanup_complete") == "1":
        return
    after = _state(connection, "cleanup_after")
    rows = connection.execute("SELECT DISTINCT group_key FROM intelligence_projection_publications WHERE group_key > ? ORDER BY group_key LIMIT ?", (after, limit)).fetchall()
    for row in rows:
        _enqueue(connection, "group", row["group_key"])
    if rows:
        _set_state(connection, "cleanup_after", rows[-1]["group_key"])
    if len(rows) < limit:
        _set_state(connection, "cleanup_complete", 1)


def _search_bootstrap(connection, limit, max_bytes, result):
    if _state(connection, "search_complete") == "1":
        return
    after = _state(connection, "search_after")
    # An interrupted/missing legacy index must not be declared complete merely
    # because the latest changed IDs have postings.  Catch up independently in
    # bounded pages while the existing SQL search fallback remains usable.
    columns = ("title", "attacker", "victim", "industry", "region", "detail_text", "event_metadata_json")
    size = " + ".join("COALESCE(LENGTH(" + column + "), 0)" for column in columns)
    candidates = connection.execute("SELECT event_id, " + size + " AS characters FROM normalized_intelligence_events "
                                    "WHERE event_id > ? ORDER BY event_id LIMIT ?", (after, limit)).fetchall()
    total = 0
    for item in candidates:
        estimated = int(item["characters"]) * 4
        if result["search_body_rows_read"] and total + estimated > max_bytes:
            break
        row = connection.execute("SELECT * FROM normalized_intelligence_events WHERE event_id = ?", (item["event_id"],)).fetchone()
        if row:
            search_index.sync_search_document_delta(connection, [dict(row)])
            result["search_body_rows_read"] += 1
        total += estimated
        after = item["event_id"]
        _set_state(connection, "search_after", after)
    more = connection.execute("SELECT 1 FROM normalized_intelligence_events WHERE event_id > ? LIMIT 1", (after,)).fetchone()
    if more:
        return
    orphans = [row["event_id"] for row in connection.execute("""SELECT s.event_id FROM intelligence_search_documents s
        LEFT JOIN normalized_intelligence_events n ON n.event_id = s.event_id WHERE n.event_id IS NULL LIMIT ?""", (limit,)).fetchall()]
    search_index.sync_search_document_delta(connection, [], orphans)
    if len(orphans) < limit:
        _set_state(connection, "search_complete", 1)
        result["search_completed"] = True


def reset_incremental_projection(connection):
    """After an explicit full repair, rebuild helpers without hiding its output."""
    revision = _state(connection, "revision", "0")
    for table in ("intelligence_projection_state", "intelligence_projection_candidates", "intelligence_projection_identities",
                  "intelligence_projection_work", "intelligence_projection_dependencies", "intelligence_projection_publications"):
        connection.execute("DELETE FROM " + table)
    # Published cache keys and leased outbox acknowledgements must never see a
    # previous generation again after an explicit repair/rebootstrap.
    _set_state(connection, "revision", revision)
    connection.execute("DELETE FROM intelligence_source_bootstrap")
    # Keep change revision tombstones: removing them would allow an ABA race
    # with a collector that already has an observed revision.
    connection.execute("""UPDATE intelligence_source_changes SET
        priority = CASE WHEN revision > published_revision THEN priority ELSE 0 END,
        published_revision = 0""")


def refresh_incremental_intelligence(connection, max_rows=50, max_bytes=8 * 1024 * 1024):
    """Project one bounded batch; caller must lock first, then commit/rollback.

    Row/byte budgets apply independently to source, identity and group stages.
    A single oversized source is processed alone, preserving complete evidence
    rather than truncating it.  Large duplicate groups resume from durable cursors.
    """
    max_rows, max_bytes = max(1, min(50, int(max_rows))), max(1, min(8 * 1024 * 1024, int(max_bytes)))
    result = {"processed": 0, "published": 0, "removed": 0, "full_body_rows_read": 0, "source_bytes": 0,
              "search_body_rows_read": 0, "search_completed": False}
    # SQLite SELECT does not begin a transaction; SAVEPOINT on its own would
    # commit when released.  Keep transaction ownership with the caller.
    if getattr(connection, "backend_name", "") != "postgresql" and not connection.in_transaction:
        connection.execute("BEGIN")
    connection.execute("SAVEPOINT intelligence_projection_batch")
    try:
        now = n._now_utc()
        stamp = now.isoformat()
        revision = int(_state(connection, "revision", "0")) + 1
        domain_cache = n._load_domain_enrichment_cache()
        domain_cache["__remaining__"] = 0
        if _state(connection, "search_complete") == "":
            missing = connection.execute("""SELECT 1 FROM normalized_intelligence_events n
                LEFT JOIN intelligence_search_documents s ON s.event_id = n.event_id WHERE s.event_id IS NULL LIMIT 1""").fetchone()
            _set_state(connection, "search_complete", int(search_index.keyword_index_ready(connection) and missing is None))
        pending_changes = changes.list_changes(connection, limit=max_rows)
        available = max_rows - len(pending_changes)
        if available:
            start = int(_state(connection, "bootstrap_family", "0")) % len(SOURCE_TYPES)
            for step in range(len(SOURCE_TYPES)):
                source = SOURCE_TYPES[(start + step) % len(SOURCE_TYPES)]
                take = max(1, available // (len(SOURCE_TYPES) - step))
                info = changes.bootstrap_source_batch(connection, source, limit=take)
                available -= int(info["enqueued"])
                if available <= 0:
                    break
            _set_state(connection, "bootstrap_family", (start + 1) % len(SOURCE_TYPES))
            pending_changes = changes.list_changes(connection, limit=max_rows)
        for change in pending_changes:
            estimated = _raw_size(connection, change["source_type"], int(change["source_id"]))
            if result["processed"] and result["source_bytes"] + estimated > max_bytes:
                break
            raw = _read_raw(connection, change["source_type"], int(change["source_id"]))
            raw_size = sum(len(value.encode("utf-8")) for value in (raw or {}).values() if isinstance(value, str))
            event = None
            if raw is not None:
                builder = (n._build_forum_base_event, n._build_victim_base_event, n._build_ransomware_live_base_event,
                           n._build_vulnerability_base_event)[SOURCE_TYPES.index(change["source_type"])]
                event = builder(raw) if change["source_type"] == "vulnerability_records" else builder(raw, domain_cache=domain_cache)
                result["full_body_rows_read"] += 1
            _put_candidate(connection, change["source_type"], int(change["source_id"]), event, raw or {}, domain_cache,
                           2 if int(change["priority"]) else 0, now)
            changes.acknowledge_change(connection, change["source_type"], int(change["source_id"]), int(change["revision"]))
            result["processed"] += 1
            result["source_bytes"] += raw_size
        _catalog(connection, max_rows)
        _expire(connection, max_rows, now)
        _dependencies(connection, max_rows, domain_cache)
        _merge_work(connection, "identity", max_rows, max_bytes, domain_cache, None)
        complete = _state(connection, "sources_indexed") == "1"
        if not complete and _bootstrap_complete(connection):
            unpublished = connection.execute("SELECT 1 FROM intelligence_source_changes WHERE revision > published_revision LIMIT 1").fetchone()
            incomplete_identity = connection.execute("SELECT 1 FROM intelligence_projection_work WHERE kind = 'identity' LIMIT 1").fetchone()
            if unpublished is None and incomplete_identity is None:
                complete = True
                _set_state(connection, "sources_indexed", 1)
        _cleanup(connection, max_rows)
        _merge_work(connection, "group", max_rows, max_bytes, domain_cache,
                    lambda group, event, priority: _publication(connection, group, event, priority, stamp, revision, complete, result))
        _search_bootstrap(connection, max_rows, max_bytes, result)
        cache = connection.execute("SELECT * FROM normalized_intelligence_cache_state WHERE id = 1").fetchone()
        if result["published"] or result["removed"] or cache is None:
            count = connection.execute("SELECT COUNT(*) AS total FROM normalized_intelligence_events").fetchone()["total"]
            signature = f"incremental:{n.NORMALIZATION_SCHEMA_VERSION}:{revision}"
            if _state(connection, "search_complete") == "1":
                upsert_normalized_intelligence_cache_state(connection, source_signature=signature, event_count=int(count), refreshed_at=stamp)
            else:
                connection.execute("""INSERT INTO normalized_intelligence_cache_state(id, source_signature, event_count, refreshed_at)
                    VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET source_signature = excluded.source_signature,
                    event_count = excluded.event_count, refreshed_at = excluded.refreshed_at""", (signature, int(count), stamp))
            _set_state(connection, "revision", revision)
        elif _state(connection, "search_complete") == "1" and result["search_completed"]:
            search_index.mark_search_index_revision(connection, cache["source_signature"], cache["event_count"], cache["refreshed_at"])
        if _state(connection, "search_complete") != "1":
            connection.execute("DELETE FROM intelligence_search_state")
        pending = int(connection.execute("SELECT COUNT(*) AS total FROM intelligence_source_changes WHERE revision > published_revision").fetchone()["total"])
        for table in ("intelligence_projection_work", "intelligence_projection_dependencies"):
            pending += int(connection.execute("SELECT COUNT(*) AS total FROM " + table).fetchone()["total"])
        bootstrap_pending = int(not complete) + int(_state(connection, "catalog_complete") != "1") + int(_state(connection, "cleanup_complete") != "1") + int(_state(connection, "search_complete") != "1")
        result.update(pending=pending + bootstrap_pending, bootstrap_pending=bootstrap_pending)
    except Exception:
        connection.execute("ROLLBACK TO SAVEPOINT intelligence_projection_batch")
        connection.execute("RELEASE SAVEPOINT intelligence_projection_batch")
        raise
    connection.execute("RELEASE SAVEPOINT intelligence_projection_batch")
    return result
