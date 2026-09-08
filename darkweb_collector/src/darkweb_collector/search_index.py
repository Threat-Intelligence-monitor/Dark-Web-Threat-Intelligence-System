"""Transactional substring candidates, with the original SQL LIKE as final authority."""
from __future__ import annotations

from hashlib import sha256
import json
from time import perf_counter
from uuid import uuid4

FIELDS = ("title", "attacker", "victim", "victim_key", "industry", "region",
          "source_site_name", "category", "detail_text", "source_url", "event_metadata_json")
SEARCH_TEXT = "LOWER(" + " || ' ' || ".join(f"COALESCE({field}, '')" for field in FIELDS) + ")"
SEARCH_EXPRESSION = SEARCH_TEXT
KINDS = ("data_leak", "ransomware", "vulnerability")
ORDERS = {
    "latest": "report_time DESC, event_id DESC",
    "oldest": "report_time ASC, event_id ASC",
    "severity": "severity_rank DESC, risk_score DESC, report_time DESC, event_id DESC",
}


def _postgres(connection):
    return getattr(connection, "backend_name", "sqlite") == "postgresql"


def ensure_keyword_index_schema(connection, *, postgres=None):
    pg = _postgres(connection) if postgres is None else postgres
    connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_search_documents (
        event_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, search_text TEXT NOT NULL,
        event_type TEXT NOT NULL, report_time TEXT, severity_rank INTEGER NOT NULL,
        risk_score INTEGER NOT NULL, text_length INTEGER NOT NULL""" + (", grams TEXT[] NOT NULL)" if pg else ")"))
    connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_search_state (
        id INTEGER PRIMARY KEY, source_signature TEXT NOT NULL,
        event_count INTEGER NOT NULL, refreshed_at TEXT NOT NULL)""")
    connection.execute("CREATE TABLE IF NOT EXISTS intelligence_search_pending "
                       "(id INTEGER PRIMARY KEY, token TEXT NOT NULL)")
    if pg:
        connection.execute("CREATE INDEX IF NOT EXISTS idx_intelligence_search_grams "
                           "ON intelligence_search_documents USING GIN (grams)")
    else:
        connection.execute("CREATE VIRTUAL TABLE IF NOT EXISTS intelligence_search_fts "
                           "USING fts5(grams, detail=none, columnsize=0)")


def _grams(text):
    return sorted({"g" + text[start:start + length].encode("utf-8").hex()
                   for length in (1, 2) for start in range(len(text) - length + 1)})


def _fingerprint(row):
    values = [row.get(field) or "" for field in FIELDS]
    return sha256(json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _lock(connection):
    if _postgres(connection):
        connection.execute("SELECT pg_advisory_xact_lock(hashtext(current_schema()), "
                           "hashtext('intelligence_search_v1'))")
    else:
        # Acquire the writer lock even when the state table has not been populated.
        connection.execute("UPDATE intelligence_search_state SET id = id WHERE id = 1")


def sync_search_documents(connection, rows=None):
    """Caller owns commit; retain unchanged postings across normalized full refreshes."""
    _lock(connection)
    pg = _postgres(connection)
    previous = {row["event_id"]: dict(row) for row in connection.execute(
        "SELECT event_id, fingerprint, event_type, report_time, severity_rank, risk_score "
        "FROM intelligence_search_documents").fetchall()}
    if rows is None:
        rows = [dict(row) for row in connection.execute(
            "SELECT event_id, event_type, disclosure_time, updated_at, severity, risk_score, "
            + ", ".join(FIELDS) + " FROM normalized_intelligence_events").fetchall()]
    changed = {}
    metadata = []
    current_ids = set()
    for row in rows:
        event_id = row["event_id"]
        current_ids.add(event_id)
        fingerprint = _fingerprint(row)
        report_time = row.get("disclosure_time") or row["updated_at"]
        severity = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(row["severity"]).lower(), 0)
        values = (row["event_type"], report_time, severity, row["risk_score"])
        old = previous.get(event_id)
        if old is None or old["fingerprint"] != fingerprint:
            changed[event_id] = (fingerprint, values)
        elif values != tuple(old[key] for key in ("event_type", "report_time", "severity_rank", "risk_score")):
            metadata.append((*values, event_id))
    if metadata:
        connection.executemany("UPDATE intelligence_search_documents SET event_type=?, "
                               "report_time=?, severity_rank=?, risk_score=? WHERE event_id=?", metadata)
    removed = previous.keys() - current_ids
    for event_id in removed:
        if not pg:
            connection.execute("DELETE FROM intelligence_search_fts WHERE rowid = "
                               "(SELECT rowid FROM intelligence_search_documents WHERE event_id=?)", (event_id,))
        connection.execute("DELETE FROM intelligence_search_documents WHERE event_id=?", (event_id,))
    ids = list(changed)
    for offset in range(0, len(ids), 200):
        batch = ids[offset:offset + 200]
        source = connection.execute(
            f"SELECT event_id, {SEARCH_TEXT} AS search_text FROM normalized_intelligence_events "
            f"WHERE event_id IN ({','.join('?' for _ in batch)})", batch).fetchall()
        documents = []
        gram_map = {}
        for row in source:
            event_id, text = row["event_id"], row["search_text"]
            # SQLite LIKE terminates at NUL; the index represents that same haystack.
            effective_text = text if pg else text.split("\x00", 1)[0]
            grams = _grams(effective_text)
            fingerprint, values = changed[event_id]
            documents.append((event_id, fingerprint, text, *values, len(effective_text), *([grams] if pg else [])))
            gram_map[event_id] = grams
        columns = "event_id, fingerprint, search_text, event_type, report_time, severity_rank, risk_score, text_length"
        if pg:
            columns += ", grams"
        updates = ", ".join(f"{column}=excluded.{column}" for column in columns.split(", ")[1:])
        connection.executemany(f"INSERT INTO intelligence_search_documents ({columns}) "
                               f"VALUES ({','.join('?' for _ in range(9 if pg else 8))}) "
                               f"ON CONFLICT(event_id) DO UPDATE SET {updates}", documents)
        if not pg:
            mapped = connection.execute("SELECT rowid, event_id FROM intelligence_search_documents "
                f"WHERE event_id IN ({','.join('?' for _ in batch)})", batch).fetchall()
            connection.executemany("DELETE FROM intelligence_search_fts WHERE rowid=?", [(row[0],) for row in mapped])
            connection.executemany("INSERT INTO intelligence_search_fts(rowid, grams) VALUES (?, ?)",
                [(row[0], " ".join(gram_map[row["event_id"]])) for row in mapped])
    if pg and len(changed) + len(removed) >= 1000:
        # New GIN indexes otherwise wait for autovacuum before useful estimates exist.
        connection.execute("ANALYZE intelligence_search_documents")
    token = uuid4().hex
    connection.execute("INSERT INTO intelligence_search_pending(id, token) VALUES(1, ?) "
                       "ON CONFLICT(id) DO UPDATE SET token=excluded.token", (token,))
    connection._search_index_synced = token
    return {"updated": len(changed), "metadata_updated": len(metadata), "deleted": len(removed)}


def mark_search_index_revision(connection, source_signature, event_count, refreshed_at):
    token = getattr(connection, "_search_index_synced", None)
    connection._search_index_synced = False
    if not token:
        return
    # A Python flag survives rollback; its transaction-owned token does not.
    if connection.execute("DELETE FROM intelligence_search_pending WHERE id=1 AND token=?", (token,)).rowcount != 1:
        return
    connection.execute("""INSERT INTO intelligence_search_state(id, source_signature, event_count, refreshed_at)
        VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET source_signature=excluded.source_signature,
        event_count=excluded.event_count, refreshed_at=excluded.refreshed_at""",
        (source_signature, event_count, refreshed_at))


def _revision(connection, table):
    row = connection.execute(f"SELECT source_signature, event_count, refreshed_at FROM {table} WHERE id=1").fetchone()
    return tuple(row[index] for index in range(3)) if row else None


def keyword_index_ready(connection):
    revision = _revision(connection, "normalized_intelligence_cache_state")
    state = connection.execute("""SELECT source_signature, event_count, refreshed_at
        FROM intelligence_search_state WHERE id=1
        AND NOT EXISTS (SELECT 1 FROM intelligence_search_pending WHERE id=1)""").fetchone()
    return revision is not None and state is not None and revision == tuple(state[index] for index in range(3))


def ensure_keyword_index_ready(connection):
    _lock(connection)
    if keyword_index_ready(connection):
        return False
    revision = _revision(connection, "normalized_intelligence_cache_state")
    if revision is None:
        return False
    sync_search_documents(connection)
    mark_search_index_revision(connection, *revision)
    return True


def _query_plan(query, pg):
    grams, checks = set(), []
    for term in str(query or "").casefold().split():
        pattern = f"%{term}%"
        # A literal one/two-character substring is exactly represented by its gram.
        exact = len(term) <= 2 and not any(char in term for char in "%_\x00") and (not pg or "\\" not in term)
        if exact:
            grams.add("g" + term.encode("utf-8").hex())
            continue
        checks.append(pattern)
        effective = pattern if pg else pattern.split("\x00", 1)[0]
        run = ""
        index = 0
        while index < len(effective):
            char = effective[index]
            if pg and char == "\\" and index + 1 < len(effective):
                index += 1
                run += effective[index]
            elif char in "%_":
                grams.update(_grams(run))
                run = ""
            else:
                run += char
            index += 1
        grams.update(_grams(run))
    # Bigrams imply their own unigrams, so retain only unigrams not covered by one.
    bigrams = {gram for gram in grams if len(bytes.fromhex(gram[1:]).decode("utf-8")) == 2}
    covered = {"g" + char.encode("utf-8").hex() for gram in bigrams for char in bytes.fromhex(gram[1:]).decode("utf-8")}
    return sorted(grams - covered), checks


def search_indexed_events(connection, *, query, event_type="", sort="latest", limit=20, page=1, counts=None):
    started = perf_counter()
    if sort not in ORDERS:
        raise ValueError(f"unsupported normalized intelligence sort: {sort}")
    if not keyword_index_ready(connection):
        return None
    limit = int(limit)
    if limit < 1:
        raise ValueError("limit must be positive")
    grams, checks = _query_plan(query, _postgres(connection))
    parameters, conditions = [], []
    if grams:
        if _postgres(connection):
            conditions.append("grams @> ?::text[]")
            parameters.append(grams)
        else:
            conditions.append("rowid IN (SELECT rowid FROM intelligence_search_fts WHERE intelligence_search_fts MATCH ?)")
            parameters.append(" AND ".join(grams))
    for pattern in checks:
        if set(pattern) <= {"%", "_"}:
            conditions.append("text_length >= ?")
            parameters.append(pattern.count("_"))
        else:
            conditions.append("search_text LIKE ?")
            parameters.append(pattern)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    # Fetch only narrow matches. Both totals and page selection reuse this result;
    # bodies/JSON are fetched for the selected page alone.
    previous_seqscan = None
    if grams and _postgres(connection):
        previous_seqscan = connection.execute("SHOW enable_seqscan").fetchone()[0]
        if previous_seqscan == "on":
            # The planner underprices decompressing every large TOAST gram array.
            # Prefer GIN only for this candidate lookup, not other application SQL.
            connection.execute("SET LOCAL enable_seqscan = off")
    matched = connection.execute("SELECT event_id, event_type FROM intelligence_search_documents"
        + where + " ORDER BY " + ORDERS[sort], parameters).fetchall()
    if previous_seqscan == "on":
        connection.execute("SET LOCAL enable_seqscan = on")
    # A failed SELECT aborts the transaction; caller rollback also restores SET LOCAL.
    result_counts = {kind: 0 for kind in KINDS}
    selected = []
    for row in matched:
        if row["event_type"] in result_counts:
            result_counts[row["event_type"]] += 1
        if not event_type or row["event_type"] == event_type:
            selected.append(row["event_id"])
    page = min(max(1, int(page)), max(1, (len(selected) + limit - 1) // limit))
    selected = selected[(page - 1) * limit:page * limit]
    rows = []
    if selected:
        by_id = {row["event_id"]: dict(row) for row in connection.execute(
            "SELECT * FROM normalized_intelligence_events WHERE event_id IN ("
            + ",".join("?" for _ in selected) + ")", selected).fetchall()}
        rows = [by_id[event_id] for event_id in selected]
    return {"rows": rows, "counts": result_counts, "page": page,
            "timings": {"index": (perf_counter() - started) * 1000}}
