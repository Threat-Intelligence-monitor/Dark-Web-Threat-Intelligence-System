"""Durable, transaction-owned raw changes for bounded intelligence publication."""
from __future__ import annotations


SOURCE_TYPES = ("forum_details", "victims", "ransomware_live_victims", "vulnerability_records")
_CHILDREN = {
    "forum_victims": ("forum_details", "forum_detail_id"),
    "victim_details": ("victims", "victim_id"),
}
_TOPIC_FIELDS = ("site_name", "section", "url", "title")


def _enqueue_sql(source_type, ids, operation="upsert", priority=1):
    return f"""INSERT INTO intelligence_source_changes
        (source_type, source_id, revision, published_revision, operation, priority, queued_at)
        SELECT '{source_type}', changed.id, 1, 0, '{operation}', {priority}, CAST(CURRENT_TIMESTAMP AS TEXT)
        FROM ({ids}) AS changed WHERE 1=1
        ON CONFLICT(source_type, source_id) DO UPDATE SET
            revision=intelligence_source_changes.revision+1,
            operation=excluded.operation,
            priority=CASE WHEN intelligence_source_changes.revision > intelligence_source_changes.published_revision
                         AND intelligence_source_changes.priority > excluded.priority
                         THEN intelligence_source_changes.priority ELSE excluded.priority END,
            queued_at=CASE WHEN intelligence_source_changes.revision > intelligence_source_changes.published_revision
                          THEN intelligence_source_changes.queued_at ELSE excluded.queued_at END"""


def _columns(connection, postgres):
    tables = (*SOURCE_TYPES, *_CHILDREN, "forum_topics")
    if postgres:
        cursor = connection.execute("SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema=current_schema() AND table_name IN ("
            + ",".join(f"'{table}'" for table in tables) + ")")
        rows = (cursor or connection).fetchall()
        result = {}
        for row in rows:
            result.setdefault(row[0], set()).add(row[1])
        return result
    return {table: {row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
            for table in tables}


def _changed(columns, postgres):
    operator = "IS DISTINCT FROM" if postgres else "IS NOT"
    return " OR ".join(f"OLD.{column} {operator} NEW.{column}" for column in sorted(columns)) or "FALSE"


def _install_triggers(connection, postgres):
    columns = _columns(connection, postgres)
    schema = ""
    if postgres:
        cursor = connection.execute("SELECT current_schema()")
        schema = (cursor or connection).fetchone()[0]
    for table in (*SOURCE_TYPES, *_CHILDREN, "forum_topics"):
        fields = columns.get(table, set())
        if "id" not in fields:
            continue
        if table in SOURCE_TYPES:
            changed = _changed(fields, postgres)
            insert = _enqueue_sql(table, "SELECT NEW.id AS id")
            delete = _enqueue_sql(table, "SELECT OLD.id AS id", "delete")
            update = _enqueue_sql(table, "SELECT OLD.id AS id WHERE OLD.id <> NEW.id", "delete") + ";\n" + insert
        elif table in _CHILDREN:
            parent, key = _CHILDREN[table]
            if key not in fields or "id" not in columns.get(parent, set()):
                continue
            changed = _changed(fields, postgres)
            insert = _enqueue_sql(parent, f"SELECT id FROM {parent} WHERE id=NEW.{key}")
            delete = _enqueue_sql(parent, f"SELECT id FROM {parent} WHERE id=OLD.{key}")
            update = _enqueue_sql(parent, f"SELECT id FROM {parent} WHERE id=NEW.{key} OR id=OLD.{key}")
        else:
            if not set(_TOPIC_FIELDS) <= fields or not {"id", "site_name", "section", "topic_url"} <= columns.get("forum_details", set()):
                continue
            changed = _changed(_TOPIC_FIELDS, postgres)
            def matching(alias):
                return f"site_name={alias}.site_name AND section={alias}.section AND topic_url={alias}.url"
            insert = _enqueue_sql("forum_details", "SELECT id FROM forum_details WHERE " + matching("NEW"))
            delete = _enqueue_sql("forum_details", "SELECT id FROM forum_details WHERE " + matching("OLD"))
            update = _enqueue_sql("forum_details", "SELECT id FROM forum_details WHERE ("
                                  + matching("NEW") + ") OR (" + matching("OLD") + ")")
        name = "dwti_intelligence_change_" + table
        if postgres:
            # Bind the trigger to its release schema even for schema-qualified writers.
            quoted_schema = '"' + schema.replace('"', '""') + '"'
            connection.execute(f"""CREATE OR REPLACE FUNCTION {name}() RETURNS trigger
                LANGUAGE plpgsql SET search_path TO {quoted_schema}, pg_temp AS $change$
                BEGIN
                    IF TG_OP = 'INSERT' THEN {insert};
                    ELSIF TG_OP = 'DELETE' THEN {delete};
                    ELSIF {changed} THEN {update};
                    END IF;
                    RETURN NULL;
                END $change$""")
            cursor = connection.execute("SELECT 1 FROM pg_trigger WHERE tgname='" + name
                + "' AND tgrelid='" + table + "'::regclass AND NOT tgisinternal")
            exists = (cursor or connection).fetchone()
            if exists is None:
                connection.execute(f"CREATE TRIGGER {name} AFTER INSERT OR UPDATE OR DELETE ON {table} "
                                   f"FOR EACH ROW EXECUTE FUNCTION {name}()")
        else:
            for operation, body in (("INSERT", insert), ("UPDATE", update), ("DELETE", delete)):
                when = " WHEN " + changed if operation == "UPDATE" else ""
                connection.execute(f"CREATE TRIGGER IF NOT EXISTS {name}_{operation.lower()} "
                    f"AFTER {operation} ON {table}{when} BEGIN {body}; END")


def ensure_change_schema(connection, *, postgres=None):
    """Install once during schema initialization; callers own the transaction."""
    postgres = getattr(connection, "backend_name", "") == "postgresql" if postgres is None else postgres
    connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_source_changes (
        source_type TEXT NOT NULL, source_id BIGINT NOT NULL,
        revision BIGINT NOT NULL, published_revision BIGINT NOT NULL,
        operation TEXT NOT NULL, priority INTEGER NOT NULL, queued_at TEXT NOT NULL,
        PRIMARY KEY(source_type, source_id))""")
    connection.execute("""CREATE INDEX IF NOT EXISTS idx_intelligence_source_changes_pending
        ON intelligence_source_changes(priority DESC, queued_at, source_type, source_id)
        WHERE revision > published_revision""")
    connection.execute("""CREATE TABLE IF NOT EXISTS intelligence_source_bootstrap (
        source_type TEXT PRIMARY KEY, before_id BIGINT, complete INTEGER NOT NULL)""")
    _install_triggers(connection, postgres)


def enqueue_change(connection, source_type, source_id, *, operation="upsert", priority=1):
    if source_type not in SOURCE_TYPES or operation not in {"upsert", "delete"}:
        raise ValueError("unsupported intelligence source change")
    connection.execute(_enqueue_sql(source_type, "SELECT ? AS id", operation, int(priority)), (int(source_id),))


def list_changes(connection, *, limit=50):
    return [dict(row) for row in connection.execute("""SELECT source_type, source_id, revision, operation, priority
        FROM intelligence_source_changes WHERE revision > published_revision
        ORDER BY priority DESC, queued_at, source_type, source_id LIMIT ?""", (max(1, int(limit)),)).fetchall()]


def acknowledge_change(connection, source_type, source_id, revision):
    # Retaining acknowledged rows prevents revision reuse after delete/reinsert.
    return connection.execute("""UPDATE intelligence_source_changes SET published_revision=?
        WHERE source_type=? AND source_id=? AND revision=? AND published_revision < ?""",
        (int(revision), source_type, int(source_id), int(revision), int(revision))).rowcount == 1


def bootstrap_source_batch(connection, source_type, *, limit=50):
    """Resume a bounded newest-first upgrade scan without replacing fresh changes."""
    if source_type not in SOURCE_TYPES:
        raise ValueError("unsupported intelligence source type")
    state = connection.execute("SELECT before_id, complete FROM intelligence_source_bootstrap WHERE source_type=?",
                               (source_type,)).fetchone()
    before_id = state[0] if state else None
    if state and state[1]:
        return {"enqueued": 0, "before_id": before_id, "complete": True}
    limit = max(1, int(limit))
    where = "" if before_id is None else " WHERE id < ?"
    rows = connection.execute(f"SELECT id FROM {source_type}" + where + " ORDER BY id DESC LIMIT ?",
                              (limit,) if before_id is None else (before_id, limit)).fetchall()
    enqueued = 0
    for row in rows:
        enqueued += connection.execute("""INSERT INTO intelligence_source_changes
            (source_type, source_id, revision, published_revision, operation, priority, queued_at)
            VALUES (?, ?, 1, 0, 'upsert', 0, CAST(CURRENT_TIMESTAMP AS TEXT))
            ON CONFLICT(source_type, source_id) DO NOTHING""", (source_type, row[0])).rowcount
    before_id = rows[-1][0] if rows else before_id
    complete = len(rows) < limit
    connection.execute("""INSERT INTO intelligence_source_bootstrap(source_type, before_id, complete)
        VALUES (?, ?, ?) ON CONFLICT(source_type) DO UPDATE SET
        before_id=excluded.before_id, complete=excluded.complete""", (source_type, before_id, int(complete)))
    return {"enqueued": enqueued, "before_id": before_id, "complete": complete}
