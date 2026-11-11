from __future__ import annotations

import atexit
from collections.abc import Iterator, Mapping
from decimal import Decimal
from hashlib import sha256
import os
from pathlib import Path
import re
from sys import intern
from threading import BoundedSemaphore, Lock
from typing import Any, Callable, Sequence
from uuid import uuid4

from darkweb_collector.crawl_frontier import ensure_frontier_schema
from darkweb_collector.search_schema import ensure_search_indexes
from darkweb_collector.search_index import ensure_keyword_index_schema


class PostgreSQLBackendError(RuntimeError):
    pass


_POOL_LOCK = Lock()
_POOLS: dict[tuple[str, str, str, str], Any] = {}
_POOL_IDENTITY_TABLES: dict[tuple[str, str, str, str], frozenset[str]] = {}
_POOL_GATES: dict[tuple[str, str, str, str], BoundedSemaphore] = {}
_RUNTIME_SCHEMA_MIGRATION = "runtime_collector_schema_v1"
_RUNTIME_TABLE_COLUMNS = {
    "crawl_frontier": "site_name target_url section discovery_lane metadata_json observed_version fetched_version claimed_version artifacts_complete status lease_token lease_until next_retry first_seen_at observed_at updated_at last_claimed_at last_error",
    "crawl_frontier_admission": "site_name updated_at",
    "crawl_page_cursors": "site_name source_url next_page last_signature completed_at updated_at",
    "crawl_detail_control": "site_name target_url source_version request_count budget_until failure_count failure_kind next_retry last_error owner_token owner_until worker_pid worker_started activity_path body_hash updated_at",
    "crawl_site_control": "site_name failure_kind next_retry updated_at",
    "crawl_source_request_control": "site_name request_at",
    "crawl_detail_site_control": "site_name failure_kind next_retry updated_at",
    "crawl_detail_results": "job_id site_name target_url outcome new_count updated_count unchanged_count finished_at",
    "normalized_intelligence_events": "report_time",
    "intelligence_search_documents": "event_id fingerprint search_text event_type report_time severity_rank risk_score text_length grams",
    "intelligence_search_state": "id source_signature event_count refreshed_at",
    "intelligence_search_pending": "id token",
    "intelligence_source_changes": "source_type source_id revision published_revision operation priority queued_at",
    "intelligence_source_bootstrap": "source_type before_id complete",
    "intelligence_projection_state": "name value",
    "intelligence_projection_candidates": "source_type source_id event_id payload payload_bytes summary source_rank order_time victim_key country_known country_score industry_known industry_score confidence actor site industry region disclosure_at time_window next_expiry",
    "intelligence_projection_identities": "event_id group_key payload payload_bytes source_rank order_time source_id",
    "intelligence_projection_work": "kind work_key priority revision cursor_json payload",
    "intelligence_projection_dependencies": "kind label priority cursor_type cursor_id repeat",
    "intelligence_projection_publications": "event_id group_key source_type source_id",
    "normalized_notification_outbox": "event_id payload revision enqueued_at attempts next_retry lease_until",
    "collector_metrics_state": "name value",
    "collector_visible_events": "event_id site_name published_at",
    "collector_visible_groups": "group_key",
    "collector_queue_snapshots": "sampled_at pending_recent pending_backfill",
}
_RUNTIME_INDEXES = """
idx_crawl_frontier_pending idx_crawl_frontier_section idx_detail_control_owner
idx_detail_control_active idx_detail_control_activity idx_detail_results_finished
idx_victim_details_victim_id idx_intelligence_report_order idx_intelligence_report_order_type
idx_intelligence_severity_order idx_intelligence_severity_order_type idx_intelligence_search_grams
idx_intelligence_source_changes_pending idx_projection_candidate_identity idx_projection_country
idx_projection_industry_context idx_projection_actor idx_projection_victim idx_projection_industry
idx_projection_region idx_projection_expiry idx_projection_identity_group idx_projection_work_priority
idx_projection_publication_group idx_projection_publication_source idx_projection_legacy_source
idx_projection_legacy_title idx_normalized_outbox_ready idx_collector_visible_time
idx_crawl_jobs_site_type_id idx_crawl_jobs_site_type_outcome idx_crawl_jobs_active_status
""".split()
_RUNTIME_TRIGGER_TABLES = "forum_details victims ransomware_live_victims vulnerability_records forum_victims victim_details forum_topics".split()


def _runtime_schema_fingerprint(cursor=None) -> str:
    # Also invalidate existing trigger functions when their implementation changes.
    digest = sha256()
    for name in ("postgres_backend", "crawl_frontier", "detail_lifecycle", "search_schema",
                 "search_index", "intelligence_changes", "incremental_intelligence", "collector_metrics"):
        source = Path(__file__).with_name(name + ".py").read_text(encoding="utf-8")
        digest.update((name + "\n" + source.replace("\r\n", "\n").replace("\r", "\n")).encode("utf-8"))
    if cursor is not None:
        # Older releases replace these functions without updating our marker.
        cursor.execute("""SELECT p.proname, pg_catalog.pg_get_functiondef(p.oid)
            FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = current_schema() AND p.proname = ANY(%s) AND p.pronargs = 0
            ORDER BY p.proname""", (["dwti_intelligence_change_" + table for table in _RUNTIME_TRIGGER_TABLES],))
        for name, definition in cursor.fetchall():
            digest.update((name + "\n" + definition.replace("\r\n", "\n").replace("\r", "\n")).encode("utf-8"))
    return digest.hexdigest()


def _runtime_schema_ready(cursor, fingerprint: str = "") -> bool:
    if fingerprint:
        cursor.execute("SELECT checksum FROM schema_migrations WHERE version = %s", (_RUNTIME_SCHEMA_MIGRATION,))
        row = cursor.fetchone()
        if not row or row[0] != fingerprint:
            return False
    cursor.execute("""SELECT c.relname, c.relkind, i.indisvalid, i.indisready
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
        WHERE n.nspname = current_schema() AND c.relname = ANY(%s)""",
        (list(_RUNTIME_TABLE_COLUMNS) + _RUNTIME_INDEXES,))
    objects = {row[0]: row[1:] for row in cursor.fetchall()}
    if any(objects.get(name, (None,))[0] not in {"r", "p"} for name in _RUNTIME_TABLE_COLUMNS):
        return False
    if any(objects.get(name) not in {("i", True, True), ("I", True, True)} for name in _RUNTIME_INDEXES):
        return False
    cursor.execute("""SELECT c.relname, a.attname FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relname = ANY(%s)
            AND a.attnum > 0 AND NOT a.attisdropped""", (list(_RUNTIME_TABLE_COLUMNS),))
    columns = set(cursor.fetchall())
    if any((table, column) not in columns for table, names in _RUNTIME_TABLE_COLUMNS.items() for column in names.split()):
        return False
    cursor.execute("""SELECT c.relname FROM pg_catalog.pg_trigger t
        JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
        WHERE n.nspname = current_schema() AND c.relname = ANY(%s)
            AND t.tgname = 'dwti_intelligence_change_' || c.relname
            AND p.proname = t.tgname AND p.pronamespace = n.oid
            AND t.tgenabled IN ('O', 'A') AND NOT t.tgisinternal""", (_RUNTIME_TRIGGER_TABLES,))
    return {row[0] for row in cursor.fetchall()} == set(_RUNTIME_TRIGGER_TABLES)


def _compat_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


class CompatRow(Mapping[str, Any]):
    def __init__(self, columns: Sequence[str], values: Sequence[Any]) -> None:
        self._columns = tuple(columns)
        self._values = tuple(_compat_value(value) for value in values)
        self._mapping = dict(zip(self._columns, self._values))

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._mapping[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._columns)

    def __len__(self) -> int:
        return len(self._columns)


def _replace_qmark_parameters(sql: str) -> str:
    result: list[str] = []
    index = 0
    state = "normal"
    while index < len(sql):
        char = sql[index]
        next_char = sql[index + 1] if index + 1 < len(sql) else ""
        if state == "normal":
            if char == "'":
                state = "single"
            elif char == '"':
                state = "double"
            elif char == "-" and next_char == "-":
                state = "line_comment"
                result.append(char)
                index += 1
                char = next_char
            elif char == "/" and next_char == "*":
                state = "block_comment"
                result.append(char)
                index += 1
                char = next_char
            elif char == "?":
                result.append("%s")
                index += 1
                continue
        elif state == "single":
            if char == "'" and next_char == "'":
                result.extend([char, next_char])
                index += 2
                continue
            if char == "'":
                state = "normal"
        elif state == "double":
            if char == '"' and next_char == '"':
                result.extend([char, next_char])
                index += 2
                continue
            if char == '"':
                state = "normal"
        elif state == "line_comment":
            if char in "\r\n":
                state = "normal"
        elif state == "block_comment" and char == "*" and next_char == "/":
            result.extend([char, next_char])
            index += 2
            state = "normal"
            continue
        result.append(char)
        index += 1
    return "".join(result)


def translate_sql(sql: str) -> str:
    translated = _replace_qmark_parameters(sql)
    translated = re.sub(r"\bifnull\s*\(", "COALESCE(", translated, flags=re.IGNORECASE)
    translated = re.sub(
        r"\bGROUP_CONCAT\s*\(", "STRING_AGG(", translated, flags=re.IGNORECASE
    )
    if re.search(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", translated, flags=re.IGNORECASE):
        translated = re.sub(
            r"\bINSERT\s+OR\s+IGNORE\s+INTO\b",
            "INSERT INTO",
            translated,
            flags=re.IGNORECASE,
        )
        stripped = translated.rstrip()
        suffix = ";" if stripped.endswith(";") else ""
        if suffix:
            stripped = stripped[:-1].rstrip()
        translated = stripped + " ON CONFLICT DO NOTHING" + suffix
    return translated


def _insert_table(sql: str) -> str | None:
    match = re.match(
        r"\s*INSERT\s+INTO\s+(?:public\.)?[\"']?([A-Za-z_][A-Za-z0-9_]*)",
        sql,
        flags=re.IGNORECASE,
    )
    return match.group(1).lower() if match else None


class PostgresCursor:
    def __init__(self, connection: "PostgresConnection") -> None:
        self._connection = connection
        self._cursor = connection._raw.cursor()
        self.lastrowid: int | None = None

    @property
    def rowcount(self) -> int:
        return int(self._cursor.rowcount)

    @property
    def description(self):
        return self._cursor.description

    def execute(self, sql: str, parameters: Sequence[Any] | None = None) -> "PostgresCursor":
        translated = translate_sql(sql)
        table_name = _insert_table(translated)
        should_return_id = (
            table_name in self._connection.identity_tables
            and not re.search(r"\bRETURNING\b", translated, flags=re.IGNORECASE)
        )
        if should_return_id:
            stripped = translated.rstrip()
            suffix = ";" if stripped.endswith(";") else ""
            if suffix:
                stripped = stripped[:-1].rstrip()
            translated = stripped + " RETURNING id" + suffix
        self._cursor.execute(translated, tuple(parameters or ()))
        if should_return_id:
            row = self._cursor.fetchone()
            self.lastrowid = int(row[0]) if row else None
        return self

    def fetchone(self) -> CompatRow | None:
        row = self._cursor.fetchone()
        if row is None:
            return None
        columns = [item[0] for item in self._cursor.description]
        return CompatRow(columns, row)

    def fetchall(self) -> list[CompatRow]:
        rows = self._cursor.fetchall()
        columns = [item[0] for item in self._cursor.description]
        return [CompatRow(columns, row) for row in rows]

    def close(self) -> None:
        self._cursor.close()


class PostgresConnection:
    backend_name = "postgresql"

    def __init__(
        self,
        raw_connection,
        *,
        identity_tables: frozenset[str],
        release: Callable[[Any], None],
    ) -> None:
        self._raw = raw_connection
        self._release = release
        self._closed = False
        self.identity_tables = identity_tables

    def cursor(self) -> PostgresCursor:
        return PostgresCursor(self)

    def execute(self, sql: str, parameters: Sequence[Any] | None = None) -> PostgresCursor:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, parameters: Sequence[Sequence[Any]]) -> PostgresCursor:
        cursor = self.cursor()
        cursor._cursor.executemany(translate_sql(sql), parameters)
        return cursor

    def iter_rows(self, sql: str, parameters: Sequence[Any] = (), *, batch_size: int = 1) -> Iterator[CompatRow]:
        from psycopg2.extensions import TRANSACTION_STATUS_INTRANS

        # fetchmany on an ordinary psycopg cursor still buffers the whole result in libpq.
        cursor = self._raw.cursor(name="dwti_stream_" + uuid4().hex)
        try:
            cursor.execute(translate_sql(sql), tuple(parameters))
            while rows := cursor.fetchmany(max(1, int(batch_size))):
                columns = [intern(column[0]) for column in cursor.description]
                for row in rows:
                    yield CompatRow(columns, row)
        finally:
            # Commit/rollback already discards a named cursor on the server.
            if not self._closed and self._raw.get_transaction_status() == TRANSACTION_STATUS_INTRANS:
                cursor.close()

    def commit(self) -> None:
        self._raw.commit()

    def rollback(self) -> None:
        self._raw.rollback()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        raw = self._raw
        self._raw = None
        self._release(raw)

    def __enter__(self) -> "PostgresConnection":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def _positive_int_from_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _validate_schema_name(schema: str) -> None:
    if schema and not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
        raise PostgreSQLBackendError("Invalid PostgreSQL release schema")


def _validate_pool_connection(
    raw,
    *,
    expected_fingerprint: str,
    expected_version: str,
    expected_schema: str = "",
) -> frozenset[str]:
    try:
        with raw.cursor() as cursor:
            cursor.execute("SELECT current_schema()")
            actual_schema = cursor.fetchone()[0]
            if actual_schema is None or (expected_schema and actual_schema != expected_schema):
                raise PostgreSQLBackendError("Configured PostgreSQL schema is missing or inaccessible")
            cursor.execute(
                """
                SELECT version, source_schema_fingerprint
                FROM schema_migrations
                ORDER BY version
                """
            )
            migrations = {str(row[0]): row[1] for row in cursor.fetchall()}
            cursor.execute(
                """
                SELECT table_name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND column_name = 'id'
                  AND is_identity = 'YES'
                """
            )
            identity_tables = frozenset(str(row[0]).lower() for row in cursor.fetchall())
        baseline_fingerprint = migrations.get("0001_baseline")
        if not expected_fingerprint:
            raise PostgreSQLBackendError("Expected PostgreSQL schema fingerprint is required")
        if baseline_fingerprint != expected_fingerprint:
            raise PostgreSQLBackendError(
                "PostgreSQL baseline fingerprint does not match this application"
            )
        if expected_version and expected_version not in migrations:
            raise PostgreSQLBackendError(
                f"Required PostgreSQL migration is not applied: {expected_version}"
            )
        return identity_tables
    finally:
        raw.rollback()


def _get_pool(
    database_url: str,
    *,
    schema: str,
    expected_fingerprint: str,
    expected_version: str,
):
    try:
        from psycopg2.pool import ThreadedConnectionPool  # type: ignore
    except ImportError as exc:
        raise PostgreSQLBackendError(
            "PostgreSQL selected but psycopg2 is not installed"
        ) from exc

    _validate_schema_name(schema)
    key = (database_url, schema, expected_fingerprint, expected_version)
    with _POOL_LOCK:
        pool = _POOLS.get(key)
        if pool is not None:
            return pool, _POOL_IDENTITY_TABLES[key], _POOL_GATES[key]
        minimum = _positive_int_from_env("DARKWEB_POSTGRES_POOL_MIN", 1)
        maximum = max(minimum, _positive_int_from_env("DARKWEB_POSTGRES_POOL_MAX", 8))
        options = f"-c search_path={schema},public" if schema else ""
        connect_kwargs = {"application_name": "darkweb-threat-intelligence"}
        if options:
            connect_kwargs["options"] = options
        pool = ThreadedConnectionPool(minimum, maximum, database_url, **connect_kwargs)
        try:
            raw = pool.getconn()
            try:
                identity_tables = _validate_pool_connection(
                    raw,
                    expected_fingerprint=expected_fingerprint,
                    expected_version=expected_version,
                    expected_schema=schema,
                )
                with raw.cursor() as cursor:
                    fingerprint = _runtime_schema_fingerprint(cursor)
                    if not _runtime_schema_ready(cursor, fingerprint):
                        from darkweb_collector.normalized_intelligence import NORMALIZED_REFRESH_ADVISORY_LOCK_ID

                        # CREATE INDEX IF NOT EXISTS still takes a ShareLock.  Wait
                        # for projection DML before taking any initialization locks.
                        cursor.execute("SET LOCAL lock_timeout = '10s'")
                        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (NORMALIZED_REFRESH_ADVISORY_LOCK_ID,))
                        cursor.execute("SELECT pg_advisory_xact_lock(hashtext(current_schema()), hashtext('crawl_frontier_v1'))")
                        fingerprint = _runtime_schema_fingerprint(cursor)
                        if not _runtime_schema_ready(cursor, fingerprint):
                            ensure_frontier_schema(cursor)
                            cursor.execute("CREATE INDEX IF NOT EXISTS idx_victim_details_victim_id ON victim_details(victim_id, id)")
                            ensure_search_indexes(cursor)
                            ensure_keyword_index_schema(cursor, postgres=True)
                            from darkweb_collector.intelligence_changes import ensure_change_schema
                            from darkweb_collector.incremental_intelligence import ensure_incremental_projection_schema

                            ensure_change_schema(cursor, postgres=True)
                            ensure_incremental_projection_schema(cursor, postgres=True)
                            from darkweb_collector.collector_metrics import ensure_metrics_schema
                            ensure_metrics_schema(cursor, postgres=True)
                            if not _runtime_schema_ready(cursor):
                                raise PostgreSQLBackendError("PostgreSQL runtime schema is incomplete; initialization was rolled back")
                            fingerprint = _runtime_schema_fingerprint(cursor)
                            cursor.execute("""INSERT INTO schema_migrations(version, checksum) VALUES (%s, %s)
                                ON CONFLICT(version) DO UPDATE SET checksum = excluded.checksum, applied_at = CURRENT_TIMESTAMP""",
                                (_RUNTIME_SCHEMA_MIGRATION, fingerprint))
                raw.commit()
            except Exception:
                raw.rollback()
                raise
            finally:
                pool.putconn(raw)
        except Exception:
            pool.closeall()
            raise
        _POOLS[key] = pool
        _POOL_IDENTITY_TABLES[key] = identity_tables
        _POOL_GATES[key] = BoundedSemaphore(maximum)
        return pool, identity_tables, _POOL_GATES[key]


def _return_pool_connection(pool, gate: BoundedSemaphore, raw) -> None:
    if raw is None:
        gate.release()
        return
    close_connection = False
    try:
        if raw.closed:
            close_connection = True
        else:
            raw.rollback()
    except Exception:
        close_connection = True
    try:
        pool.putconn(raw, close=close_connection)
    finally:
        gate.release()


def close_postgres_pools() -> None:
    with _POOL_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
        _POOL_IDENTITY_TABLES.clear()
        _POOL_GATES.clear()
    for pool in pools:
        try:
            pool.closeall()
        except Exception:
            pass


def connect_postgres(
    database_url: str,
    *,
    schema: str = "",
    expected_fingerprint: str = "",
    expected_version: str = "0002_sqlite_compat",
) -> PostgresConnection:
    pool, identity_tables, gate = _get_pool(
        database_url,
        schema=schema,
        expected_fingerprint=expected_fingerprint,
        expected_version=expected_version,
    )
    wait_seconds = _positive_int_from_env("DARKWEB_POSTGRES_POOL_WAIT_SECONDS", 10)
    if not gate.acquire(timeout=wait_seconds):
        raise PostgreSQLBackendError("PostgreSQL connection pool wait timed out")
    try:
        raw = pool.getconn()
    except Exception as exc:
        gate.release()
        raise PostgreSQLBackendError("PostgreSQL connection pool is exhausted") from exc
    try:
        connection = PostgresConnection(
            raw,
            identity_tables=identity_tables,
            release=lambda connection: _return_pool_connection(pool, gate, connection),
        )
        connection.cache_identity = (
            "postgresql", schema, raw.info.host, raw.info.port, raw.info.dbname, raw.info.user,
        )
        return connection
    except Exception:
        _return_pool_connection(pool, gate, raw)
        raise


atexit.register(close_postgres_pools)
