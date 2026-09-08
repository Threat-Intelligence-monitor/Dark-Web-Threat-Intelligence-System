from __future__ import annotations

import atexit
from collections.abc import Iterator, Mapping
from decimal import Decimal
import os
import re
from threading import BoundedSemaphore, Lock
from typing import Any, Callable, Sequence

from darkweb_collector.crawl_frontier import ensure_frontier_schema
from darkweb_collector.search_schema import ensure_search_indexes
from darkweb_collector.search_index import ensure_keyword_index_schema


class PostgreSQLBackendError(RuntimeError):
    pass


_POOL_LOCK = Lock()
_POOLS: dict[tuple[str, str, str, str], Any] = {}
_POOL_IDENTITY_TABLES: dict[tuple[str, str, str, str], frozenset[str]] = {}
_POOL_GATES: dict[tuple[str, str, str, str], BoundedSemaphore] = {}


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
) -> frozenset[str]:
    try:
        with raw.cursor() as cursor:
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
                )
                with raw.cursor() as cursor:
                    cursor.execute("SELECT pg_advisory_xact_lock(hashtext(current_schema()), hashtext('crawl_frontier_v1'))")
                    ensure_frontier_schema(cursor)
                    ensure_search_indexes(cursor)
                    ensure_keyword_index_schema(cursor, postgres=True)
                raw.commit()
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
