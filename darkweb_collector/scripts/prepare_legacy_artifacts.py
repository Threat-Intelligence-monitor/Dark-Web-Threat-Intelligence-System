"""Prepare committed evidence for a stopped legacy release before managed rollback."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import sys
from threading import Event, Thread
import time

import psutil


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from darkweb_collector.collection_errors import safe_failure_text
from darkweb_collector.config import load_site_configs
from darkweb_collector.detail_artifacts import materialize_legacy_views
from darkweb_collector.runtime import configured_database_schema, configured_database_url, default_db_path
from darkweb_collector.storage_paths import app_root, data_root, update_state_root


@contextmanager
def _controller_lifetime():
    controller = int(os.environ.get("DARKWEB_ARTIFACT_CONTROLLER_PID", "0"))
    created = float(os.environ.get("DARKWEB_ARTIFACT_CONTROLLER_STARTED", "0"))
    if controller <= 0 or not math.isfinite(created) or created <= 0:
        raise ValueError("Evidence preparation requires a managed controller identity")
    if controller not in {parent.pid for parent in psutil.Process().parents()}:
        raise ValueError("Evidence controller is not an ancestor of this preparation process")

    def alive():
        try:
            process = psutil.Process(controller)
            return process.is_running() and abs(process.create_time() - created) <= 0.001
        except psutil.Error:
            return False

    if not alive():
        raise ValueError("Evidence controller identity changed")
    stopped = Event()

    def watch():
        while not stopped.wait(0.2):
            if not alive():
                # Do not keep rewriting the rollback view after its controller dies.
                os._exit(2)

    watcher = Thread(target=watch, name="artifact-controller-watch", daemon=True)
    watcher.start()
    try:
        yield
    finally:
        stopped.set()
        watcher.join(timeout=1)


def _managed_target(path: Path) -> Path:
    absolute = path.absolute()
    if any(parent.is_symlink() or parent.is_junction() for parent in (absolute, *absolute.parents)):
        raise ValueError("Linked legacy release directories are not allowed")
    target = absolute.resolve(strict=True)
    installation = json.loads((update_state_root() / "installation.json").read_text(encoding="utf-8-sig"))
    version = json.loads((target / "version.json").read_text(encoding="utf-8-sig"))
    if (installation.get("format") != 1 or target.parent != (app_root() / "releases").resolve()
            or target != Path(str(installation.get("current_root") or "")).resolve()
            or data_root().resolve() != Path(str(installation.get("data_root") or "")).resolve()
            or version.get("version") != installation.get("current_version")):
        raise ValueError("Legacy evidence preparation must match the active managed release")
    return target


@contextmanager
def _read_only_connection():
    database_url = configured_database_url()
    if database_url:
        import psycopg2
        from psycopg2 import sql
        from darkweb_collector.postgres_backend import PostgresConnection

        raw = psycopg2.connect(database_url, connect_timeout=5,
                               options="-c default_transaction_read_only=on -c statement_timeout=30000 -c lock_timeout=2000")
        try:
            raw.set_session(readonly=True, isolation_level="REPEATABLE READ", autocommit=False)
            with raw.cursor() as cursor:
                schema = configured_database_schema()
                if schema:
                    cursor.execute(sql.SQL("SET LOCAL search_path TO {},public").format(sql.Identifier(schema)))
                cursor.execute("SELECT current_schema()")
                actual_schema = cursor.fetchone()[0]
                if actual_schema is None or (schema and actual_schema != schema):
                    raise ValueError("Configured evidence database schema is unavailable")
            connection = PostgresConnection(raw, identity_tables=frozenset(), release=lambda item: item.close())
        except Exception:
            raw.close()
            raise
    else:
        path = default_db_path().resolve(strict=True)
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
    try:
        yield connection
    finally:
        try:
            connection.rollback()
        finally:
            connection.close()


def _projection_state(connection, name: str, default: str = "") -> str:
    row = connection.execute("SELECT value FROM intelligence_projection_state WHERE name=?", (name,)).fetchone()
    return str(row[0]) if row else default


def _foreground_pending(connection) -> bool:
    if connection.execute("SELECT 1 FROM intelligence_source_changes WHERE revision>published_revision AND priority>0 LIMIT 1").fetchone():
        return True
    return any(connection.execute("SELECT 1 FROM " + table + " WHERE priority>0 LIMIT 1").fetchone()
               for table in ("intelligence_projection_work", "intelligence_projection_dependencies"))


@contextmanager
def _projection_connection():
    from darkweb_collector.db import get_db_connection
    from darkweb_collector import normalized_intelligence

    release_local = False
    try:
        with get_db_connection() as connection:
            if getattr(connection, "backend_name", "") == "postgresql":
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                connection.execute("SET LOCAL lock_timeout = '10s'")
                connection.execute("SET LOCAL statement_timeout = '30s'")
            acquired, release_local = normalized_intelligence._try_acquire_normalized_refresh_lock(connection)
            if not acquired:
                raise RuntimeError("Normalization is still active; legacy services must remain stopped")
            yield connection
    finally:
        if release_local:
            normalized_intelligence._NORMALIZED_REFRESH_LOCK.release()


def _prepare_legacy_projection(signature: str) -> dict:
    from darkweb_collector.detail_artifacts import iter_committed_artifact_sources, legacy_artifact_view
    from darkweb_collector.intelligence_changes import enqueue_change
    from darkweb_collector.incremental_intelligence import refresh_incremental_intelligence

    # A completed view is reusable only under the same materialization and
    # projection rules, including when a failed preparation is retried after a fix.
    contract = hashlib.sha256(signature.encode("utf-8"))
    for path in (Path(__file__), *(ROOT / "src" / "darkweb_collector" / name for name in (
            "detail_artifacts.py", "normalized_intelligence.py", "incremental_intelligence.py"))):
        contract.update(path.read_bytes().replace(b"\r\n", b"\n"))
    signature = contract.hexdigest()
    key = "artifact_legacy_projection_v1"
    def save(connection, phase, full_bootstrap):
        value = json.dumps({"signature": signature, "phase": phase,
                            "revision": _projection_state(connection, "revision", "0"),
                            "full_bootstrap": full_bootstrap}, sort_keys=True)
        connection.execute("INSERT INTO intelligence_projection_state(name,value) VALUES (?,?) "
                           "ON CONFLICT(name) DO UPDATE SET value=excluded.value", (key, value))

    enqueued = 0
    with _projection_connection() as connection:
        try:
            previous = json.loads(_projection_state(connection, key, "{}"))
        except (TypeError, ValueError):
            previous = {}
        if not isinstance(previous, dict):
            previous = {}
        reusable = (previous.get("signature") == signature
                    and previous.get("revision") == _projection_state(connection, "revision", "0")
                    and _projection_state(connection, "artifact_view_mode") == "legacy")
        if (reusable and previous.get("phase") == "ready" and not _foreground_pending(connection)
                and _projection_state(connection, "sources_indexed") == "1"):
            return {"complete": True, "enqueued": 0, "cycles": 0}
        full_bootstrap = (bool(previous.get("full_bootstrap")) if reusable and previous.get("phase") == "queued"
                          else any(_projection_state(connection, name) != "1" for name in ("sources_indexed", "catalog_complete")))
        if not reusable or previous.get("phase") != "queued":
            for source_type, source_id in iter_committed_artifact_sources(connection):
                enqueue_change(connection, source_type, source_id, priority=1)
                enqueued += 1
            connection.execute("INSERT INTO intelligence_projection_state(name,value) VALUES ('artifact_view_mode','legacy') "
                               "ON CONFLICT(name) DO UPDATE SET value=excluded.value")
            save(connection, "queued", full_bootstrap)

    deadline = time.monotonic() + 900
    cycles = 0
    with legacy_artifact_view():
        while time.monotonic() < deadline:
            with _projection_connection() as connection:
                batch = refresh_incremental_intelligence(connection)
                complete = (not _foreground_pending(connection) and _projection_state(connection, "sources_indexed") == "1"
                            and (not full_bootstrap or not batch["pending"]))
                save(connection, "ready" if complete else "queued", full_bootstrap)
            cycles += 1
            if complete:
                return {"complete": True, "enqueued": enqueued, "cycles": cycles}
    raise RuntimeError("Legacy projection preparation is incomplete; retry while application services remain stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare evidence before starting a stopped legacy release")
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--quiesced", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not args.quiesced:
        parser.error("The managed launcher must first verify application processes have stopped")
    try:
        with _controller_lifetime():
            _managed_target(args.target_root)
            # The failed candidate may have collected a newly introduced site.
            candidate_sites = update_state_root() / "config" / f"sites-{ROOT.parent.name}.json"
            if candidate_sites.is_file():
                os.environ["DARKWEB_COLLECTOR_SITES_FILE"] = str(candidate_sites)
            configs = load_site_configs()
            with _read_only_connection() as connection:
                result = materialize_legacy_views(connection, configs, quiesced=True)
            if result.get("complete") is not True:
                raise RuntimeError("Legacy evidence preparation did not complete")
            # A legacy API combines its cached projection with raw detail data.
            # Prepare both under quiescence so it cannot mix old text with new images.
            result["projection"] = (_prepare_legacy_projection(result["signature"]) if result["records"]
                                    else {"complete": True, "enqueued": 0, "cycles": 0})
            print(json.dumps(result, ensure_ascii=True))
    except Exception as exc:
        print(f"Legacy evidence preparation failed ({type(exc).__name__}): {safe_failure_text(str(exc))}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
