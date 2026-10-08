from __future__ import annotations

import hashlib
from contextlib import contextmanager
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Iterator

from darkweb_collector.runtime import default_db_path


ASSIGNABLE_MODULES = (
    "intelligence_search",
    "ransomware",
    "data_leak",
    "vulnerability_alerts",
    "collector_control",
    "file_monitoring",
    "social_monitoring",
)

_PASSWORD_SCHEME = "pbkdf2_sha256"
_PASSWORD_ITERATIONS = 310_000


def auth_accounts_db_path() -> Path:
    configured_path = os.environ.get("DARKWEB_AUTH_ACCOUNTS_DB", "").strip()
    if configured_path:
        return Path(configured_path).expanduser().resolve()
    return default_db_path().with_name("auth_accounts.db").resolve()


def normalize_modules(modules: list[str] | tuple[str, ...] | None) -> list[str]:
    requested = {str(module or "").strip() for module in (modules or [])}
    invalid = sorted(requested.difference(ASSIGNABLE_MODULES))
    if invalid:
        raise ValueError(f"未知模块权限：{', '.join(invalid)}")
    return [module for module in ASSIGNABLE_MODULES if module in requested]


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PASSWORD_ITERATIONS,
    )
    return f"{_PASSWORD_SCHEME}${_PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations_text, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != _PASSWORD_SCHEME:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations_text),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (TypeError, ValueError):
        return False


@contextmanager
def _connect() -> Iterator[sqlite3.Connection]:
    db_path = auth_accounts_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS auth_accounts (
            username TEXT PRIMARY KEY COLLATE NOCASE,
            display_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            modules_json TEXT NOT NULL DEFAULT '[]',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )
        """
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def _row_payload(row: sqlite3.Row | None, *, include_password: bool = False) -> dict[str, object] | None:
    if row is None:
        return None
    try:
        modules = normalize_modules(json.loads(str(row["modules_json"] or "[]")))
    except (TypeError, ValueError, json.JSONDecodeError):
        modules = []
    payload: dict[str, object] = {
        "username": str(row["username"]),
        "display_name": str(row["display_name"] or row["username"]),
        "role": "user",
        "is_admin": False,
        "modules": modules,
        "enabled": bool(row["enabled"]),
        "fixed": False,
        "created_at": float(row["created_at"] or 0),
        "updated_at": float(row["updated_at"] or 0),
    }
    if include_password:
        payload["password_hash"] = str(row["password_hash"] or "")
    return payload


def list_accounts() -> list[dict[str, object]]:
    with _connect() as connection:
        rows = connection.execute(
            "SELECT * FROM auth_accounts ORDER BY created_at ASC, username COLLATE NOCASE ASC"
        ).fetchall()
    return [_row_payload(row) for row in rows if row is not None]


def get_account(username: str, *, include_password: bool = False) -> dict[str, object] | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT * FROM auth_accounts WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
    return _row_payload(row, include_password=include_password)


def create_account(
    *,
    username: str,
    display_name: str,
    password: str,
    modules: list[str],
) -> dict[str, object] | None:
    now = time.time()
    normalized_modules = normalize_modules(modules)
    try:
        with _connect() as connection:
            connection.execute(
                """
                INSERT INTO auth_accounts (
                    username, display_name, password_hash, modules_json, enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    username,
                    display_name or username,
                    hash_password(password),
                    json.dumps(normalized_modules, ensure_ascii=False),
                    now,
                    now,
                ),
            )
            connection.commit()
    except sqlite3.IntegrityError:
        return None
    return get_account(username)


def update_account(
    username: str,
    *,
    display_name: str,
    modules: list[str],
    enabled: bool,
) -> dict[str, object] | None:
    normalized_modules = normalize_modules(modules)
    with _connect() as connection:
        cursor = connection.execute(
            """
            UPDATE auth_accounts
            SET display_name = ?, modules_json = ?, enabled = ?, updated_at = ?
            WHERE username = ? COLLATE NOCASE
            """,
            (
                display_name or username,
                json.dumps(normalized_modules, ensure_ascii=False),
                int(enabled),
                time.time(),
                username,
            ),
        )
        connection.commit()
    if cursor.rowcount < 1:
        return None
    return get_account(username)


def update_account_profile(
    username: str,
    *,
    new_username: str,
    display_name: str,
    new_password: str = "",
) -> dict[str, object] | None:
    fields = ["username = ?", "display_name = ?", "updated_at = ?"]
    values: list[object] = [new_username, display_name or new_username, time.time()]
    if new_password:
        fields.append("password_hash = ?")
        values.append(hash_password(new_password))
    values.append(username)
    try:
        with _connect() as connection:
            cursor = connection.execute(
                f"UPDATE auth_accounts SET {', '.join(fields)} WHERE username = ? COLLATE NOCASE",
                values,
            )
            connection.commit()
    except sqlite3.IntegrityError:
        return None
    if cursor.rowcount < 1:
        return None
    return get_account(new_username)


def update_account_password(username: str, password: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute(
            """
            UPDATE auth_accounts
            SET password_hash = ?, updated_at = ?
            WHERE username = ? COLLATE NOCASE
            """,
            (hash_password(password), time.time(), username),
        )
        connection.commit()
    return cursor.rowcount > 0


def delete_account(username: str) -> bool:
    with _connect() as connection:
        cursor = connection.execute(
            "DELETE FROM auth_accounts WHERE username = ? COLLATE NOCASE",
            (username,),
        )
        connection.commit()
    return cursor.rowcount > 0
