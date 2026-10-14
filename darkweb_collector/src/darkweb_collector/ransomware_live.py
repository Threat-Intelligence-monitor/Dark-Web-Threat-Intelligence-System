from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.request import Request, urlopen

from darkweb_collector.db import (
    get_db_connection,
    get_ransomware_live_sync_state,
    upsert_ransomware_live_victim,
)
from darkweb_collector.runtime import default_db_path


RANSOMWARE_LIVE_API_URL = "https://api-pro.ransomware.live/victims/recent?order=discovered"
RANSOMWARE_LIVE_API_KEY_ENV = "RANSOMWARE_LIVE_API_KEY"
RANSOMWARE_LIVE_SETTINGS_PATH_ENV = "DARKWEB_RANSOMWARE_LIVE_SETTINGS_PATH"
RANSOMWARE_LIVE_SETTINGS_FILE = "ransomware_live_settings.json"
RANSOMWARE_LIVE_SYNC_STATUS_PATH_ENV = "DARKWEB_RANSOMWARE_LIVE_SYNC_STATUS_PATH"
RANSOMWARE_LIVE_SYNC_STATUS_FILE = "ransomware_live_sync_status.json"
RANSOMWARE_LIVE_SYNC_TTL_SECONDS = 3600
RANSOMWARE_LIVE_DEFAULT_LIMIT = 0
RANSOMWARE_LIVE_SYNC_ADVISORY_LOCK_ID = 0x44575449524C5359
HTTP_HEADERS = {
    "Accept": "application/json",
    "User-Agent": "bishe-threat-intel/1.0",
}

_settings_lock = Lock()
_sync_lock = Lock()


def _settings_path() -> Path:
    raw_path = str(os.environ.get(RANSOMWARE_LIVE_SETTINGS_PATH_ENV) or "").strip()
    if raw_path:
        return Path(raw_path).expanduser().resolve()
    return default_db_path().with_name(RANSOMWARE_LIVE_SETTINGS_FILE).resolve()


def _load_settings() -> dict[str, Any]:
    path = _settings_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_settings(payload: dict[str, Any]) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _sync_status_path() -> Path:
    raw_path = str(os.environ.get(RANSOMWARE_LIVE_SYNC_STATUS_PATH_ENV) or "").strip()
    if raw_path:
        return Path(raw_path).expanduser().resolve()
    return _settings_path().with_name(RANSOMWARE_LIVE_SYNC_STATUS_FILE)


def _load_sync_status() -> dict[str, Any]:
    path = _sync_status_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def save_ransomware_live_sync_status(payload: dict[str, Any]) -> dict[str, Any]:
    path = _sync_status_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    merged = {**_load_sync_status(), **payload}
    normalized = {
        "last_job_id": _normalize_text(merged.get("last_job_id")),
        "last_tick_at": _normalize_datetime(merged.get("last_tick_at")),
        "last_success_at": _normalize_datetime(merged.get("last_success_at")),
        "last_error": _normalize_text(merged.get("last_error")),
        "last_source": _normalize_text(merged.get("last_source")),
        "last_fetched": max(0, int(merged.get("last_fetched") or 0)),
        "last_ingested": max(0, int(merged.get("last_ingested") or 0)),
        "last_new": max(0, int(merged.get("last_new") or 0)),
        "last_updated": max(0, int(merged.get("last_updated") or 0)),
        "last_unchanged": max(0, int(merged.get("last_unchanged") or 0)),
        "updated_at": _now_utc_iso(),
    }
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(json.dumps(normalized, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return normalized


def get_ransomware_live_sync_status_snapshot() -> dict[str, Any]:
    payload = _load_sync_status()
    return {
        "last_job_id": _normalize_text(payload.get("last_job_id")),
        "last_tick_at": _normalize_datetime(payload.get("last_tick_at")),
        "last_success_at": _normalize_datetime(payload.get("last_success_at")),
        "last_error": _normalize_text(payload.get("last_error")),
        "last_source": _normalize_text(payload.get("last_source")),
        "last_fetched": max(0, int(payload.get("last_fetched") or 0)),
        "last_ingested": max(0, int(payload.get("last_ingested") or 0)),
        "last_new": max(0, int(payload.get("last_new") or 0)),
        "last_updated": max(0, int(payload.get("last_updated") or 0)),
        "last_unchanged": max(0, int(payload.get("last_unchanged") or 0)),
    }


def _mask_api_key(value: str) -> str:
    key = _normalize_text(value)
    if not key:
        return ""
    if len(key) <= 8:
        return "*" * len(key)
    return f"{key[:4]}{'*' * max(4, len(key) - 8)}{key[-4:]}"


def get_ransomware_live_api_key() -> str:
    env_value = str(os.environ.get(RANSOMWARE_LIVE_API_KEY_ENV) or "").strip()
    if env_value:
        return env_value
    return _normalize_text(_load_settings().get("api_key"))


def has_ransomware_live_api_key() -> bool:
    return bool(get_ransomware_live_api_key())


def set_ransomware_live_api_key(api_key: str) -> dict[str, Any]:
    normalized = _normalize_text(api_key)
    if not normalized:
        raise RuntimeError("api_key must not be empty")
    with _settings_lock:
        settings = _load_settings()
        settings.update(
            {
                "api_key": normalized,
                "updated_at": _now_utc_iso(),
            }
        )
        _save_settings(settings)
    os.environ[RANSOMWARE_LIVE_API_KEY_ENV] = normalized
    return get_ransomware_live_config_status()


def get_ransomware_live_sync_config() -> dict[str, Any]:
    settings = _load_settings()
    try:
        interval_seconds = max(60, int(settings.get("sync_interval_seconds") or RANSOMWARE_LIVE_SYNC_TTL_SECONDS))
    except (TypeError, ValueError):
        interval_seconds = RANSOMWARE_LIVE_SYNC_TTL_SECONDS
    try:
        limit = max(0, int(settings.get("sync_limit") or RANSOMWARE_LIVE_DEFAULT_LIMIT))
    except (TypeError, ValueError):
        limit = RANSOMWARE_LIVE_DEFAULT_LIMIT
    return {
        "enabled": bool(settings.get("sync_enabled", False)),
        "interval_seconds": interval_seconds,
        "limit": limit,
        "started_at": _normalize_datetime(settings.get("sync_started_at")),
        "updated_at": _normalize_datetime(settings.get("sync_updated_at")),
    }


def set_ransomware_live_sync_config(
    *,
    enabled: bool,
    interval_seconds: int = RANSOMWARE_LIVE_SYNC_TTL_SECONDS,
    limit: int = RANSOMWARE_LIVE_DEFAULT_LIMIT,
) -> dict[str, Any]:
    normalized_interval = max(60, int(interval_seconds or RANSOMWARE_LIVE_SYNC_TTL_SECONDS))
    normalized_limit = max(0, int(limit or RANSOMWARE_LIVE_DEFAULT_LIMIT))
    now = _now_utc_iso()
    with _settings_lock:
        settings = _load_settings()
        previous_enabled = bool(settings.get("sync_enabled", False))
        settings.update(
            {
                "sync_enabled": bool(enabled),
                "sync_interval_seconds": normalized_interval,
                "sync_limit": normalized_limit,
                "sync_updated_at": now,
            }
        )
        if enabled and not previous_enabled:
            settings["sync_started_at"] = now
        _save_settings(settings)
    return get_ransomware_live_sync_config()


def get_ransomware_live_config_status() -> dict[str, Any]:
    env_value = str(os.environ.get(RANSOMWARE_LIVE_API_KEY_ENV) or "").strip()
    settings = _load_settings()
    saved_value = _normalize_text(settings.get("api_key"))
    effective = env_value or saved_value
    source = "environment" if env_value else "saved_file" if saved_value else "none"
    return {
        "has_api_key": bool(effective),
        "masked_api_key": _mask_api_key(effective),
        "source": source,
        "env_var": RANSOMWARE_LIVE_API_KEY_ENV,
        "settings_path": str(_settings_path()),
        "updated_at": _normalize_text(settings.get("updated_at")),
        "sync_status_path": str(_sync_status_path()),
    }


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_utc_iso() -> str:
    return _now_utc().isoformat()


def _normalize_text(value: Any) -> str:
    return str(value or "").strip()


def _normalize_datetime(value: Any) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _apply_record_limit(victims: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    if limit is None:
        return victims
    try:
        normalized = int(limit)
    except (TypeError, ValueError):
        return victims
    if normalized <= 0:
        return victims
    return victims[:normalized]


def _fetch_json(url: str, *, timeout: int = 30) -> dict[str, Any]:
    api_key = get_ransomware_live_api_key()
    if not api_key:
        raise RuntimeError(f"{RANSOMWARE_LIVE_API_KEY_ENV} is not set")
    request = Request(
        url,
        headers={
            **HTTP_HEADERS,
            "X-API-KEY": api_key,
        },
    )
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _load_sample_payload(sample_file: str | Path) -> dict[str, Any]:
    path = Path(sample_file).expanduser().resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("records"), list):
        return {"victims": payload.get("records") or [], "count": len(payload.get("records") or [])}
    if isinstance(payload, list):
        return {"victims": payload, "count": len(payload)}
    return payload if isinstance(payload, dict) else {"victims": [], "count": 0}


def normalize_ransomware_live_victim(record: dict[str, Any], *, last_seen_at: str | None = None) -> dict[str, Any]:
    raw_json = dict(record)
    discovered_at = _normalize_datetime(record.get("discovered"))
    attacked_at = _normalize_datetime(record.get("attackdate"))
    effective_last_seen_at = _normalize_datetime(last_seen_at) or _now_utc_iso()
    return {
        "victim_id": _normalize_text(record.get("id")),
        "group_name": _normalize_text(record.get("group")),
        "victim_name": _normalize_text(record.get("victim")),
        "website": _normalize_text(record.get("website")),
        "country_code": _normalize_text(record.get("country")).upper(),
        "activity": _normalize_text(record.get("activity")),
        "discovered_at": discovered_at,
        "attacked_at": attacked_at or discovered_at,
        "post_url": _normalize_text(record.get("post_url")),
        "permalink": _normalize_text(record.get("permalink")),
        "screenshot_url": _normalize_text(record.get("screenshot")),
        "description": _normalize_text(record.get("description")),
        "press_url": _normalize_text(record.get("press")),
        "raw_json": raw_json,
        "last_seen_at": effective_last_seen_at,
    }


def fetch_recent_ransomware_live_victims(
    *,
    limit: int = RANSOMWARE_LIVE_DEFAULT_LIMIT,
    sample_file: str | Path | None = None,
    prefer_live: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if sample_file is not None:
        payload = _load_sample_payload(sample_file)
    elif prefer_live:
        payload = _fetch_json(RANSOMWARE_LIVE_API_URL)
    else:
        payload = {"victims": [], "count": 0}
    victims = payload.get("victims") or []
    if not isinstance(victims, list):
        victims = []
    limited = _apply_record_limit(victims, limit)
    observed_at = _now_utc_iso()
    records = [
        normalize_ransomware_live_victim(item, last_seen_at=observed_at)
        for item in limited
        if isinstance(item, dict) and _normalize_text(item.get("id"))
    ]
    return records, payload


def _try_acquire_sync_lock(connection) -> tuple[bool, bool]:
    if getattr(connection, "backend_name", "") == "postgresql":
        row = connection.execute(
            "SELECT pg_try_advisory_xact_lock(?) AS acquired",
            (RANSOMWARE_LIVE_SYNC_ADVISORY_LOCK_ID,),
        ).fetchone()
        return bool(row and row["acquired"]), False
    return _sync_lock.acquire(blocking=False), True


def sync_ransomware_live_victims(
    *,
    limit: int = RANSOMWARE_LIVE_DEFAULT_LIMIT,
    sample_file: str | Path | None = None,
    prefer_live: bool = True,
    refresh_normalized: bool = True,
) -> dict[str, Any]:
    release_local_lock = False
    with get_db_connection() as connection:
        acquired, release_local_lock = _try_acquire_sync_lock(connection)
        if not acquired:
            raise RuntimeError("ransomware.live sync is already running")
        try:
            records, payload = fetch_recent_ransomware_live_victims(
                limit=limit,
                sample_file=sample_file,
                prefer_live=prefer_live,
            )
            outcome_counts = {"new": 0, "updated": 0, "unchanged": 0}
            for record in records:
                _, outcome = upsert_ransomware_live_victim(connection, record, return_outcome=True)
                outcome_counts[outcome] += 1
            if refresh_normalized:
                from darkweb_collector.normalized_intelligence import ensure_normalized_intelligence

                ensure_normalized_intelligence(connection, force=True, load_events=False)
            connection.commit()
            sync_state = get_ransomware_live_sync_state(connection)
        finally:
            if release_local_lock:
                _sync_lock.release()
                release_local_lock = False
    ingested = outcome_counts["new"] + outcome_counts["updated"]
    return {
        "fetched": len(records),
        "ingested": ingested,
        "new_count": outcome_counts["new"],
        "updated_count": outcome_counts["updated"],
        "unchanged_count": outcome_counts["unchanged"],
        "count": int(sync_state.get("count") or 0),
        "latest_seen_at": _normalize_text(sync_state.get("latest_seen_at")),
        "latest_disclosure_time": _normalize_text(sync_state.get("latest_disclosure_time")),
        "source": RANSOMWARE_LIVE_API_URL,
        "payload_count": int(payload.get("count") or 0),
    }
