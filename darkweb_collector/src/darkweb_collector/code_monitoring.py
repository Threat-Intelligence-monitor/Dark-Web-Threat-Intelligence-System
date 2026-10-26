from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import base64
from html import unescape
from html.parser import HTMLParser
from hashlib import sha1
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import ssl
from threading import Lock, Thread
import time
from typing import Any
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote_plus, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from darkweb_collector.db import (
    add_code_hit_review,
    delete_code_watchlist,
    get_code_search_state,
    get_code_hit,
    get_code_watchlist,
    get_db_connection,
    insert_code_hit_snapshot,
    insert_code_scan_run,
    list_code_search_states,
    list_code_hit_reviews,
    list_code_hit_snapshots,
    list_code_hits,
    list_code_scan_runs,
    list_code_watch_terms,
    list_code_watchlists,
    replace_code_watch_terms,
    update_code_hit_last_snapshot,
    update_code_scan_run,
    upsert_code_search_state,
    upsert_code_hit_with_state,
    upsert_code_watchlist,
)
from darkweb_collector.document_exposure_browser import fetch_page_artifacts_with_session
from darkweb_collector.document_exposure_platforms import PLATFORMS, ExposurePlatform, get_exposure_platform
from darkweb_collector.document_exposure_sessions import build_platform_session_payloads, platform_storage_state_path
from darkweb_collector.github_app_auth import github_app_config_status, github_app_installation_token
from darkweb_collector.runtime import output_root
from darkweb_collector.utils import dump_json, dump_text, safe_stem


logger = logging.getLogger("darkweb_collector.code_monitoring")
SHANGHAI_TZ = timezone(timedelta(hours=8))
_CODE_SCAN_LOCK = Lock()
_CODE_HITS_PAYLOAD_CACHE_LOCK = Lock()
_CODE_HITS_PAYLOAD_CACHE_TTL_SECONDS = 3600.0
_CODE_HITS_PAYLOAD_CACHE: dict[tuple[Any, ...], tuple[float, list[dict[str, Any]]]] = {}
_CODE_HITS_WARMUP_LOCK = Lock()
_CODE_HITS_WARMUP_RUNNING = False
_SQLITE_LOCK_RETRY_DELAYS = (0.2, 0.5, 1.0, 2.0, 4.0)
_GITHUB_API_REQUEST_LOCK = Lock()
_GITHUB_API_STATE_LOCK = Lock()
_GITHUB_API_CACHE_LOCK = Lock()
_GITHUB_API_LAST_REQUEST_MONOTONIC = 0.0
_GITHUB_API_QUERY_CACHE: dict[tuple[str, str, int], tuple[float, list[dict[str, Any]], dict[str, Any]]] = {}
_GITHUB_API_STATE: dict[str, Any] = {
    "last_request_at": "",
    "last_success_at": "",
    "last_error": "",
    "limit": None,
    "remaining": None,
    "reset_at": "",
    "cooldown_until": 0.0,
    "cache_hits": 0,
    "last_used_channel": "",
    "fallback_used": False,
    "degraded": False,
}

DEFAULT_CODE_PLATFORMS = ["github", "gitlab", "gitee"]
DEFAULT_FILE_EXTENSIONS = ["env", "yaml", "yml", "json", "ini", "conf", "properties", "py", "js", "ts", "java"]
LEGACY_NARROW_FILE_EXTENSIONS = ["env", "yaml", "yml", "json"]
DEFAULT_SEARCH_PAGE_LIMIT = 0
DEFAULT_MAX_RESULTS_PER_TERM = 0
UNLIMITED_SEARCH_PAGE_SAFETY_CAP = 50
DEFAULT_RULE_KEYS = [
    "api_key",
    "token",
    "ak_sk",
    "db_url",
    "jwt_secret",
    "redis_url",
    "private_key",
    "internal_url",
    "password",
]
DEFAULT_ENTERPRISE_PROFILE = {
    "official_names": [],
    "brand_aliases": [],
    "english_aliases": [],
    "root_domains": [],
    "trusted_subdomain_patterns": [],
    "internal_system_keywords": [],
    "negative_aliases": [],
    "short_alias_guard": [],
}
SEARCH_URL_TEMPLATES = {
    "github": "https://github.com/search?q={query}&type=code",
    "gitlab": "https://gitlab.com/search?search={query}&nav_source=navbar&type=blobs",
    "gitee": "https://search.gitee.com/?skin=rec&type=code&q={query}",
}
GITEE_WIDGET_API_BASE = "https://so.gitee.com/v1"
GITEE_REPO_SEARCH_WIDGET = "wong1slagnlmzwvsu5ya"
GITEE_WIDGET_PAGE_SIZE = 20
SEARCH_CHALLENGE_MARKERS: tuple[str, ...] = (
    "安全验证码",
    "独立验证",
    "security verification",
    "verify you are human",
    "cf-challenge",
    "please move your mouse or press a key",
    "please wait while we verify",
    "just a moment",
)
GITEE_WIDGET_MAX_OFFSET = 180
GITHUB_CODE_SEARCH_API = "https://api.github.com/search/code"
GITHUB_CODE_SEARCH_PER_PAGE = 100
GITHUB_CODE_SEARCH_MAX_PAGES = 10
GITHUB_CODE_SEARCH_DEFAULT_PAGES = 2
GITHUB_CODE_SEARCH_DEFAULT_CACHE_SECONDS = 300.0
GITHUB_CODE_SEARCH_DEFAULT_MIN_INTERVAL_SECONDS = 6.1
REPO_FALLBACK_FILE_EXTENSIONS = [
    "env", "yaml", "yml", "json", "ini", "conf", "properties",
    "py", "js", "ts", "java", "go", "rb", "php", "sh", "toml", "xml", "txt", "csv",
]
CODE_CLUE_RULE_KEY = "clue"
CODE_CLUE_RULE_LABEL = "关键词线索"
CODE_CLASSIFICATION_VERSION = 2
CLUE_MARKERS: tuple[tuple[str, int], ...] = (
    ("password", 9),
    ("passwd", 9),
    ("pwd", 8),
    ("token", 8),
    ("secret", 8),
    ("apikey", 8),
    ("api_key", 8),
    ("jwt", 7),
    ("redis", 7),
    ("database", 6),
    ("db_host", 6),
    ("smtp", 6),
    ("mail", 5),
    ("auth", 5),
    ("login", 4),
    ("credential", 7),
    ("dotenv", 6),
    ("os.getenv", 7),
    ("process.env", 7),
)


@dataclass(frozen=True)
class SensitiveRule:
    key: str
    label: str
    pattern: re.Pattern[str]
    weight: int
    secret_like: bool = False


SENSITIVE_RULES: tuple[SensitiveRule, ...] = (
    SensitiveRule("api_key", "API Key", re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}"), 26, True),
    SensitiveRule("token", "访问 Token", re.compile(r"(?i)(?:token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{12,}"), 24, True),
    SensitiveRule("ak_sk", "AK/SK", re.compile(r"(?i)(?:access[_-]?key|secret[_-]?key|app[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9/\+=_\-]{12,}"), 28, True),
    SensitiveRule("db_url", "数据库连接串", re.compile(r"(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?):\/\/[^\s'\"<>]{8,}"), 22, True),
    SensitiveRule("jwt_secret", "JWT Secret", re.compile(r"(?i)jwt[_-]?secret\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/\+=]{8,}"), 24, True),
    SensitiveRule("redis_url", "Redis URL", re.compile(r"(?i)redis:\/\/[^\s'\"<>]{6,}"), 18, True),
    SensitiveRule("private_key", "私钥", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), 35, True),
    SensitiveRule("internal_url", "内网地址", re.compile(r"(?i)https?:\/\/(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.0\.0\.1|localhost)[^\s'\"<>]*"), 16, False),
    SensitiveRule("password", "账号口令", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"<>]{4,}"), 20, True),
)
SENSITIVE_RULE_MAP = {item.key: item for item in SENSITIVE_RULES}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\u00a0", " ").split()).strip()


def _strip_html(value: str) -> str:
    return _normalize_text(re.sub(r"<[^>]+>", " ", unescape(str(value or ""))))


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


class GitHubCodeSearchUnavailable(RuntimeError):
    pass


def _github_search_mode() -> str:
    value = _normalize_text(os.environ.get("DARKWEB_GITHUB_CODE_SEARCH_MODE")).lower()
    return value if value in {"auto", "api", "browser"} else "auto"


def _github_api_token() -> tuple[str, str]:
    direct_token = _normalize_text(os.environ.get("DARKWEB_GITHUB_TOKEN"))
    if direct_token:
        return direct_token, "DARKWEB_GITHUB_TOKEN"
    token_file = _normalize_text(os.environ.get("DARKWEB_GITHUB_TOKEN_FILE"))
    if token_file:
        try:
            file_token = Path(token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError:
            file_token = ""
        if file_token:
            return file_token, "token_file"
    app_token = github_app_installation_token()
    if app_token:
        return app_token, "github_app"
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        token = _normalize_text(os.environ.get(name))
        if token:
            return token, name
    return "", ""


def _github_env_float(name: str, default: float, minimum: float) -> float:
    try:
        return max(minimum, float(os.environ.get(name, default)))
    except (TypeError, ValueError):
        return default


def _github_cache_seconds() -> float:
    return _github_env_float(
        "DARKWEB_GITHUB_CODE_SEARCH_CACHE_SECONDS",
        GITHUB_CODE_SEARCH_DEFAULT_CACHE_SECONDS,
        0.0,
    )


def _github_min_interval_seconds() -> float:
    return _github_env_float(
        "DARKWEB_GITHUB_CODE_SEARCH_MIN_INTERVAL_SECONDS",
        GITHUB_CODE_SEARCH_DEFAULT_MIN_INTERVAL_SECONDS,
        0.0,
    )


def _github_page_limit(value: int) -> int:
    requested = int(value or 0)
    return min(GITHUB_CODE_SEARCH_MAX_PAGES, requested if requested > 0 else GITHUB_CODE_SEARCH_DEFAULT_PAGES)


def _github_api_enabled() -> bool:
    token, _ = _github_api_token()
    return _github_search_mode() in {"auto", "api"} and bool(token)


def _github_iso_from_epoch(value: Any) -> str:
    try:
        timestamp = float(value or 0)
    except (TypeError, ValueError):
        return ""
    if timestamp <= 0:
        return ""
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _github_header_int(headers: Any, name: str) -> int | None:
    try:
        value = headers.get(name)
        return int(value) if value not in {None, ""} else None
    except (AttributeError, TypeError, ValueError):
        return None


def _update_github_api_state(**changes: Any) -> None:
    with _GITHUB_API_STATE_LOCK:
        _GITHUB_API_STATE.update(changes)


def github_code_search_status_payload() -> dict[str, Any]:
    token, token_source = _github_api_token()
    app_status = github_app_config_status()
    mode = _github_search_mode()
    now_epoch = time.time()
    now_monotonic = time.monotonic()
    with _GITHUB_API_CACHE_LOCK:
        expired = [key for key, value in _GITHUB_API_QUERY_CACHE.items() if value[0] <= now_monotonic]
        for key in expired:
            _GITHUB_API_QUERY_CACHE.pop(key, None)
        cache_entries = len(_GITHUB_API_QUERY_CACHE)
    with _GITHUB_API_STATE_LOCK:
        state = dict(_GITHUB_API_STATE)
    cooldown_epoch = float(state.get("cooldown_until") or 0)
    active_channel = "browser"
    if mode == "api" and not token:
        active_channel = "unavailable"
    elif mode in {"auto", "api"} and token:
        active_channel = "api"
    return {
        "mode": mode,
        "activeChannel": active_channel,
        "fallbackChannel": "browser" if mode == "auto" else "",
        "apiConfigured": bool(token),
        "tokenSource": token_source,
        "credentialType": "github_app" if token_source == "github_app" else ("token" if token else ""),
        "appConfigured": bool(app_status.get("configured")),
        "appId": app_status.get("appId"),
        "installationId": app_status.get("installationId"),
        "appLastValidatedAt": str(app_status.get("lastValidatedAt") or ""),
        "appTokenExpiresAt": str(app_status.get("tokenExpiresAt") or ""),
        "appLastError": str(app_status.get("lastError") or ""),
        "rateLimit": state.get("limit"),
        "rateRemaining": state.get("remaining"),
        "rateResetAt": str(state.get("reset_at") or ""),
        "cooldownUntil": _github_iso_from_epoch(cooldown_epoch) if cooldown_epoch > now_epoch else "",
        "lastRequestAt": str(state.get("last_request_at") or ""),
        "lastSuccessAt": str(state.get("last_success_at") or ""),
        "lastError": str(state.get("last_error") or ""),
        "lastUsedChannel": str(state.get("last_used_channel") or ""),
        "fallbackUsed": bool(state.get("fallback_used")),
        "degraded": bool(state.get("degraded")),
        "cacheEntries": cache_entries,
        "cacheHits": int(state.get("cache_hits") or 0),
        "cacheSeconds": _github_cache_seconds(),
        "minIntervalSeconds": _github_min_interval_seconds(),
        "defaultBranchOnly": True,
    }


def _github_retry_epoch(headers: Any, fallback_seconds: int) -> float:
    now_epoch = time.time()
    reset_epoch = _github_header_int(headers, "X-RateLimit-Reset") or 0
    retry_after = _github_header_int(headers, "Retry-After") or 0
    if retry_after > 0:
        return now_epoch + retry_after
    if reset_epoch > now_epoch:
        return float(reset_epoch)
    return now_epoch + max(1, fallback_seconds)


def _github_api_request_json(url: str, token: str) -> dict[str, Any]:
    global _GITHUB_API_LAST_REQUEST_MONOTONIC
    with _GITHUB_API_REQUEST_LOCK:
        now_epoch = time.time()
        with _GITHUB_API_STATE_LOCK:
            cooldown_until = float(_GITHUB_API_STATE.get("cooldown_until") or 0)
        if cooldown_until > now_epoch:
            _update_github_api_state(last_error="rate_limited", degraded=True)
            raise GitHubCodeSearchUnavailable("rate_limited")
        wait_seconds = _github_min_interval_seconds() - (time.monotonic() - _GITHUB_API_LAST_REQUEST_MONOTONIC)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
        _GITHUB_API_LAST_REQUEST_MONOTONIC = time.monotonic()
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github.text-match+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "Dark-Web-Threat-Intelligence-System",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        _update_github_api_state(last_request_at=_now_utc_iso())
        try:
            with urlopen(request, timeout=60) as response:  # noqa: S310
                headers = response.headers
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except HTTPError as exc:
            headers = exc.headers
            remaining = _github_header_int(headers, "X-RateLimit-Remaining")
            limit = _github_header_int(headers, "X-RateLimit-Limit")
            reset_epoch = _github_header_int(headers, "X-RateLimit-Reset") or 0
            retry_after = _github_header_int(headers, "Retry-After") or 0
            try:
                error_text = exc.read(4096).decode("utf-8", errors="replace").lower()
            except Exception:
                error_text = ""
            rate_limited = (
                exc.code == 429
                or remaining == 0
                or retry_after > 0
                or "rate limit" in error_text
                or "abuse detection" in error_text
            )
            if exc.code in {403, 429} and rate_limited:
                reason = "rate_limited"
                cooldown_until = _github_retry_epoch(headers, 60)
            elif exc.code == 403:
                reason = "access_denied"
                cooldown_until = 0.0
            elif exc.code == 401:
                reason = "authentication_failed"
                cooldown_until = _github_retry_epoch(headers, 300)
            elif exc.code == 422:
                reason = "invalid_query"
                cooldown_until = 0.0
            else:
                reason = f"http_{exc.code}"
                cooldown_until = _github_retry_epoch(headers, 30) if exc.code >= 500 else 0.0
            _update_github_api_state(
                last_error=reason,
                limit=limit,
                remaining=remaining,
                reset_at=_github_iso_from_epoch(reset_epoch),
                cooldown_until=cooldown_until,
                degraded=True,
            )
            raise GitHubCodeSearchUnavailable(reason) from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            _update_github_api_state(last_error="transport_or_response_error", degraded=True)
            raise GitHubCodeSearchUnavailable("transport_or_response_error") from exc
        if not isinstance(payload, dict):
            _update_github_api_state(last_error="invalid_response", degraded=True)
            raise GitHubCodeSearchUnavailable("invalid_response")
        remaining = _github_header_int(headers, "X-RateLimit-Remaining")
        limit = _github_header_int(headers, "X-RateLimit-Limit")
        reset_epoch = _github_header_int(headers, "X-RateLimit-Reset") or 0
        cooldown_until = float(reset_epoch) if remaining == 0 and reset_epoch else 0.0
        _update_github_api_state(
            last_success_at=_now_utc_iso(),
            last_error="",
            limit=limit,
            remaining=remaining,
            reset_at=_github_iso_from_epoch(reset_epoch),
            cooldown_until=cooldown_until,
        )
        return payload


def _github_api_item_to_candidate(item: dict[str, Any]) -> dict[str, Any] | None:
    repository = item.get("repository") if isinstance(item.get("repository"), dict) else {}
    if bool(repository.get("private")):
        return None
    file_url = _normalize_text(item.get("html_url"))
    file_path = _normalize_text(item.get("path") or item.get("name"))
    repository_url = _normalize_text(repository.get("html_url"))
    full_name = _normalize_text(repository.get("full_name"))
    owner_payload = repository.get("owner") if isinstance(repository.get("owner"), dict) else {}
    owner = _normalize_text(owner_payload.get("login"))
    repository_name = _normalize_text(repository.get("name"))
    if full_name and "/" in full_name:
        owner = owner or full_name.split("/", 1)[0]
        repository_name = repository_name or full_name.split("/", 1)[1]
    if not file_url or not file_path or not repository_url or not owner or not repository_name:
        return None
    location = _parse_code_location("github", file_url) or {}
    branch = _normalize_text(repository.get("default_branch") or location.get("branch")) or "main"
    fragments = []
    for text_match in item.get("text_matches") or []:
        if isinstance(text_match, dict):
            fragment = str(text_match.get("fragment") or "").strip()
            if fragment:
                fragments.append(fragment)
    return {
        "platform": "github",
        "platformLabel": "GitHub",
        "fileUrl": file_url,
        "title": _normalize_text(item.get("name")) or file_path,
        "repositoryOwner": owner,
        "repositoryName": repository_name,
        "repositoryUrl": repository_url,
        "branch": branch,
        "filePath": file_path,
        "lineStart": 0,
        "lineEnd": 0,
        "snippetText": "\n".join(fragments)[:8000],
        "searchChannel": "github_api",
    }


def _github_api_code_search(query: str, page_limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    token, _ = _github_api_token()
    if not token:
        raise GitHubCodeSearchUnavailable("auth_required")
    effective_limit = min(GITHUB_CODE_SEARCH_MAX_PAGES, max(1, int(page_limit or 1)))
    cache_key = (
        sha1(token.encode("utf-8", errors="ignore")).hexdigest()[:16],
        _normalize_text(query).lower(),
        effective_limit,
    )
    now_monotonic = time.monotonic()
    with _GITHUB_API_CACHE_LOCK:
        cached = _GITHUB_API_QUERY_CACHE.get(cache_key)
        if cached and cached[0] > now_monotonic:
            with _GITHUB_API_STATE_LOCK:
                _GITHUB_API_STATE["cache_hits"] = int(_GITHUB_API_STATE.get("cache_hits") or 0) + 1
                _GITHUB_API_STATE["last_used_channel"] = "api"
                _GITHUB_API_STATE["fallback_used"] = False
                _GITHUB_API_STATE["degraded"] = bool(cached[2].get("incomplete_results"))
            return [dict(item) for item in cached[1]], {**cached[2], "cache_hit": True}

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_count = 0
    incomplete_results = False
    pages_fetched = 0
    for page in range(1, effective_limit + 1):
        api_url = f"{GITHUB_CODE_SEARCH_API}?{urlencode({'q': query, 'per_page': GITHUB_CODE_SEARCH_PER_PAGE, 'page': page})}"
        payload = _github_api_request_json(api_url, token)
        pages_fetched = page
        total_count = max(total_count, int(payload.get("total_count") or 0))
        incomplete_results = incomplete_results or bool(payload.get("incomplete_results"))
        items = payload.get("items") if isinstance(payload.get("items"), list) else []
        if not items:
            break
        for item in items:
            candidate = _github_api_item_to_candidate(item) if isinstance(item, dict) else None
            if not candidate:
                continue
            key = _candidate_identity(candidate)
            if key and key not in seen:
                seen.add(key)
                results.append(candidate)
        if len(items) < GITHUB_CODE_SEARCH_PER_PAGE or len(results) >= min(total_count, 1000):
            break

    metadata = {
        "pages_fetched": pages_fetched,
        "total_count": total_count,
        "incomplete_results": incomplete_results,
        "cache_hit": False,
    }
    cache_seconds = _github_cache_seconds()
    if cache_seconds > 0:
        with _GITHUB_API_CACHE_LOCK:
            now_monotonic = time.monotonic()
            expired = [key for key, value in _GITHUB_API_QUERY_CACHE.items() if value[0] <= now_monotonic]
            for key in expired:
                _GITHUB_API_QUERY_CACHE.pop(key, None)
            if len(_GITHUB_API_QUERY_CACHE) >= 128:
                oldest_key = min(_GITHUB_API_QUERY_CACHE, key=lambda key: _GITHUB_API_QUERY_CACHE[key][0])
                _GITHUB_API_QUERY_CACHE.pop(oldest_key, None)
            _GITHUB_API_QUERY_CACHE[cache_key] = (
                now_monotonic + cache_seconds,
                [dict(item) for item in results],
                dict(metadata),
            )
    _update_github_api_state(
        last_used_channel="api",
        fallback_used=False,
        degraded=incomplete_results,
    )
    return results, metadata


def _is_sqlite_locked_error(exc: Exception) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and "database is locked" in str(exc).lower()


def _commit_db_write(write_operation):
    for attempt in range(len(_SQLITE_LOCK_RETRY_DELAYS) + 1):
        try:
            with get_db_connection() as connection:
                result = write_operation(connection)
                connection.commit()
                return result
        except sqlite3.OperationalError as exc:
            if not _is_sqlite_locked_error(exc) or attempt >= len(_SQLITE_LOCK_RETRY_DELAYS):
                raise
            time.sleep(_SQLITE_LOCK_RETRY_DELAYS[attempt])
    return None


def _persist_code_scan_run(
    scan_run_id: int | None,
    *,
    watchlist_id: int,
    selected_platforms: list[str],
    terms: list[dict[str, Any]],
    candidate_count: int,
    hit_count: int,
    clue_hit_count: int,
    sensitive_hit_count: int,
    errors: list[str],
    status: str,
    started_at: str,
    finished_at: str,
) -> int:
    payload = {
        "watchlist_id": int(watchlist_id),
        "platforms_json": _json_dumps(selected_platforms),
        "requested_terms_json": _json_dumps([_normalize_text(item.get("term")) for item in terms if _normalize_text(item.get("term"))]),
        "candidate_count": candidate_count,
        "hit_count": hit_count,
        "clue_hit_count": clue_hit_count,
        "sensitive_hit_count": sensitive_hit_count,
        "error_count": len(errors),
        "status": status,
        "errors_json": _json_dumps(errors),
        "started_at": started_at,
        "finished_at": finished_at,
    }

    def write_scan_run(connection):
        if scan_run_id:
            update_code_scan_run(connection, scan_run_id, payload)
            return scan_run_id
        return insert_code_scan_run(connection, payload)

    return int(_commit_db_write(write_scan_run) or 0)


def _parse_json(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return default


def _is_access_limited_scan_error(message: str) -> bool:
    lowered = str(message or "").lower()
    markers = (
        "login_required",
        "captcha_or_security_verification",
        "login_or_challenge_required",
        "rate_limited",
        "http_search_fetch_failed",
        "ssl_transport_error",
        "http error 404",
        "http error 403",
        "http error 429",
        "too many requests",
    )
    return any(marker in lowered for marker in markers)


def _watchlist_metadata(payload: dict[str, Any] | None) -> dict[str, Any]:
    data = _parse_json((payload or {}).get("metadata_json"), {})
    return data if isinstance(data, dict) else {}


def _normalize_string_list(value: Any, *, lower: bool = False, fallback: list[str] | None = None) -> list[str]:
    items = _parse_json(value, value)
    if isinstance(items, str):
        items = [part.strip() for part in items.split(",")]
    if not isinstance(items, list):
        items = []
    seen: set[str] = set()
    rows: list[str] = []
    for item in items:
        normalized = _normalize_text(item)
        if lower:
            normalized = normalized.lower().lstrip(".")
        if normalized and normalized not in seen:
            seen.add(normalized)
            rows.append(normalized)
    return rows or list(fallback or [])


def _normalize_code_file_extensions(value: Any) -> list[str]:
    extensions = _normalize_string_list(value, lower=True, fallback=DEFAULT_FILE_EXTENSIONS)
    if extensions == LEGACY_NARROW_FILE_EXTENSIONS:
        return list(DEFAULT_FILE_EXTENSIONS)
    return extensions


def _normalize_profile_list(value: Any, *, lower: bool = False) -> list[str]:
    return [item for item in _normalize_string_list(value, lower=lower, fallback=[]) if item]


def _normalize_domain_value(value: str) -> str:
    text = _normalize_text(value).lower().lstrip("@")
    if text.startswith("*."):
        text = text[2:]
    while text.startswith("."):
        text = text[1:]
    return text


def _domain_pattern_from_root(domain: str) -> str:
    normalized = _normalize_domain_value(domain)
    return f"*.{normalized}" if normalized else ""


def _derived_search_terms_from_profile(profile: dict[str, Any] | None) -> list[dict[str, Any]]:
    source = profile if isinstance(profile, dict) else {}
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    mappings = (
        ("official_names", "company_name"),
        ("brand_aliases", "company_name"),
        ("english_aliases", "company_name"),
        ("root_domains", "domain"),
        ("internal_system_keywords", "custom"),
    )
    for field, term_type in mappings:
        for value in _normalize_profile_list(source.get(field)):
            term = _normalize_domain_value(value) if term_type == "domain" else _normalize_text(value)
            key = term.casefold()
            if not term or key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "term": term,
                    "term_type": term_type,
                    "weight": 10,
                    "enabled": True,
                    "source": "enterprise_profile",
                }
            )
    return rows


def _effective_code_watch_terms(
    enterprise_profile: dict[str, Any] | None,
    supplemental_terms: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    rows = [*_derived_search_terms_from_profile(enterprise_profile), *(supplemental_terms or [])]
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not bool(row.get("enabled", True)):
            continue
        term = _normalize_text(row.get("term"))
        term_type = _normalize_text(row.get("term_type")) or "custom"
        key = term.casefold()
        if not term or key in seen:
            continue
        seen.add(key)
        deduped.append({**row, "term": term, "term_type": term_type})
    return deduped


def _metadata_enterprise_profile(metadata: dict[str, Any] | None, *, organization_name: str = "", terms: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    profile_payload = ((metadata or {}).get("enterprise_profile") or {}) if isinstance(metadata, dict) else {}
    profile_payload = profile_payload if isinstance(profile_payload, dict) else {}
    term_rows = terms if isinstance(terms, list) else []

    official_names = [item for item in _normalize_profile_list(profile_payload.get("official_names")) if item != "示例企业"]
    brand_aliases = _normalize_profile_list(profile_payload.get("brand_aliases"))
    english_aliases = _normalize_profile_list(profile_payload.get("english_aliases"), lower=True)
    root_domains = [
        value
        for item in _normalize_profile_list(profile_payload.get("root_domains"), lower=True)
        if (value := _normalize_domain_value(item)) and value != "example.com"
    ]
    trusted_subdomain_patterns = []
    for item in _normalize_profile_list(profile_payload.get("trusted_subdomain_patterns"), lower=True):
        normalized = _normalize_text(item).lower()
        if normalized:
            trusted_subdomain_patterns.append(normalized if normalized.startswith("*.") else _domain_pattern_from_root(normalized))
    internal_system_keywords = _normalize_profile_list(profile_payload.get("internal_system_keywords"), lower=True)
    negative_aliases = _normalize_profile_list(profile_payload.get("negative_aliases"), lower=True)
    short_alias_guard = _normalize_profile_list(profile_payload.get("short_alias_guard"), lower=True)

    if organization_name and _normalize_text(organization_name) != "示例企业":
        normalized_org = _normalize_text(organization_name)
        if normalized_org and normalized_org not in official_names:
            official_names.append(normalized_org)

    for row in term_rows:
        if not bool(row.get("enabled", True)):
            continue
        term = _normalize_text(row.get("term"))
        term_type = _normalize_text(row.get("term_type"))
        if not term:
            continue
        if term in {"示例企业", "example.com"}:
            continue
        if term_type == "domain":
            normalized_domain = _normalize_domain_value(term)
            if normalized_domain and normalized_domain not in root_domains:
                root_domains.append(normalized_domain)
            pattern = _domain_pattern_from_root(normalized_domain)
            if pattern and pattern not in trusted_subdomain_patterns:
                trusted_subdomain_patterns.append(pattern)
            continue
        if term_type == "company_name":
            if term not in official_names:
                official_names.append(term)
            continue
        lowered_term = term.lower()
        if re.search(r"[a-z]", lowered_term):
            if lowered_term not in english_aliases:
                english_aliases.append(lowered_term)
            if len(re.sub(r"[^a-z0-9]", "", lowered_term)) <= 4 and lowered_term not in short_alias_guard:
                short_alias_guard.append(lowered_term)
        elif term not in brand_aliases:
            brand_aliases.append(term)

    for domain in list(root_domains):
        pattern = _domain_pattern_from_root(domain)
        if pattern and pattern not in trusted_subdomain_patterns:
            trusted_subdomain_patterns.append(pattern)

    return {
        "official_names": official_names,
        "brand_aliases": brand_aliases,
        "english_aliases": english_aliases,
        "root_domains": root_domains,
        "trusted_subdomain_patterns": trusted_subdomain_patterns,
        "internal_system_keywords": internal_system_keywords,
        "negative_aliases": negative_aliases,
        "short_alias_guard": short_alias_guard,
    }


def _watchlist_enterprise_profile(watchlist: dict[str, Any] | None, terms: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    metadata = _watchlist_metadata(watchlist or {})
    return _metadata_enterprise_profile(
        metadata,
        organization_name=str((watchlist or {}).get("organization_name") or ""),
        terms=terms,
    )


def _watchlist_stored_enterprise_profile(watchlist: dict[str, Any] | None) -> dict[str, Any]:
    return _watchlist_enterprise_profile(watchlist, [])


def _is_legacy_code_placeholder(payload: dict[str, Any] | None) -> bool:
    item = payload or {}
    return (
        _normalize_text(item.get("name") or item.get("watchlist_name") or item.get("watchlistName")) == "默认代码监测对象"
        and _normalize_text(item.get("organization_name") or item.get("organizationName")) == "示例企业"
    )


def _code_watchlist_public_identity(
    payload: dict[str, Any] | None,
    terms: list[dict[str, Any]] | None = None,
) -> tuple[str, str]:
    item = payload or {}
    name = _normalize_text(item.get("name") or item.get("watchlist_name") or item.get("watchlistName"))
    organization = _normalize_text(item.get("organization_name") or item.get("organizationName"))
    if not _is_legacy_code_placeholder(item):
        return name, organization
    rows = [row for row in (terms or []) if isinstance(row, dict) and bool(row.get("enabled", True))]
    for term_type in ("company_name", "domain"):
        value = next(
            (
                _normalize_text(row.get("term"))
                for row in rows
                if _normalize_text(row.get("term_type")) == term_type
                and _normalize_text(row.get("term")) not in {"示例企业", "example.com"}
            ),
            "",
        )
        if value:
            return value, value
    fallback_term = next(
        (
            _normalize_text(row.get("term"))
            for row in rows
            if _normalize_text(row.get("term")) not in {"", "示例企业", "example.com"}
        ),
        "",
    )
    if fallback_term:
        return fallback_term, fallback_term
    profile = _watchlist_enterprise_profile(item, rows)
    fallback = next(iter(profile.get("official_names") or profile.get("root_domains") or []), "")
    return (fallback, fallback) if fallback else ("", "")


def _payload_enterprise_profile(payload: dict[str, Any] | None) -> dict[str, Any]:
    profile_payload = ((payload or {}).get("enterprise_profile") or {}) if isinstance(payload, dict) else {}
    return _metadata_enterprise_profile(
        {"enterprise_profile": profile_payload},
        organization_name=str((payload or {}).get("organization_name") or ""),
        terms=[],
    )


def _public_code_watchlist_payload(
    watchlist: dict[str, Any] | None,
    terms: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    item = watchlist or {}
    public_terms = [
        dict(row)
        for row in terms or []
        if _normalize_text(row.get("term")) not in {"", "示例企业", "example.com"}
    ]
    public_name, public_organization = _code_watchlist_public_identity(item, public_terms)
    metadata = _watchlist_metadata(item)
    public_row = {key: value for key, value in item.items() if key != "metadata_json"}
    profile_source = {
        **item,
        "name": public_name,
        "organization_name": public_organization,
    }
    enterprise_profile = _watchlist_stored_enterprise_profile(profile_source)
    derived_terms = _derived_search_terms_from_profile(enterprise_profile)
    derived_keys = {_normalize_text(row.get("term")).casefold() for row in derived_terms}
    supplemental_terms = [
        row
        for row in public_terms
        if _normalize_text(row.get("term")).casefold() not in derived_keys
    ]
    return {
        **public_row,
        "name": public_name,
        "organization_name": public_organization,
        "terms": supplemental_terms,
        "derived_terms": derived_terms,
        "platforms": _normalize_string_list(metadata.get("platforms"), fallback=DEFAULT_CODE_PLATFORMS),
        "file_extensions": _normalize_code_file_extensions(metadata.get("file_extensions")),
        "search_page_limit": _normalize_search_page_limit(metadata.get("search_page_limit")),
        "max_results_per_term": _normalize_result_budget(metadata.get("max_results_per_term")),
        "detail_fetch": bool(metadata.get("detail_fetch", True)),
        "enabled_rule_keys": _normalize_string_list(metadata.get("enabled_rule_keys"), fallback=DEFAULT_RULE_KEYS),
        "enterprise_profile": enterprise_profile,
    }


def _enterprise_profile_enabled(profile: dict[str, Any] | None) -> bool:
    if not isinstance(profile, dict):
        return False
    return any(bool(profile.get(key)) for key in DEFAULT_ENTERPRISE_PROFILE)


def _normalize_search_page_limit(value: Any) -> int:
    try:
        limit = DEFAULT_SEARCH_PAGE_LIMIT if value is None or value == "" else int(value)
    except (TypeError, ValueError):
        limit = DEFAULT_SEARCH_PAGE_LIMIT
    if limit <= 0:
        return 0
    return min(limit, UNLIMITED_SEARCH_PAGE_SAFETY_CAP)


def _normalize_result_budget(value: Any) -> int:
    try:
        limit = DEFAULT_MAX_RESULTS_PER_TERM if value is None or value == "" else int(value)
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_RESULTS_PER_TERM
    return max(0, limit)


def _code_output_root() -> Path:
    path = output_root() / "code_monitoring"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _watchlist_output_root(watchlist_name: str) -> Path:
    return _code_output_root() / safe_stem(watchlist_name, "watchlist")


def _query_output_dir(watchlist_name: str, platform_key: str, term: str) -> Path:
    base = _watchlist_output_root(watchlist_name) / safe_stem(platform_key, "platform") / safe_stem(term, "term")
    base.mkdir(parents=True, exist_ok=True)
    return base


def _snapshot_file_stem(value: str | None) -> str:
    stem = safe_stem(value, "code-hit")
    if len(stem) <= 80:
        return stem
    digest = sha1(stem.encode("utf-8", errors="ignore")).hexdigest()[:10]
    prefix = stem[:69].rstrip("._-") or "code-hit"
    return f"{prefix}-{digest}"


def _public_output_url(path: Path) -> str:
    base = output_root().resolve()
    try:
        relative = path.resolve().relative_to(base)
    except ValueError:
        return path.resolve().as_uri()
    return f"/collector-output/{relative.as_posix()}"


def _load_storage_state_path(platform_key: str) -> str | None:
    rows = {row["platform"]: row for row in build_platform_session_payloads(module="code_monitoring")}
    row = rows.get(platform_key)
    if not row or not row.get("configured"):
        return None
    raw_path = str(row.get("storage_state_path") or "").strip()
    if raw_path and Path(raw_path).exists():
        return raw_path
    path = platform_storage_state_path(platform_key)
    return str(path) if path.exists() else None


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.anchors: list[dict[str, str]] = []
        self._in_script = False
        self._current_href = ""
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._in_script = True
            return
        if self._in_script:
            return
        if tag == "a":
            attr_map = dict(attrs)
            self._current_href = str(attr_map.get("href") or "")
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"}:
            self._in_script = False
            return
        if self._in_script:
            return
        if tag == "a":
            href = _normalize_text(self._current_href)
            text = _normalize_text("".join(self._current_text))
            if href:
                self.anchors.append({"href": href, "text": text})
            self._current_href = ""
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            return
        text = _normalize_text(data)
        if text and self._current_href:
            self._current_text.append(text)


def _platform_label(platform_key: str) -> str:
    return get_exposure_platform(platform_key).label if platform_key in PLATFORMS else platform_key


def _parse_line_range(fragment: str) -> tuple[int, int]:
    text = str(fragment or "").lstrip("#")
    match = re.search(r"L(\d+)(?:-L?(\d+))?", text, re.IGNORECASE)
    if not match:
        return 0, 0
    start = int(match.group(1))
    end = int(match.group(2) or start)
    return start, end


def _parse_code_location(platform_key: str, absolute_url: str) -> dict[str, Any] | None:
    parsed = urlparse(absolute_url)
    path = parsed.path.strip("/")
    if not path:
        return None
    if platform_key == "github":
        parts = path.split("/")
        if len(parts) < 5 or parts[2] != "blob":
            return None
        owner, repo, _, branch = parts[:4]
        file_path = "/".join(parts[4:])
        line_start, line_end = _parse_line_range(parsed.fragment)
        return {
            "repository_owner": owner,
            "repository_name": repo,
            "repository_url": f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
            "branch": branch,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
        }
    if platform_key == "gitee":
        parts = path.split("/")
        if len(parts) < 5 or parts[2] != "blob":
            return None
        owner, repo, _, branch = parts[:4]
        file_path = "/".join(parts[4:])
        line_start, line_end = _parse_line_range(parsed.fragment)
        return {
            "repository_owner": owner,
            "repository_name": repo,
            "repository_url": f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}",
            "branch": branch,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
        }
    if platform_key == "gitlab":
        if "/-/blob/" not in path:
            return None
        repo_path, blob_path = path.split("/-/blob/", 1)
        repo_parts = [part for part in repo_path.split("/") if part]
        blob_parts = [part for part in blob_path.split("/") if part]
        if len(repo_parts) < 2 or len(blob_parts) < 2:
            return None
        line_start, line_end = _parse_line_range(parsed.fragment)
        return {
            "repository_owner": "/".join(repo_parts[:-1]),
            "repository_name": repo_parts[-1],
            "repository_url": f"{parsed.scheme}://{parsed.netloc}/{repo_path}",
            "branch": blob_parts[0],
            "file_path": "/".join(blob_parts[1:]),
            "line_start": line_start,
            "line_end": line_end,
        }
    return None


def _raw_file_url(platform_key: str, absolute_url: str) -> str:
    parsed = urlparse(absolute_url)
    path = parsed.path.strip("/")
    if platform_key == "github":
        parts = path.split("/")
        if len(parts) >= 5 and parts[2] == "blob":
            owner, repo = parts[0], parts[1]
            branch = parts[3]
            file_path = "/".join(parts[4:])
            return f"{parsed.scheme}://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_path}"
    if platform_key == "gitlab" and "/-/blob/" in path:
        return f"{parsed.scheme}://{parsed.netloc}/{path.replace('/-/blob/', '/-/raw/', 1)}"
    if platform_key == "gitee":
        parts = path.split("/")
        if len(parts) >= 5 and parts[2] == "blob":
            owner, repo = parts[0], parts[1]
            branch = parts[3]
            file_path = "/".join(parts[4:])
            return f"{parsed.scheme}://{parsed.netloc}/{owner}/{repo}/raw/{branch}/{file_path}"
    return absolute_url


def _language_from_path(file_path: str) -> str:
    suffix = Path(file_path or "").suffix.lower()
    mapping = {
        ".py": "Python",
        ".js": "JavaScript",
        ".ts": "TypeScript",
        ".java": "Java",
        ".go": "Go",
        ".rb": "Ruby",
        ".php": "PHP",
        ".sh": "Shell",
        ".yaml": "YAML",
        ".yml": "YAML",
        ".json": "JSON",
        ".env": "ENV",
        ".properties": "Properties",
        ".ini": "INI",
        ".conf": "Config",
    }
    return mapping.get(suffix, suffix.lstrip(".").upper())


def _matches_extension(file_path: str, extensions: list[str]) -> bool:
    if not extensions:
        return True
    file_name = Path(file_path or "").name.lower()
    suffix = Path(file_path or "").suffix.lower().lstrip(".")
    if not suffix and file_name.startswith(".env"):
        suffix = "env"
    return bool(suffix and suffix in {item.lower().lstrip(".") for item in extensions})


def _repo_fallback_extensions(extensions: list[str]) -> list[str]:
    normalized = []
    seen: set[str] = set()
    for item in [*(extensions or []), *DEFAULT_FILE_EXTENSIONS, *REPO_FALLBACK_FILE_EXTENSIONS]:
        value = _normalize_text(item).lower().lstrip(".")
        if value and value not in seen:
            seen.add(value)
            normalized.append(value)
    return normalized


def _candidate_priority(candidate: dict[str, Any], enabled_rule_keys: list[str]) -> int:
    file_path = str(candidate.get("filePath") or "").lower()
    snippet_text = str(candidate.get("snippetText") or "")
    hint_score = int(candidate.get("riskScoreHint") or 0)
    query_priority_hint = int(candidate.get("queryPriorityHint") or 0)
    novelty_hint = int(candidate.get("noveltyHint") or 0)
    score = 0
    if file_path.endswith(".env") or "/.env" in file_path:
        score += 80
    elif file_path.endswith((".yaml", ".yml", ".ini", ".conf", ".properties")):
        score += 45
    elif file_path.endswith((".json", ".py", ".js", ".ts", ".java")):
        score += 20
    findings = _collect_findings(snippet_text, enabled_rule_keys)
    score += len(findings) * 120
    if snippet_text:
        lowered = snippet_text.lower()
        for marker in ("password", "secret", "token", "redis://", "db_host", "aws_secret_access_key", "jwt"):
            if marker in lowered:
                score += 25
    return max(score, hint_score) + query_priority_hint + novelty_hint


def _file_path_priority(file_path: str) -> int:
    lowered = str(file_path or "").lower()
    score = 0
    if lowered.endswith(".env") or "/.env" in lowered:
        score += 90
    elif lowered.endswith((".yaml", ".yml", ".ini", ".conf", ".properties", ".toml", ".json", ".xml")):
        score += 50
    elif lowered.endswith((".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh")):
        score += 20
    for marker in ("secret", "token", "password", "credential", "config", "setting", "redis", "jwt", "db", "auth", "prod"):
        if marker in lowered:
            score += 12
    return score


def _search_url(platform_key: str, term: str) -> str:
    template = SEARCH_URL_TEMPLATES.get(platform_key)
    if not template:
        raise ValueError(f"search URL template not configured for platform: {platform_key}")
    return template.format(query=quote_plus(term))


def _search_markers(enabled_rule_keys: list[str]) -> list[str]:
    marker_map = {
        "api_key": "api key",
        "token": "token",
        "ak_sk": "secret key",
        "db_url": "database",
        "jwt_secret": "jwt",
        "redis_url": "redis",
        "private_key": "private key",
        "internal_url": "internal url",
        "password": "password",
    }
    markers = []
    seen: set[str] = set()
    for key in enabled_rule_keys:
        marker = marker_map.get(str(key or "").strip())
        if marker and marker not in seen:
            seen.add(marker)
            markers.append(marker)
    return markers


def _expanded_search_queries(term: str, enabled_rule_keys: list[str]) -> list[str]:
    normalized = _normalize_text(term)
    if not normalized:
        return []
    queries: list[str] = []
    seen: set[str] = set()

    def add_query(value: str) -> None:
        text = _normalize_text(value)
        if text and text not in seen:
            seen.add(text)
            queries.append(text)

    domain_like = "." in normalized and " " not in normalized
    if domain_like:
        add_query(f"@{normalized.lower()}")
    for marker in _search_markers(enabled_rule_keys)[:4]:
        add_query(f"{normalized} {marker}")
        if domain_like:
            add_query(f"@{normalized.lower()} {marker}")
    return queries[:8]


def _expanded_search_queries_for_platform(
    platform_key: str,
    term: str,
    enabled_rule_keys: list[str],
) -> list[str]:
    queries = _expanded_search_queries(term, enabled_rule_keys)
    if platform_key != "github" or not _github_api_enabled():
        return queries
    normalized = _normalize_text(term)
    domain_query = f"@{normalized.lower()}" if "." in normalized and " " not in normalized else ""
    return [domain_query] if domain_query and domain_query in queries else []


def _query_priority_bonus(query: str, term: str) -> int:
    normalized_query = _normalize_text(query).lower()
    normalized_term = _normalize_text(term).lower()
    bonus = 0
    if normalized_query.startswith("@"):
        bonus += 45
    if normalized_term and normalized_query != normalized_term:
        bonus += 20
    for marker in ("token", "password", "secret", "jwt", "redis", "database", "private key"):
        if marker in normalized_query:
            bonus += 12
    return bonus


def _effective_search_page_limit(search_page_limit: int) -> int:
    return UNLIMITED_SEARCH_PAGE_SAFETY_CAP if int(search_page_limit or 0) <= 0 else int(search_page_limit)


def _gitee_widget_max_pages() -> int:
    return max(1, (GITEE_WIDGET_MAX_OFFSET // GITEE_WIDGET_PAGE_SIZE) + 1)


def _candidate_evaluation_limit(max_results_per_term: int, search_page_limit: int) -> int | None:
    base = int(max_results_per_term or 0)
    pages = _effective_search_page_limit(search_page_limit)
    if base <= 0:
        return None
    return min(200, max(12, base * pages * 4))


def _search_page_url(platform_key: str, search_url: str, page: int) -> str:
    if page <= 1:
        return search_url
    parsed = urlparse(search_url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if platform_key == "github":
        query["p"] = str(page)
    elif platform_key == "gitlab":
        query["page"] = str(page)
    elif platform_key == "gitee":
        query["page"] = str(page)
    else:
        return search_url
    return urlunparse(parsed._replace(query=urlencode(query)))


def _candidate_identity(candidate: dict[str, Any]) -> str:
    repository_url = str(candidate.get("repositoryUrl") or "").strip().rstrip("/")
    branch = str(candidate.get("branch") or "").strip()
    file_path = str(candidate.get("filePath") or "").strip().lstrip("/")
    if repository_url and file_path:
        return "|".join([repository_url, branch, file_path])
    file_url = str(candidate.get("fileUrl") or "").strip()
    parsed = urlparse(file_url)
    return urlunparse(parsed._replace(query="", fragment="")) if file_url else ""


def _candidate_signature(candidates: list[dict[str, Any]]) -> str:
    payload = [_candidate_identity(item) for item in candidates if _candidate_identity(item)]
    return sha1(_json_dumps(payload).encode("utf-8")).hexdigest() if payload else ""


def _candidate_keys(candidates: list[dict[str, Any]], limit: int = 200) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        key = _candidate_identity(item)
        if key and key not in seen:
            seen.add(key)
            rows.append(key)
        if len(rows) >= limit:
            break
    return rows


def _candidate_keys_json(candidates: list[dict[str, Any]], limit: int = 200) -> str:
    return _json_dumps(_candidate_keys(candidates, limit=limit))


def _repository_urls(candidates: list[dict[str, Any]], limit: int = 200) -> list[str]:
    payload: list[str] = []
    seen: set[str] = set()
    for item in candidates:
        repo_url = str(item.get("repositoryUrl") or "").strip()
        if repo_url and repo_url not in seen:
            seen.add(repo_url)
            payload.append(repo_url)
        if len(payload) >= limit:
            break
    return payload


def _repository_urls_json(candidates: list[dict[str, Any]], limit: int = 200) -> str:
    return _json_dumps(_repository_urls(candidates, limit=limit))


def _load_json_string_list(value: Any) -> list[str]:
    rows = _parse_json(value, [])
    return [str(item).strip() for item in rows if str(item).strip()] if isinstance(rows, list) else []


def _merge_string_lists(current: list[str], previous: list[str], limit: int = 200) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for item in [*(current or []), *(previous or [])]:
        text = _normalize_text(item)
        if text and text not in seen:
            seen.add(text)
            rows.append(text)
        if len(rows) >= limit:
            break
    return rows


def _search_state_query_key(term: str, query: str) -> str:
    normalized_term = _normalize_text(term).lower()
    normalized_query = _normalize_text(query).lower()
    if not normalized_query or normalized_query == normalized_term:
        return "base"
    digest = sha1(normalized_query.encode("utf-8")).hexdigest()[:16]
    return f"query:{digest}"


def _state_string_union(states: list[dict[str, Any]], field_name: str, limit: int = 200) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for state in states:
        for item in _load_json_string_list((state or {}).get(field_name)):
            if item and item not in seen:
                seen.add(item)
                rows.append(item)
            if len(rows) >= limit:
                return rows
    return rows


def _persist_search_state(
    watchlist_id: int,
    platform_key: str,
    term: str,
    query_key: str,
    next_search_state: dict[str, Any] | None,
    started_at: str,
) -> None:
    if not next_search_state:
        return
    now = _now_utc_iso()
    def write_state(connection):
        upsert_code_search_state(
            connection,
            {
                "watchlist_id": int(watchlist_id),
                "platform": platform_key,
                "term": term,
                "query_key": query_key,
                "last_page_scanned": int(next_search_state.get("last_page_scanned") or 0),
                "last_candidate_signature": next_search_state.get("last_candidate_signature") or "",
                "last_candidate_keys_json": next_search_state.get("last_candidate_keys_json") or "[]",
                "last_repository_urls_json": next_search_state.get("last_repository_urls_json") or "[]",
                "last_run_started_at": started_at,
                "last_run_finished_at": now,
                "updated_at": now,
            },
        )

    _commit_db_write(write_state)


def _apply_incremental_hints(
    candidates: list[dict[str, Any]],
    *,
    previous_candidate_keys: list[str],
    previous_repository_urls: list[str],
    new_page_bonus: int = 60,
) -> list[dict[str, Any]]:
    previous_key_set = set(previous_candidate_keys)
    previous_repo_set = set(previous_repository_urls)
    rows: list[dict[str, Any]] = []
    for item in candidates:
        key = _candidate_identity(item)
        repo_url = str(item.get("repositoryUrl") or "").strip()
        novelty = new_page_bonus
        if key and key not in previous_key_set:
            novelty += 30
        if repo_url and repo_url not in previous_repo_set:
            novelty += 20
        rows.append({**item, "noveltyHint": novelty})
    return rows


def _parse_code_search_results(platform: ExposurePlatform, html: str, requested_url: str) -> list[dict[str, Any]]:
    parser = _AnchorParser()
    parser.feed(html)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in parser.anchors:
        absolute = urljoin(requested_url, item["href"])
        location = _parse_code_location(platform.key, absolute)
        if location is not None:
            dedupe_key = f"{platform.key}|{location['repository_url']}|{location['branch']}|{location['file_path']}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            results.append(
                {
                    "platform": platform.key,
                    "platformLabel": platform.label,
                    "fileUrl": absolute,
                    "title": _normalize_text(item.get("text")) or location["file_path"] or absolute,
                    "repositoryOwner": location["repository_owner"],
                    "repositoryName": location["repository_name"],
                    "repositoryUrl": location["repository_url"],
                    "branch": location["branch"],
                    "filePath": location["file_path"],
                    "lineStart": location["line_start"],
                    "lineEnd": location["line_end"],
                }
            )
            continue
        if platform.key == "gitlab":
            parsed = urlparse(absolute)
            path = parsed.path.strip("/")
            parts = [part for part in path.split("/") if part]
            excluded_roots = {"projects", "groups", "dashboard", "help", "users", "explore", "admin", "-"}
            if (
                len(parts) >= 2
                and parts[0] not in excluded_roots
                and "/users/" not in absolute
                and "/search?" not in absolute
                and "/-/" not in absolute
            ):
                repo_owner = "/".join(parts[:-1])
                repo_name = parts[-1]
                dedupe_key = f"gitlab-project|{repo_owner}|{repo_name}"
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                results.append(
                    {
                        "platform": platform.key,
                        "platformLabel": platform.label,
                        "fileUrl": absolute,
                        "title": _normalize_text(item.get("text")) or repo_name,
                        "repositoryOwner": repo_owner,
                        "repositoryName": repo_name,
                        "repositoryUrl": f"{parsed.scheme}://{parsed.netloc}/{'/'.join(parts)}",
                        "branch": "",
                        "filePath": "",
                        "lineStart": 0,
                        "lineEnd": 0,
                    }
                )
    return results


def _build_gitlab_project_code_search_url(repository_url: str, term: str) -> str:
    base = repository_url.rstrip("/")
    return f"{base}/-/search?search={quote_plus(term)}&nav_source=navbar&project_id=&scope=blobs&search_code=true"


def _cookie_header_from_storage_state(storage_state_path: str | None, domain_fragment: str) -> str:
    if not storage_state_path:
        return ""
    path = Path(storage_state_path)
    if not path.exists():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    cookies = []
    for item in payload.get("cookies", []):
        domain = str(item.get("domain") or "")
        if domain_fragment in domain and item.get("name") and item.get("value"):
            cookies.append(f"{item['name']}={item['value']}")
    return "; ".join(cookies)


def _exception_chain_messages(exc: Exception) -> list[str]:
    messages: list[str] = []
    seen: set[int] = set()
    current: Exception | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        text = _normalize_text(current)
        if text:
            messages.append(text)
        reason = getattr(current, "reason", None)
        if isinstance(reason, Exception) and id(reason) not in seen:
            current = reason
            continue
        cause = getattr(current, "__cause__", None)
        if isinstance(cause, Exception) and id(cause) not in seen:
            current = cause
            continue
        context = getattr(current, "__context__", None)
        if isinstance(context, Exception) and id(context) not in seen:
            current = context
            continue
        current = None
    return messages


def _is_ssl_transport_error(exc: Exception) -> bool:
    if isinstance(exc, ssl.SSLError):
        return True
    lowered = " | ".join(_exception_chain_messages(exc)).lower()
    markers = (
        "ssl:",
        "unexpected eof while reading",
        "eof occurred in violation of protocol",
        "tlsv1",
        "wrong version number",
        "decryption failed or bad record mac",
        "sslv3",
        "certificate verify failed",
    )
    return any(marker in lowered for marker in markers)


def _has_search_challenge_text(text: str, current_url: str = "") -> bool:
    lowered = f"{text}\n{current_url}".lower()
    return any(marker.lower() in lowered for marker in SEARCH_CHALLENGE_MARKERS)


def _read_http_text(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int = 60,
    platform_key: str = "",
    retries: int = 1,
) -> tuple[str, str]:
    attempts = max(1, retries + 1)
    last_exc: Exception | None = None
    for attempt in range(attempts):
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310
                text = response.read().decode("utf-8", errors="replace")
                current_url = ""
                try:
                    current_url = str(response.geturl() or url)
                except Exception:
                    current_url = url
                return text, current_url
        except Exception as exc:
            last_exc = exc
            if _is_ssl_transport_error(exc) and attempt + 1 < attempts:
                continue
            if _is_ssl_transport_error(exc):
                raise RuntimeError("ssl_transport_error") from exc
            raise
    if last_exc is not None:
        raise last_exc
    return "", url


def _http_get_json(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int = 60,
    platform_key: str = "",
    retries: int = 1,
) -> Any:
    text, current_url = _read_http_text(
        url,
        headers=headers,
        timeout=timeout,
        platform_key=platform_key,
        retries=retries,
    )
    if platform_key == "gitee" and _has_search_challenge_text(text, current_url):
        raise RuntimeError("captcha_or_security_verification")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if platform_key == "gitee" and ("<html" in text.lower() or _has_search_challenge_text(text, current_url)):
            raise RuntimeError("captcha_or_security_verification") from exc
        raise


def _http_get_html(
    url: str,
    *,
    headers: dict[str, str],
    timeout: int = 60,
    platform_key: str = "",
    retries: int = 1,
) -> str:
    text, _ = _read_http_text(
        url,
        headers=headers,
        timeout=timeout,
        platform_key=platform_key,
        retries=retries,
    )
    return text


def _search_request_headers(platform_key: str, storage_state_path: str | None) -> dict[str, str]:
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    domain_fragment = {
        "github": "github.com",
        "gitlab": "gitlab.com",
        "gitee": "gitee.com",
    }.get(platform_key, "")
    if domain_fragment:
        cookie_header = _cookie_header_from_storage_state(storage_state_path, domain_fragment)
        if cookie_header:
            headers["Cookie"] = cookie_header
    referer = {
        "github": "https://github.com/search",
        "gitlab": "https://gitlab.com/search",
        "gitee": "https://search.gitee.com/",
    }.get(platform_key)
    if referer:
        headers["Referer"] = referer
    return headers


def _is_gitlab_repository_url(repository_url: Any) -> bool:
    parsed = urlparse(str(repository_url or "").strip())
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() != "gitlab.com":
        return False
    return len([part for part in parsed.path.strip("/").split("/") if part]) >= 2


def _gitlab_project_blob_search(repository_url: str, term: str, storage_state_path: str | None) -> list[dict[str, Any]]:
    if not _is_gitlab_repository_url(repository_url):
        return []
    parsed = urlparse(repository_url)
    repo_path = parsed.path.strip("/")
    parts = [part for part in repo_path.split("/") if part]
    if len(parts) < 2:
        return []
    cookie_header = _cookie_header_from_storage_state(storage_state_path, "gitlab.com")
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
    }
    if cookie_header:
        headers["Cookie"] = cookie_header
    encoded_project = quote_plus(repo_path)
    api_url = f"https://gitlab.com/api/v4/projects/{encoded_project}/search?scope=blobs&search={quote_plus(term)}"
    rows = _http_get_json(api_url, headers=headers, timeout=60, platform_key="gitlab", retries=1)
    if not isinstance(rows, list):
        return []
    repository_owner = "/".join(parts[:-1])
    repository_name = parts[-1]
    results: list[dict[str, Any]] = []
    for row in rows:
        file_path = _normalize_text(row.get("path"))
        ref = _normalize_text(row.get("ref")) or "main"
        start_line = int(row.get("startline") or 0)
        if not file_path:
            continue
        file_url = f"{parsed.scheme}://{parsed.netloc}/{repo_path}/-/blob/{ref}/{file_path}"
        if start_line:
            file_url = f"{file_url}#L{start_line}"
        results.append(
            {
                "platform": "gitlab",
                "platformLabel": "GitLab",
                "fileUrl": file_url,
                "title": _normalize_text(row.get("filename") or file_path),
                "repositoryOwner": repository_owner,
                "repositoryName": repository_name,
                "repositoryUrl": f"{parsed.scheme}://{parsed.netloc}/{repo_path}",
                "branch": ref,
                "filePath": file_path,
                "lineStart": start_line,
                "lineEnd": start_line,
                "snippetText": str(row.get("data") or ""),
            }
        )
    return results


def _gitlab_repo_search(term: str, page_limit: int = 1) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in range(1, max(1, page_limit) + 1):
        url = f"https://gitlab.com/api/v4/projects?search={quote_plus(term)}&simple=true&per_page=10&order_by=last_activity_at&sort=desc&page={page}"
        rows = _http_get_json(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/json",
            },
            timeout=60,
            platform_key="gitlab",
            retries=1,
        )
        if not isinstance(rows, list) or not rows:
            break
        new_count = 0
        for item in rows:
            repo_url = _normalize_text(item.get("web_url"))
            path_with_namespace = _normalize_text(item.get("path_with_namespace"))
            if not repo_url or not path_with_namespace or "/" not in path_with_namespace or repo_url in seen:
                continue
            seen.add(repo_url)
            parts = path_with_namespace.split("/")
            results.append(
                {
                    "platform": "gitlab",
                    "platformLabel": "GitLab",
                    "repositoryOwner": "/".join(parts[:-1]),
                    "repositoryName": parts[-1],
                    "repositoryUrl": repo_url,
                }
            )
            new_count += 1
        if new_count == 0:
            break
    return results


def _gitlab_repo_fallback_code_search(
    term: str,
    storage_state_path: str | None,
    extensions: list[str],
    max_results: int,
    page_limit: int = 1,
) -> list[dict[str, Any]]:
    repos = _gitlab_repo_search(term, page_limit=page_limit)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    first_issue = ""
    effective_max = max_results if max_results > 0 else 60
    for repo in repos[: min(10, effective_max)]:
        try:
            nested_candidates = _gitlab_project_blob_search(repo["repositoryUrl"], term, storage_state_path)
        except Exception as exc:
            if not first_issue:
                first_issue = str(exc)
            continue
        for item in nested_candidates:
            file_path = str(item.get("filePath") or "")
            key = f"{item.get('repositoryUrl')}|{item.get('branch')}|{file_path}"
            if key in seen or not _matches_extension(file_path, extensions):
                continue
            seen.add(key)
            results.append(item)
            if len(results) >= effective_max:
                return results
    if not results and first_issue:
        raise RuntimeError(first_issue)
    return results


def _github_repo_search(term: str, page_limit: int = 1) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for page in range(1, max(1, page_limit) + 1):
        url = f"https://api.github.com/search/repositories?q={quote_plus(term)}&per_page=8&page={page}"
        payload = _http_get_json(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/vnd.github+json",
            },
            timeout=60,
        )
        items = (payload or {}).get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list) or not items:
            break
        new_count = 0
        for item in items:
            repo_url = _normalize_text(item.get("html_url"))
            owner = _normalize_text(((item.get("owner") or {}) if isinstance(item.get("owner"), dict) else {}).get("login"))
            repo_name = _normalize_text(item.get("name"))
            default_branch = _normalize_text(item.get("default_branch")) or "main"
            if not repo_url or not owner or not repo_name or repo_url in seen:
                continue
            seen.add(repo_url)
            results.append(
                {
                    "platform": "github",
                    "platformLabel": "GitHub",
                    "repositoryOwner": owner,
                    "repositoryName": repo_name,
                    "repositoryUrl": repo_url,
                    "branch": default_branch,
                }
            )
            new_count += 1
        if new_count == 0:
            break
    return results


def _github_repo_default_branch(owner: str, repo: str) -> str:
    url = f"https://api.github.com/repos/{quote_plus(owner)}/{quote_plus(repo)}"
    payload = _http_get_json(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/vnd.github+json",
        },
        timeout=60,
    )
    if not isinstance(payload, dict):
        return "main"
    return _normalize_text(payload.get("default_branch")) or "main"


def _github_repo_tree(owner: str, repo: str, branch: str) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{quote_plus(owner)}/{quote_plus(repo)}/git/trees/{quote_plus(branch)}?recursive=1"
    payload = _http_get_json(
        url,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/vnd.github+json",
        },
        timeout=60,
    )
    tree = (payload or {}).get("tree") if isinstance(payload, dict) else None
    return tree if isinstance(tree, list) else []


def _http_get_text(url: str, *, headers: dict[str, str], timeout: int = 60) -> str:
    text, _ = _read_http_text(url, headers=headers, timeout=timeout, retries=1)
    return text


def _github_blob_content(owner: str, repo: str, branch: str, file_path: str) -> str:
    encoded_path = "/".join(quote_plus(part) for part in str(file_path or "").split("/"))
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{encoded_path}"
    try:
        return _http_get_text(
            url,
            headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "text/plain",
            },
            timeout=45,
        )
    except Exception:
        return ""


def _github_repo_fallback_code_search(
    term: str,
    extensions: list[str],
    enabled_rule_keys: list[str],
    max_results: int,
    page_limit: int = 1,
) -> list[dict[str, Any]]:
    repos = _github_repo_search(term, page_limit=page_limit)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    fallback_extensions = _repo_fallback_extensions(extensions)
    effective_max = max_results if max_results > 0 else 60
    repo_cap = effective_max if effective_max > 0 else len(repos)
    for repo in repos[: min(10, repo_cap)]:
        owner = _normalize_text(repo.get("repositoryOwner"))
        repo_name = _normalize_text(repo.get("repositoryName"))
        repo_url = _normalize_text(repo.get("repositoryUrl"))
        if not owner or not repo_name or not repo_url:
            continue
        branch = _normalize_text(repo.get("branch")) or _github_repo_default_branch(owner, repo_name)
        try:
            tree = _github_repo_tree(owner, repo_name, branch)
        except Exception:
            continue
        candidate_paths = []
        for item in tree:
            file_path = _normalize_text(item.get("path"))
            if item.get("type") != "blob" or not _matches_extension(file_path, fallback_extensions):
                continue
            candidate_paths.append((_file_path_priority(file_path), file_path))
        candidate_paths.sort(key=lambda row: (row[0], row[1]), reverse=True)
        for _, file_path in candidate_paths[:30]:
            key = f"{repo_url}|{branch}|{file_path}"
            if key in seen:
                continue
            code_text = _github_blob_content(owner, repo_name, branch, file_path)
            if not code_text:
                continue
            classification = _classify_code_hit(
                term,
                file_path,
                code_text,
                enabled_rule_keys,
                context_metadata={"repositoryOwner": owner, "repositoryName": repo_name, "repositoryUrl": repo_url},
            )
            if not classification:
                continue
            candidate = {
                "platform": "github",
                "platformLabel": "GitHub",
                "fileUrl": f"https://github.com/{owner}/{repo_name}/blob/{branch}/{file_path}",
                "title": file_path,
                "repositoryOwner": owner,
                "repositoryName": repo_name,
                "repositoryUrl": repo_url,
                "branch": branch,
                "filePath": file_path,
                "lineStart": 0,
                "lineEnd": 0,
                "snippetText": code_text[:1200],
                "resultLayerHint": classification["result_layer"],
                "riskScoreHint": classification["risk_score"],
                "severityHint": classification["severity"],
            }
            seen.add(key)
            results.append(candidate)
            if len(results) >= effective_max:
                return results
    return results


def _collect_gitee_repo_search_window(
    term: str,
    *,
    start_page: int = 1,
    page_count: int = 1,
    initial_seen: set[str] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set(initial_seen or set())
    size = GITEE_WIDGET_PAGE_SIZE
    max_pages = _gitee_widget_max_pages()
    first_page = max(1, int(start_page or 1))
    total_pages = max(1, int(page_count or 1))
    if first_page > max_pages:
        return [], max_pages
    last_page_scanned = first_page - 1
    for page in range(first_page, min(max_pages, first_page + total_pages - 1) + 1):
        from_offset = (page - 1) * size
        url = f"{GITEE_WIDGET_API_BASE}/search/widget/{GITEE_REPO_SEARCH_WIDGET}?q={quote_plus(term)}&from={from_offset}&size={size}"
        try:
            rows = _http_get_json(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "application/json",
                    "Referer": "https://search.gitee.com/",
                },
                timeout=60,
                platform_key="gitee",
                retries=1,
            )
        except Exception:
            if page == first_page and not results:
                raise
            break
        last_page_scanned = page
        hits = (((rows or {}).get("hits") or {}).get("hits") or []) if isinstance(rows, dict) else []
        if not hits:
            break
        new_count = 0
        for item in hits:
            fields = item.get("fields") or {}
            repo_url = _normalize_text((fields.get("url") or [""])[0])
            title = _normalize_text((fields.get("title") or [""])[0])
            path_name = _normalize_text((fields.get("path") or [""])[0])
            owner_path = _normalize_text((fields.get("owner.path.keyword") or [""])[0])
            if not repo_url or not owner_path or not path_name or repo_url in seen:
                continue
            seen.add(repo_url)
            results.append(
                {
                    "platform": "gitee",
                    "platformLabel": "Gitee",
                    "fileUrl": repo_url,
                    "title": title or path_name,
                    "repositoryOwner": owner_path,
                    "repositoryName": path_name,
                    "repositoryUrl": repo_url,
                    "branch": "",
                    "filePath": "",
                    "lineStart": 0,
                    "lineEnd": 0,
                    "snippetText": _normalize_text((fields.get("description") or [""])[0]),
                }
            )
            new_count += 1
        if new_count == 0:
            continue
    return results, last_page_scanned


def _gitee_repo_search(term: str, page_limit: int = 1) -> list[dict[str, Any]]:
    results, _ = _collect_gitee_repo_search_window(term, start_page=1, page_count=page_limit)
    return results


def _gitee_repo_default_branch(owner: str, repo: str) -> str:
    url = f"https://gitee.com/api/v5/repos/{owner}/{repo}"
    payload = _http_get_json(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, timeout=60, platform_key="gitee", retries=1)
    if not isinstance(payload, dict):
        return "master"
    return _normalize_text(payload.get("default_branch")) or "master"


def _gitee_repo_tree(owner: str, repo: str, branch: str) -> list[dict[str, Any]]:
    url = f"https://gitee.com/api/v5/repos/{owner}/{repo}/git/trees/{quote_plus(branch)}?recursive=1"
    payload = _http_get_json(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, timeout=60, platform_key="gitee", retries=1)
    if not isinstance(payload, dict):
        return []
    tree = payload.get("tree") or []
    return tree if isinstance(tree, list) else []


def _gitee_blob_content(owner: str, repo: str, branch: str, file_path: str) -> str:
    encoded_path = "/".join(quote_plus(part) for part in file_path.split("/"))
    url = f"https://gitee.com/api/v5/repos/{owner}/{repo}/contents/{encoded_path}?ref={quote_plus(branch)}"
    payload = _http_get_json(url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}, timeout=60, platform_key="gitee", retries=1)
    if isinstance(payload, dict):
        if payload.get("type") == "file" and payload.get("encoding") == "base64" and payload.get("content"):
            try:
                return base64.b64decode(str(payload["content"])).decode("utf-8", errors="replace")
            except Exception:
                return ""
    return ""


def _gitee_repo_candidates_to_code_results(
    repo_candidates: list[dict[str, Any]],
    term: str,
    extensions: list[str],
    enabled_rule_keys: list[str],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    first_issue = ""
    for repo_candidate in repo_candidates:
        owner = _normalize_text(repo_candidate.get("repositoryOwner"))
        repo = _normalize_text(repo_candidate.get("repositoryName"))
        repo_url = _normalize_text(repo_candidate.get("repositoryUrl"))
        if not owner or not repo or not repo_url:
            continue
        try:
            branch = _gitee_repo_default_branch(owner, repo)
            tree = _gitee_repo_tree(owner, repo, branch)
        except Exception as exc:
            if not first_issue:
                first_issue = str(exc)
            continue
        for item in tree:
            file_path = _normalize_text(item.get("path"))
            if item.get("type") != "blob" or not _matches_extension(file_path, extensions):
                continue
            dedupe_key = f"{repo_url}|{branch}|{file_path}"
            if dedupe_key in seen:
                continue
            try:
                code_text = _gitee_blob_content(owner, repo, branch, file_path)
            except Exception as exc:
                if not first_issue:
                    first_issue = str(exc)
                code_text = ""
            if not code_text:
                continue
            classification = _classify_code_hit(
                term,
                file_path,
                code_text,
                enabled_rule_keys,
                context_metadata={"repositoryOwner": owner, "repositoryName": repo, "repositoryUrl": repo_url},
            )
            if not classification:
                continue
            seen.add(dedupe_key)
            file_url = f"https://gitee.com/{owner}/{repo}/blob/{branch}/{file_path}"
            results.append(
                {
                    "platform": "gitee",
                    "platformLabel": "Gitee",
                    "fileUrl": file_url,
                    "title": file_path,
                    "repositoryOwner": owner,
                    "repositoryName": repo,
                    "repositoryUrl": repo_url,
                    "branch": branch,
                    "filePath": file_path,
                    "lineStart": 0,
                    "lineEnd": 0,
                    "snippetText": code_text[:1200],
                    "resultLayerHint": classification["result_layer"],
                    "riskScoreHint": classification["risk_score"],
                    "severityHint": classification["severity"],
                }
            )
    if not results and first_issue:
        raise RuntimeError(first_issue)
    results.sort(key=lambda item: _candidate_priority(item, enabled_rule_keys), reverse=True)
    return results


def _gitee_repo_code_search_incremental(
    term: str,
    extensions: list[str],
    enabled_rule_keys: list[str],
    *,
    page_limit: int,
    previous_state: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    effective_limit = min(_effective_search_page_limit(page_limit), _gitee_widget_max_pages())
    state = previous_state or {}
    previous_signature = _normalize_text(state.get("last_candidate_signature"))
    previous_last_page = int(state.get("last_page_scanned") or 0)
    previous_candidate_keys = _load_json_string_list(state.get("last_candidate_keys_json"))
    previous_repository_urls = _load_json_string_list(state.get("last_repository_urls_json"))

    first_repo_rows, _ = _collect_gitee_repo_search_window(term, start_page=1, page_count=1)
    first_signature = _candidate_signature(first_repo_rows)
    signature_changed = not previous_signature or previous_signature != first_signature
    if signature_changed or previous_last_page <= 0:
        cursor_mode = "full"
        repo_candidates = list(first_repo_rows)
        last_page_scanned = 1 if first_repo_rows else 0
        if effective_limit > 1:
            more_repo_rows, last_page_scanned = _collect_gitee_repo_search_window(
                term,
                start_page=2,
                page_count=effective_limit - 1,
                initial_seen={_candidate_identity(item) for item in first_repo_rows if _candidate_identity(item)},
            )
            repo_candidates.extend(more_repo_rows)
    else:
        cursor_mode = "incremental"
        repo_candidates, last_page_scanned = _collect_gitee_repo_search_window(
            term,
            start_page=max(2, previous_last_page + 1),
            page_count=effective_limit,
        )

    results = _gitee_repo_candidates_to_code_results(repo_candidates, term, extensions, enabled_rule_keys)
    current_candidate_keys = _candidate_keys(results)
    current_repository_urls = _repository_urls(results)
    if cursor_mode == "incremental" and not signature_changed:
        current_candidate_keys = _merge_string_lists(current_candidate_keys, previous_candidate_keys)
        current_repository_urls = _merge_string_lists(current_repository_urls, previous_repository_urls)
    next_state = {
        "last_page_scanned": max(last_page_scanned, 1 if first_repo_rows else 0),
        "last_candidate_signature": first_signature,
        "last_candidate_keys_json": _json_dumps(current_candidate_keys),
        "last_repository_urls_json": _json_dumps(current_repository_urls),
        "cursor_mode": cursor_mode,
        "signature_changed": signature_changed,
    }
    return results, next_state


def _gitee_repo_code_search(term: str, extensions: list[str], enabled_rule_keys: list[str], page_limit: int = 1) -> list[dict[str, Any]]:
    repo_candidates = _gitee_repo_search(term, page_limit=page_limit)
    return _gitee_repo_candidates_to_code_results(repo_candidates, term, extensions, enabled_rule_keys)


def _detect_code_search_issue(platform: ExposurePlatform, html: str, page_url: str, page_title: str) -> str:
    lowered = f"{html}\n{page_url}\n{page_title}".lower()
    challenge_signals = _has_search_challenge_text(html, f"{page_url}\n{page_title}")
    if challenge_signals:
        return f"{platform.key}:captcha_or_security_verification"
    if "/users/sign_in" in lowered or "just a moment" in lowered or "cf-challenge" in lowered:
        return f"{platform.key}:login_or_challenge_required"
    if any(token.lower() in lowered for token in platform.login_indicators) or "sign in" in lowered:
        return f"{platform.key}:login_required"
    if "too many requests" in lowered or "rate limit" in lowered:
        return f"{platform.key}:rate_limited"
    return ""


def _extract_embedded_raw_lines(html: str) -> list[str]:
    text = str(html or "")
    decoder = json.JSONDecoder()
    scanned: set[str] = set()
    for candidate_text in (text, unescape(text)):
        if not candidate_text or candidate_text in scanned:
            continue
        scanned.add(candidate_text)
        for match in re.finditer(r'"rawLines"\s*:\s*', candidate_text):
            try:
                value, _ = decoder.raw_decode(candidate_text[match.end():])
            except json.JSONDecodeError:
                continue
            if not isinstance(value, list):
                continue
            rows = [str(item).rstrip() for item in value if str(item).strip()]
            if rows:
                return rows
    return []


def _extract_code_text(html: str) -> str:
    embedded_lines = _extract_embedded_raw_lines(html)
    if embedded_lines:
        return "\n".join(embedded_lines)
    selectors = [
        r"<div[^>]*id=\"LC\d+\"[^>]*>(.*?)</div>",
        r"<td[^>]*class=\"[^\"]*(?:blob-code|code-content|line_content)[^\"]*\"[^>]*>(.*?)</td>",
        r"<span[^>]*id=\"LC\d+\"[^>]*>(.*?)</span>",
        r"<pre[^>]*>(.*?)</pre>",
        r"<code[^>]*>(.*?)</code>",
    ]
    for pattern in selectors:
        chunks = re.findall(pattern, html, flags=re.IGNORECASE | re.DOTALL)
        cleaned = [_strip_html(chunk) for chunk in chunks if _strip_html(chunk)]
        if cleaned:
            return "\n".join(cleaned)
    return _strip_html(html)


def _extract_code_lines(html: str) -> list[tuple[int, str]]:
    line_patterns = [
        r"<div[^>]*id=\"LC(\d+)\"[^>]*>(.*?)</div>",
        r"<td[^>]*data-line-number=\"(\d+)\"[^>]*>.*?</td>\s*<td[^>]*class=\"[^\"]*(?:blob-code|code-content|line_content)[^\"]*\"[^>]*>(.*?)</td>",
    ]
    for pattern in line_patterns:
        matches = re.findall(pattern, html, flags=re.IGNORECASE | re.DOTALL)
        rows: list[tuple[int, str]] = []
        for line_no, chunk in matches:
            cleaned = _strip_html(chunk)
            if cleaned:
                rows.append((int(line_no), cleaned))
        if rows:
            return rows
    embedded_lines = _extract_embedded_raw_lines(html)
    if embedded_lines:
        return [(index + 1, line) for index, line in enumerate(embedded_lines) if line.strip()]
    code_text = _extract_code_text(html)
    if not code_text:
        return []
    return [(index + 1, line) for index, line in enumerate(code_text.splitlines()) if line.strip()]


def _read_text_file(path_value: Any) -> str:
    raw_path = str(path_value or "").strip()
    if not raw_path:
        return ""
    path = Path(raw_path)
    if not path.exists() or not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _payload_candidate_snippet(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    candidate = payload.get("candidate")
    if not isinstance(candidate, dict):
        return ""
    for key in ("snippetText", "codeText", "text"):
        text = str(candidate.get(key) or "")
        if _normalize_text(text):
            return text
    return ""


def _snapshot_analysis_text(latest_snapshot: dict[str, Any], raw_payload: dict[str, Any]) -> str:
    raw_payload = raw_payload if isinstance(raw_payload, dict) else {}
    latest_snapshot = latest_snapshot if isinstance(latest_snapshot, dict) else {}
    source_texts = [str(raw_payload.get("code_text") or "")]
    artifact_payload = _parse_json(_read_text_file(latest_snapshot.get("rawArtifactPath") or latest_snapshot.get("raw_artifact_path")), {})
    if isinstance(artifact_payload, dict):
        source_texts.extend(
            [
                str(artifact_payload.get("code_text") or ""),
                _payload_candidate_snippet(artifact_payload),
                str(artifact_payload.get("code_fragment") or ""),
            ]
        )
    source_texts.extend(
        [
            _payload_candidate_snippet(raw_payload),
            str(raw_payload.get("code_fragment") or ""),
            str(latest_snapshot.get("codeFragment") or latest_snapshot.get("code_fragment") or ""),
            str(raw_payload.get("masked_fragment") or ""),
            str(latest_snapshot.get("maskedFragment") or latest_snapshot.get("masked_fragment") or ""),
        ]
    )
    for code_text in source_texts:
        if _normalize_text(code_text):
            return code_text
    return ""


def _build_code_lines_from_text(code_text: str) -> list[tuple[int, str]]:
    return [(index + 1, line.rstrip()) for index, line in enumerate(str(code_text or "").splitlines()) if line.strip()]


def _load_snapshot_code_lines(latest_snapshot: dict[str, Any], raw_payload: dict[str, Any]) -> list[tuple[int, str]]:
    html_text = _read_text_file(latest_snapshot.get("htmlPath"))
    code_lines = _extract_code_lines(html_text) if html_text else []
    if code_lines:
        return code_lines
    code_text = _snapshot_analysis_text(latest_snapshot, raw_payload)
    if _normalize_text(code_text):
        return _build_code_lines_from_text(code_text)
    return []


def _line_window(code_lines: list[tuple[int, str]], start_line: int, end_line: int, *, before: int = 1, after: int = 1) -> tuple[str, int, int]:
    if not code_lines:
        return "", 0, 0
    indexes = [index for index, (line_no, _) in enumerate(code_lines) if start_line <= line_no <= max(start_line, end_line)]
    if not indexes:
        return "", 0, 0
    start_index = max(0, min(indexes) - before)
    end_index = min(len(code_lines), max(indexes) + after + 1)
    return (
        "\n".join(text for _, text in code_lines[start_index:end_index]),
        code_lines[start_index][0],
        code_lines[end_index - 1][0],
    )


def _mask_preview_text(text: str, findings: list[dict[str, Any]] | None) -> str:
    masked = str(text or "")
    for finding in findings or []:
        value = str(finding.get("value") or "")
        if value:
            masked = masked.replace(value, _mask_value(value))
    return masked


def _normalize_findings_payload(value: Any) -> list[dict[str, Any]]:
    rows = _parse_json(value, [])
    if not isinstance(rows, list):
        return []
    return [item for item in rows if isinstance(item, dict)]


def _line_match_score(line_text: str, probe: str) -> int:
    normalized_line = re.sub(r"\s+", "", str(line_text or "")).lower()
    normalized_probe = re.sub(r"\s+", "", str(probe or "")).lower()
    if not normalized_line or not normalized_probe:
        return 0
    if normalized_probe in normalized_line:
        return len(normalized_probe)
    tokens = [token for token in re.split(r"[^a-z0-9_.@:/-]+", normalized_probe) if token]
    if not tokens:
        return 0
    return sum(len(token) for token in tokens if token in normalized_line)


def _find_finding_line_window(code_lines: list[tuple[int, str]], findings: list[dict[str, Any]], *, before: int = 8, after: int = 18) -> tuple[str, int, int]:
    if not code_lines or not findings:
        return "", 0, 0
    best_index = -1
    best_score = 0
    for finding in findings:
        probes = [str(finding.get("value") or "").strip(), str(finding.get("excerpt") or "").strip()]
        for index, (_, line_text) in enumerate(code_lines):
            score = max(_line_match_score(line_text, probe) for probe in probes if probe)
            if score > best_score:
                best_score = score
                best_index = index
    if best_index < 0:
        return "", 0, 0
    start_index = max(0, best_index - before)
    end_index = min(len(code_lines), best_index + after + 1)
    return (
        "\n".join(text for _, text in code_lines[start_index:end_index]),
        code_lines[start_index][0],
        code_lines[end_index - 1][0],
    )


def _rebuild_code_preview(matched_term: str, latest_snapshot: dict[str, Any], raw_payload: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    code_lines = _load_snapshot_code_lines(latest_snapshot, raw_payload)
    lowered_term = _normalize_text(matched_term).lower()
    snippet = ""
    if code_lines:
        snippet, _, _ = _find_finding_line_window(code_lines, findings, before=8, after=18)
        line_start = int(latest_snapshot.get("lineStart") or 0)
        line_end = int(latest_snapshot.get("lineEnd") or line_start)
        if line_start and not snippet:
            snippet, _, _ = _line_window(code_lines, line_start, line_end, before=1, after=1)
        if lowered_term and (not snippet or lowered_term not in snippet.lower()):
            for index, (line_no, line_text) in enumerate(code_lines):
                if lowered_term not in line_text.lower():
                    continue
                start_index = max(0, index - 6)
                end_index = min(len(code_lines), index + 10)
                snippet = "\n".join(text for _, text in code_lines[start_index:end_index])
                break
    if snippet:
        return _mask_preview_text(snippet, findings)
    return str(latest_snapshot.get("maskedFragment") or latest_snapshot.get("codeFragment") or "")


def _extract_matched_term_contexts(term: str, row: dict[str, Any], latest_snapshot: dict[str, Any], raw_payload: dict[str, Any]) -> list[dict[str, Any]]:
    normalized_term = _normalize_text(term)
    if not normalized_term:
        return []
    lowered_term = normalized_term.lower()
    contexts: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_context(kind: str, label: str, text: str, *, line_start: int = 0, line_end: int = 0) -> None:
        lines = [part.rstrip() for part in str(text or "").splitlines()]
        display_text = "\n".join(lines).strip() if kind == "code" else _normalize_text(text)
        if not display_text:
            return
        key = f"{kind}|{label}|{line_start}|{line_end}|{display_text}"
        if key in seen:
            return
        seen.add(key)
        contexts.append(
            {
                "kind": kind,
                "label": label,
                "text": display_text,
                "lineStart": int(line_start or 0),
                "lineEnd": int(line_end or 0),
            }
        )

    candidate = raw_payload.get("candidate") if isinstance(raw_payload, dict) else {}
    candidate = candidate if isinstance(candidate, dict) else {}
    code_lines = _load_snapshot_code_lines(latest_snapshot, raw_payload)

    if code_lines:
        line_start = int(latest_snapshot.get("lineStart") or 0)
        line_end = int(latest_snapshot.get("lineEnd") or line_start)
        if line_start:
            window_text, context_start, context_end = _line_window(code_lines, line_start, line_end, before=1, after=1)
            if window_text and lowered_term in window_text.lower():
                add_context("code", "代码上下文", window_text, line_start=context_start, line_end=context_end)
        code_matches = 0
        for index, (_, line) in enumerate(code_lines):
            if lowered_term not in line.lower():
                continue
            start_index = max(0, index - 1)
            end_index = min(len(code_lines), index + 2)
            add_context(
                "code",
                "代码上下文",
                "\n".join(text for _, text in code_lines[start_index:end_index]),
                line_start=code_lines[start_index][0],
                line_end=code_lines[end_index - 1][0],
            )
            code_matches += 1
            if code_matches >= 3:
                break

    repository_full_name = "/".join(
        part for part in [row.get("repository_owner") or "", row.get("repository_name") or ""] if part
    )
    if lowered_term in repository_full_name.lower():
        add_context("repository", "仓库名", repository_full_name)
    if lowered_term in str(row.get("repository_url") or "").lower():
        add_context("repository_url", "仓库地址", str(row.get("repository_url") or ""))
    if lowered_term in str(row.get("file_path") or "").lower():
        add_context("file", "文件路径", str(row.get("file_path") or ""))
    if lowered_term in str(row.get("file_url") or "").lower():
        add_context("file_url", "文件地址", str(row.get("file_url") or ""))
    if lowered_term in str(candidate.get("title") or "").lower():
        add_context("title", "结果标题", str(candidate.get("title") or ""))

    return contexts


def _term_matches_context(term: str, candidate: dict[str, Any], code_text: str) -> bool:
    lowered = term.lower()
    haystack = " ".join(
        [
            str(candidate.get("repositoryOwner") or ""),
            str(candidate.get("repositoryName") or ""),
            str(candidate.get("filePath") or ""),
            str(candidate.get("title") or ""),
            code_text[:6000],
        ]
    ).lower()
    return lowered in haystack


def _contains_text_anchor(haystack: str, anchor: str) -> bool:
    lowered_haystack = str(haystack or "").lower()
    lowered_anchor = _normalize_text(anchor).lower()
    if not lowered_haystack or not lowered_anchor:
        return False
    if re.search(r"[a-z0-9]", lowered_anchor) and re.fullmatch(r"[a-z0-9_.-]+", lowered_anchor):
        pattern = rf"(?<![a-z0-9]){re.escape(lowered_anchor)}(?![a-z0-9])"
        return bool(re.search(pattern, lowered_haystack))
    return lowered_anchor in lowered_haystack


def _find_domain_anchor_matches(text: str, root_domain: str) -> list[dict[str, str]]:
    lowered_text = str(text or "").lower()
    normalized_domain = _normalize_domain_value(root_domain)
    if not lowered_text or not normalized_domain:
        return []
    rows: list[dict[str, str]] = []
    root_pattern = re.compile(rf"(?<![a-z0-9.-]){re.escape(normalized_domain)}(?![a-z0-9.-])")
    email_pattern = re.compile(rf"@[a-z0-9._%+-]+@?{re.escape(normalized_domain)}(?![a-z0-9.-])")
    subdomain_pattern = re.compile(rf"(?<![a-z0-9.-])([a-z0-9-]+\.)+{re.escape(normalized_domain)}(?![a-z0-9.-])")
    for match in root_pattern.finditer(lowered_text):
        rows.append({"type": "root_domain", "label": "企业主域名", "value": match.group(0)})
        break
    for match in email_pattern.finditer(lowered_text):
        rows.append({"type": "email_domain", "label": "企业邮箱域名", "value": match.group(0).lstrip("@")})
        break
    for match in subdomain_pattern.finditer(lowered_text):
        value = match.group(0)
        if value != normalized_domain:
            rows.append({"type": "subdomain", "label": "企业子域名", "value": value})
            break
    return rows


def _find_pattern_anchor_match(text: str, pattern: str) -> dict[str, str] | None:
    lowered_text = str(text or "").lower()
    normalized = _normalize_text(pattern).lower()
    if not lowered_text or not normalized.startswith("*."):
        return None
    base = _normalize_domain_value(normalized)
    if not base:
        return None
    compiled = re.compile(rf"(?<![a-z0-9.-])([a-z0-9-]+\.)+{re.escape(base)}(?![a-z0-9.-])")
    match = compiled.search(lowered_text)
    if not match:
        return None
    return {"type": "subdomain", "label": "企业子域名", "value": match.group(0)}


def _detect_system_keywords(text: str, profile: dict[str, Any]) -> list[str]:
    lowered_text = str(text or "").lower()
    rows: list[str] = []
    for keyword in profile.get("internal_system_keywords") or []:
        normalized = _normalize_text(keyword).lower()
        if normalized and normalized in lowered_text and normalized not in rows:
            rows.append(normalized)
    return rows


def _is_negative_alias(alias: str, profile: dict[str, Any]) -> bool:
    lowered_alias = _normalize_text(alias).lower()
    return lowered_alias in {item.lower() for item in profile.get("negative_aliases") or []}


def _enterprise_match_level(anchors: list[dict[str, str]], system_keywords: list[str]) -> str:
    anchor_types = {item.get("type") for item in anchors}
    if anchor_types & {"official_name", "root_domain", "email_domain", "subdomain"}:
        return "strong"
    if anchor_types & {"brand_alias", "english_alias"}:
        return "alias"
    if anchor_types & {"weak_alias"} and system_keywords:
        return "weak"
    return "none"


def _evaluate_enterprise_match(
    profile: dict[str, Any],
    term: str,
    candidate: dict[str, Any],
    code_text: str,
) -> dict[str, Any]:
    texts = [
        str(candidate.get("repositoryOwner") or ""),
        str(candidate.get("repositoryName") or ""),
        str(candidate.get("repositoryUrl") or ""),
        str(candidate.get("filePath") or ""),
        str(candidate.get("fileUrl") or ""),
        str(candidate.get("title") or ""),
        str(code_text or "")[:12000],
    ]
    combined = "\n".join(texts)
    anchors: list[dict[str, str]] = []
    seen: set[str] = set()

    def add_anchor(anchor_type: str, label: str, value: str) -> None:
        normalized_value = _normalize_text(value)
        if not normalized_value:
            return
        key = f"{anchor_type}|{normalized_value.lower()}"
        if key in seen:
            return
        seen.add(key)
        anchors.append({"type": anchor_type, "label": label, "value": normalized_value})

    for official_name in profile.get("official_names") or []:
        if _contains_text_anchor(combined, official_name):
            add_anchor("official_name", "企业全称", official_name)

    for domain in profile.get("root_domains") or []:
        for item in _find_domain_anchor_matches(combined, domain):
            add_anchor(str(item.get("type") or "root_domain"), str(item.get("label") or "企业域名"), str(item.get("value") or domain))

    for pattern in profile.get("trusted_subdomain_patterns") or []:
        match = _find_pattern_anchor_match(combined, pattern)
        if match:
            add_anchor(str(match.get("type") or "subdomain"), str(match.get("label") or "企业子域名"), str(match.get("value") or ""))

    guarded_aliases = {item.lower() for item in profile.get("short_alias_guard") or []}
    for alias in profile.get("brand_aliases") or []:
        if _is_negative_alias(alias, profile) or not _contains_text_anchor(combined, alias):
            continue
        anchor_type = "weak_alias" if alias.lower() in guarded_aliases or len(re.sub(r"[^a-z0-9]", "", alias.lower())) <= 4 else "brand_alias"
        add_anchor(anchor_type, "品牌别名", alias)

    for alias in profile.get("english_aliases") or []:
        if _is_negative_alias(alias, profile) or not _contains_text_anchor(combined, alias):
            continue
        anchor_type = "weak_alias" if alias.lower() in guarded_aliases or len(re.sub(r"[^a-z0-9]", "", alias.lower())) <= 4 else "english_alias"
        add_anchor(anchor_type, "英文别名", alias)

    system_keywords = _detect_system_keywords(combined, profile)
    level = _enterprise_match_level(anchors, system_keywords)
    return {
        "valid": level != "none",
        "level": level,
        "anchors": anchors,
        "system_keywords": system_keywords,
        "term": _normalize_text(term),
    }


def _collect_findings(code_text: str, enabled_rule_keys: list[str]) -> list[dict[str, Any]]:
    enabled = [SENSITIVE_RULE_MAP[key] for key in enabled_rule_keys if key in SENSITIVE_RULE_MAP]
    findings: list[dict[str, Any]] = []
    for rule in enabled:
        for match in rule.pattern.finditer(code_text):
            value = match.group(0)
            findings.append(
                {
                    "ruleKey": rule.key,
                    "label": rule.label,
                    "secretLike": rule.secret_like,
                    "weight": rule.weight,
                    "start": match.start(),
                    "end": match.end(),
                    "value": value,
                    "excerpt": _normalize_text(value)[:220],
                }
            )
            if len(findings) >= 12:
                return findings
    return findings


def _mask_value(value: str) -> str:
    text = str(value or "")
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}***{text[-4:]}"


def _extract_snippet(code_text: str, findings: list[dict[str, Any]]) -> str:
    if not code_text:
        return ""
    if not findings:
        return code_text[:800]
    start = max(0, int(findings[0]["start"]) - 260)
    end = min(len(code_text), int(findings[0]["end"]) + 260)
    return code_text[start:end]


def _mask_snippet(snippet: str, findings: list[dict[str, Any]]) -> str:
    masked = str(snippet or "")
    for finding in findings:
        value = str(finding.get("value") or "")
        if value:
            masked = masked.replace(value, _mask_value(value), 1)
    return masked


def _normalize_code_suffix(file_path: str) -> str:
    file_name = Path(file_path or "").name.lower()
    suffix = Path(file_path or "").suffix.lower()
    if not suffix and file_name.startswith(".env"):
        return ".env"
    return suffix


def _looks_literal_secret(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if "-----begin" in lowered and "private key-----" in lowered:
        return True
    if "://" in text:
        return True
    if re.search(r"[:=]\s*['\"][A-Za-z0-9_./+\-=:@]{16,}", text):
        return True
    if re.search(r"[:=]\s*['\"][^'\"]{6,}['\"]", text):
        return True
    rhs_match = re.search(r"[:=]\s*([^\s].*)$", text)
    rhs = rhs_match.group(1).strip().rstrip(",") if rhs_match else text
    if "(" in rhs or ")" in rhs:
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", rhs):
        return False
    if re.fullmatch(r"[A-Za-z0-9_./+\-=:@]{16,}", rhs):
        return True
    return False


def _finding_signal_score(finding: dict[str, Any]) -> int:
    rule_weight = int(finding.get("weight") or 0)
    value = str(finding.get("value") or "")
    if _looks_literal_secret(value):
        return rule_weight + 16
    if "(" in value or ")" in value:
        return max(8, int(rule_weight * 0.45))
    return int(rule_weight * 0.7)


def _file_exposure_bonus(file_path: str) -> int:
    suffix = _normalize_code_suffix(file_path)
    if suffix == ".env":
        return 16
    if suffix in {".yaml", ".yml", ".ini", ".conf", ".properties"}:
        return 12
    if suffix == ".json":
        return 8
    if suffix in {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh"}:
        return 5
    return 2


def _severity_from_score(score: int) -> str:
    if score >= 58:
        return "high"
    if score >= 32:
        return "medium"
    return "low"


def _file_exposure_label(file_path: str) -> str:
    suffix = _normalize_code_suffix(file_path)
    if suffix == ".env":
        return "环境变量文件"
    if suffix in {".yaml", ".yml", ".ini", ".conf", ".properties"}:
        return "配置文件"
    if suffix == ".json":
        return "结构化配置文件"
    if suffix in {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh"}:
        return "源码文件"
    return "普通文本"


def _collect_clue_markers(term: str, code_text: str) -> list[str]:
    lowered = str(code_text or "").lower()
    markers: list[str] = []
    seen: set[str] = set()
    for marker, _score in CLUE_MARKERS:
        if marker in lowered and marker not in seen:
            seen.add(marker)
            markers.append(marker)
    normalized_term = _normalize_text(term).lower()
    if "." in normalized_term and f"@{normalized_term}" in lowered and f"@{normalized_term}" not in seen:
        markers.append(f"@{normalized_term}")
    return markers


def _term_type_bonus(term_type: str) -> int:
    normalized = _normalize_text(term_type)
    if normalized == "domain":
        return 12
    if normalized in {"project", "product"}:
        return 8
    if normalized == "company_name":
        return 4
    return 0


def _is_demo_or_mock_context(file_path: str, code_text: str) -> bool:
    lowered = "\n".join([str(file_path or ""), str(code_text or "")[:12000]]).lower()
    markers = (
        "seed",
        "demo",
        "mock",
        "sample",
        "example",
        "faker",
        "fixture",
        "finetune/data",
        "training/data",
        "password123",
        "hashedpassword",
        "create users",
        "create materials",
        "localhost",
        "127.0.0.1",
    )
    return any(marker in lowered for marker in markers)


def _is_documentation_context(file_path: str, code_text: str) -> bool:
    lowered_path = str(file_path or "").lower()
    lowered = "\n".join([lowered_path, str(code_text or "")[:8000].lower()])
    markers = (
        "readme",
        "/docs/",
        "doc/",
        "tutorial",
        "guide",
        "example",
        "quickstart",
        "usage:",
    )
    return lowered_path.endswith((".md", ".rst", ".adoc")) or any(marker in lowered for marker in markers)


def _is_auth_flow_context(file_path: str, code_text: str) -> bool:
    lowered = "\n".join([str(file_path or ""), str(code_text or "")[:12000]]).lower()
    markers = (
        "authenticate_user",
        "create_access_token",
        "www-authenticate",
        "incorrect username or password",
        "user_input",
        "conf_password",
        "form_data.password",
        "password = user_input",
        "token = access_token",
        "login(",
        "async_step_user",
    )
    return any(marker in lowered for marker in markers)


def _is_hashed_secret_context(code_text: str) -> bool:
    lowered = str(code_text or "").lower()
    markers = (
        "hashedpassword",
        "hashed_password",
        "bcrypt.hash",
        "get_password_hash",
        "password_hash(",
        "sha256(",
        "argon2",
    )
    return any(marker in lowered for marker in markers)


def _is_local_default_config_context(code_text: str, findings: list[dict[str, Any]]) -> bool:
    lowered = str(code_text or "").lower()
    markers = (
        "localhost",
        "127.0.0.1",
        "redis://localhost",
        "redis://127.0.0.1",
        "jdbc:postgresql://localhost",
        "mysql://localhost",
    )
    if any(marker in lowered for marker in markers):
        return True
    return _is_local_db_connection(findings)


def _is_log_or_comment_context(code_text: str) -> bool:
    lowered = str(code_text or "").lower()
    markers = (
        "traceback",
        "exception",
        "logger.",
        "console.error",
        "console.log",
        "incorrect username or password",
        "token expired",
    )
    return any(marker in lowered for marker in markers)


def _is_public_api_example_context(code_text: str) -> bool:
    lowered = str(code_text or "").lower()
    markers = (
        "get_api_key(",
        "_get_api_key",
        "os.getenv",
        "process.env",
        "dotenv",
        "api key from env",
        "示例token",
        "example token",
        "replace with real token",
        "需要替换为真实的token",
        "注册获取",
        "replace it with your own token",
    )
    return any(marker in lowered for marker in markers)


def _is_local_db_connection(findings: list[dict[str, Any]]) -> bool:
    for finding in findings:
        value = str(finding.get("value") or "").lower()
        if "localhost" in value or "127.0.0.1" in value:
            return True
    return False


def _is_public_market_context(file_path: str, code_text: str) -> bool:
    lowered = "\n".join([str(file_path or ""), str(code_text or "")[:12000]]).lower()
    chinese_markers = (
        "行情", "证券", "研报", "年报", "年度报告", "收盘价", "净利润", "主力资金", "股票", "a股", "新能源", "市值",
    )
    english_markers = (
        r"\bticker\b",
        r"\bsymbol\b",
        r"\bstock\b",
        r"\bstocks\b",
        r"\bmarket data\b",
        r"\ba-share\b",
        r"\ba shares\b",
        r"\bmarketcap\b",
        r"\brealtime\b",
        r"\bkline\b",
        r"\bnews\b",
        r"\bfinance\b",
        r"\bashare\b",
        r"\ba-share monitor\b",
        r"\bannual report\b",
        r"\binvestor relations\b",
        r"\btushare\b",
        r"\bpro_api\b",
    )
    signal_count = sum(1 for marker in chinese_markers if marker in lowered)
    signal_count += sum(1 for marker in english_markers if re.search(marker, lowered))
    ticker_code_match = re.search(r"\b300750\b|\b\d{6}\.(?:sz|ss|hk)\b", lowered)
    return bool(ticker_code_match) or signal_count >= 2


def _is_contact_directory_context(file_path: str, code_text: str) -> bool:
    lowered = "\n".join([str(file_path or ""), str(code_text or "")[:12000]]).lower()
    email_hits = re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", lowered)
    phone_like_hits = re.findall(r"(?:\+?\d[\d\s-]{7,}\d)", lowered)
    directory_markers = (
        "suppliercontact",
        "contact",
        "phone",
        "email",
        "vendor",
        "employee",
        "department",
    )
    return (
        len(email_hits) >= 2
        or (email_hits and phone_like_hits)
    ) and any(marker in lowered for marker in directory_markers)


def _is_domain_inventory_context(file_path: str, code_text: str) -> bool:
    lowered_path = str(file_path or "").lower()
    lowered = str(code_text or "").lower()[:16000]
    path_markers = (
        "domain-list",
        "domainlist",
        "domains",
        "site/",
        "sites/",
        "ioc",
        "indicator",
        "allowlist",
        "blocklist",
        "whitelist",
        "blacklist",
    )
    domain_hits = re.findall(r"\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b", lowered)
    unique_domains = {item for item in domain_hits if "." in item}
    quoted_domain_lines = 0
    for raw_line in lowered.splitlines()[:200]:
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r'["\']?[a-z0-9][a-z0-9.-]*\.[a-z]{2,}["\']?\s*,?', line):
            quoted_domain_lines += 1
    has_list_shape = quoted_domain_lines >= 3 or (
        len(unique_domains) >= 4
        and len(unique_domains) >= max(3, int(len(lowered.splitlines()[:120]) * 0.08))
    )
    structured_suffix = lowered_path.endswith((".json", ".txt", ".csv", ".yml", ".yaml"))
    return has_list_shape and (structured_suffix or any(marker in lowered_path for marker in path_markers))


def _is_reference_catalog_context(file_path: str, code_text: str) -> bool:
    lowered_path = str(file_path or "").lower()
    lowered = str(code_text or "").lower()[:16000]
    structured_suffix = lowered_path.endswith((".json", ".txt", ".csv", ".js", ".ts", ".py", ".yml", ".yaml"))

    location_signals = 0
    for marker in ("place_id", "lat :", "lat:", "lng :", "lng:", "location : {", "location: {", "google . maps", "google.maps", "poi"):
        if marker in lowered:
            location_signals += 1

    bank_signals = 0
    for marker in ("bankcard", "cardbin", "bankbin", "unionpay", "借记卡", "贷记卡", "银行卡", "银行"):
        if marker in lowered_path or marker in lowered:
            bank_signals += 1
    if re.search(r'"\d{6}"\s*:\s*"', lowered) or re.search(r"\[\s*['\"]\d{6}['\"]\s*,", lowered):
        bank_signals += 2
    if re.search(r"\bcode\s*:\s*['\"]", lowered) and re.search(r"\bname\s*:\s*['\"]", lowered):
        bank_signals += 1

    company_directory_signals = 0
    for marker in ("glassdoor.com", "/salary/", "@@", "company salaries", "salary/"):
        if marker in lowered:
            company_directory_signals += 1
    unique_domains = {item for item in re.findall(r"\b[a-z0-9][a-z0-9.-]*\.[a-z]{2,}\b", lowered) if "." in item}
    if len(unique_domains) >= 3:
        company_directory_signals += 1

    keyword_corpus_signals = 0
    for marker in ("tags = [", "keywords = [", "keyword = [", "synonyms = [", "aliases = [", "alias = ["):
        if marker in lowered:
            keyword_corpus_signals += 1

    structured_entry_lines = 0
    nested_string_array_lines = 0
    for raw_line in lowered.splitlines()[:160]:
        line = raw_line.strip()
        if not line:
            continue
        if re.fullmatch(r'["\'].*["\']\s*,?', line):
            structured_entry_lines += 1
        elif re.fullmatch(r"\[\s*['\"].*['\"].*\]\s*,?", line):
            structured_entry_lines += 1
        elif re.search(r'["\']?\d{4,}["\']?\s*:\s*["\']', line):
            structured_entry_lines += 1
        elif re.search(r"\b(?:code|name|title|place_id)\s*:", line):
            structured_entry_lines += 1
        if re.fullmatch(r"\[\s*['\"].*['\"](?:\s*,\s*['\"].*['\"])*\s*\]\s*,?", line):
            nested_string_array_lines += 1

    if structured_suffix and location_signals >= 2:
        return True
    if structured_suffix and bank_signals >= 2 and structured_entry_lines >= 2:
        return True
    if structured_suffix and company_directory_signals >= 2:
        return True
    if structured_suffix and keyword_corpus_signals >= 1 and nested_string_array_lines >= 3:
        return True
    if structured_suffix and structured_entry_lines >= 4 and ("banks" in lowered_path or "bank" in lowered_path or "locations" in lowered_path):
        return True
    public_corpus_markers = (
        "public/data/",
        "benchmark/data/",
        "dataset/",
        "datasets/",
        "pdf_docs/",
        "basic_info.txt",
        "careers-audit",
        "career-data",
        "salary-data",
        "annual-report",
        "annual_report",
        "年度报告",
        "年报",
    )
    if any(marker in lowered_path or marker in lowered for marker in public_corpus_markers):
        return True
    if lowered_path.startswith("reports/") and lowered_path.endswith((".json", ".yml", ".yaml", ".txt")):
        return True
    if lowered_path.endswith(("evidence.json", "evidence.yml", "evidence.yaml")):
        return True
    return False


def _detect_system_access_signals(code_text: str, enterprise_match: dict[str, Any]) -> list[str]:
    del enterprise_match
    lowered = str(code_text or "").lower()
    rows: list[str] = []
    access_markers = {
        "zapi.login": "login-call",
        "login(": "login-call",
        "authenticate(": "authenticate-call",
        "api_token": "api-token-usage",
        "requests.post": "http-client-call",
        "session.": "session-usage",
        "connect(": "connect-call",
        "jdbc:": "database-connection",
        "redis://": "redis-connection",
        "zabbixapi": "zabbix-client",
    }
    for marker, label in access_markers.items():
        if marker in lowered and label not in rows:
            rows.append(label)
    return rows


def _promotion_reason_payload(
    enterprise_match: dict[str, Any],
    findings: list[dict[str, Any]],
    *,
    credential_literal_detected: bool,
    system_access_signals: list[str],
    demo_or_mock: bool,
    public_market: bool,
    contact_directory: bool,
    domain_inventory: bool,
    reference_catalog: bool,
    auth_flow: bool,
    documentation: bool,
    hashed_secret: bool,
    local_default: bool,
    public_api_example: bool,
    log_or_comment: bool,
) -> list[str]:
    reasons: list[str] = []
    anchor_labels = [item.get("label") for item in enterprise_match.get("anchors") or [] if item.get("label")]
    if anchor_labels:
        reasons.append(f"企业锚点：{' / '.join(anchor_labels[:4])}")
    if credential_literal_detected:
        reasons.append("存在硬编码字面量凭据")
    if system_access_signals:
        reasons.append(f"检测到系统访问能力：{' / '.join(system_access_signals[:4])}")
    if demo_or_mock:
        reasons.append("检测到演示/种子/本地化上下文，风险已降权")
    if public_market:
        reasons.append("检测到证券/行情上下文，风险已降权")
    if contact_directory:
        reasons.append("检测到联系人/目录型邮箱上下文，风险已降权")
    if domain_inventory:
        reasons.append("检测到域名清单/站点列表上下文，风险已降权")
    if reference_catalog:
        reasons.append("检测到公开参考数据集/字典上下文，风险已降权")
    if auth_flow:
        reasons.append("检测到认证/登录业务流程上下文，风险已降权")
    if documentation:
        reasons.append("检测到 README/文档/教程上下文，风险已降权")
    if hashed_secret:
        reasons.append("检测到哈希/加密口令上下文，风险已降权")
    if local_default:
        reasons.append("检测到本地默认配置上下文，风险已降权")
    if public_api_example:
        reasons.append("检测到环境变量/API示例上下文，风险已降权")
    if log_or_comment:
        reasons.append("检测到日志/注释型上下文，风险已降权")
    if any(str(item.get("ruleKey") or "") == "db_url" for item in findings) and not _is_local_db_connection(findings):
        reasons.append("检测到非本地数据库连接串")
    return reasons


def _score_clue_hit(
    term: str,
    file_path: str,
    code_text: str,
    term_type: str = "",
    enterprise_match: dict[str, Any] | None = None,
) -> tuple[int, str, list[str]]:
    markers = _collect_clue_markers(term, code_text)
    score = _file_exposure_bonus(file_path)
    score += _term_type_bonus(term_type)
    match_level = str((enterprise_match or {}).get("level") or "none")
    if match_level == "strong":
        score += 18
    elif match_level == "alias":
        score += 10
    elif match_level == "weak":
        score += 4
    if markers:
        score += min(28, sum(next((weight for key, weight in CLUE_MARKERS if key == marker), 10) for marker in markers[:4]))
    lowered_term = _normalize_text(term).lower()
    lowered_code = str(code_text or "").lower()
    if lowered_term and lowered_term in lowered_code:
        score += 12
    if "." in lowered_term and f"@{lowered_term}" in lowered_code:
        score += 12
    if "os.getenv" in lowered_code or "process.env" in lowered_code or "dotenv" in lowered_code:
        score += 8
    if "config" in lowered_code and "password" in lowered_code:
        score += 6
    normalized_term = _normalize_text(term)
    if len(normalized_term) <= 3 and "." not in normalized_term:
        score = max(0, score - 10)
    if enterprise_match is not None and match_level == "none":
        score = 0
    score = min(score, 100)
    severity = _severity_from_score(score)
    return score, severity, markers


def _build_code_clue_reasons(matched_term: str, file_path: str, markers: list[str]) -> list[str]:
    reasons = [f"检索命中词：{matched_term or '-'}"]
    if markers:
        reasons.append(f"命中线索标记：{' / '.join(markers[:5])}")
    reasons.append(f"文件暴露面：{_file_exposure_label(file_path)}")
    reasons.append("当前为线索命中，尚未识别到明确敏感凭据或密钥。")
    return reasons


def _code_result_layer(sensitive_type: str, raw_payload: dict[str, Any] | None = None, persisted_layer: str = "") -> str:
    payload_layer = _normalize_text((raw_payload or {}).get("result_layer"))
    if payload_layer in {"clue", "sensitive"}:
        return payload_layer
    persisted_text = _normalize_text(persisted_layer)
    if persisted_text in {"clue", "sensitive"}:
        return persisted_text
    return "clue" if str(sensitive_type or "").strip() == CODE_CLUE_RULE_KEY else "sensitive"


def _build_code_risk_reasons(matched_term: str, file_path: str, findings: list[dict[str, Any]]) -> list[str]:
    reasons = [f"检索命中词：{matched_term or '-'}"]
    if not findings:
        reasons.append("当前未提取到敏感规则命中。")
        return reasons
    unique_rules = []
    seen_rules: set[str] = set()
    for item in findings:
        rule_key = str(item.get("ruleKey") or "")
        label = str(item.get("label") or rule_key or "未知")
        if rule_key and rule_key not in seen_rules:
            seen_rules.add(rule_key)
            unique_rules.append(label)
    reasons.append(f"发现 {len(findings)} 处命中，涉及 {len(unique_rules)} 类敏感规则。")
    if unique_rules:
        reasons.append(f"敏感类型：{' / '.join(unique_rules[:4])}")
    if any(_looks_literal_secret(str(item.get('value') or '')) for item in findings):
        reasons.append("包含硬编码字面量、连接串或密钥材料，泄露确定性较高。")
    elif any(bool(item.get("secretLike")) for item in findings):
        reasons.append("存在敏感变量或凭据引用，需结合上下文复核是否为真实泄露。")
    reasons.append(f"文件暴露面：{_file_exposure_label(file_path)}")
    return reasons


def _suppression_reason_payload(
    *,
    demo_or_mock: bool,
    public_market: bool,
    contact_directory: bool,
    domain_inventory: bool,
    reference_catalog: bool,
    auth_flow: bool,
    documentation: bool,
    hashed_secret: bool,
    local_default: bool,
    public_api_example: bool,
    log_or_comment: bool,
) -> list[str]:
    reasons: list[str] = []
    if public_market:
        reasons.append("公开证券/行情/金融信息上下文")
    if contact_directory:
        reasons.append("联系人/目录型邮箱上下文")
    if domain_inventory:
        reasons.append("域名清单/站点列表上下文")
    if reference_catalog:
        reasons.append("公开参考数据集/字典上下文")
    if demo_or_mock:
        reasons.append("演示/种子/测试数据上下文")
    if auth_flow:
        reasons.append("认证/登录业务流程上下文")
    if documentation:
        reasons.append("README/文档/教程上下文")
    if hashed_secret:
        reasons.append("哈希/加密口令上下文")
    if local_default:
        reasons.append("本地默认配置上下文")
    if public_api_example:
        reasons.append("公共 API/环境变量示例上下文")
    if log_or_comment:
        reasons.append("日志/报错/注释型上下文")
    return reasons


def _classification_context(
    file_path: str,
    code_text: str,
    context_metadata: dict[str, Any] | None,
) -> tuple[str, str]:
    metadata = context_metadata or {}
    repository_owner = _normalize_text(metadata.get("repositoryOwner") or metadata.get("repository_owner"))
    repository_name = _normalize_text(metadata.get("repositoryName") or metadata.get("repository_name"))
    repository_url = _normalize_text(metadata.get("repositoryUrl") or metadata.get("repository_url"))
    context_path = "/".join(part for part in (repository_owner, repository_name, str(file_path or "")) if part)
    context_text = "\n".join(part for part in (repository_url, str(code_text or "")) if part)
    return context_path, context_text


def _has_primary_sensitive_evidence(
    findings: list[dict[str, Any]],
    *,
    strong_enterprise: bool,
    system_access_detected: bool,
    blocked_public_context: bool,
) -> bool:
    if blocked_public_context:
        return False
    finding_keys = {str(item.get("ruleKey") or "") for item in findings}
    if "private_key" in finding_keys:
        return True
    literal_keys = {
        str(item.get("ruleKey") or "")
        for item in findings
        if _looks_literal_secret(str(item.get("value") or ""))
    }
    if literal_keys & {"api_key", "token", "ak_sk", "db_url", "jwt_secret", "redis_url", "password"}:
        return True
    return bool(strong_enterprise and system_access_detected and finding_keys & {"internal_url"})


def _classify_code_hit(
    term: str,
    file_path: str,
    code_text: str,
    enabled_rule_keys: list[str],
    term_type: str = "",
    enterprise_match: dict[str, Any] | None = None,
    context_metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    enterprise_payload = enterprise_match if enterprise_match is not None else {"valid": True, "level": "none", "anchors": [], "system_keywords": []}
    if not bool(enterprise_payload.get("valid", True)):
        return None
    findings = _collect_findings(code_text, enabled_rule_keys)
    context_path, full_context_text = _classification_context(file_path, code_text, context_metadata)
    risk_context_text = _extract_snippet(code_text, findings) if findings else full_context_text
    credential_literal_detected = any(_looks_literal_secret(str(item.get("value") or "")) for item in findings)
    system_access_signals = _detect_system_access_signals(risk_context_text, enterprise_payload)
    system_access_detected = bool(system_access_signals)
    anchor_types = {item.get("type") for item in enterprise_payload.get("anchors") or []}
    strong_enterprise = bool(anchor_types & {"official_name", "root_domain", "email_domain", "subdomain"})
    hard_compromise_context = bool(anchor_types & {"root_domain", "email_domain", "subdomain"}) and credential_literal_detected and system_access_detected
    demo_or_mock = _is_demo_or_mock_context(context_path, full_context_text)
    public_market = _is_public_market_context(context_path, full_context_text)
    contact_directory = _is_contact_directory_context(context_path, full_context_text)
    domain_inventory = _is_domain_inventory_context(context_path, full_context_text)
    reference_catalog = _is_reference_catalog_context(context_path, full_context_text)
    auth_flow = _is_auth_flow_context(context_path, full_context_text)
    documentation = _is_documentation_context(context_path, full_context_text)
    hashed_secret = _is_hashed_secret_context(full_context_text)
    local_default = _is_local_default_config_context(full_context_text, findings)
    public_api_example = _is_public_api_example_context(full_context_text)
    log_or_comment = _is_log_or_comment_context(full_context_text)
    suppressible_context = not hard_compromise_context
    suppression_reasons = _suppression_reason_payload(
        demo_or_mock=demo_or_mock if suppressible_context else False,
        public_market=public_market if suppressible_context else False,
        contact_directory=contact_directory if suppressible_context else False,
        domain_inventory=domain_inventory if suppressible_context else False,
        reference_catalog=reference_catalog if suppressible_context else False,
        auth_flow=auth_flow if suppressible_context else False,
        documentation=documentation if suppressible_context else False,
        hashed_secret=hashed_secret if suppressible_context else False,
        local_default=local_default if suppressible_context else False,
        public_api_example=public_api_example if suppressible_context else False,
        log_or_comment=log_or_comment if suppressible_context else False,
    )
    promotion_reasons = _promotion_reason_payload(
        enterprise_payload,
        findings,
        credential_literal_detected=credential_literal_detected,
        system_access_signals=system_access_signals,
        demo_or_mock=demo_or_mock if suppressible_context else False,
        public_market=public_market if suppressible_context else False,
        contact_directory=contact_directory if suppressible_context else False,
        domain_inventory=domain_inventory if suppressible_context else False,
        reference_catalog=reference_catalog if suppressible_context else False,
        auth_flow=auth_flow if suppressible_context else False,
        documentation=documentation if suppressible_context else False,
        hashed_secret=hashed_secret if suppressible_context else False,
        local_default=local_default if suppressible_context else False,
        public_api_example=public_api_example if suppressible_context else False,
        log_or_comment=log_or_comment if suppressible_context else False,
    )
    suppressed = suppressible_context and bool(suppression_reasons)
    if findings:
        risk_score, severity = _score_code_hit(file_path, findings)
        finding_keys = {str(item.get("ruleKey") or "") for item in findings}
        if suppressible_context and demo_or_mock and not credential_literal_detected:
            risk_score = max(18, risk_score - 14)
        if hard_compromise_context:
            risk_score = max(risk_score + 16, 76)
        elif strong_enterprise and credential_literal_detected and finding_keys & {"token", "ak_sk", "private_key"} and not public_market and not public_api_example:
            risk_score = max(risk_score + 14, 72)
        elif strong_enterprise and "db_url" in finding_keys and credential_literal_detected and not _is_local_db_connection(findings):
            risk_score = max(risk_score + 12, 68)
        elif str(enterprise_payload.get("level") or "") == "alias" and credential_literal_detected and finding_keys & {"token", "ak_sk"}:
            risk_score = max(risk_score + 8, 58)
        if not bool(anchor_types & {"root_domain", "email_domain", "subdomain"}) and (public_market or public_api_example):
            risk_score = min(risk_score, 24)
        if suppressible_context and public_market and not credential_literal_detected and not system_access_detected:
            risk_score = min(risk_score, 20)
        elif suppressible_context and contact_directory and not credential_literal_detected and not system_access_detected:
            risk_score = min(risk_score, 24)
        elif suppressible_context and domain_inventory and not credential_literal_detected and not system_access_detected:
            risk_score = min(risk_score, 20)
        elif suppressible_context and reference_catalog and not credential_literal_detected and not system_access_detected:
            risk_score = min(risk_score, 18)
        elif suppressible_context and demo_or_mock and not credential_literal_detected and not system_access_detected:
            risk_score = min(risk_score, 24)
        if suppressible_context and auth_flow and not credential_literal_detected:
            risk_score = min(risk_score, 28)
        if suppressible_context and documentation and not system_access_detected:
            risk_score = min(risk_score, 24)
        if suppressible_context and hashed_secret and not credential_literal_detected:
            risk_score = min(risk_score, 22)
        if suppressible_context and local_default:
            risk_score = min(risk_score, 24)
        if suppressible_context and public_api_example and not credential_literal_detected:
            risk_score = min(risk_score, 24)
        if suppressible_context and log_or_comment and not credential_literal_detected:
            risk_score = min(risk_score, 22)
        risk_score = min(risk_score, 100)
        severity = _severity_from_score(risk_score)
        blocked_public_context = bool(
            demo_or_mock
            or public_market
            or contact_directory
            or domain_inventory
            or reference_catalog
            or documentation
            or hashed_secret
            or local_default
            or public_api_example
            or log_or_comment
        )
        primary_sensitive = _has_primary_sensitive_evidence(
            findings,
            strong_enterprise=strong_enterprise,
            system_access_detected=system_access_detected,
            blocked_public_context=blocked_public_context,
        )
        suppressed = not primary_sensitive
        if suppressed and not suppression_reasons:
            suppression_reasons.append("未达到真实敏感证据门槛")
        if suppressed:
            risk_score = min(risk_score, 24)
            severity = _severity_from_score(risk_score)
        return {
            "classification_version": CODE_CLASSIFICATION_VERSION,
            "result_layer": "sensitive",
            "sensitive_type": findings[0]["ruleKey"],
            "matched_rule": findings[0]["label"],
            "risk_score": risk_score,
            "severity": severity,
            "findings": findings,
            "clue_markers": [],
            "enterprise_match_level": str(enterprise_payload.get("level") or "none"),
            "enterprise_anchors": list(enterprise_payload.get("anchors") or []),
            "risk_promotion_reasons": promotion_reasons,
            "credential_literal_detected": credential_literal_detected,
            "system_access_detected": system_access_detected,
            "system_access_signals": system_access_signals,
            "suppressed": suppressed,
            "suppression_reasons": suppression_reasons,
            "display_bucket": "suppressed" if suppressed else "primary",
        }
    clue_score, clue_severity, clue_markers = _score_clue_hit(
        term,
        file_path,
        code_text,
        term_type=term_type,
        enterprise_match=enterprise_match,
    )
    if public_market:
        clue_score = min(clue_score, 18)
    elif contact_directory:
        clue_score = min(clue_score, 24)
    elif domain_inventory:
        clue_score = min(clue_score, 18)
    elif reference_catalog:
        clue_score = min(clue_score, 18)
    elif demo_or_mock:
        clue_score = min(clue_score, 24)
    if auth_flow:
        clue_score = min(clue_score, 24)
    if documentation:
        clue_score = min(clue_score, 18)
    if hashed_secret:
        clue_score = min(clue_score, 20)
    if local_default:
        clue_score = min(clue_score, 22)
    if public_api_example:
        clue_score = min(clue_score, 22)
    if log_or_comment:
        clue_score = min(clue_score, 20)
    clue_severity = _severity_from_score(clue_score)
    if enterprise_match is None or not enterprise_payload.get("valid") or not (enterprise_payload.get("anchors") or []):
        return None
    suppressed_score = max(12, min(clue_score or 18, 24))
    return {
        "classification_version": CODE_CLASSIFICATION_VERSION,
        "result_layer": "clue",
        "sensitive_type": CODE_CLUE_RULE_KEY,
        "matched_rule": CODE_CLUE_RULE_LABEL,
        "risk_score": suppressed_score,
        "severity": _severity_from_score(suppressed_score),
        "findings": [],
        "clue_markers": clue_markers,
        "enterprise_match_level": str(enterprise_payload.get("level") or "none"),
        "enterprise_anchors": list(enterprise_payload.get("anchors") or []),
        "risk_promotion_reasons": promotion_reasons,
        "credential_literal_detected": False,
        "system_access_detected": system_access_detected,
        "system_access_signals": system_access_signals,
        "suppressed": True,
        "suppression_reasons": list(suppression_reasons) + ["企业关键词线索，未发现真实敏感证据"],
        "display_bucket": "suppressed",
    }


def _score_code_hit(file_path: str, findings: list[dict[str, Any]]) -> tuple[int, str]:
    if not findings:
        return 0, "low"
    unique_rules = {str(item.get("ruleKey") or "") for item in findings if str(item.get("ruleKey") or "")}
    max_signal = max(_finding_signal_score(item) for item in findings)
    multi_bonus = min(18, max(0, len(findings) - 1) * 5)
    diversity_bonus = min(12, max(0, len(unique_rules) - 1) * 6)
    file_bonus = _file_exposure_bonus(file_path)
    secret_like_count = sum(1 for item in findings if bool(item.get("secretLike")))
    secret_bonus = 0
    if secret_like_count:
        secret_bonus += 10
        secret_bonus += min(8, max(0, secret_like_count - 1) * 4)
    risk_score = min(100, max_signal + multi_bonus + diversity_bonus + file_bonus + secret_bonus)
    severity = _severity_from_score(risk_score)
    return risk_score, severity


def _write_snapshot_files(
    watchlist_name: str,
    platform_key: str,
    term: str,
    repository_name: str,
    html: str,
    payload: dict[str, Any],
) -> tuple[str, str]:
    base_dir = _query_output_dir(watchlist_name, platform_key, term)
    stem = _snapshot_file_stem(repository_name)
    html_path = base_dir / f"{stem}.html"
    artifact_path = base_dir / f"{stem}.json"
    dump_text(html_path, html)
    dump_json(artifact_path, payload)
    return str(html_path), str(artifact_path)


def _detail_payload_from_page(platform: ExposurePlatform, detail_url: str, search_url: str) -> dict[str, Any]:
    storage_state = _load_storage_state_path(platform.key)
    raw_url = _raw_file_url(platform.key, str(detail_url or ""))
    if raw_url and raw_url != detail_url:
        try:
            raw_text = _http_get_text(
                raw_url,
                headers=_search_request_headers(platform.key, storage_state),
                timeout=30,
            )
            if _normalize_text(raw_text):
                return {
                    "page_url": str(detail_url or ""),
                    "search_url": search_url,
                    "title": detail_url,
                    "html": "",
                    "screenshot_png": b"",
                    "code_text": raw_text,
                }
        except Exception:
            pass
    artifacts = fetch_page_artifacts_with_session(
        detail_url,
        storage_state_path=storage_state,
        wait_seconds=4,
        timeout_seconds=45,
    )
    html = str(artifacts.get("html") or "")
    code_text = _extract_code_text(html)
    return {
        "page_url": str(artifacts.get("url") or detail_url),
        "search_url": search_url,
        "title": _normalize_text(artifacts.get("title")) or detail_url,
        "html": html,
        "screenshot_png": artifacts.get("screenshot_png") or b"",
        "code_text": code_text,
    }


def _hydrate_detail_snapshot(platform: ExposurePlatform, detail_url: str, search_url: str) -> dict[str, Any]:
    storage_state = _load_storage_state_path(platform.key)
    artifacts = fetch_page_artifacts_with_session(
        detail_url,
        storage_state_path=storage_state,
        wait_seconds=4,
        timeout_seconds=45,
    )
    html = str(artifacts.get("html") or "")
    return {
        "page_url": str(artifacts.get("url") or detail_url),
        "search_url": search_url,
        "title": _normalize_text(artifacts.get("title")) or detail_url,
        "html": html,
        "screenshot_png": artifacts.get("screenshot_png") or b"",
        "code_text": _extract_code_text(html),
    }


def _fetch_code_search_page(
    platform: ExposurePlatform,
    search_url: str,
    storage_state_path: str | None,
    *,
    allow_browser_fallback: bool = True,
    http_timeout: int = 45,
) -> dict[str, Any]:
    headers = _search_request_headers(platform.key, storage_state_path)
    try:
        html = _http_get_html(search_url, headers=headers, timeout=http_timeout, platform_key=platform.key, retries=1)
        issue = _detect_code_search_issue(platform, html, search_url, "")
        if not issue:
            return {
                "url": search_url,
                "title": "",
                "html": html,
                "screenshot_png": b"",
            }
    except Exception:
        pass
    if not allow_browser_fallback:
        raise RuntimeError(f"http_search_fetch_failed:{search_url}")
    return fetch_page_artifacts_with_session(
        search_url,
        storage_state_path=storage_state_path,
        wait_seconds=3,
        timeout_seconds=45,
    )


def _lightweight_code_fetch(platform: ExposurePlatform, file_url: str) -> str:
    storage_state = _load_storage_state_path(platform.key)
    raw_url = _raw_file_url(platform.key, str(file_url or ""))
    if not raw_url or raw_url == file_url:
        return ""
    try:
        text = _http_get_text(
            raw_url,
            headers=_search_request_headers(platform.key, storage_state),
            timeout=30,
        )
        return text if _normalize_text(text) else ""
    except Exception:
        return ""


def _collect_search_results_across_pages(
    platform: ExposurePlatform,
    search_url: str,
    storage_state_path: str | None,
    *,
    page_limit: int,
) -> tuple[list[dict[str, Any]], str]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    issue = ""
    for page in range(1, max(1, page_limit) + 1):
        paged_url = _search_page_url(platform.key, search_url, page)
        try:
            search_page = _fetch_code_search_page(
                platform,
                paged_url,
                storage_state_path,
                allow_browser_fallback=(page == 1),
                http_timeout=(45 if page == 1 else 12),
            )
        except Exception as exc:
            if page > 1:
                try:
                    search_page = _fetch_code_search_page(
                        platform,
                        paged_url,
                        storage_state_path,
                        allow_browser_fallback=True,
                        http_timeout=45,
                    )
                except Exception:
                    break
            else:
                issue = f"{platform.key}:page_{page}:{exc}"
                break
        page_issue = _detect_code_search_issue(
            platform,
            str(search_page.get("html") or ""),
            str(search_page.get("url") or paged_url),
            str(search_page.get("title") or ""),
        )
        if page_issue:
            if page == 1:
                issue = page_issue
            break
        page_rows = _parse_code_search_results(
            platform,
            str(search_page.get("html") or ""),
            str(search_page.get("url") or paged_url),
        )
        if not page_rows:
            break
        new_count = 0
        for item in page_rows:
            key = f"{item.get('repositoryUrl')}|{item.get('branch')}|{item.get('filePath')}|{item.get('fileUrl')}"
            if key in seen:
                continue
            seen.add(key)
            results.append(item)
            new_count += 1
        if new_count == 0:
            break
    return results, issue


def _collect_github_api_search_results_incremental(
    search_url: str,
    *,
    page_limit: int,
    previous_state: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    query = _normalize_text(dict(parse_qsl(urlparse(search_url).query, keep_blank_values=True)).get("q"))
    if not query:
        return [], "github:api:invalid_query", {}
    try:
        candidates, metadata = _github_api_code_search(
            query,
            _github_page_limit(page_limit),
        )
    except GitHubCodeSearchUnavailable as exc:
        return [], f"github:api:{exc}", {}
    _update_github_api_state(
        last_used_channel="api",
        fallback_used=False,
        degraded=bool(metadata.get("incomplete_results")),
    )
    previous_signature = _normalize_text((previous_state or {}).get("last_candidate_signature"))
    signature = _candidate_signature(candidates)
    next_state = {
        "last_page_scanned": int(metadata.get("pages_fetched") or 0),
        "last_candidate_signature": signature,
        "last_candidate_keys_json": _candidate_keys_json(candidates),
        "last_repository_urls_json": _repository_urls_json(candidates),
        "cursor_mode": "api",
        "signature_changed": not previous_signature or previous_signature != signature,
        "incomplete_results": bool(metadata.get("incomplete_results")),
        "cache_hit": bool(metadata.get("cache_hit")),
    }
    return candidates, "", next_state


def _collect_web_search_results_incremental(
    platform: ExposurePlatform,
    search_url: str,
    storage_state_path: str | None,
    *,
    page_limit: int,
    previous_state: dict[str, Any] | None = None,
    browser_fallback: bool = True,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    effective_limit = max(1, _effective_search_page_limit(page_limit))
    state = previous_state or {}
    previous_signature = _normalize_text(state.get("last_candidate_signature"))
    previous_last_page = int(state.get("last_page_scanned") or 0)
    previous_candidate_keys = _load_json_string_list(state.get("last_candidate_keys_json"))
    previous_repository_urls = _load_json_string_list(state.get("last_repository_urls_json"))
    first_page_url = _search_page_url(platform.key, search_url, 1)
    try:
        first_page = _fetch_code_search_page(
            platform,
            first_page_url,
            storage_state_path,
            allow_browser_fallback=browser_fallback,
            http_timeout=45,
        )
    except Exception as exc:
        return [], f"{platform.key}:page_1:{exc}", {}
    first_issue = _detect_code_search_issue(
        platform,
        str(first_page.get("html") or ""),
        str(first_page.get("url") or first_page_url),
        str(first_page.get("title") or ""),
    )
    if first_issue:
        return [], first_issue, {}
    first_rows = _parse_code_search_results(
        platform,
        str(first_page.get("html") or ""),
        str(first_page.get("url") or first_page_url),
    )
    first_signature = _candidate_signature(first_rows)
    signature_changed = not previous_signature or previous_signature != first_signature
    if signature_changed or previous_last_page <= 0:
        page_sequence = list(range(1, effective_limit + 1))
        mode = "full"
    else:
        page_sequence = list(range(max(2, previous_last_page + 1), max(2, previous_last_page + 1) + effective_limit))
        mode = "incremental"
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    last_page_scanned = 1 if first_rows else 0
    if mode == "incremental":
        last_page_scanned = previous_last_page
    if mode == "full":
        for item in first_rows:
            key = _candidate_identity(item)
            if key and key not in seen:
                seen.add(key)
                results.append(item)
    issue = ""
    first_window_page = page_sequence[0] if page_sequence else 1
    for page in page_sequence:
        if mode == "full" and page == 1:
            continue
        paged_url = _search_page_url(platform.key, search_url, page)
        try:
            search_page = _fetch_code_search_page(
                platform,
                paged_url,
                storage_state_path,
                allow_browser_fallback=(browser_fallback and page == first_window_page),
                http_timeout=(45 if page == 1 else 12),
            )
        except Exception as exc:
            if page > 1:
                try:
                    search_page = _fetch_code_search_page(
                        platform,
                        paged_url,
                        storage_state_path,
                        allow_browser_fallback=browser_fallback,
                        http_timeout=45,
                    )
                except Exception:
                    break
            else:
                issue = f"{platform.key}:page_{page}:{exc}"
                break
        page_issue = _detect_code_search_issue(
            platform,
            str(search_page.get("html") or ""),
            str(search_page.get("url") or paged_url),
            str(search_page.get("title") or ""),
        )
        if page_issue:
            if page == 1:
                issue = page_issue
            break
        last_page_scanned = page
        page_rows = _parse_code_search_results(
            platform,
            str(search_page.get("html") or ""),
            str(search_page.get("url") or paged_url),
        )
        if not page_rows:
            break
        new_count = 0
        for item in page_rows:
            key = _candidate_identity(item)
            if key and key not in seen:
                seen.add(key)
                results.append(item)
                new_count += 1
        if new_count == 0 and mode == "full":
            break
    current_candidates = results if results else first_rows
    current_candidate_keys = _candidate_keys(current_candidates)
    current_repository_urls = _repository_urls(current_candidates)
    if mode == "incremental" and not signature_changed:
        current_candidate_keys = _merge_string_lists(current_candidate_keys, previous_candidate_keys)
        current_repository_urls = _merge_string_lists(current_repository_urls, previous_repository_urls)
    next_state = {
        "last_page_scanned": max(last_page_scanned, 1 if first_rows else 0),
        "last_candidate_signature": first_signature,
        "last_candidate_keys_json": _json_dumps(current_candidate_keys),
        "last_repository_urls_json": _json_dumps(current_repository_urls),
        "cursor_mode": mode,
        "signature_changed": signature_changed,
    }
    return results, issue, next_state


def _collect_search_results_incremental(
    platform: ExposurePlatform,
    search_url: str,
    storage_state_path: str | None,
    *,
    page_limit: int,
    previous_state: dict[str, Any] | None = None,
    browser_fallback: bool = True,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    mode = _github_search_mode()
    token, _ = _github_api_token()
    if platform.key != "github" or mode == "browser" or (mode == "auto" and not token):
        result = _collect_web_search_results_incremental(
            platform,
            search_url,
            storage_state_path,
            page_limit=page_limit,
            previous_state=previous_state,
            browser_fallback=browser_fallback,
        )
        if platform.key == "github":
            _update_github_api_state(
                last_used_channel="browser",
                fallback_used=False,
                degraded=bool(result[1]),
                last_error=str(result[1] or ""),
            )
        return result
    if mode == "api" and not token:
        _update_github_api_state(
            last_used_channel="unavailable",
            fallback_used=False,
            degraded=True,
            last_error="auth_required",
        )
        return [], "github:api:auth_required", {}

    api_rows, api_issue, api_state = _collect_github_api_search_results_incremental(
        search_url,
        page_limit=page_limit,
        previous_state=previous_state,
    )
    should_supplement = bool(browser_fallback) and (
        bool(api_issue) or not api_rows or bool(api_state.get("incomplete_results"))
    )
    if mode == "api" or not should_supplement:
        if api_issue:
            _update_github_api_state(degraded=True)
        return api_rows, api_issue, api_state

    web_rows, web_issue, web_state = _collect_web_search_results_incremental(
        platform,
        search_url,
        storage_state_path,
        page_limit=page_limit,
        previous_state=previous_state,
        browser_fallback=browser_fallback,
    )
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in [*api_rows, *web_rows]:
        key = _candidate_identity(item)
        if key and key not in seen:
            seen.add(key)
            merged.append(item)
    if not merged:
        _update_github_api_state(
            last_used_channel="browser",
            fallback_used=True,
            degraded=bool(api_issue or web_issue or api_state.get("incomplete_results")),
        )
        return [], web_issue or api_issue, web_state or api_state
    _update_github_api_state(
        last_used_channel="api+browser" if api_rows else "browser",
        fallback_used=True,
        degraded=bool(api_issue or web_issue or api_state.get("incomplete_results")),
    )
    previous_signature = _normalize_text((previous_state or {}).get("last_candidate_signature"))
    signature = _candidate_signature(merged)
    next_state = {
        **(api_state or web_state),
        "last_page_scanned": max(
            int(api_state.get("last_page_scanned") or 0),
            int(web_state.get("last_page_scanned") or 0),
        ),
        "last_candidate_signature": signature,
        "last_candidate_keys_json": _candidate_keys_json(merged),
        "last_repository_urls_json": _repository_urls_json(merged),
        "cursor_mode": "api+browser",
        "signature_changed": not previous_signature or previous_signature != signature,
    }
    return merged, "", next_state


def ensure_default_code_watchlist() -> dict[str, Any]:
    with get_db_connection() as connection:
        existing = list_code_watchlists(connection)
        if existing:
            migrated: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
            changed = False
            for watchlist in existing:
                terms = list_code_watch_terms(connection, int(watchlist["id"]))
                public = _public_code_watchlist_payload(watchlist, terms)
                if _is_legacy_code_placeholder(watchlist) and public.get("name"):
                    metadata = _watchlist_metadata(watchlist)
                    metadata["enterprise_profile"] = public["enterprise_profile"]
                    watchlist = {
                        **watchlist,
                        "name": public["name"],
                        "organization_name": public["organization_name"],
                        "metadata_json": _json_dumps(metadata),
                    }
                    upsert_code_watchlist(connection, watchlist)
                    if len(public["terms"]) != len(terms):
                        replace_code_watch_terms(connection, int(watchlist["id"]), public["terms"])
                    terms = public["terms"]
                    changed = True
                migrated.append((watchlist, terms))
            if changed:
                connection.commit()
            return _public_code_watchlist_payload(*migrated[0])
    return {
        "id": None,
        "name": "",
        "organization_name": "",
        "enabled": False,
        "notes": "",
        "terms": [],
        "platforms": list(DEFAULT_CODE_PLATFORMS),
        "file_extensions": list(DEFAULT_FILE_EXTENSIONS),
        "search_page_limit": DEFAULT_SEARCH_PAGE_LIMIT,
        "max_results_per_term": DEFAULT_MAX_RESULTS_PER_TERM,
        "detail_fetch": True,
        "enabled_rule_keys": list(DEFAULT_RULE_KEYS),
        "enterprise_profile": _payload_enterprise_profile(
            {
                "organization_name": "",
                "terms": [],
                "enterprise_profile": DEFAULT_ENTERPRISE_PROFILE,
            }
        ),
    }


def list_code_watchlists_payload() -> list[dict[str, Any]]:
    ensure_default_code_watchlist()
    with get_db_connection() as connection:
        rows = list_code_watchlists(connection)
        payloads = []
        for row in rows:
            terms = list_code_watch_terms(connection, int(row["id"]))
            public_name, public_organization = _code_watchlist_public_identity(row, terms)
            if _is_legacy_code_placeholder(row) and not public_name:
                continue
            payloads.append(_public_code_watchlist_payload(row, terms))
        return payloads


def _dedupe_code_watch_terms(rows: list[dict[str, Any]] | None, now: str) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows or []:
        term = str(row.get("term") or "").strip()
        if not term:
            continue
        term_type = str(row.get("term_type") or "").strip() or "custom"
        key = (term.casefold(), term_type.casefold())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(
            {
                "term": term,
                "term_type": term_type,
                "weight": row.get("weight", 0),
                "enabled": row.get("enabled", True),
                "created_at": now,
                "updated_at": now,
            }
        )
    return deduped


def save_code_watchlist_payload(payload: dict[str, Any]) -> dict[str, Any]:
    now = _now_utc_iso()
    enterprise_profile = _payload_enterprise_profile(payload)
    with get_db_connection() as connection:
        watchlist_id = upsert_code_watchlist(
            connection,
            {
                "id": payload.get("id"),
                "name": payload.get("name"),
                "organization_name": payload.get("organization_name"),
                "enabled": payload.get("enabled", True),
                "notes": payload.get("notes", ""),
                "metadata_json": _json_dumps(
                    {
                        "platforms": _normalize_string_list(payload.get("platforms"), fallback=DEFAULT_CODE_PLATFORMS),
                        "file_extensions": _normalize_code_file_extensions(payload.get("file_extensions")),
                        "search_page_limit": _normalize_search_page_limit(payload.get("search_page_limit")),
                        "max_results_per_term": _normalize_result_budget(payload.get("max_results_per_term")),
                        "detail_fetch": bool(payload.get("detail_fetch", True)),
                        "enabled_rule_keys": _normalize_string_list(payload.get("enabled_rule_keys"), fallback=DEFAULT_RULE_KEYS),
                        "enterprise_profile": enterprise_profile,
                    }
                ),
                "created_at": payload.get("created_at") or now,
                "updated_at": now,
            },
        )
        replace_code_watch_terms(
            connection,
            watchlist_id,
            _dedupe_code_watch_terms(payload.get("terms") or [], now),
        )
        connection.commit()
        watchlist = get_code_watchlist(connection, watchlist_id)
        return _public_code_watchlist_payload(
            watchlist,
            list_code_watch_terms(connection, watchlist_id),
        )


def delete_code_watchlist_payload(watchlist_id: int) -> dict[str, Any]:
    ensure_default_code_watchlist()
    with get_db_connection() as connection:
        watchlist = get_code_watchlist(connection, int(watchlist_id))
        if watchlist is None:
            raise ValueError(f"watchlist not found: {watchlist_id}")
        watchlist_name = str(watchlist.get("name") or "")
        delete_code_watchlist(connection, int(watchlist_id))
        connection.commit()
    output_dir = _watchlist_output_root(watchlist_name)
    if output_dir.exists():
        for child in sorted(output_dir.rglob("*"), reverse=True):
            try:
                if child.is_file():
                    child.unlink()
                else:
                    child.rmdir()
            except Exception:
                pass
        try:
            output_dir.rmdir()
        except Exception:
            pass
    try:
        from darkweb_collector.watchlist_notifications import delete_watchlist_notification_files

        delete_watchlist_notification_files(watchlist_id)
    except Exception:
        logger.exception("failed to remove watchlist notification files for %s", watchlist_id)
    return {
        "removed": True,
        "watchlistId": int(watchlist_id),
        "watchlistName": watchlist_name,
    }


def scan_code_watchlist_once(
    watchlist_id: int,
    *,
    platforms: list[str] | None = None,
    file_extensions: list[str] | None = None,
    search_page_limit: int | None = None,
    max_results_per_term: int | None = None,
    detail_fetch: bool | None = None,
    enabled_rule_keys: list[str] | None = None,
    browser_fallback: bool = True,
) -> dict[str, Any]:
    with _CODE_SCAN_LOCK:
        return _scan_code_watchlist_once_unlocked(
            watchlist_id,
            platforms=platforms,
            file_extensions=file_extensions,
            search_page_limit=search_page_limit,
            max_results_per_term=max_results_per_term,
            detail_fetch=detail_fetch,
            enabled_rule_keys=enabled_rule_keys,
            browser_fallback=browser_fallback,
        )


def _scan_code_watchlist_once_unlocked(
    watchlist_id: int,
    *,
    platforms: list[str] | None = None,
    file_extensions: list[str] | None = None,
    search_page_limit: int | None = None,
    max_results_per_term: int | None = None,
    detail_fetch: bool | None = None,
    enabled_rule_keys: list[str] | None = None,
    browser_fallback: bool = True,
) -> dict[str, Any]:
    ensure_default_code_watchlist()
    started_at = _now_utc_iso()
    with get_db_connection() as connection:
        watchlist = get_code_watchlist(connection, watchlist_id)
        if watchlist is None:
            raise ValueError(f"watchlist not found: {watchlist_id}")
        if not bool(watchlist.get("enabled")):
            return {"watchlist_id": watchlist_id, "scanned_terms": 0, "candidates": 0, "hits": 0, "message": "watchlist disabled"}
        supplemental_terms = [item for item in list_code_watch_terms(connection, watchlist_id) if bool(item.get("enabled"))]
    metadata = _watchlist_metadata(watchlist)
    stored_enterprise_profile = _watchlist_stored_enterprise_profile(watchlist)
    terms = _effective_code_watch_terms(stored_enterprise_profile, supplemental_terms)
    enterprise_profile = _watchlist_enterprise_profile(watchlist, supplemental_terms)
    selected_platforms = _normalize_string_list(platforms or metadata.get("platforms"), fallback=DEFAULT_CODE_PLATFORMS)
    selected_extensions = _normalize_code_file_extensions(file_extensions or metadata.get("file_extensions"))
    selected_search_page_limit = _normalize_search_page_limit(
        search_page_limit if search_page_limit is not None else metadata.get("search_page_limit")
    )
    selected_rule_keys = _normalize_string_list(enabled_rule_keys or metadata.get("enabled_rule_keys"), fallback=DEFAULT_RULE_KEYS)
    selected_max_results = _normalize_result_budget(max_results_per_term if max_results_per_term is not None else metadata.get("max_results_per_term"))
    selected_detail_fetch = bool(detail_fetch if detail_fetch is not None else metadata.get("detail_fetch", True))

    total_candidates = 0
    total_hits = 0
    clue_hits = 0
    sensitive_hits = 0
    new_primary_hit_count = 0
    new_suppressed_hit_count = 0
    updated_hit_count = 0
    new_sensitive_hit_count = 0
    new_clue_hit_count = 0
    errors: list[str] = []
    seen_urls: set[str] = set()
    now = _now_utc_iso()
    scan_run_id = _persist_code_scan_run(
        None,
        watchlist_id=int(watchlist["id"]),
        selected_platforms=selected_platforms,
        terms=terms,
        candidate_count=0,
        hit_count=0,
        clue_hit_count=0,
        sensitive_hit_count=0,
        errors=[],
        status="running",
        started_at=started_at,
        finished_at="",
    )

    for term_row in terms:
        term = _normalize_text(term_row.get("term"))
        term_type = _normalize_text(term_row.get("term_type"))
        if not term:
            continue
        for platform_key in selected_platforms:
            try:
                platform = get_exposure_platform(platform_key)
            except ValueError as exc:
                errors.append(f"{platform_key}:{term}:{exc}")
                continue
            storage_state = _load_storage_state_path(platform.key)
            search_state = None
            known_candidate_keys: list[str] = []
            known_repository_urls: list[str] = []
            query_search_states: dict[str, dict[str, Any]] = {}
            with get_db_connection() as connection:
                search_states = list_code_search_states(
                    connection,
                    watchlist_id=int(watchlist["id"]),
                    platform=platform.key,
                    term=term,
                )
            query_search_states = {
                str(item.get("query_key") or "base"): item
                for item in search_states
            }
            search_state = query_search_states.get("base")
            known_candidate_keys = _state_string_union(search_states, "last_candidate_keys_json")
            known_repository_urls = _state_string_union(search_states, "last_repository_urls_json")
            if platform.key == "gitee":
                try:
                    candidates, next_search_state = _gitee_repo_code_search_incremental(
                        term,
                        selected_extensions,
                        selected_rule_keys,
                        page_limit=selected_search_page_limit,
                        previous_state=search_state,
                    )
                except Exception as exc:
                    errors.append(f"{platform.key}:{term}:{exc}")
                    continue
                _persist_search_state(int(watchlist["id"]), platform.key, term, "base", next_search_state, started_at)
                candidates = _apply_incremental_hints(
                    candidates,
                    previous_candidate_keys=known_candidate_keys,
                    previous_repository_urls=known_repository_urls,
                    new_page_bonus=60 if (next_search_state or {}).get("cursor_mode") == "incremental" else 0,
                )
                known_candidate_keys = _merge_string_lists(_candidate_keys(candidates), known_candidate_keys)
                known_repository_urls = _merge_string_lists(_repository_urls(candidates), known_repository_urls)
                candidates.sort(key=lambda item: _candidate_priority(item, selected_rule_keys), reverse=True)
                evaluation_limit = _candidate_evaluation_limit(selected_max_results, selected_search_page_limit)
                evaluation_candidates = candidates if evaluation_limit is None else candidates[:evaluation_limit]
                total_candidates += len(evaluation_candidates)
                for candidate in evaluation_candidates:
                    file_url = str(candidate.get("fileUrl") or "")
                    if not file_url or file_url in seen_urls:
                        continue
                    seen_urls.add(file_url)
                    detail = {
                        "page_url": file_url,
                        "search_url": f"{GITEE_WIDGET_API_BASE}/search/widget/{GITEE_REPO_SEARCH_WIDGET}",
                        "title": candidate.get("title") or file_url,
                        "html": "",
                        "screenshot_png": b"",
                        "code_text": str(candidate.get("snippetText") or ""),
                    }
                    enterprise_match = (
                        _evaluate_enterprise_match(enterprise_profile, term, candidate, detail["code_text"])
                        if _enterprise_profile_enabled(enterprise_profile)
                        else None
                    )
                    classification = _classify_code_hit(
                        term,
                        str(candidate.get("filePath") or ""),
                        detail["code_text"],
                        selected_rule_keys,
                        term_type=term_type,
                        enterprise_match=enterprise_match,
                        context_metadata=candidate,
                    )
                    if not classification:
                        continue
                    if selected_detail_fetch and not str(detail.get("html") or "").strip():
                        try:
                            detail.update(_hydrate_detail_snapshot(platform, file_url, detail["search_url"]))
                        except Exception:
                            pass
                    enterprise_match = (
                        _evaluate_enterprise_match(enterprise_profile, term, candidate, str(detail.get("code_text") or ""))
                        if _enterprise_profile_enabled(enterprise_profile)
                        else None
                    )
                    classification = _classify_code_hit(
                        term,
                        str(candidate.get("filePath") or ""),
                        str(detail.get("code_text") or ""),
                        selected_rule_keys,
                        term_type=term_type,
                        enterprise_match=enterprise_match,
                        context_metadata=candidate,
                    )
                    if not classification:
                        continue
                    findings = classification["findings"]
                    snippet = _extract_snippet(detail["code_text"], findings)
                    masked_snippet = _mask_snippet(snippet, findings)
                    if classification["result_layer"] == "clue":
                        preview_snapshot = {
                            "lineStart": int(candidate.get("lineStart") or 0),
                            "lineEnd": int(candidate.get("lineEnd") or candidate.get("lineStart") or 0),
                        }
                        snippet = _mask_preview_text(
                            _rebuild_code_preview(term, preview_snapshot, {"candidate": candidate, "code_text": detail["code_text"]}, findings),
                            findings,
                        )
                        masked_snippet = snippet
                    risk_score = int(classification["risk_score"])
                    severity = str(classification["severity"])
                    language = _language_from_path(str(candidate.get("filePath") or ""))
                    raw_payload = {
                        "classification_version": CODE_CLASSIFICATION_VERSION,
                        "candidate": candidate,
                        "search_url": detail["search_url"],
                        "page_url": detail["page_url"],
                        "language": language,
                        "finding_count": len(findings),
                        "masked_fragment": masked_snippet,
                        "result_layer": classification["result_layer"],
                        "clue_markers": classification["clue_markers"],
                        "code_text": detail["code_text"][:40000],
                        "term_type": term_type,
                        "enterprise_match_level": classification.get("enterprise_match_level"),
                        "enterprise_anchors": classification.get("enterprise_anchors") or [],
                        "risk_promotion_reasons": classification.get("risk_promotion_reasons") or [],
                        "credential_literal_detected": bool(classification.get("credential_literal_detected")),
                        "system_access_detected": bool(classification.get("system_access_detected")),
                        "system_access_signals": classification.get("system_access_signals") or [],
                        "suppressed": bool(classification.get("suppressed")),
                        "suppression_reasons": classification.get("suppression_reasons") or [],
                        "display_bucket": classification.get("display_bucket") or ("suppressed" if classification.get("suppressed") else "primary"),
                    }
                    def write_preview_hit(connection):
                        hit_id, created = upsert_code_hit_with_state(
                            connection,
                            {
                                "watchlist_id": int(watchlist["id"]),
                                "platform": platform.key,
                                "repository_name": candidate.get("repositoryName") or "",
                                "repository_owner": candidate.get("repositoryOwner") or "",
                                "repository_url": candidate.get("repositoryUrl") or "",
                                "file_path": candidate.get("filePath") or "",
                                "branch": candidate.get("branch") or "",
                                "file_url": file_url,
                                "visibility": "public",
                                "language": language,
                                "sensitive_type": classification["sensitive_type"],
                                "matched_rule": classification["matched_rule"],
                                "matched_term": term,
                                "result_layer": classification["result_layer"],
                                "risk_score": risk_score,
                                "severity": severity,
                                "first_seen_at": now,
                                "last_seen_at": now,
                                "raw_json": _json_dumps(raw_payload),
                            },
                        )
                        snapshot_id = insert_code_hit_snapshot(
                            connection,
                            {
                                "hit_id": hit_id,
                                "fetched_at": now,
                                "search_url": detail["search_url"],
                                "page_url": detail["page_url"],
                                "html_path": "",
                                "screenshot_path": "",
                                "code_fragment": snippet,
                                "masked_fragment": masked_snippet,
                                "raw_artifact_path": "",
                                "line_start": 0,
                                "line_end": 0,
                                "language": language,
                                "findings_json": _json_dumps(findings),
                                "raw_json": _json_dumps(raw_payload),
                            },
                        )
                        update_code_hit_last_snapshot(connection, hit_id, snapshot_id)
                        return created

                    created = bool(_commit_db_write(write_preview_hit))
                    total_hits += 1
                    if created:
                        if classification.get("suppressed"):
                            new_suppressed_hit_count += 1
                        else:
                            new_primary_hit_count += 1
                        if classification["result_layer"] == "clue":
                            new_clue_hit_count += 1
                        else:
                            new_sensitive_hit_count += 1
                    else:
                        updated_hit_count += 1
                    if classification["result_layer"] == "clue":
                        clue_hits += 1
                    else:
                        sensitive_hits += 1
                continue
            search_url = _search_url(platform.key, term)
            candidates, search_issue, next_search_state = _collect_search_results_incremental(
                platform,
                search_url,
                storage_state,
                page_limit=selected_search_page_limit,
                previous_state=search_state,
                browser_fallback=browser_fallback,
            )
            _persist_search_state(int(watchlist["id"]), platform.key, term, "base", next_search_state, started_at)
            if search_issue:
                errors.append(f"{search_issue}:{term}")
                continue
            filtered_candidates = [item for item in candidates if _matches_extension(item.get("filePath") or "", selected_extensions)]
            filtered_candidates = _apply_incremental_hints(
                filtered_candidates,
                previous_candidate_keys=known_candidate_keys,
                previous_repository_urls=known_repository_urls,
                new_page_bonus=60 if (next_search_state or {}).get("cursor_mode") == "incremental" else 0,
            )
            known_candidate_keys = _merge_string_lists(_candidate_keys(filtered_candidates), known_candidate_keys)
            known_repository_urls = _merge_string_lists(_repository_urls(filtered_candidates), known_repository_urls)
            expanded_candidates: list[dict[str, Any]] = []
            expanded_seen: set[str] = {
                f"{item.get('repositoryUrl')}|{item.get('branch')}|{item.get('filePath')}|{item.get('fileUrl')}"
                for item in filtered_candidates
            }
            domain_like_term = "." in term and " " not in term
            if domain_like_term or not filtered_candidates:
                for query in _expanded_search_queries_for_platform(platform.key, term, selected_rule_keys):
                    expanded_search_url = _search_url(platform.key, query)
                    query_key = _search_state_query_key(term, query)
                    query_bonus = _query_priority_bonus(query, term)
                    expanded_rows, expanded_issue, expanded_next_state = _collect_search_results_incremental(
                        platform,
                        expanded_search_url,
                        storage_state,
                        page_limit=max(1, min(_effective_search_page_limit(selected_search_page_limit), 2)),
                        previous_state=query_search_states.get(query_key),
                        browser_fallback=browser_fallback,
                    )
                    _persist_search_state(
                        int(watchlist["id"]),
                        platform.key,
                        term,
                        query_key,
                        expanded_next_state,
                        started_at,
                    )
                    if expanded_issue:
                        continue
                    expanded_rows = _apply_incremental_hints(
                        expanded_rows,
                        previous_candidate_keys=known_candidate_keys,
                        previous_repository_urls=known_repository_urls,
                        new_page_bonus=60 if (expanded_next_state or {}).get("cursor_mode") == "incremental" else 0,
                    )
                    for item in expanded_rows:
                        file_path = str(item.get("filePath") or "")
                        key = f"{item.get('repositoryUrl')}|{item.get('branch')}|{file_path}|{item.get('fileUrl')}"
                        if key in expanded_seen or not _matches_extension(file_path, _repo_fallback_extensions(selected_extensions)):
                            continue
                        expanded_seen.add(key)
                        item = {**item, "queryPriorityHint": query_bonus}
                        expanded_candidates.append(item)
                    known_candidate_keys = _merge_string_lists(_candidate_keys(expanded_rows), known_candidate_keys)
                    known_repository_urls = _merge_string_lists(_repository_urls(expanded_rows), known_repository_urls)
                    if len(expanded_candidates) >= max(selected_max_results * 2, 12):
                        break
                filtered_candidates.extend(expanded_candidates)
            if platform.key == "gitlab" and not filtered_candidates:
                project_candidates = [item for item in candidates if _is_gitlab_repository_url(item.get("repositoryUrl"))]
                project_candidate_limit = selected_max_results if selected_max_results > 0 else 12
                for project_candidate in project_candidates[:project_candidate_limit]:
                    try:
                        nested_candidates = _gitlab_project_blob_search(
                            project_candidate["repositoryUrl"],
                            term,
                            storage_state,
                        )
                        filtered_candidates.extend(
                            item for item in nested_candidates
                            if _matches_extension(item.get("filePath") or "", selected_extensions)
                        )
                    except Exception as exc:
                        errors.append(f"{platform.key}:{project_candidate.get('repositoryUrl')}:nested_search:{exc}")
                deduped_nested = []
                nested_seen: set[str] = set()
                for item in filtered_candidates:
                    key = f"{item.get('repositoryUrl')}|{item.get('branch')}|{item.get('filePath')}"
                    if key in nested_seen:
                        continue
                    nested_seen.add(key)
                    deduped_nested.append(item)
                filtered_candidates = deduped_nested
            if platform.key == "gitlab" and not filtered_candidates:
                try:
                    filtered_candidates = _gitlab_repo_fallback_code_search(
                        term,
                        storage_state,
                        _repo_fallback_extensions(selected_extensions),
                        max(selected_max_results * 2, 12),
                        page_limit=max(1, min(_effective_search_page_limit(selected_search_page_limit), 3)),
                    )
                except Exception as exc:
                    errors.append(f"{platform.key}:{term}:repo_fallback:{exc}")
            if platform.key == "github" and not filtered_candidates and not _github_api_enabled():
                try:
                    filtered_candidates = _github_repo_fallback_code_search(
                        term,
                        selected_extensions,
                        selected_rule_keys,
                        max(selected_max_results * 2, 12),
                        page_limit=max(1, min(_effective_search_page_limit(selected_search_page_limit), 3)),
                    )
                except Exception as exc:
                    errors.append(f"{platform.key}:{term}:repo_fallback:{exc}")
            filtered_candidates.sort(
                key=lambda item: _candidate_priority(item, selected_rule_keys),
                reverse=True,
            )
            evaluation_limit = _candidate_evaluation_limit(selected_max_results, selected_search_page_limit)
            evaluation_candidates = filtered_candidates if evaluation_limit is None else filtered_candidates[:evaluation_limit]
            total_candidates += len(evaluation_candidates)
            for candidate in evaluation_candidates:
                file_url = str(candidate.get("fileUrl") or "")
                if not file_url or file_url in seen_urls:
                    continue
                seen_urls.add(file_url)
                try:
                    if platform.key == "gitlab" and candidate.get("snippetText"):
                        detail = {
                            "page_url": file_url,
                            "search_url": search_url,
                            "title": candidate.get("title") or file_url,
                            "html": "",
                            "screenshot_png": b"",
                            "code_text": str(candidate.get("snippetText") or ""),
                        }
                    elif selected_detail_fetch:
                        detail = _detail_payload_from_page(platform, file_url, search_url)
                    else:
                        detail = {
                            "page_url": file_url,
                            "search_url": search_url,
                            "title": candidate.get("title") or file_url,
                            "html": "",
                            "screenshot_png": b"",
                            "code_text": candidate.get("snippetText") or candidate.get("title") or "",
                        }
                except Exception as exc:
                    errors.append(f"{platform.key}:{file_url}:{exc}")
                    continue
                if not selected_detail_fetch and not str(candidate.get("snippetText") or "").strip():
                    lightweight_text = _lightweight_code_fetch(platform, file_url)
                    if lightweight_text:
                        detail["code_text"] = lightweight_text
                if candidate.get("snippetText") and (
                    not detail.get("code_text")
                    or str(detail.get("code_text") or "").startswith(".turbo-progress-bar")
                ):
                    detail["code_text"] = str(candidate.get("snippetText") or "")
                elif candidate.get("snippetText"):
                    snippet_text = str(candidate.get("snippetText") or "")
                    detail_findings = _collect_findings(str(detail.get("code_text") or ""), selected_rule_keys)
                    snippet_findings = _collect_findings(snippet_text, selected_rule_keys)
                    if snippet_findings and not detail_findings:
                        detail["code_text"] = snippet_text
                enterprise_match = (
                    _evaluate_enterprise_match(enterprise_profile, term, candidate, str(detail.get("code_text") or ""))
                    if _enterprise_profile_enabled(enterprise_profile)
                    else None
                )
                if enterprise_match is not None and not enterprise_match.get("valid"):
                    continue
                location = _parse_code_location(platform.key, file_url) or {}
                effective_file_path = str(candidate.get("filePath") or location.get("file_path") or "")
                classification = _classify_code_hit(
                    term,
                    effective_file_path,
                    str(detail.get("code_text") or ""),
                    selected_rule_keys,
                    term_type=term_type,
                    enterprise_match=enterprise_match,
                    context_metadata=candidate,
                )
                if not classification:
                    continue
                if selected_detail_fetch and not str(detail.get("html") or "").strip():
                    try:
                        detail.update(_hydrate_detail_snapshot(platform, file_url, search_url))
                    except Exception:
                        pass
                    enterprise_match = (
                        _evaluate_enterprise_match(enterprise_profile, term, candidate, str(detail.get("code_text") or ""))
                        if _enterprise_profile_enabled(enterprise_profile)
                        else None
                    )
                    classification = _classify_code_hit(
                        term,
                        effective_file_path,
                        str(detail.get("code_text") or ""),
                        selected_rule_keys,
                        term_type=term_type,
                        enterprise_match=enterprise_match,
                        context_metadata=candidate,
                    )
                    if not classification:
                        continue
                findings = classification["findings"]
                snippet = _extract_snippet(detail["code_text"], findings)
                masked_snippet = _mask_snippet(snippet, findings)
                if classification["result_layer"] == "clue":
                    preview_snapshot = {
                        "lineStart": int(candidate.get("lineStart") or location.get("line_start") or 0),
                        "lineEnd": int(candidate.get("lineEnd") or location.get("line_end") or candidate.get("lineStart") or location.get("line_start") or 0),
                    }
                    snippet = _rebuild_code_preview(term, preview_snapshot, {"candidate": candidate, "code_text": detail["code_text"]}, findings)
                    masked_snippet = snippet
                risk_score = int(classification["risk_score"])
                severity = str(classification["severity"])
                language = _language_from_path(str(candidate.get("filePath") or location.get("file_path") or ""))
                raw_payload = {
                    "classification_version": CODE_CLASSIFICATION_VERSION,
                    "candidate": candidate,
                    "search_url": search_url,
                    "page_url": detail["page_url"],
                    "language": language,
                    "finding_count": len(findings),
                    "masked_fragment": masked_snippet,
                    "result_layer": classification["result_layer"],
                    "clue_markers": classification["clue_markers"],
                    "code_text": detail["code_text"][:40000],
                    "term_type": term_type,
                    "enterprise_match_level": classification.get("enterprise_match_level"),
                    "enterprise_anchors": classification.get("enterprise_anchors") or [],
                    "risk_promotion_reasons": classification.get("risk_promotion_reasons") or [],
                    "credential_literal_detected": bool(classification.get("credential_literal_detected")),
                    "system_access_detected": bool(classification.get("system_access_detected")),
                    "system_access_signals": classification.get("system_access_signals") or [],
                    "suppressed": bool(classification.get("suppressed")),
                    "suppression_reasons": classification.get("suppression_reasons") or [],
                    "display_bucket": classification.get("display_bucket") or ("suppressed" if classification.get("suppressed") else "primary"),
                }
                html_path = ""
                artifact_path = ""
                html_path, artifact_path = _write_snapshot_files(
                    str(watchlist["name"]),
                    platform.key,
                    term,
                    f"{candidate.get('repositoryName')}-{safe_stem(candidate.get('filePath') or '', 'file')}",
                    str(detail.get("html") or ""),
                    {
                        **raw_payload,
                        "findings": findings,
                        "code_fragment": snippet,
                        "masked_fragment": masked_snippet,
                    },
                )

                def write_detail_hit(connection):
                    hit_id, created = upsert_code_hit_with_state(
                        connection,
                        {
                            "watchlist_id": int(watchlist["id"]),
                            "platform": platform.key,
                            "repository_name": candidate.get("repositoryName") or location.get("repository_name") or "",
                            "repository_owner": candidate.get("repositoryOwner") or location.get("repository_owner") or "",
                            "repository_url": candidate.get("repositoryUrl") or location.get("repository_url") or "",
                            "file_path": candidate.get("filePath") or location.get("file_path") or "",
                            "branch": candidate.get("branch") or location.get("branch") or "",
                            "file_url": file_url,
                            "visibility": "public",
                            "language": language,
                            "sensitive_type": classification["sensitive_type"],
                            "matched_rule": classification["matched_rule"],
                            "matched_term": term,
                            "result_layer": classification["result_layer"],
                            "risk_score": risk_score,
                            "severity": severity,
                            "first_seen_at": now,
                            "last_seen_at": now,
                            "raw_json": _json_dumps(raw_payload),
                        },
                    )
                    snapshot_id = insert_code_hit_snapshot(
                        connection,
                        {
                            "hit_id": hit_id,
                            "fetched_at": now,
                            "search_url": search_url,
                            "page_url": detail["page_url"],
                            "html_path": html_path,
                            "screenshot_path": "",
                            "code_fragment": snippet,
                            "masked_fragment": masked_snippet,
                            "raw_artifact_path": artifact_path,
                            "line_start": int(candidate.get("lineStart") or location.get("line_start") or 0),
                            "line_end": int(candidate.get("lineEnd") or location.get("line_end") or 0),
                            "language": language,
                            "findings_json": _json_dumps(findings),
                            "raw_json": _json_dumps(raw_payload),
                        },
                    )
                    update_code_hit_last_snapshot(connection, hit_id, snapshot_id)
                    return created

                created = bool(_commit_db_write(write_detail_hit))
                total_hits += 1
                if created:
                    if classification.get("suppressed"):
                        new_suppressed_hit_count += 1
                    else:
                        new_primary_hit_count += 1
                    if classification["result_layer"] == "clue":
                        new_clue_hit_count += 1
                    else:
                        new_sensitive_hit_count += 1
                else:
                    updated_hit_count += 1
                if classification["result_layer"] == "clue":
                    clue_hits += 1
                else:
                    sensitive_hits += 1

    finished_at = _now_utc_iso()
    access_limited_only = bool(errors) and all(_is_access_limited_scan_error(item) for item in errors)
    final_status = "partial" if errors and (total_hits > 0 or access_limited_only) else "failed" if errors else "succeeded"
    _persist_code_scan_run(
        scan_run_id or None,
        watchlist_id=int(watchlist["id"]),
        selected_platforms=selected_platforms,
        terms=terms,
        candidate_count=total_candidates,
        hit_count=total_hits,
        clue_hit_count=clue_hits,
        sensitive_hit_count=sensitive_hits,
        errors=errors,
        status=final_status,
        started_at=started_at,
        finished_at=finished_at,
    )
    push_notifications: dict[str, Any]
    try:
        new_primary_hits = [
            item
            for item in list_code_hits_payload(
                watchlist_id=int(watchlist["id"]),
                limit=None,
                include_suppressed=False,
            )
            if _normalize_text(item.get("firstSeenAt")) == now
        ]
        from darkweb_collector.code_monitoring_notifications import notify_code_monitoring_hits

        push_notifications = notify_code_monitoring_hits(new_primary_hits)
    except Exception as exc:
        logger.exception("failed to send code monitoring notifications")
        push_notifications = {
            "eligible": 0,
            "sent": 0,
            "failed": 1,
            "skipped": 0,
            "channels": {},
            "errors": [{"error": str(exc)}],
        }
    schedule_code_monitoring_cache_warmup()
    return {
        "watchlist_id": watchlist_id,
        "watchlist_name": watchlist["name"],
        "scanned_terms": len(terms),
        "candidates": total_candidates,
        "hits": total_hits,
        "clue_hits": clue_hits,
        "sensitive_hits": sensitive_hits,
        "new_primary_hit_count": new_primary_hit_count,
        "new_suppressed_hit_count": new_suppressed_hit_count,
        "updated_hit_count": updated_hit_count,
        "new_sensitive_hit_count": new_sensitive_hit_count,
        "new_clue_hit_count": new_clue_hit_count,
        "errors": errors,
        "platforms": selected_platforms,
        "file_extensions": selected_extensions,
        "search_page_limit": selected_search_page_limit,
        "max_results_per_term": selected_max_results,
        "detail_fetch": selected_detail_fetch,
        "enabled_rule_keys": selected_rule_keys,
        "github_search": github_code_search_status_payload(),
        "push_notifications": push_notifications,
        "started_at": started_at,
        "finished_at": finished_at,
    }


def _build_code_hits_payload(
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    sensitive_type: str | None = None,
    limit: int | None = 200,
    include_suppressed: bool = False,
) -> list[dict[str, Any]]:
    ensure_default_code_watchlist()
    payloads: list[dict[str, Any]] = []
    query_limit = None if include_suppressed else limit
    with get_db_connection() as connection:
        watchlist_profile_cache: dict[int, dict[str, Any]] = {}
        watchlist_rule_cache: dict[int, list[str]] = {}
        watchlist_terms_cache: dict[int, list[dict[str, Any]]] = {}
        watchlist_identity_cache: dict[int, tuple[str, str]] = {}
        rows = list_code_hits(
            connection,
            watchlist_id=watchlist_id,
            review_status=review_status,
            platform=platform,
            sensitive_type=sensitive_type,
            limit=query_limit,
        )
        for row in rows:
            watchlist_key = int(row.get("watchlist_id") or 0)
            if watchlist_key not in watchlist_identity_cache:
                watchlist_terms_cache[watchlist_key] = list_code_watch_terms(connection, watchlist_key)
                watchlist_identity_cache[watchlist_key] = _code_watchlist_public_identity(
                    row,
                    watchlist_terms_cache[watchlist_key],
                )
            public_watchlist_name, public_organization_name = watchlist_identity_cache[watchlist_key]
            if _is_legacy_code_placeholder(row) and not public_watchlist_name:
                continue
            raw_payload = _parse_json(row.get("raw_json"), {})
            stored_payload = _build_stored_code_hit_payload(row, raw_payload)
            if stored_payload is not None:
                if stored_payload.get("__skip"):
                    continue
                if bool(stored_payload.get("suppressed")) and not include_suppressed:
                    continue
                stored_payload["watchlistName"] = public_watchlist_name
                stored_payload["organizationName"] = public_organization_name
                payloads.append(stored_payload)
                continue
            latest_snapshot = (list_code_hit_snapshots(connection, int(row["id"])) or [{}])[0]
            if watchlist_key not in watchlist_profile_cache:
                metadata = _parse_json(row.get("watchlist_metadata_json"), {})
                watchlist_profile_cache[watchlist_key] = _metadata_enterprise_profile(
                    metadata,
                    organization_name=public_organization_name,
                    terms=watchlist_terms_cache[watchlist_key],
                )
                watchlist_rule_cache[watchlist_key] = _normalize_string_list(
                    (metadata or {}).get("enabled_rule_keys"),
                    fallback=DEFAULT_RULE_KEYS,
                )
            term_type = _normalize_text(((raw_payload or {}).get("term_type") or ""))
            enterprise_profile = watchlist_profile_cache.get(watchlist_key) or {}
            analysis_text = _snapshot_analysis_text(latest_snapshot, raw_payload)
            candidate = ((raw_payload or {}).get("candidate") or {}) if isinstance(raw_payload, dict) else {}
            enterprise_match = (
                _evaluate_enterprise_match(enterprise_profile, str(row.get("matched_term") or ""), candidate, analysis_text)
                if _enterprise_profile_enabled(enterprise_profile)
                else None
            )
            if enterprise_match is not None and not enterprise_match.get("valid"):
                continue
            classification = _classify_code_hit(
                str(row.get("matched_term") or ""),
                str(row.get("file_path") or ""),
                analysis_text,
                watchlist_rule_cache.get(watchlist_key) or list(DEFAULT_RULE_KEYS),
                term_type=term_type,
                enterprise_match=enterprise_match,
                context_metadata=candidate,
            )
            if classification is None:
                continue
            if bool(classification.get("suppressed")) and not include_suppressed:
                continue
            findings = classification.get("findings") or []
            result_layer = classification.get("result_layer") or _code_result_layer(
                str(row.get("sensitive_type") or ""),
                raw_payload,
                str(row.get("result_layer") or ""),
            )
            computed_sensitive_type = str(classification.get("sensitive_type") or row.get("sensitive_type") or "")
            computed_matched_rule = str(classification.get("matched_rule") or row.get("matched_rule") or "")
            clue_text = _rebuild_code_preview(
                str(row.get("matched_term") or ""),
                {
                    "htmlPath": latest_snapshot.get("html_path") or latest_snapshot.get("htmlPath") or "",
                    "rawArtifactPath": latest_snapshot.get("raw_artifact_path") or latest_snapshot.get("rawArtifactPath") or "",
                    "lineStart": latest_snapshot.get("line_start") or latest_snapshot.get("lineStart") or 0,
                    "lineEnd": latest_snapshot.get("line_end") or latest_snapshot.get("lineEnd") or 0,
                    "maskedFragment": latest_snapshot.get("masked_fragment") or latest_snapshot.get("maskedFragment") or "",
                    "codeFragment": latest_snapshot.get("code_fragment") or latest_snapshot.get("codeFragment") or "",
                },
                raw_payload,
                findings,
            )
            computed_score = int(classification.get("risk_score") or row.get("risk_score") or 0)
            computed_severity = str(classification.get("severity") or row.get("severity") or "low")
            sensitive_label = CODE_CLUE_RULE_LABEL if result_layer == "clue" else SENSITIVE_RULE_MAP.get(computed_sensitive_type, SensitiveRule("", "", re.compile(""), 0)).label or computed_sensitive_type
            payloads.append(
                {
                    "id": int(row["id"]),
                    "watchlistId": int(row["watchlist_id"]),
                    "watchlistName": public_watchlist_name,
                    "organizationName": public_organization_name,
                    "platform": row.get("platform") or "",
                    "platformLabel": _platform_label(str(row.get("platform") or "")),
                    "repositoryName": row.get("repository_name") or "",
                    "repositoryOwner": row.get("repository_owner") or "",
                    "repositoryFullName": "/".join(
                        part for part in [row.get("repository_owner") or "", row.get("repository_name") or ""] if part
                    ),
                    "repositoryUrl": row.get("repository_url") or "",
                    "filePath": row.get("file_path") or "",
                    "branch": row.get("branch") or "",
                    "fileUrl": row.get("file_url") or "",
                    "visibility": row.get("visibility") or "public",
                    "language": row.get("language") or "",
                    "sensitiveType": computed_sensitive_type,
                    "sensitiveLabel": sensitive_label,
                    "matchedRule": computed_matched_rule,
                    "matchedTerm": row.get("matched_term") or "",
                    "resultLayer": result_layer,
                    "resultLayerLabel": "敏感命中" if result_layer == "sensitive" else "线索命中",
                    "riskScore": computed_score,
                    "severity": computed_severity,
                    "enterpriseMatchLevel": classification.get("enterprise_match_level") or str((enterprise_match or {}).get("level") or "none"),
                    "enterpriseAnchors": classification.get("enterprise_anchors") or list((enterprise_match or {}).get("anchors") or []),
                    "riskPromotionReasons": classification.get("risk_promotion_reasons") or [],
                    "credentialLiteralDetected": bool(classification.get("credential_literal_detected")),
                    "systemAccessDetected": bool(classification.get("system_access_detected")),
                    "suppressed": bool(classification.get("suppressed")),
                    "suppressionReasons": classification.get("suppression_reasons") or [],
                    "displayBucket": classification.get("display_bucket") or ("suppressed" if classification.get("suppressed") else "primary"),
                    "reviewStatus": row.get("review_status") or "new",
                    "evidenceCount": int(row.get("evidence_count") or 0),
                    "firstSeenAt": row.get("first_seen_at") or "",
                    "lastSeenAt": row.get("last_seen_at") or "",
                    "lastSnapshotId": row.get("last_snapshot_id"),
                    "summary": _normalize_text(clue_text)[:220],
                    "secretLike": any(bool(item.get("secretLike")) for item in findings),
                }
            )
    severity_rank = {"high": 3, "medium": 2, "low": 1}
    payloads.sort(
        key=lambda item: (
            severity_rank.get(str(item.get("severity") or "low"), 0),
            int(item.get("riskScore") or 0),
            str(item.get("lastSeenAt") or ""),
            int(item.get("id") or 0),
        ),
        reverse=True,
    )
    if not include_suppressed:
        return payloads[: int(limit)] if limit else payloads
    if not limit:
        return payloads
    primary_hits = [item for item in payloads if item.get("displayBucket") != "suppressed"][: int(limit)]
    suppressed_hits = [item for item in payloads if item.get("displayBucket") == "suppressed"][: int(limit)]
    return primary_hits + suppressed_hits


def _code_hits_payload_cache_revision() -> tuple[Any, ...]:
    ensure_default_code_watchlist()
    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM code_hits) AS hit_count,
                (SELECT COALESCE(MAX(id), 0) FROM code_hits) AS max_hit_id,
                (SELECT COALESCE(MAX(last_seen_at), '') FROM code_hits) AS max_hit_seen_at,
                (SELECT COALESCE(MAX(last_snapshot_id), 0) FROM code_hits) AS max_snapshot_id,
                (SELECT COUNT(*) FROM code_hit_reviews) AS review_count,
                (SELECT COALESCE(MAX(id), 0) FROM code_hit_reviews) AS max_review_id,
                (SELECT COALESCE(MAX(updated_at), '') FROM code_watchlists) AS watchlist_updated_at,
                (SELECT COUNT(*) FROM code_watch_terms) AS term_count,
                (SELECT COALESCE(MAX(updated_at), '') FROM code_watch_terms) AS term_updated_at
            """
        ).fetchone()
    if row is None:
        return (CODE_CLASSIFICATION_VERSION,)
    fields = (
        "hit_count",
        "max_hit_id",
        "max_hit_seen_at",
        "max_snapshot_id",
        "review_count",
        "max_review_id",
        "watchlist_updated_at",
        "term_count",
        "term_updated_at",
    )
    return (CODE_CLASSIFICATION_VERSION, *(row[field] for field in fields))


def _slice_code_hits_payloads(payloads: list[dict[str, Any]], limit: int | None) -> list[dict[str, Any]]:
    if not limit:
        return [dict(item) for item in payloads]
    primary_hits = [item for item in payloads if item.get("displayBucket") != "suppressed"][: int(limit)]
    suppressed_hits = [item for item in payloads if item.get("displayBucket") == "suppressed"][: int(limit)]
    return [dict(item) for item in [*primary_hits, *suppressed_hits]]


def _prune_code_hits_payload_cache(active_key: tuple[Any, ...]) -> None:
    if len(_CODE_HITS_PAYLOAD_CACHE) <= 8:
        return
    for key in list(_CODE_HITS_PAYLOAD_CACHE):
        if key != active_key:
            _CODE_HITS_PAYLOAD_CACHE.pop(key, None)


def _clear_code_hits_payload_cache() -> None:
    with _CODE_HITS_PAYLOAD_CACHE_LOCK:
        _CODE_HITS_PAYLOAD_CACHE.clear()


def _coerce_payload_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _coerce_payload_int(value: Any, fallback: Any = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(fallback)
        except (TypeError, ValueError):
            return 0


def _payload_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if _normalize_text(item)]


def _payload_dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _stored_code_hit_summary(raw_payload: dict[str, Any]) -> str:
    for value in (
        raw_payload.get("masked_fragment"),
        raw_payload.get("code_fragment"),
        _payload_candidate_snippet(raw_payload),
        str(raw_payload.get("code_text") or "")[:2000],
    ):
        text = _normalize_text(value)
        if text:
            return text[:220]
    return ""


def _build_stored_code_hit_payload(row: dict[str, Any], raw_payload: Any) -> dict[str, Any] | None:
    if not isinstance(raw_payload, dict):
        return None
    if _coerce_payload_bool(raw_payload.get("list_excluded")):
        return {"__skip": True}
    if _coerce_payload_int(raw_payload.get("classification_version")) != CODE_CLASSIFICATION_VERSION:
        return None
    if "display_bucket" not in raw_payload:
        return None
    result_layer = _normalize_text(raw_payload.get("result_layer") or row.get("result_layer") or "")
    if result_layer not in {"clue", "sensitive"}:
        result_layer = _code_result_layer(str(row.get("sensitive_type") or ""), raw_payload, str(row.get("result_layer") or ""))
    computed_sensitive_type = _normalize_text(raw_payload.get("sensitive_type") or row.get("sensitive_type") or "")
    computed_matched_rule = _normalize_text(raw_payload.get("matched_rule") or row.get("matched_rule") or "")
    computed_score = _coerce_payload_int(raw_payload.get("risk_score"), row.get("risk_score") or 0)
    computed_severity = _normalize_text(raw_payload.get("severity") or row.get("severity") or "low")
    display_bucket = _normalize_text(raw_payload.get("display_bucket"))
    if display_bucket not in {"primary", "suppressed"}:
        display_bucket = "suppressed" if _coerce_payload_bool(raw_payload.get("suppressed")) else "primary"
    suppressed = display_bucket == "suppressed" or _coerce_payload_bool(raw_payload.get("suppressed"))
    sensitive_label = (
        CODE_CLUE_RULE_LABEL
        if result_layer == "clue"
        else SENSITIVE_RULE_MAP.get(computed_sensitive_type, SensitiveRule("", "", re.compile(""), 0)).label
        or computed_sensitive_type
    )
    secret_like_rule = SENSITIVE_RULE_MAP.get(computed_sensitive_type)
    return {
        "id": int(row["id"]),
        "watchlistId": int(row["watchlist_id"]),
        "watchlistName": row.get("watchlist_name") or "",
        "organizationName": row.get("organization_name") or "",
        "platform": row.get("platform") or "",
        "platformLabel": _platform_label(str(row.get("platform") or "")),
        "repositoryName": row.get("repository_name") or "",
        "repositoryOwner": row.get("repository_owner") or "",
        "repositoryFullName": "/".join(
            part for part in [row.get("repository_owner") or "", row.get("repository_name") or ""] if part
        ),
        "repositoryUrl": row.get("repository_url") or "",
        "filePath": row.get("file_path") or "",
        "branch": row.get("branch") or "",
        "fileUrl": row.get("file_url") or "",
        "visibility": row.get("visibility") or "public",
        "language": row.get("language") or raw_payload.get("language") or "",
        "sensitiveType": computed_sensitive_type,
        "sensitiveLabel": sensitive_label,
        "matchedRule": computed_matched_rule,
        "matchedTerm": row.get("matched_term") or "",
        "resultLayer": result_layer,
        "resultLayerLabel": "敏感命中" if result_layer == "sensitive" else "线索命中",
        "riskScore": computed_score,
        "severity": computed_severity,
        "enterpriseMatchLevel": _normalize_text(raw_payload.get("enterprise_match_level") or "none"),
        "enterpriseAnchors": _payload_dict_list(raw_payload.get("enterprise_anchors")),
        "riskPromotionReasons": _payload_string_list(raw_payload.get("risk_promotion_reasons")),
        "credentialLiteralDetected": _coerce_payload_bool(raw_payload.get("credential_literal_detected")),
        "systemAccessDetected": _coerce_payload_bool(raw_payload.get("system_access_detected")),
        "suppressed": suppressed,
        "suppressionReasons": _payload_string_list(raw_payload.get("suppression_reasons")),
        "displayBucket": display_bucket,
        "reviewStatus": row.get("review_status") or "new",
        "evidenceCount": int(row.get("evidence_count") or 0),
        "firstSeenAt": row.get("first_seen_at") or "",
        "lastSeenAt": row.get("last_seen_at") or "",
        "lastSnapshotId": row.get("last_snapshot_id"),
        "summary": _stored_code_hit_summary(raw_payload),
        "secretLike": bool((secret_like_rule and secret_like_rule.secret_like) or _coerce_payload_bool(raw_payload.get("credential_literal_detected"))),
    }


def list_code_hits_payload(
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    sensitive_type: str | None = None,
    limit: int | None = 200,
    include_suppressed: bool = False,
) -> list[dict[str, Any]]:
    if not include_suppressed:
        return _build_code_hits_payload(
            watchlist_id=watchlist_id,
            review_status=review_status,
            platform=platform,
            sensitive_type=sensitive_type,
            limit=limit,
            include_suppressed=include_suppressed,
        )

    revision = _code_hits_payload_cache_revision()
    cache_key = (
        int(watchlist_id) if watchlist_id is not None else None,
        str(review_status or ""),
        str(platform or ""),
        str(sensitive_type or ""),
        bool(include_suppressed),
        revision,
    )
    now = time.monotonic()
    with _CODE_HITS_PAYLOAD_CACHE_LOCK:
        cached = _CODE_HITS_PAYLOAD_CACHE.get(cache_key)
        if cached and now - cached[0] <= _CODE_HITS_PAYLOAD_CACHE_TTL_SECONDS:
            return _slice_code_hits_payloads(cached[1], limit)
        payloads = _build_code_hits_payload(
            watchlist_id=watchlist_id,
            review_status=review_status,
            platform=platform,
            sensitive_type=sensitive_type,
            limit=None,
            include_suppressed=include_suppressed,
        )
        _CODE_HITS_PAYLOAD_CACHE[cache_key] = (time.monotonic(), payloads)
        _prune_code_hits_payload_cache(cache_key)
        return _slice_code_hits_payloads(payloads, limit)


def _parse_code_hit_filter_datetime(value: str) -> datetime | None:
    text = _normalize_text(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid code hit timestamp: {text}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def paginate_code_hits_payloads(
    items: list[dict[str, Any]],
    *,
    query: str = "",
    severity: str = "",
    result_layer: str = "",
    bucket: str = "all",
    seen_after: str = "",
    seen_before: str = "",
    offset: int = 0,
    limit: int | None = 50,
) -> dict[str, Any]:
    normalized_query = _normalize_text(query).casefold()
    normalized_severity = _normalize_text(severity).lower()
    normalized_layer = _normalize_text(result_layer).lower()
    normalized_bucket = _normalize_text(bucket).lower() or "all"
    if normalized_bucket not in {"all", "primary", "suppressed"}:
        raise ValueError("bucket must be one of: all, primary, suppressed")
    after = _parse_code_hit_filter_datetime(seen_after)
    before = _parse_code_hit_filter_datetime(seen_before)
    filtered: list[dict[str, Any]] = []
    for item in items:
        item_bucket = "suppressed" if bool(item.get("suppressed")) or item.get("displayBucket") == "suppressed" else "primary"
        if normalized_bucket != "all" and item_bucket != normalized_bucket:
            continue
        if normalized_severity and _normalize_text(item.get("severity")).lower() != normalized_severity:
            continue
        if normalized_layer and _normalize_text(item.get("resultLayer")).lower() != normalized_layer:
            continue
        seen_at = _parse_code_hit_filter_datetime(str(item.get("firstSeenAt") or ""))
        if after is not None and (seen_at is None or seen_at < after):
            continue
        if before is not None and (seen_at is None or seen_at > before):
            continue
        if normalized_query:
            haystack = "\n".join(
                str(value or "")
                for value in (
                    item.get("repositoryFullName"),
                    item.get("repositoryName"),
                    item.get("repositoryUrl"),
                    item.get("filePath"),
                    item.get("matchedTerm"),
                    item.get("sensitiveLabel"),
                    item.get("matchedRule"),
                    item.get("watchlistName"),
                    item.get("organizationName"),
                    " ".join(item.get("suppressionReasons") or []),
                )
            ).casefold()
            if normalized_query not in haystack:
                continue
        filtered.append(item)
    safe_offset = max(0, int(offset or 0))
    safe_limit = None if limit is None else min(200, max(1, int(limit or 50)))
    end = None if safe_limit is None else safe_offset + safe_limit
    return {
        "items": [dict(item) for item in filtered[safe_offset:end]],
        "total": len(filtered),
        "offset": safe_offset,
        "limit": safe_limit,
    }


def search_code_hits_page(
    *,
    watchlist_id: int | None = None,
    platform: str = "",
    query: str = "",
    severity: str = "",
    result_layer: str = "",
    bucket: str = "all",
    seen_after: str = "",
    seen_before: str = "",
    recent_hours: int | None = None,
    offset: int = 0,
    limit: int | None = 50,
) -> dict[str, Any]:
    if recent_hours is not None:
        if recent_hours <= 0 or recent_hours > 24 * 365:
            raise ValueError("recent_hours must be between 1 and 8760")
        if _normalize_text(seen_after):
            raise ValueError("recent_hours and seen_after cannot be used together")
        seen_after = (datetime.now(timezone.utc) - timedelta(hours=recent_hours)).isoformat()
    items = list_code_hits_payload(
        watchlist_id=watchlist_id,
        platform=platform or None,
        limit=None,
        include_suppressed=True,
    )
    return paginate_code_hits_payloads(
        items,
        query=query,
        severity=severity,
        result_layer=result_layer,
        bucket=bucket,
        seen_after=seen_after,
        seen_before=seen_before,
        offset=offset,
        limit=limit,
    )


def build_code_hit_detail(hit_id: int) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        row = get_code_hit(connection, hit_id)
        if row is None:
            return None
        watchlist = get_code_watchlist(connection, int(row["watchlist_id"]))
        watchlist_terms = list_code_watch_terms(connection, int(row["watchlist_id"]))
        public_watchlist_name, public_organization_name = _code_watchlist_public_identity(watchlist, watchlist_terms)
        if _is_legacy_code_placeholder(watchlist) and not public_watchlist_name:
            return None
        snapshots = list_code_hit_snapshots(connection, hit_id)
        reviews = list_code_hit_reviews(connection, hit_id)
    raw_payload = _parse_json(row.get("raw_json"), {})
    formatted_snapshots: list[dict[str, Any]] = []
    for item in snapshots:
        html_path = Path(str(item.get("html_path") or "")) if item.get("html_path") else None
        artifact_path = Path(str(item.get("raw_artifact_path") or "")) if item.get("raw_artifact_path") else None
        formatted_snapshots.append(
            {
                "id": int(item["id"]),
                "fetchedAt": item.get("fetched_at") or "",
                "searchUrl": item.get("search_url") or "",
                "pageUrl": item.get("page_url") or "",
                "htmlPath": str(html_path or ""),
                "htmlUrl": _public_output_url(html_path) if html_path else "",
                "screenshotPath": "",
                "screenshotUrl": "",
                "rawArtifactPath": str(artifact_path or ""),
                "rawArtifactUrl": _public_output_url(artifact_path) if artifact_path else "",
                "codeFragment": item.get("code_fragment") or "",
                "maskedFragment": item.get("masked_fragment") or "",
                "lineStart": int(item.get("line_start") or 0),
                "lineEnd": int(item.get("line_end") or 0),
                "language": item.get("language") or "",
                "findings": _normalize_findings_payload(item.get("findings_json")),
            }
        )
    latest_snapshot = formatted_snapshots[0] if formatted_snapshots else {}
    preview_assets = []
    if latest_snapshot.get("htmlUrl"):
        preview_assets.append({"kind": "html", "label": "页面快照", "url": latest_snapshot["htmlUrl"]})
    if latest_snapshot.get("rawArtifactUrl"):
        preview_assets.append({"kind": "artifact", "label": "原始抓取", "url": latest_snapshot["rawArtifactUrl"]})
    term_type = _normalize_text(((raw_payload or {}).get("term_type") or ""))
    enterprise_profile = _watchlist_enterprise_profile(watchlist, watchlist_terms)
    analysis_text = _snapshot_analysis_text(latest_snapshot, raw_payload)
    candidate = ((raw_payload or {}).get("candidate") or {}) if isinstance(raw_payload, dict) else {}
    enterprise_match = (
        _evaluate_enterprise_match(enterprise_profile, str(row.get("matched_term") or ""), candidate, analysis_text)
        if _enterprise_profile_enabled(enterprise_profile)
        else None
    )
    findings = latest_snapshot.get("findings") or []
    classification = _classify_code_hit(
        str(row.get("matched_term") or ""),
        str(row.get("file_path") or ""),
        analysis_text,
        _normalize_string_list(_watchlist_metadata(watchlist or {}).get("enabled_rule_keys"), fallback=DEFAULT_RULE_KEYS),
        term_type=term_type,
        enterprise_match=enterprise_match,
        context_metadata=candidate,
    )
    if classification is not None:
        findings = classification.get("findings") or findings
    result_layer = (classification or {}).get("result_layer") or _code_result_layer(
        str(row.get("sensitive_type") or ""),
        raw_payload,
        str(row.get("result_layer") or ""),
    )
    computed_sensitive_type = str((classification or {}).get("sensitive_type") or row.get("sensitive_type") or "")
    computed_matched_rule = str((classification or {}).get("matched_rule") or row.get("matched_rule") or "")
    code_preview = _rebuild_code_preview(
        str(row.get("matched_term") or ""),
        latest_snapshot,
        raw_payload,
        findings,
    )
    risk_score = int((classification or {}).get("risk_score") or row.get("risk_score") or 0)
    severity = str((classification or {}).get("severity") or row.get("severity") or "low")
    matched_term_contexts = _extract_matched_term_contexts(str(row.get("matched_term") or ""), row, latest_snapshot, raw_payload)
    clue_markers = list(raw_payload.get("clue_markers") or []) if isinstance(raw_payload, dict) else _collect_clue_markers(str(row.get("matched_term") or ""), code_preview)
    risk_reasons = (
        _build_code_risk_reasons(str(row.get("matched_term") or ""), str(row.get("file_path") or ""), findings)
        if result_layer == "sensitive"
        else _build_code_clue_reasons(str(row.get("matched_term") or ""), str(row.get("file_path") or ""), clue_markers)
    )
    risk_reasons.extend([item for item in (classification or {}).get("risk_promotion_reasons") or [] if item not in risk_reasons])
    risk_reasons.extend([item for item in (classification or {}).get("suppression_reasons") or [] if item not in risk_reasons])
    sensitive_label = CODE_CLUE_RULE_LABEL if result_layer == "clue" else SENSITIVE_RULE_MAP.get(computed_sensitive_type, SensitiveRule("", "", re.compile(""), 0)).label or computed_sensitive_type
    return {
        "id": int(row["id"]),
        "watchlistId": int(row["watchlist_id"]),
        "watchlistName": public_watchlist_name,
        "organizationName": public_organization_name,
        "platform": row.get("platform") or "",
        "platformLabel": _platform_label(str(row.get("platform") or "")),
        "repositoryName": row.get("repository_name") or "",
        "repositoryOwner": row.get("repository_owner") or "",
        "repositoryFullName": "/".join(
            part for part in [row.get("repository_owner") or "", row.get("repository_name") or ""] if part
        ),
        "repositoryUrl": row.get("repository_url") or "",
        "filePath": row.get("file_path") or "",
        "branch": row.get("branch") or "",
        "fileUrl": row.get("file_url") or "",
        "visibility": row.get("visibility") or "public",
        "language": row.get("language") or "",
        "sensitiveType": computed_sensitive_type,
        "sensitiveLabel": sensitive_label,
        "matchedRule": computed_matched_rule,
        "matchedTerm": row.get("matched_term") or "",
        "resultLayer": result_layer,
        "resultLayerLabel": "敏感命中" if result_layer == "sensitive" else "线索命中",
        "matchedTermContexts": matched_term_contexts,
        "riskScore": risk_score,
        "severity": severity,
        "enterpriseMatchLevel": (classification or {}).get("enterprise_match_level") or str((enterprise_match or {}).get("level") or "none"),
        "enterpriseAnchors": (classification or {}).get("enterprise_anchors") or list((enterprise_match or {}).get("anchors") or []),
        "riskPromotionReasons": (classification or {}).get("risk_promotion_reasons") or [],
        "credentialLiteralDetected": bool((classification or {}).get("credential_literal_detected")),
        "systemAccessDetected": bool((classification or {}).get("system_access_detected")),
        "suppressed": bool((classification or {}).get("suppressed")),
        "suppressionReasons": (classification or {}).get("suppression_reasons") or [],
        "displayBucket": (classification or {}).get("display_bucket") or ("suppressed" if (classification or {}).get("suppressed") else "primary"),
        "reviewStatus": row.get("review_status") or "new",
        "evidenceCount": int(row.get("evidence_count") or 0),
        "firstSeenAt": row.get("first_seen_at") or "",
        "lastSeenAt": row.get("last_seen_at") or "",
        "rawPayload": raw_payload,
        "latestSnapshot": latest_snapshot,
        "previewAssets": preview_assets,
        "snapshots": formatted_snapshots,
        "reviews": reviews,
        "findings": findings,
        "codePreview": code_preview,
        "sourceLinks": [
            {"label": "仓库地址", "url": row.get("repository_url") or ""},
            {"label": "文件地址", "url": row.get("file_url") or ""},
            {"label": "检索页面", "url": latest_snapshot.get("searchUrl") or ""},
        ],
        "riskAnalysis": {
            "score": risk_score,
            "severity": severity,
            "reasons": risk_reasons,
        },
    }


def add_code_monitoring_review(hit_id: int, *, status: str, reviewer: str = "", note: str = "") -> dict[str, Any]:
    with get_db_connection() as connection:
        add_code_hit_review(
            connection,
            {
                "hit_id": int(hit_id),
                "status": status,
                "reviewer": reviewer,
                "note": note,
                "created_at": _now_utc_iso(),
            },
        )
        connection.commit()
    detail = build_code_hit_detail(hit_id)
    if detail is None:
        raise ValueError(f"code hit not found: {hit_id}")
    return detail


def list_code_scan_runs_payload(watchlist_id: int | None = None, limit: int | None = 50) -> list[dict[str, Any]]:
    ensure_default_code_watchlist()
    with get_db_connection() as connection:
        rows = list_code_scan_runs(connection, watchlist_id=watchlist_id, limit=limit)
    payloads: list[dict[str, Any]] = []
    for row in rows:
        requested_terms = _parse_json(row.get("requested_terms_json"), [])
        term_rows = [item if isinstance(item, dict) else {"term": item, "term_type": ""} for item in requested_terms]
        public_name, public_organization = _code_watchlist_public_identity(row, term_rows)
        if _is_legacy_code_placeholder(row) and not public_name:
            continue
        payloads.append(
            {
                "id": int(row["id"]),
                "watchlistId": int(row["watchlist_id"]),
                "watchlistName": public_name,
                "organizationName": public_organization,
                "platforms": _normalize_string_list(row.get("platforms_json"), fallback=DEFAULT_CODE_PLATFORMS),
                "requestedTerms": requested_terms,
                "candidateCount": int(row.get("candidate_count") or 0),
                "hitCount": int(row.get("hit_count") or 0),
                "clueHitCount": int(row.get("clue_hit_count") or 0),
                "sensitiveHitCount": int(row.get("sensitive_hit_count") or 0),
                "errorCount": int(row.get("error_count") or 0),
                "status": str(row.get("status") or "unknown"),
                "errors": _parse_json(row.get("errors_json"), []),
                "startedAt": str(row.get("started_at") or ""),
                "finishedAt": str(row.get("finished_at") or ""),
            }
        )
    return payloads


def _format_day_bucket(value: str) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:10]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(SHANGHAI_TZ).date().isoformat()


def build_code_monitoring_summary() -> dict[str, Any]:
    rows = list_code_hits_payload(limit=None, include_suppressed=True)
    now = datetime.now(SHANGHAI_TZ).date()
    trend_counter: dict[str, int] = {}
    for offset in range(6, -1, -1):
        day = (now - timedelta(days=offset)).isoformat()
        trend_counter[day] = 0
    for row in rows:
        bucket = _format_day_bucket(row.get("firstSeenAt"))
        if bucket in trend_counter:
            trend_counter[bucket] += 1

    platform_counts: dict[str, int] = {}
    sensitive_counts: dict[str, int] = {}
    risk_counts = {"high": 0, "medium": 0, "low": 0}
    review_counts: dict[str, int] = {}
    high_risk_repos: set[str] = set()
    secret_like_count = 0
    recent_count = 0
    clue_hit_count = 0
    sensitive_hit_count = 0
    suppressed_hit_count = 0
    primary_hit_count = 0
    repositories: dict[str, str] = {}
    severity_rank = {"low": 1, "medium": 2, "high": 3}
    for row in rows:
        platform_counts[row["platformLabel"]] = platform_counts.get(row["platformLabel"], 0) + 1
        sensitive_label = _normalize_text(row.get("sensitiveLabel")) or (
            SENSITIVE_RULE_MAP.get(str(row.get("sensitiveType") or ""), SensitiveRule("", "", re.compile(""), 0)).label
            or str(row.get("sensitiveType") or "未知")
        )
        sensitive_counts[sensitive_label] = sensitive_counts.get(sensitive_label, 0) + 1
        risk_counts[str(row.get("severity") or "low")] = risk_counts.get(str(row.get("severity") or "low"), 0) + 1
        review_key = str(row.get("reviewStatus") or "new")
        review_counts[review_key] = review_counts.get(review_key, 0) + 1
        if str(row.get("severity") or "low") == "high":
            high_risk_repos.add(str(row.get("repositoryUrl") or ""))
        if bool(row.get("secretLike")):
            secret_like_count += 1
        if bool(row.get("suppressed")):
            suppressed_hit_count += 1
        else:
            primary_hit_count += 1
        if str(row.get("resultLayer") or "sensitive") == "clue":
            clue_hit_count += 1
        else:
            sensitive_hit_count += 1
        repository_key = _normalize_text(row.get("repositoryFullName") or row.get("repositoryUrl") or row.get("repositoryName"))
        repository_severity = str(row.get("severity") or "low")
        if repository_key and severity_rank.get(repository_severity, 0) > severity_rank.get(repositories.get(repository_key, ""), 0):
            repositories[repository_key] = repository_severity
        if _format_day_bucket(row.get("firstSeenAt")) == now.isoformat():
            recent_count += 1

    watchlists = list_code_watchlists_payload()
    enabled_term_count = sum(
        1
        for watchlist in watchlists
        for term in (watchlist.get("terms") or [])
        if bool(term.get("enabled"))
    )
    sessions = build_platform_session_payloads(module="code_monitoring", manageable_only=True)
    configured_sessions = [item for item in sessions if bool(item.get("configured"))]
    invalid_sessions = [item for item in sessions if str(item.get("status") or "") in {"invalid", "missing", "unavailable"}]
    latest_scan = list_code_scan_runs_payload(limit=1)
    latest_scan_row = latest_scan[0] if latest_scan else {}
    return {
        "totalHits": len(rows),
        "sensitiveSnippetCount": sensitive_hit_count,
        "clueHitCount": clue_hit_count,
        "primaryHitCount": primary_hit_count,
        "suppressedHitCount": suppressed_hit_count,
        "repositoryCount": len(repositories),
        "publicRepositoryCount": len(repositories),
        "highRiskRepositoryCount": sum(1 for value in repositories.values() if value == "high"),
        "repositoryRiskDistribution": [
            {"name": "高危", "value": sum(1 for value in repositories.values() if value == "high")},
            {"name": "中危", "value": sum(1 for value in repositories.values() if value == "medium")},
            {"name": "低危", "value": sum(1 for value in repositories.values() if value == "low")},
        ],
        "secretLikeCount": secret_like_count,
        "highRiskRepoCount": len([item for item in high_risk_repos if item]),
        "platformCount": len(platform_counts),
        "configuredSessionCount": len(configured_sessions),
        "invalidSessionCount": len(invalid_sessions),
        "watchlistCount": len(watchlists),
        "enabledTermCount": enabled_term_count,
        "lastScanAt": str(latest_scan_row.get("finishedAt") or ""),
        "lastCandidateCount": int(latest_scan_row.get("candidateCount") or 0),
        "lastHitCount": int(latest_scan_row.get("hitCount") or 0),
        "lastErrorCount": int(latest_scan_row.get("errorCount") or 0),
        "githubSearch": github_code_search_status_payload(),
        "recentCount": recent_count,
        "trend": [{"date": key, "value": value} for key, value in trend_counter.items()],
        "platformDistribution": [{"name": key, "value": value} for key, value in sorted(platform_counts.items(), key=lambda item: item[1], reverse=True)],
        "sensitiveTypeTop": [{"name": key, "value": value} for key, value in sorted(sensitive_counts.items(), key=lambda item: item[1], reverse=True)[:8]],
        "riskDistribution": [
            {"key": "high", "label": "高危", "value": risk_counts.get("high", 0)},
            {"key": "medium", "label": "中危", "value": risk_counts.get("medium", 0)},
            {"key": "low", "label": "低危", "value": risk_counts.get("low", 0)},
        ],
        "reviewDistribution": [{"key": key, "value": value} for key, value in sorted(review_counts.items(), key=lambda item: item[1], reverse=True)],
    }


def warm_code_monitoring_cache() -> dict[str, Any]:
    started_at = time.perf_counter()
    payload = build_code_monitoring_summary()
    logger.info(
        "code monitoring cache warmup completed in %.2fs for %s hits",
        time.perf_counter() - started_at,
        int(payload.get("totalHits") or 0),
    )
    return payload


def schedule_code_monitoring_cache_warmup() -> bool:
    global _CODE_HITS_WARMUP_RUNNING
    with _CODE_HITS_WARMUP_LOCK:
        if _CODE_HITS_WARMUP_RUNNING:
            return False
        _CODE_HITS_WARMUP_RUNNING = True

    def run() -> None:
        global _CODE_HITS_WARMUP_RUNNING
        try:
            warm_code_monitoring_cache()
        except Exception:
            logger.exception("code monitoring cache warmup failed")
        finally:
            with _CODE_HITS_WARMUP_LOCK:
                _CODE_HITS_WARMUP_RUNNING = False

    Thread(target=run, name="code-monitoring-cache-warmup", daemon=True).start()
    return True
