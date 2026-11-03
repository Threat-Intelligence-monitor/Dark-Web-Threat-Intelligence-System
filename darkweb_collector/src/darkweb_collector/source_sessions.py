"""Verified browser sessions shared with same-origin, same-proxy HTTP requests."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlsplit

from darkweb_collector.runtime import user_data_root
from darkweb_collector.session_cookies import resolve_session_cookie


def source_origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{host}:{port}"


def same_source(initial_url: str, final_url: str) -> bool:
    initial, final = source_origin(initial_url), source_origin(final_url)
    return bool(initial and (initial == final or (
        initial.startswith("http://") and initial.endswith(":80")
        and final == "https://" + initial[7:-3] + ":443"
    )))


def _state_path(config) -> Path:
    configured = str(config.extras.get("browser_storage_state_file") or "").strip()
    path = Path(configured).expanduser() if configured else Path("browser-state") / config.site_name / "storage-state.json"
    return (path if path.is_absolute() else user_data_root() / path).resolve()


def _sidecar(path: Path) -> Path:
    return path.with_name(path.name + ".session.json")


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _digest(value: bytes | None) -> str:
    return hashlib.sha256(value).hexdigest() if value is not None else "missing"


def _proxy_digest(proxy_server) -> str:
    return _digest(str(proxy_server or "direct").encode("utf-8"))


def _decode(raw: bytes | None) -> dict:
    try:
        value = json.loads(raw or b"{}")
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError):
        return {}


def _state_metadata(metadata_raw: bytes | None, state_raw: bytes | None) -> dict:
    document = _decode(metadata_raw)
    if isinstance(document.get("states"), dict):
        selected = document["states"].get(_digest(state_raw), {})
        return selected if isinstance(selected, dict) else {}
    return document  # Existing flat sidecars remain readable.


def _snapshot(path: Path, url: str, proxy_server):
    raw, metadata_raw = _read(path), _read(_sidecar(path))
    state, metadata = _decode(raw), _state_metadata(metadata_raw, raw)
    verified = bool(raw and metadata.get("state_sha256") == _digest(raw)
                    and metadata.get("origin") == source_origin(url)
                    and metadata.get("proxy_sha256") == _proxy_digest(proxy_server)
                    and metadata.get("user_agent"))
    return state, metadata, verified, _digest(raw) + ":" + _digest(metadata_raw), metadata_raw is not None


def _cookie_matches(cookie: dict, url: str, *, match_path=True) -> bool:
    if not isinstance(cookie.get("name"), str) or not cookie["name"] or not isinstance(cookie.get("value"), str):
        return False
    parsed = urlsplit(url)
    host, domain = (parsed.hostname or "").lower(), str(cookie.get("domain") or "").lower()
    if not domain or not (host == domain.lstrip(".") or domain.startswith(".") and host.endswith(domain)):
        return False
    if cookie.get("secure") and parsed.scheme != "https":
        return False
    try:
        expires = float(cookie.get("expires", -1))
    except (TypeError, ValueError):
        return False
    if not math.isfinite(expires) or expires != -1 and expires <= time.time():
        return False
    path, requested = str(cookie.get("path") or "/"), parsed.path or "/"
    return not match_path or requested == path or requested.startswith(path) and (path.endswith("/") or requested[len(path):].startswith("/"))


def read_browser_session(path: Path, url: str, proxy_server, engine: str):
    state, metadata, verified, revision, has_metadata = _snapshot(path, url, proxy_server)
    if has_metadata and (not verified or metadata.get("browser_engine") != engine):
        return None, revision, None
    # Configured legacy Playwright files may be loaded by the browser. HTTP
    # reuse only starts after this browser has verified the current source.
    cookies = state.get("cookies", [])
    origins = state.get("origins", [])
    if not isinstance(cookies, list) or not isinstance(origins, list):
        return None, revision, None
    filtered = {
        "cookies": [cookie for cookie in cookies if isinstance(cookie, dict) and _cookie_matches(cookie, url, match_path=False)],
        "origins": [origin for origin in origins if isinstance(origin, dict) and source_origin(str(origin.get("origin") or "")) == source_origin(url)],
    }
    return filtered, revision, str(metadata["user_agent"]) if verified else None


@contextmanager
def _session_lock(path: Path):
    with path.with_name(path.name + ".lock").open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def persist_browser_session(state: dict, path: Path, *, url: str, proxy_server,
                            user_agent: str, engine: str, expected_revision: str) -> bool:
    """Commit a verified context only if no newer session replaced our input."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _session_lock(path):
        previous_raw, previous_metadata_raw = _read(path), _read(_sidecar(path))
        revision = _digest(previous_raw) + ":" + _digest(previous_metadata_raw)
        if revision != expected_revision:
            return False
        raw = json.dumps(state, ensure_ascii=False).encode("utf-8")
        if raw == previous_raw:
            # Keep adjacent commits distinguishable even when cookies do not
            # change; a final newline is still standard Playwright JSON.
            raw += b"\n"
        metadata = {"origin": source_origin(url), "proxy_sha256": _proxy_digest(proxy_server),
                    "user_agent": user_agent, "browser_engine": engine,
                    "state_sha256": _digest(raw), "verified_at_ns": time.time_ns()}
        states = {_digest(raw): metadata}
        previous_metadata = _state_metadata(previous_metadata_raw, previous_raw)
        if previous_raw is not None and previous_metadata.get("state_sha256") == _digest(previous_raw):
            states[_digest(previous_raw)] = previous_metadata
        manifest = json.dumps({"states": states}, ensure_ascii=False).encode("utf-8")
        temporary = []
        try:
            # Stage both generations' metadata first. Replacing the state file
            # is the commit point; any failure leaves its matching metadata.
            for destination, content in ((_sidecar(path), manifest), (path, raw)):
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".session-", delete=False) as stream:
                    temporary.append((Path(stream.name), destination))
                    stream.write(content)
            for source, destination in temporary:
                os.replace(source, destination)
        finally:
            for source, _ in temporary:
                source.unlink(missing_ok=True)
    return True


def _explicit_cookie(config, url: str) -> str | None:
    if not any(same_source(seed, url) for seed in config.seed_urls):
        return None
    return resolve_session_cookie(config)


def browser_session_options(config, url: str, proxy_server=None) -> dict:
    allowed = any(same_source(seed, url) for seed in config.seed_urls)
    default_engine = "chromium" if config.site_name in {"cracked", "xforums"} else "firefox"
    return {"browser_engine": str(config.extras.get("browser_engine") or default_engine).strip().lower(),
            "storage_state_path": str(_state_path(config)) if allowed else None, "persist_storage_state": allowed,
            "cookie_header": _explicit_cookie(config, url)}


def http_session_options(config, url: str, proxy_server=None) -> dict:
    if not any(same_source(seed, url) for seed in config.seed_urls):
        return {"cookie_header": None, "user_agent": None, "cookies": []}
    state, metadata, verified, _, _ = _snapshot(_state_path(config), url, proxy_server)
    cookies = state.get("cookies", []) if verified else []
    user_agent = str(metadata.get("user_agent") or "") if verified else ""
    if not isinstance(cookies, list) or not user_agent or re.search(r"[\r\n\x00]", user_agent):
        cookies, user_agent = [], ""
    selected_cookies = []
    for cookie in sorted((row for row in cookies if isinstance(row, dict)), key=lambda row: -len(str(row.get("path") or "/"))):
        name, value = str(cookie.get("name") or ""), str(cookie.get("value") or "")
        if name and not re.search(r"[\s=;\x00-\x1f\x7f]", name) and not re.search(r"[;\r\n\x00]", value) and _cookie_matches(cookie, url):
            selected_cookies.append(dict(cookie))
    # Existing explicit env > file > inline policy wins over learned cookies
    # with the same name, while preserving the browser's other clearance cookies.
    selected = {}
    for item in str(_explicit_cookie(config, url) or "").split(";"):
        name, separator, value = item.strip().partition("=")
        if separator and name and not re.search(r"[\s=;\x00-\x1f\x7f]", name) and not re.search(r"[\r\n\x00]", value):
            selected[name] = value
    return {"cookie_header": "; ".join(f"{name}={value}" for name, value in selected.items()) or None,
            "user_agent": user_agent or None,
            "cookies": [cookie for cookie in selected_cookies if cookie["name"] not in selected]}
