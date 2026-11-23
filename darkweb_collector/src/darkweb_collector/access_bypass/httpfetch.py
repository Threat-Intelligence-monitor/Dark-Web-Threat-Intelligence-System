"""HTTP fetching with a browser fingerprint.

The plain ``curl`` path in :mod:`darkweb_collector.tor_fetch` loses against every
modern edge because its TLS ClientHello (JA3/JA4), HTTP/2 settings and header
*sets* are not those of a browser.  The User-Agent is irrelevant by comparison:
``darkforums.as`` answers a real Chrome or ``curl_cffi --impersonate chrome``
with the full forum page and answers plain curl with ``403 cf-mitigated:
challenge``, same UA, same IP.

This module is the HTTP side of the bypass module:

1. replay a persisted clearance cookie when one is valid for this host *and*
   this user-agent family *and* this egress path (:mod:`clearance`),
2. pace the host (:mod:`pacing`),
3. send a browser-consistent header set (:mod:`headers`) over a ``curl_cffi``
   impersonated TLS/HTTP2 stack,
4. classify whatever came back (:mod:`detect`) and raise the collector's
   ``CollectionFailure`` kinds so the adapter falls back to the browser route
   instead of pretending the page is empty.

``curl_cffi`` is optional.  When it is missing the module degrades to
``curl.exe`` with the same header set (a weaker fingerprint, but no import
error on a stock install).
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from darkweb_collector.access_bypass import clearance, detect, pacing
from darkweb_collector.access_bypass.headers import build_headers, identity_for
from darkweb_collector.access_bypass.model import BypassProfile, ProtectionSignal
from darkweb_collector.collection_errors import (
    CollectionFailure,
    managed_request,
    request_attempt,
)

try:  # pragma: no cover - exercised through the fallback test
    from curl_cffi import requests as _cffi_requests
    from curl_cffi import CurlError as _CffiCurlError

    CURL_CFFI_AVAILABLE = True
except Exception:  # pragma: no cover - curl_cffi is an optional dependency
    _cffi_requests = None  # type: ignore[assignment]
    _CffiCurlError = ()  # type: ignore[assignment]
    CURL_CFFI_AVAILABLE = False

#: Impersonation targets that are actually installed, in preference order.
PREFERRED_IMPERSONATIONS = ("chrome", "chrome136", "chrome131", "safari", "firefox")

#: Session cache bounds (per thread).
MAX_SESSIONS = 8
SESSION_IDLE_SECONDS = 900.0

_LOCAL = threading.local()


@dataclass(frozen=True)
class HttpFetchOptions:
    """Resolved options for one HTTP request."""

    profile: BypassProfile
    impersonate: str = "chrome"
    proxy: str = ""
    user_agent: str = ""
    deadline: float | None = None
    on_event: Callable[[Mapping[str, Any]], None] | None = None


def host_key(url: str) -> str:
    """Normalised host (with port) used as the pacing/clearance key."""

    parts = urlsplit(url or "")
    return (parts.netloc or "").strip().lower()


def supported_impersonations() -> tuple[str, ...]:
    if not CURL_CFFI_AVAILABLE:
        return ()
    try:
        from curl_cffi.requests import BrowserType  # type: ignore

        return tuple(item.value for item in BrowserType)  # type: ignore[attr-defined]
    except Exception:
        return PREFERRED_IMPERSONATIONS


def resolve_impersonation(preferred: str, *, user_agent: str = "") -> str:
    """Pick an installed impersonation target, or ``""`` when unavailable."""

    if not CURL_CFFI_AVAILABLE:
        return ""
    available = supported_impersonations()
    candidates = [preferred, *PREFERRED_IMPERSONATIONS]
    # A persisted browser UA must drive the impersonation, otherwise the TLS
    # profile and the claimed version disagree on every request.
    lowered = (user_agent or "").lower()
    if "firefox/" in lowered:
        candidates = ["firefox", "firefox135", "firefox133", *candidates]
    elif "edg/" in lowered:
        candidates = ["edge", "edge101", *candidates]
    elif "safari/" in lowered and "chrome/" not in lowered:
        candidates = ["safari", "safari184", "safari180", *candidates]
    for name in candidates:
        if not name:
            continue
        if name in available:
            return name
        if not available:  # pragma: no cover - unknown curl_cffi layout
            return name
    return available[0] if available else ""


def _proxy_url(*, proxy_host: str | None, proxy_port: int | str | None) -> str:
    """Resolve the egress proxy for the impersonation route.

    ``PROXY_HOST``/``PROXY_PORT`` win (the collector's own names).  When they are
    unset — which is the common case on machines where only the shell exports a
    proxy — fall back to ``HTTPS_PROXY``/``HTTP_PROXY``/``ALL_PROXY``: sites such
    as ``spear.cx`` resolve only through that proxy, and a TLS handshake sent
    direct is dropped before any HTTP status exists to classify.
    """

    host = (proxy_host or os.environ.get("PROXY_HOST") or "").strip()
    port = proxy_port if proxy_port not in (None, "") else os.environ.get("PROXY_PORT")
    if host and port:
        if "://" in host:
            scheme, _, rest = host.partition("://")
            return f"{scheme}://{rest}:{port}"
        return f"http://{host}:{port}"
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        value = (os.environ.get(name) or "").strip()
        if not value:
            continue
        if "://" not in value:
            value = f"http://{value}"
        if value.lower().startswith("socks"):
            # Tor-style socks proxies are not usable with curl_cffi's HTTP client.
            continue
        return value
    return ""


def _session(impersonate: str, proxy: str) -> Any:
    """Thread-local ``curl_cffi`` session, reused to keep TLS sessions warm."""

    cache = getattr(_LOCAL, "sessions", None)
    if cache is None:
        cache = {}
        _LOCAL.sessions = cache
    key = (impersonate, proxy)
    now = time.time()
    entry = cache.get(key)
    if entry and now - entry[1] < SESSION_IDLE_SECONDS:
        entry[1] = now
        return entry[0]
    if len(cache) >= MAX_SESSIONS:
        oldest = min(cache.items(), key=lambda item: item[1][1])[0]
        try:
            cache.pop(oldest)[0].close()
        except Exception:
            cache.pop(oldest, None)
    session = _cffi_requests.Session(impersonate=impersonate)  # type: ignore[union-attr]
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}  # type: ignore[attr-defined]
    cache[key] = [session, now]
    return session


def _session_cookies(session: Any) -> list[dict[str, Any]]:
    """Read the session jar as plain dicts (curl_cffi exposes a CookieJar)."""

    jar = getattr(session, "cookies", None)
    if jar is None:
        return []
    cookies: list[dict[str, Any]] = []
    try:
        for cookie in jar.jar:  # http.cookiejar.CookieJar
            cookies.append({
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain or "",
                "path": cookie.path or "/",
                "expires": cookie.expires or 0,
                "secure": bool(cookie.secure),
                "httpOnly": "HttpOnly" in (getattr(cookie, "_rest", {}) or {}),
            })
        return cookies
    except Exception:
        pass
    try:
        for name, value in jar.get_dict().items():  # pragma: no cover - API drift
            cookies.append({"name": name, "value": value})
    except Exception:
        pass
    return cookies


def _seed_cookies(session: Any, cookies: Iterable[Mapping[str, Any]], host: str) -> None:
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        if not name:
            continue
        domain = str(cookie.get("domain") or "") or host
        try:
            session.cookies.set(
                name,
                str(cookie.get("value") or ""),
                domain=domain,
                path=str(cookie.get("path") or "/"),
            )
        except TypeError:  # pragma: no cover - older signature
            session.cookies.set(name, str(cookie.get("value") or ""))


def _merge_cookies(explicit: Iterable[Mapping[str, Any]],
                   stored: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Explicit session cookies win; stored clearance fills the gaps."""

    merged: dict[str, dict[str, Any]] = {}
    for cookie in stored:
        name = str(cookie.get("name") or "")
        if name:
            merged[name.lower()] = dict(cookie)
    for cookie in explicit:
        name = str(cookie.get("name") or "")
        if name:
            merged[name.lower()] = dict(cookie)
    return list(merged.values())


def _parse_cookie_header(cookie_header: str | None) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for part in (cookie_header or "").split(";"):
        name, sep, value = part.partition("=")
        if sep and name.strip():
            cookies.append({"name": name.strip(), "value": value.strip()})
    return cookies


def _header_dict(headers: Mapping[str, Any] | None) -> dict[str, str]:
    return {str(name): str(value) for name, value in (headers or {}).items()}


def _timeout_left(options: HttpFetchOptions, timeout: float) -> float:
    if options.deadline is None:
        return timeout
    return max(1.0, min(float(timeout), options.deadline - time.time()))


def _emit(options: HttpFetchOptions, payload: Mapping[str, Any]) -> None:
    if options.on_event is None:
        return
    try:
        options.on_event(payload)
    except Exception:
        pass


def _describe_failure(signal: ProtectionSignal, url: str) -> str:
    detail = signal.describe()
    return f"access blocked for {host_key(url)}: {detail}" if host_key(url) else f"access blocked: {detail}"


def _raise_for_status(status: int, html: str, headers: Mapping[str, Any] | None) -> None:
    """Delegate unknown statuses to the collector's existing taxonomy.

    Imported lazily: ``tor_fetch`` imports this module, so a module-level import
    would be circular.
    """

    from darkweb_collector.tor_fetch import raise_for_http_status

    raise_for_http_status(status, html, headers=dict(headers or {}))


def _raise_for_signal(signal: ProtectionSignal, url: str, *, headers: Mapping[str, Any] | None) -> None:
    host = host_key(url)
    if signal.kind == "rate-limit":
        pacing.penalise(host, seconds=signal.retry_after, status=signal.status or 429)
        raise CollectionFailure("rate_limited", _describe_failure(signal, url), scope="site",
                                retry_after=signal.retry_after)
    if signal.kind == "challenge":
        raise CollectionFailure("blocked", _describe_failure(signal, url), scope="target",
                                verification_provider=signal.vendor)
    if signal.kind == "login":
        raise CollectionFailure("auth_required", _describe_failure(signal, url), scope="site")
    if signal.kind == "forbidden":
        raise CollectionFailure("blocked", _describe_failure(signal, url), scope="target")


def fetch_via_http_proxy(
    url: str,
    proxy_host: str | None = None,
    proxy_port: int | None = None,
    timeout: int = 90,
    retries: int = 3,
    backoff_seconds: float = 3.0,
    cookie_header: str | None = None,
    bypass_proxy: bool = False,
    user_agent: str | None = None,
    cookies: list[dict] | None = None,
    *,
    profile: BypassProfile | None = None,
    deadline: float | None = None,
    on_event: Callable[[Mapping[str, Any]], None] | None = None,
) -> str:
    """Fetch ``url`` over HTTP with impersonation, clearance replay and pacing.

    Returns the HTML text.  Raises :class:`CollectionFailure` with the kinds the
    adapter layer already understands; ``blocked`` is deliberately *not*
    terminal there, so the caller can retry the same URL through the browser.
    """

    options = HttpFetchOptions(
        profile=profile or BypassProfile(),
        proxy="" if bypass_proxy else _proxy_url(proxy_host=proxy_host, proxy_port=proxy_port),
        user_agent=(user_agent or "").strip(),
        deadline=deadline,
        on_event=on_event,
    )
    strategy = options.profile.http_strategy
    impersonate = ""
    if strategy in {"auto", "impersonate", "browser"}:
        impersonate = resolve_impersonation(options.profile.impersonate, user_agent=options.user_agent)
    if strategy == "curl" or not impersonate:
        return _fetch_with_curl_cli(
            url, options=options, timeout=timeout, retries=retries,
            backoff_seconds=backoff_seconds, cookie_header=cookie_header, cookies=cookies,
        )
    options = HttpFetchOptions(
        profile=options.profile, impersonate=impersonate, proxy=options.proxy,
        user_agent=options.user_agent, deadline=options.deadline, on_event=options.on_event,
    )
    return _fetch_with_impersonation(
        url, options=options, timeout=timeout, retries=retries,
        backoff_seconds=backoff_seconds, cookie_header=cookie_header, cookies=cookies,
    )


def _fetch_with_impersonation(
    url: str,
    *,
    options: HttpFetchOptions,
    timeout: float,
    retries: int,
    backoff_seconds: float,
    cookie_header: str | None,
    cookies: list[dict] | None,
) -> str:
    host = host_key(url)
    stored = clearance.cookies_for(host, user_agent=options.user_agent, proxy_server=options.proxy)
    if stored and not options.user_agent:
        slot = clearance.slot_for(host, user_agent="", proxy_server=options.proxy)
        if slot and slot.user_agent:
            options = HttpFetchOptions(
                profile=options.profile, impersonate=options.impersonate, proxy=options.proxy,
                user_agent=slot.user_agent, deadline=options.deadline, on_event=options.on_event,
            )
    explicit = _merge_cookies(_parse_cookie_header(cookie_header), cookies or [])
    merged = _merge_cookies(explicit, stored)
    headers = build_headers(
        url,
        profile=options.profile.header_profile,
        impersonate=options.impersonate,
        user_agent=options.user_agent,
        include_user_agent=bool(options.user_agent),
    )
    attempts = 1 if managed_request() else max(0, int(retries)) + 1
    session = _session(options.impersonate, options.proxy)
    if merged:
        _seed_cookies(session, merged, host)

    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        wait_for = _timeout_left(options, timeout)
        pacing.wait(host, min_interval=options.profile.min_interval_seconds,
                    max_interval=options.profile.max_interval_seconds,
                    deadline=time.time() + wait_for)
        request_attempt()
        started = time.monotonic()
        try:
            response = session.request(
                "GET", url, headers=headers, timeout=wait_for,
                allow_redirects=True, impersonate=options.impersonate,
            )
        except Exception as exc:  # curl_cffi raises a family of transport errors
            last_error = exc
            pacing.mark_request(host, status=0)
            _emit(options, {"route": "impersonate", "url": url, "attempt": attempt,
                            "error": type(exc).__name__})
            if attempt < attempts:
                time.sleep(max(0.5, backoff_seconds * attempt))
                continue
            raise CollectionFailure("network", f"impersonated fetch failed for {host}: {exc}") from exc

        status = int(getattr(response, "status_code", 0) or 0)
        headers_in = _header_dict(getattr(response, "headers", None))
        html = _response_text(response)
        pacing.mark_request(host, status=status)
        signal = detect.classify_response(status, headers_in, html)
        _emit(options, {
            "route": "impersonate", "url": url, "attempt": attempt, "status": status,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "signal": signal.describe(), "bytes": len(html),
        })

        if signal.is_challenge:
            if stored:
                clearance.invalidate(host, user_agent=options.user_agent, proxy_server=options.proxy)
            raise CollectionFailure("blocked", _describe_failure(signal, url), scope="target",
                                    verification_provider=signal.vendor)
        if signal.kind == "rate-limit":
            _raise_for_signal(signal, url, headers=headers_in)
        if 200 <= status < 300:
            observed = _session_cookies(session)
            if detect.has_clearance_cookie(observed):
                clearance.record(host, observed, user_agent=options.user_agent,
                                 proxy_server=options.proxy, source="impersonate",
                                 challenge=signal.challenge)
            return html
        if signal.kind in {"login", "forbidden"}:
            _raise_for_signal(signal, url, headers=headers_in)
        if attempt < attempts and status in {0, 408, 425, 500, 502, 503, 504}:
            time.sleep(max(0.5, min(float(backoff_seconds) * attempt, 10.0)))
            continue
        _raise_for_status(status, html, headers_in)

    raise CollectionFailure("network", f"impersonated fetch failed for {host}: {last_error}")


def _response_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(response, "content", b"") or b""
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content)


def _fetch_with_curl_cli(
    url: str,
    *,
    options: HttpFetchOptions,
    timeout: float,
    retries: int,
    backoff_seconds: float,
    cookie_header: str | None,
    cookies: list[dict] | None,
) -> str:
    """``curl.exe`` fallback: same header set, no TLS impersonation."""

    host = host_key(url)
    curl = shutil.which("curl")
    if not curl:  # pragma: no cover - Windows always ships curl
        raise CollectionFailure("infrastructure", "curl not found in PATH")

    stored = clearance.cookies_for(host, user_agent=options.user_agent, proxy_server=options.proxy)
    if stored and not options.user_agent:
        slot = clearance.slot_for(host, user_agent="", proxy_server=options.proxy)
        if slot and slot.user_agent:
            options = HttpFetchOptions(
                profile=options.profile, impersonate="", proxy=options.proxy,
                user_agent=slot.user_agent, deadline=options.deadline, on_event=options.on_event,
            )
    identity = identity_for(options.profile.header_profile, impersonate="", user_agent=options.user_agent)
    headers = build_headers(url, identity=identity, user_agent=options.user_agent,
                            include_user_agent=True, navigation=True)
    # ``Connection`` is implied by curl and would be a hop-by-hop lie here.
    header_args: list[str] = []
    for name, value in headers.items():
        header_args.extend(["-H", f"{name}: {value}"])

    attempts = 1 if managed_request() else max(0, int(retries)) + 1
    with tempfile.TemporaryDirectory(prefix="dwti-http-fetch-") as temp_dir:
        cookie_file = os.path.join(temp_dir, "cookies.txt")
        output_file = os.path.join(temp_dir, "body.html")
        header_file = os.path.join(temp_dir, "headers.txt")
        _write_cookie_jar(cookie_file, url, [*_parse_cookie_header(cookie_header), *(cookies or []), *stored])
        for attempt in range(1, attempts + 1):
            wait_for = _timeout_left(options, timeout)
            pacing.wait(host, min_interval=options.profile.min_interval_seconds,
                        max_interval=options.profile.max_interval_seconds,
                        deadline=time.time() + wait_for)
            command = [
                curl, "--silent", "--show-error", "--location", "--compressed",
                "--max-time", str(int(wait_for)),
                "--write-out", "%{http_code}",
                "--cookie-jar", cookie_file, "--cookie", cookie_file,
                "--dump-header", header_file, "--output", output_file,
            ]
            if options.proxy:
                command.extend(["--proxy", options.proxy])
            else:
                command.extend(["--noproxy", "*"])
            command.extend(header_args)
            command.append(url)
            request_attempt()
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, check=False)
            status = _int_status(result.stdout)
            headers_in = _read_headers(header_file)
            try:
                with open(output_file, "r", encoding="utf-8", errors="replace") as handle:
                    html = handle.read()
            except OSError:
                html = ""
            pacing.mark_request(host, status=status)
            signal = detect.classify_response(status, headers_in, html)
            _emit(options, {
                "route": "curl", "url": url, "attempt": attempt, "status": status,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "signal": signal.describe(), "bytes": len(html),
                "exit": result.returncode,
            })
            if signal.is_challenge:
                raise CollectionFailure("blocked", _describe_failure(signal, url), scope="target",
                                        verification_provider=signal.vendor)
            if signal.kind == "rate-limit":
                _raise_for_signal(signal, url, headers=headers_in)
            if result.returncode == 0:
                _record_from_jar(cookie_file, host, options)
                _raise_for_status(status, html, headers_in)
                return html
            if attempt < attempts:
                time.sleep(max(0.5, min(float(backoff_seconds) * attempt, 10.0)))
                continue
            kind = "timeout" if result.returncode == 28 else "network"
            raise CollectionFailure(
                kind,
                f"curl fetch failed for {host}: {_stderr_text(result.stderr)}",
            )
    raise CollectionFailure("network", f"curl fetch failed for {host}")


def _record_from_jar(cookie_file: str, host: str, options: HttpFetchOptions) -> None:
    """Persist clearance cookies curl stored in its jar after a successful fetch."""

    cookies: list[dict[str, Any]] = []
    try:
        with open(cookie_file, "r", encoding="utf-8", errors="replace") as handle:
            rows = [line.rstrip("\n").split("\t") for line in handle if line.strip()]
    except OSError:
        return
    for row in rows:
        if len(row) < 7:
            continue  # header comment or malformed row
        domain, _flag, path, secure, expires, name, value = row[:7]
        cookies.append({"name": name, "value": value, "domain": domain, "path": path,
                        "secure": secure.upper() == "TRUE",
                        "expires": int(expires) if expires.isdigit() else 0})
    if detect.has_clearance_cookie(cookies):
        clearance.record(host, cookies, user_agent=options.user_agent,
                         proxy_server=options.proxy, source="curl")


def _write_cookie_jar(path: str, url: str, cookies: Iterable[Mapping[str, Any]]) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    rows = []
    for cookie in cookies:
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        value = str(cookie.get("value") or "")
        if any(ord(char) < 32 or ord(char) == 127 for char in f"{name}{value}"):
            continue
        domain = str(cookie.get("domain") or host).lstrip(".") or host
        rows.append((
            domain, "TRUE" if cookie.get("domain") else "FALSE",
            str(cookie.get("path") or "/"), "TRUE" if cookie.get("secure") else "FALSE",
            str(int(cookie.get("expires") or 0)), name, value,
        ))
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Netscape HTTP Cookie File\n")
        for row in rows:
            handle.write("\t".join(row) + "\n")


def _int_status(stdout: bytes | str | None) -> int:
    text = stdout.decode("ascii", errors="ignore") if isinstance(stdout, bytes) else str(stdout or "")
    text = text.strip()
    return int(text) if text.isdigit() else 0


def _read_headers(path: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    try:
        with open(path, "r", encoding="iso-8859-1", errors="replace") as handle:
            for line in handle:
                name, sep, value = line.partition(":")
                if sep and not line.startswith(" "):
                    headers[name.strip()] = value.strip()
    except OSError:
        pass
    return headers


def _stderr_text(stderr: bytes | str | None) -> str:
    if stderr is None:
        return "unknown curl error"
    text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
    return " ".join(text.split())[:300] or "unknown curl error"


def close_sessions() -> None:
    """Drop cached curl_cffi sessions (tests, or after a proxy change)."""

    cache = getattr(_LOCAL, "sessions", None) or {}
    for session, _stamp in list(cache.values()):
        try:
            session.close()
        except Exception:
            pass
    cache.clear()
    _LOCAL.sessions = cache


__all__ = [
    "CURL_CFFI_AVAILABLE",
    "HttpFetchOptions",
    "close_sessions",
    "fetch_via_http_proxy",
    "host_key",
    "resolve_impersonation",
    "supported_impersonations",
]
