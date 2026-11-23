from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import shutil
import subprocess
import time
import os
import tempfile
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlparse

from darkweb_collector.collection_errors import CollectionFailure, managed_request, request_attempt, raise_if_error_page, safe_failure_text


class TorFetchError(CollectionFailure):
    """Raised when a Tor-backed fetch fails."""

    def __init__(self, message: str, *, kind: str = "network") -> None:
        super().__init__(kind, message)


class ProxyFetchError(CollectionFailure):
    """Raised when a proxy-backed fetch fails."""

    def __init__(self, message: str, *, kind: str = "network") -> None:
        super().__init__(kind, message)


def _stderr_text(stderr: str | bytes | None) -> str:
    if stderr is None:
        return "unknown curl error"
    if isinstance(stderr, bytes):
        return stderr.decode("utf-8", errors="replace").strip()
    return stderr.strip()


def _retry_after_seconds(headers: Mapping[str, str] | None) -> float:
    value = next((str(value).strip() for name, value in (headers or {}).items() if name.lower() == "retry-after"), "")
    if not value:
        return 0.0
    try:
        return max(0.0, float(int(value)))
    except (ValueError, OverflowError):
        pass
    try:
        deadline = parsedate_to_datetime(value)
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return max(0.0, (deadline - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return 0.0


def _read_retry_after_headers(path: str) -> dict[str, str]:
    value = ""
    try:
        with open(path, "r", encoding="iso-8859-1") as response_headers:
            for line in response_headers:
                if line.startswith("HTTP/"):
                    value = ""
                elif line.lower().startswith("retry-after:"):
                    value = line.partition(":")[2].strip()
    except OSError:
        return {}
    return {"retry-after": value} if value else {}


def _write_curl_cookies(path: str, url: str, cookie_header: str | None, cookies: list[dict] | None) -> None:
    origin = urlparse(url)
    host = (origin.hostname or "").lower()
    explicit = SimpleCookie()
    if cookie_header:
        if any(ord(char) < 32 or ord(char) == 127 for char in cookie_header):
            raise CollectionFailure("infrastructure", "invalid source cookie configuration")
        try:
            explicit.load(cookie_header)
        except CookieError as exc:
            raise CollectionFailure("infrastructure", "invalid source cookie configuration") from exc
        if not explicit or any(ord(char) < 32 or ord(char) == 127
                               for item in explicit.values() for char in item.value):
            raise CollectionFailure("infrastructure", "invalid source cookie configuration")
    rows = []
    for cookie in cookies or []:
        name, value = str(cookie.get("name") or ""), str(cookie.get("value") or "")
        domain = str(cookie.get("domain") or "").lower()
        bare_domain = domain.lstrip(".")
        include_subdomains = domain.startswith(".") and not cookie.get("hostOnly", False)
        if not bare_domain or not (host == bare_domain or include_subdomains and host.endswith("." + bare_domain)):
            continue
        if name in explicit:
            continue
        try:
            expires = float(cookie.get("expires", -1))
            if expires != -1 and expires <= time.time():
                continue
            expires = max(0, int(expires))
        except (ValueError, TypeError, OverflowError):
            continue
        cookie_path = str(cookie.get("path") or "/")
        fields = (domain, name, value, cookie_path)
        if not name or any(ord(char) < 32 or ord(char) == 127 for field in fields for char in field):
            continue
        if not cookie_path.startswith("/") or any(char in domain for char in "/\\: "):
            continue
        rows.append((domain if include_subdomains else bare_domain, include_subdomains, cookie_path,
                     bool(cookie.get("secure")), expires, name, value))
    # An explicit Cookie header has no scope metadata. Restrict it to the
    # requested host, with Secure set for an HTTPS origin, rather than forwarding
    # the raw header through redirects.
    rows.extend((host, False, "/", origin.scheme == "https", 0, name, value.value)
                for name, value in explicit.items())
    with open(path, "w", encoding="utf-8", newline="\n") as stream:
        stream.write("# Netscape HTTP Cookie File\n")
        for domain, subdomains, cookie_path, secure, expires, name, value in rows:
            stream.write("\t".join((domain, str(subdomains).upper(), cookie_path,
                                   str(secure).upper(), str(expires), name, value)) + "\n")


def raise_for_http_status(
    status: int, html: str | None = None, *, headers: Mapping[str, str] | None = None,
) -> None:
    if status == 429:
        raise CollectionFailure(
            "rate_limited", "HTTP 429; source rate limit reached", scope="site",
            retry_after=_retry_after_seconds(headers),
        )
    if html is not None and html.strip():
        try:
            raise_if_error_page(html)
        except CollectionFailure as exc:
            message = f"HTTP {status}; {exc}" if status else str(exc)
            raise CollectionFailure(exc.kind, message, scope=exc.scope, retry_after=exc.retry_after,
                                    verification_provider=exc.verification_provider) from exc
    if status == 401:
        raise CollectionFailure("auth_required", "HTTP 401; source requires authentication", scope="site")
    if status == 403:
        raise CollectionFailure("blocked", "HTTP 403; source refused the request", scope="target")
    if status in {404, 410}:
        raise CollectionFailure("not_found", f"HTTP {status}; target availability is unconfirmed", scope="target")
    if status in {408, 504}:
        raise CollectionFailure("timeout", f"HTTP {status}; source request timed out")
    if isinstance(status, int) and 500 <= status < 600:
        raise CollectionFailure("network", f"HTTP {status}; source returned a temporary server error", scope="site")
    if html is not None and not html.strip():
        raise_if_error_page(html)


def is_onion_hostname(hostname: str | None) -> bool:
    return bool(hostname and hostname.lower().endswith(".onion"))


def _bypass_profile(site_key: str | None, url: str):
    """Access-bypass policy for one request; ``None`` means "no bypass layer"."""

    try:
        from darkweb_collector.access_bypass import profiles

        return profiles.profile_for(site_key, url=url)
    except Exception:
        return None


def is_onion_url(url: str) -> bool:
    return is_onion_hostname(urlparse(url).hostname)


def get_tor_socks_settings() -> tuple[str, int]:
    env_host = os.environ.get("TOR_SOCKS_HOST")
    env_port = os.environ.get("TOR_SOCKS_PORT")
    if env_host or env_port:
        return env_host or "127.0.0.1", int(env_port or "9150")
    try:
        from darkweb_collector.tor_bridge_control import active_socks_settings

        configured = active_socks_settings()
    except Exception:
        configured = None
    if configured:
        return configured
    return "127.0.0.1", 9150


def get_http_proxy_settings() -> tuple[str | None, int | None]:
    proxy_host = os.environ.get("PROXY_HOST")
    proxy_port_str = os.environ.get("PROXY_PORT")
    proxy_port = int(proxy_port_str) if proxy_port_str else None
    return proxy_host, proxy_port


def browser_proxy_server_for_url(url: str) -> str | None:
    if is_onion_url(url):
        socks_host, socks_port = get_tor_socks_settings()
        return f"socks5://{socks_host}:{socks_port}"
    proxy_host, proxy_port = get_http_proxy_settings()
    if proxy_host and proxy_port:
        return f"http://{proxy_host}:{proxy_port}"
    return None


def fetch_url(
    url: str,
    mode: str,
    timeout_seconds: int,
    render_wait_seconds: int = 8,
    retries: int = 1,
    cookie_header: str | None = None,
    user_agent: str | None = None,
    cookies: list[dict] | None = None,
    site_key: str | None = None,
) -> str:
    if mode == "browser":
        from darkweb_collector.browser_client import fetch_html_with_browser

        return fetch_html_with_browser(
            url=url,
            wait_seconds=render_wait_seconds,
            timeout_seconds=timeout_seconds,
            proxy_server=browser_proxy_server_for_url(url),
            cookie_header=cookie_header,
            bypass_profile=_bypass_profile(site_key, url),
        )

    if is_onion_url(url):
        socks_host, socks_port = get_tor_socks_settings()
        return fetch_via_tor_curl(
            url=url,
            socks_host=socks_host,
            socks_port=socks_port,
            timeout=timeout_seconds,
            retries=retries,
            cookie_header=cookie_header,
            user_agent=user_agent,
            cookies=cookies,
        )

    proxy_host, proxy_port = get_http_proxy_settings()
    return fetch_via_http_proxy(
        url=url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=timeout_seconds,
        retries=retries,
        backoff_seconds=3.0,
        cookie_header=cookie_header,
        user_agent=user_agent,
        cookies=cookies,
        site_key=site_key,
    )


def fetch_page_artifacts(
    url: str,
    mode: str,
    timeout_seconds: int,
    render_wait_seconds: int = 8,
    screenshot_selector: str | None = None,
    screenshot_selectors: tuple[str, ...] = (),
    hide_selectors: tuple[str, ...] = (),
    screenshot_styles: str = "",
    render_html_for_screenshot: bool = False,
    cookie_header: str | None = None,
    validate_html: Callable[[str], bool] | None = None,
    on_artifact_error: Callable[[str], None] | None = None,
    site_key: str | None = None,
) -> tuple[str, bytes | None]:
    if mode == "browser":
        from darkweb_collector.browser_client import fetch_page_artifacts_with_browser

        html, screenshot_png = fetch_page_artifacts_with_browser(
            url=url,
            wait_seconds=render_wait_seconds,
            timeout_seconds=timeout_seconds,
            proxy_server=browser_proxy_server_for_url(url),
            screenshot_selector=screenshot_selector,
            screenshot_selectors=screenshot_selectors,
            hide_selectors=hide_selectors,
            screenshot_styles=screenshot_styles,
            cookie_header=cookie_header,
            validate_html=validate_html,
            on_artifact_error=on_artifact_error,
            bypass_profile=_bypass_profile(site_key, url),
        )
        return html, screenshot_png

    html = fetch_url(
        url=url,
        mode=mode,
        timeout_seconds=timeout_seconds,
        render_wait_seconds=render_wait_seconds,
        retries=1,
        cookie_header=cookie_header,
        site_key=site_key,
    )
    if validate_html is not None and validate_html(html) is False:
        raise CollectionFailure("parse", "source detail did not pass content validation")

    try:
        if render_html_for_screenshot:
            from darkweb_collector.browser_client import screenshot_html_with_browser

            screenshot_png = screenshot_html_with_browser(
                html=html,
                base_url=url,
                wait_seconds=render_wait_seconds,
                timeout_seconds=timeout_seconds,
                proxy_server=browser_proxy_server_for_url(url),
                screenshot_selector=screenshot_selector,
                screenshot_selectors=screenshot_selectors,
                hide_selectors=hide_selectors,
                screenshot_styles=screenshot_styles,
                cookie_header=cookie_header,
            )
        else:
            from darkweb_collector.browser_client import fetch_page_artifacts_with_browser

            rendered_html, screenshot_png = fetch_page_artifacts_with_browser(
                url=url,
                wait_seconds=render_wait_seconds,
                timeout_seconds=timeout_seconds,
                proxy_server=browser_proxy_server_for_url(url),
                screenshot_selector=screenshot_selector,
                screenshot_selectors=screenshot_selectors,
                hide_selectors=hide_selectors,
                screenshot_styles=screenshot_styles,
                cookie_header=cookie_header,
                on_artifact_error=on_artifact_error,
            )
            if validate_html is not None and validate_html(rendered_html) is False:
                raise CollectionFailure("parse", "rendered detail did not pass content validation")
            html = rendered_html
        return html, screenshot_png
    except Exception as exc:
        if validate_html is not None and validate_html(html) is False:
            raise CollectionFailure("parse", "stored source detail did not pass content validation") from exc
        error = safe_failure_text(f"artifact: evidence capture failed ({type(exc).__name__}): {exc}")
        if on_artifact_error is not None:
            on_artifact_error(error)
        print(f"[screenshot] {error}")
        return html, None


def fetch_via_tor_curl(
    url: str,
    socks_host: str,
    socks_port: int,
    timeout: int = 90,
    retries: int = 0,
    backoff_seconds: float = 2.0,
    cookie_header: str | None = None,
    user_agent: str | None = None,
    cookies: list[dict] | None = None,
) -> str:
    curl = shutil.which("curl")
    if not curl:
        raise TorFetchError("curl not found in PATH", kind="infrastructure")

    if user_agent and any(ord(char) < 32 or ord(char) == 127 for char in user_agent):
        raise CollectionFailure("infrastructure", "invalid source user-agent configuration")
    attempts = 1 if managed_request() else retries + 1
    with tempfile.TemporaryDirectory(prefix="dwti-tor-fetch-") as temp_dir:
        cookie_file = os.path.join(temp_dir, "cookies.txt")
        headers_file = os.path.join(temp_dir, "headers.txt")
        _write_curl_cookies(cookie_file, url, cookie_header, cookies)
        for attempt in range(1, attempts + 1):
            command = [
                curl,
                "--socks5-hostname",
                f"{socks_host}:{socks_port}",
                "--noproxy", "",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                str(timeout),
                "--write-out",
                "\nDWTI_HTTP_STATUS:%{http_code}",
                "--user-agent",
                user_agent or ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                               "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
                "--cookie", cookie_file,
                "--cookie-jar", cookie_file,
                "--dump-header", headers_file,
            ]
            command.append(url)

            request_attempt()
            result = subprocess.run(command, capture_output=True, check=False)
            response_headers = _read_retry_after_headers(headers_file)
            output = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else str(result.stdout or "")
            body, marker, code = output.rpartition("\nDWTI_HTTP_STATUS:")
            status = int(code.strip()) if marker and code.strip().isdigit() else 0
            if result.returncode == 0:
                content = body if marker else output
                raise_for_http_status(status, content, headers=response_headers)
                return content
            raise_for_http_status(status, headers=response_headers)

            if attempt < attempts:
                time.sleep(backoff_seconds * attempt)

        raise TorFetchError(f"curl fetch failed (exit {result.returncode})", kind="timeout" if result.returncode == 28 else "network")

def fetch_via_http_proxy(
    url: str,
    proxy_host: str = None,
    proxy_port: int = None,
    timeout: int = 90,
    retries: int = 3,
    backoff_seconds: float = 3.0,
    cookie_header: str | None = None,
    bypass_proxy: bool = False,
    user_agent: str | None = None,
    cookies: list[dict] | None = None,
    *,
    site_key: str | None = None,
    deadline: float | None = None,
) -> str:
    """Fetch a clear-web URL through the access-bypass HTTP route.

    This keeps the historical signature every adapter already calls, but the
    request is now made by :mod:`darkweb_collector.access_bypass.httpfetch`:

    * TLS/HTTP2 impersonation (``curl_cffi``) instead of a randomised UA string,
      because the edge scores the handshake, not the header;
    * a persisted ``cf_clearance``/``__ddg*`` cookie replayed with the UA family
      and egress path that earned it;
    * jittered per-host pacing, so a retry no longer looks like a burst.

    Failures keep the collector's taxonomy (``blocked``, ``rate_limited``,
    ``auth_required``, ``timeout``, ``network``), which is what lets the
    adapters fall back to the browser route for this same URL.
    """

    from darkweb_collector.access_bypass import httpfetch, profiles

    profile = profiles.profile_for(site_key, url=url)
    return httpfetch.fetch_via_http_proxy(
        url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=timeout,
        retries=retries,
        backoff_seconds=backoff_seconds,
        cookie_header=cookie_header,
        bypass_proxy=bypass_proxy,
        user_agent=user_agent,
        cookies=cookies,
        profile=profile,
        deadline=deadline,
    )


def fetch_with_proxy_bypass(
    url: str,
    proxy_host: str = None,
    proxy_port: int = None,
    timeout: int = 90,
    retries: int = 3,
) -> str:
    """Deprecated alias kept for older call sites; use ``fetch_via_http_proxy``."""

    return fetch_via_http_proxy(
        url=url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=timeout,
        retries=retries,
        backoff_seconds=3.0,
    )
