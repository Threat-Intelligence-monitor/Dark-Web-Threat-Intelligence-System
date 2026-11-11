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
) -> str:
    if mode == "browser":
        from darkweb_collector.browser_client import fetch_html_with_browser

        return fetch_html_with_browser(
            url=url,
            wait_seconds=render_wait_seconds,
            timeout_seconds=timeout_seconds,
            proxy_server=browser_proxy_server_for_url(url),
            cookie_header=cookie_header,
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
        )
        return html, screenshot_png

    html = fetch_url(
        url=url,
        mode=mode,
        timeout_seconds=timeout_seconds,
        render_wait_seconds=render_wait_seconds,
        retries=1,
        cookie_header=cookie_header,
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

def fetch_with_cloudflare_bypass(
    url: str,
    socks_host: str,
    socks_port: int,
    timeout: int = 90,
    retries: int = 3,
    backoff_seconds: float = 3.0,
) -> str:
    """Fetch URL with Cloudflare protection bypass"""
    import random
    import time
    
    # Add random delay before request
    time.sleep(random.uniform(2, 5))
    
    # Use different user agents
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:123.0) Gecko/20100101 Firefox/123.0"
    ]
    
    # Randomly select a user agent
    user_agent = random.choice(user_agents)
    
    # Generate random accept headers
    accept_languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "en-CA,en;q=0.9,en-US;q=0.8",
        "en-AU,en;q=0.9,en-US;q=0.8"
    ]
    
    accept_language = random.choice(accept_languages)
    
    # Use curl with enhanced anti-crawler headers
    curl = shutil.which("curl")
    if not curl:
        raise TorFetchError("curl not found in PATH")
    
    attempts = 1 if managed_request() else retries + 1
    last_error = "unknown curl error"
    
    for attempt in range(1, attempts + 1):
        # Generate random headers using -H option
        headers = [
            f"-H", f"User-Agent: {user_agent}",
            f"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            f"-H", f"Accept-Language: {accept_language}",
            f"-H", "Accept-Encoding: gzip, deflate, br",
            f"-H", "Connection: keep-alive",
            f"-H", "Upgrade-Insecure-Requests: 1",
            f"-H", "Cache-Control: max-age=0",
            f"-H", "Sec-Fetch-Dest: document",
            f"-H", "Sec-Fetch-Mode: navigate",
            f"-H", "Sec-Fetch-Site: none",
            f"-H", "Sec-Fetch-User: ?1"
        ]
        
        # Build curl command with decompression
        command = [
            curl,
            "--socks5-hostname", f"{socks_host}:{socks_port}",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time", str(timeout),
            "--cookie-jar", "/tmp/cookies.txt",
            "--cookie", "/tmp/cookies.txt",
            "--compressed",  # Automatically decompress gzip/brotli
            "--output", "/tmp/temp.html"  # Save to file to avoid encoding issues
        ] + headers + [url]
        
        # Execute curl command with proper encoding handling
        request_attempt()
        result = subprocess.run(command, capture_output=True, check=False)
        
        if result.returncode == 0:
            try:
                # Read from the output file
                with open("/tmp/temp.html", "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                
                # Check if we got a Cloudflare page
                if "Checking your browser" in content:
                    # Add more delay and try again
                    time.sleep(random.uniform(5, 10))
                    continue
                return content
            except Exception as e:
                # If reading as UTF-8 fails, try other encodings
                encodings = ['latin-1', 'cp1252']
                for encoding in encodings:
                    try:
                        with open("/tmp/temp.html", "r", encoding=encoding, errors="replace") as f:
                            content = f.read()
                        if "Checking your browser" in content:
                            # Add more delay and try again
                            time.sleep(random.uniform(5, 10))
                            continue
                        return content
                    except:
                        continue
                # If all encodings fail, try binary read
                try:
                    with open("/tmp/temp.html", "rb") as f:
                        content = f.read()
                    return content.decode('utf-8', errors='replace')
                except:
                    return ""
        
        last_error = _stderr_text(result.stderr)
        if attempt < attempts:
            # Add exponential backoff
            time.sleep(backoff_seconds * attempt)
    
    raise TorFetchError(f"Cloudflare bypass failed for {url}: {last_error}")


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
) -> str:
    """
    Fetch URL using HTTP/HTTPS proxy (e.g., Clash, Shadowsocks, etc.)
    If no proxy is configured, fetches directly.

    Args:
        url: The URL to fetch
        proxy_host: Proxy host (default: from env PROXY_HOST or None)
        proxy_port: Proxy port (default: from env PROXY_PORT or None)
        timeout: Request timeout in seconds
        retries: Number of retries on failure
        backoff_seconds: Base backoff time between retries

    Returns:
        The HTML content of the page
    """
    import random

    # Get proxy settings from environment (no defaults - must be explicitly set)
    if bypass_proxy:
        proxy_host = None
        proxy_port = None
    else:
        proxy_host = proxy_host or os.environ.get("PROXY_HOST")
        proxy_port_str = os.environ.get("PROXY_PORT")
        proxy_port = proxy_port or (int(proxy_port_str) if proxy_port_str else None)

    # Use different user agents
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:123.0) Gecko/20100101 Firefox/123.0"
    ]

    # Keep the validated browser session's user agent when one is supplied.
    user_agent = user_agent or random.choice(user_agents)
    if any(ord(char) < 32 or ord(char) == 127 for char in user_agent):
        raise CollectionFailure("infrastructure", "invalid source user-agent configuration")

    # Generate random accept headers
    accept_languages = [
        "en-US,en;q=0.9",
        "en-GB,en;q=0.9,en-US;q=0.8",
        "en-CA,en;q=0.9,en-US;q=0.8",
        "en-AU,en;q=0.9,en-US;q=0.8"
    ]

    accept_language = random.choice(accept_languages)

    # Use curl with HTTP proxy
    curl = shutil.which("curl")
    if not curl:
        raise ProxyFetchError("curl not found in PATH", kind="infrastructure")

    attempts = 1 if managed_request() else retries + 1

    with tempfile.TemporaryDirectory(prefix="dwti-http-fetch-") as temp_dir:
        cookie_file = os.path.join(temp_dir, "cookies.txt")
        output_file = os.path.join(temp_dir, "temp.html")
        headers_file = os.path.join(temp_dir, "headers.txt")
        _write_curl_cookies(cookie_file, url, cookie_header, cookies)
        for attempt in range(1, attempts + 1):
            # Generate headers
            # Note: Not sending Accept-Encoding to avoid compressed responses
            headers = [
                f"-H", f"User-Agent: {user_agent}",
                f"-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                f"-H", f"Accept-Language: {accept_language}",
                f"-H", "Connection: keep-alive",
                f"-H", "Upgrade-Insecure-Requests: 1",
                f"-H", "Cache-Control: max-age=0",
                f"-H", "Sec-Fetch-Dest: document",
                f"-H", "Sec-Fetch-Mode: navigate",
                f"-H", "Sec-Fetch-Site: none",
                f"-H", "Sec-Fetch-User: ?1",
                f"-H", "DNT: 1"
            ]

            # Build curl command
            command = [
                curl,
                "--silent",
                "--show-error",
                "--location",
                "--max-time", str(timeout),
                "--write-out", "%{http_code}",
                "--cookie-jar", cookie_file,
                "--cookie", cookie_file,
                "--dump-header", headers_file,
                "--output", output_file
            ]

            # Add proxy if configured
            if bypass_proxy or not (proxy_host and proxy_port):
                command.extend(["--noproxy", "*"])
            else:
                command.extend(["--proxy", f"http://{proxy_host}:{proxy_port}", "--noproxy", ""])

            command.extend(headers + [url])

            # Execute curl command
            request_attempt()
            result = subprocess.run(command, capture_output=True, check=False)
            response_headers = _read_retry_after_headers(headers_file)
            status_text = result.stdout.decode("ascii", errors="ignore") if isinstance(result.stdout, bytes) else str(result.stdout or "")
            status = int(status_text.strip()) if status_text.strip().isdigit() else 0

            if result.returncode == 0:
                try:
                    # Try UTF-8 first
                    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except OSError as exc:
                    raise ProxyFetchError("HTTP response body could not be read", kind="parse") from exc
                raise_for_http_status(status, content, headers=response_headers)
                return content
            raise_for_http_status(status, headers=response_headers)

            if attempt < attempts:
                time.sleep(backoff_seconds * attempt)

        raise ProxyFetchError(f"proxy fetch failed (exit {result.returncode})", kind="timeout" if result.returncode == 28 else "network")


def fetch_with_proxy_bypass(
    url: str,
    proxy_host: str = None,
    proxy_port: int = None,
    timeout: int = 90,
    retries: int = 3,
) -> str:
    """
    Fetch URL with proxy and anti-detection measures
    
    This is a convenience wrapper around fetch_via_http_proxy
    """
    return fetch_via_http_proxy(
        url=url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=timeout,
        retries=retries,
        backoff_seconds=3.0
    )
