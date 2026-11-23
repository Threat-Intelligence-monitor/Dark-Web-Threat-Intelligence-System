"""Route probe: which access path actually works for a given source, today.

The collector's failure taxonomy tells you *that* a source is blocked; it does
not tell you whether the TLS-impersonation route would have worked, or whether
the block is a challenge a browser can clear.  This module answers that, in
isolation from the scheduler, so an operator can re-check a source without
starting a full collection run.

Usage::

    python -m darkweb_collector.access_bypass.probe --list
    python -m darkweb_collector.access_bypass.probe --site darkforums
    python -m darkweb_collector.access_bypass.probe --site darkforums --route browser
    python -m darkweb_collector.access_bypass.probe --url https://example.com/

Every route is attempted in cheapest-first order and each attempt is reported
separately; the process exit code is 0 when at least one route served the page.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import sys
import time
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

from darkweb_collector.access_bypass import challenge, clearance, detect, httpfetch, profiles
from darkweb_collector.access_bypass.model import BypassProfile
from darkweb_collector.access_bypass.headers import build_headers
from darkweb_collector.collection_errors import CollectionFailure

ROUTES = ("impersonate", "curl", "browser")


@dataclass
class ProbeResult:
    site: str
    url: str
    route: str
    ok: bool = False
    status: int = 0
    signal: str = ""
    size: int = 0
    elapsed_ms: int = 0
    detail: str = ""
    cookies: int = 0
    error: str = ""

    def line(self) -> str:
        state = "OK  " if self.ok else "FAIL"
        return (f"{state} {self.site:12s} {self.route:12s} status={self.status:<4d} "
                f"size={self.size:<7d} {self.elapsed_ms:>6d}ms "
                f"{self.signal or '-':24s} {self.detail or self.error}")


def probe_url(
    url: str,
    *,
    site: str = "",
    profile: BypassProfile | None = None,
    routes: Sequence[str] = ROUTES,
    timeout: float = 40.0,
    allow_browser: bool = True,
) -> list[ProbeResult]:
    """Try every requested route against ``url`` and return one result each."""

    profile = profile or profiles.profile_for(site, url=url)
    site = site or profile.key
    results: list[ProbeResult] = []
    for route in routes:
        if route == "browser" and not allow_browser:
            continue
        started = time.monotonic()
        result = ProbeResult(site=site, url=url, route=route)
        try:
            if route == "impersonate":
                _probe_impersonate(result, url, profile)
            elif route == "curl":
                _probe_curl(result, url, profile)
            elif route == "browser":
                _probe_browser(result, url, profile)
            else:
                raise ValueError(f"unknown route {route!r}")
        except CollectionFailure as exc:
            result.ok = False
            result.error = f"{exc.kind}: {exc}"
        except Exception as exc:  # browser missing, network stack error, ...
            result.ok = False
            result.error = f"{type(exc).__name__}: {exc}"
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        results.append(result)
        if result.ok:
            break
    return results


def _classify(result: ProbeResult, status: int, headers: Any, html: str) -> None:
    signal = detect.classify_response(status, headers, html)
    result.status = status
    result.size = len(html)
    result.signal = signal.describe()

    def _clean_detail(text: str) -> str:
        return " ".join((text or "").split())[:160]

    title = detect.document_title(html)
    result.detail = _clean_detail(title) if title else ""
    result.ok = signal.kind == "none" and 200 <= status < 400 and bool(html.strip())


def _probe_impersonate(result: ProbeResult, url: str, profile: BypassProfile) -> None:
    if _is_onion(url):
        result.error = "onion host: use the curl or browser route"
        return
    if not httpfetch.CURL_CFFI_AVAILABLE:
        result.error = "curl_cffi not installed"
        return
    impersonate = httpfetch.resolve_impersonation(profile.impersonate)
    if not impersonate:
        result.error = "no usable impersonation target"
        return
    proxy = _http_proxy()
    headers = build_headers(url, profile=profile.header_profile, impersonate=impersonate,
                            include_user_agent=False)
    session = httpfetch._session(impersonate, proxy)
    response = session.request("GET", url, headers=headers, timeout=35.0,
                               allow_redirects=True, impersonate=impersonate)
    html = httpfetch._response_text(response)
    _classify(result, int(response.status_code), dict(response.headers), html)
    result.cookies = len(httpfetch._session_cookies(session))
    result.detail = f"{result.detail} impersonate={impersonate}".strip()
    stored = clearance.cookies_for(httpfetch.host_key(url), proxy_server=proxy)
    if stored and result.ok:
        result.detail += f" clearance={len(stored)}"


def _probe_curl(result: ProbeResult, url: str, profile: BypassProfile) -> None:
    host = httpfetch.host_key(url)
    events: list[dict] = []
    options = httpfetch.HttpFetchOptions(
        profile=profile, user_agent="", proxy=_route_proxy(url), on_event=events.append,
    )
    html = httpfetch._fetch_with_curl_cli(
        url, options=options, timeout=35.0, retries=0, backoff_seconds=1.0,
        cookie_header=None, cookies=None,
    )
    status = int(events[-1].get("status") or 0) if events else 0
    _classify(result, status, None, html)
    result.detail = f"{result.detail} host={host}".strip()


def _probe_browser(result: ProbeResult, url: str, profile: BypassProfile) -> None:
    from playwright.sync_api import sync_playwright

    from darkweb_collector.access_bypass import stealth

    plan = stealth.plan_for(profile.stealth, engine=profile.browser_engine)
    proxy = _browser_proxy(url)
    errors: list[str] = []
    with sync_playwright() as playwright:
        launch_kwargs = stealth.launch_kwargs(plan, headless=True)
        engine = getattr(playwright, profile.browser_engine, None)
        if engine is None:
            raise RuntimeError(f"playwright has no engine {profile.browser_engine!r}")
        candidates = []
        if profile.browser_channel:
            candidates.append({**launch_kwargs, "channel": profile.browser_channel})
        candidates.append(launch_kwargs)
        browser = None
        for kwargs in candidates:
            try:
                browser = engine.launch(**kwargs)
                break
            except Exception as exc:  # missing bundled build -> retry with system channel
                errors.append(f"{kwargs.get('channel') or 'bundled'}: {type(exc).__name__}")
        if browser is None:
            raise RuntimeError("browser launch failed: " + "; ".join(errors))
        try:
            context_kwargs = stealth.context_kwargs(plan, viewport={"width": 1440, "height": 960})
            if proxy:
                context_kwargs["proxy"] = {"server": proxy}
            context = browser.new_context(**context_kwargs)
            stealth.apply_to_context(context, plan)
            page = context.new_page()
            response = page.goto(url, wait_until="domcontentloaded", timeout=45_000)
            status = int(getattr(response, "status", 0) or 0)
            solve = challenge.solve(page, lambda: page.content(), profile=profile,
                                    deadline=time.monotonic() + profile.challenge_wait_seconds)
            html = solve.html if solve.solved else page.content()
            headers = dict(response.headers) if response is not None else {}
            _classify(result, status, headers, html)
            result.cookies = len(solve.cookies)
            result.detail = f"{result.detail} {solve.describe()}".strip()
            if result.ok and detect.has_clearance_cookie(solve.cookies):
                result.detail += f" clearance={len(detect.clearance_cookie_names(solve.cookies))}"
            result.signal = solve.signal.describe()
            result.ok = result.ok and not solve.signal.is_challenge
            context.close()
        finally:
            browser.close()


def _is_onion(url: str) -> bool:
    return (urlsplit(url).hostname or "").lower().endswith(".onion")


def _http_proxy() -> str:
    return httpfetch._proxy_url(proxy_host=os.environ.get("PROXY_HOST"),
                                proxy_port=os.environ.get("PROXY_PORT"))


def _tor_proxy() -> str:
    from darkweb_collector.tor_fetch import get_tor_socks_settings

    socks_host, socks_port = get_tor_socks_settings()
    return f"socks5h://{socks_host}:{socks_port}"


def _route_proxy(url: str) -> str:
    """Proxy for a direct HTTP request, or the Tor SOCKS endpoint for onion."""

    return _tor_proxy() if _is_onion(url) else _http_proxy()


def _browser_proxy(url: str) -> str:
    return _tor_proxy().replace("socks5h://", "socks5://") if _is_onion(url) else _http_proxy()


def _seed_sites(include_onion: bool = False) -> list[tuple[str, str]]:
    """``(site_key, seed_url)`` pairs from sites.yaml, for ``--list``/``--all``."""

    try:
        from darkweb_collector.config import load_site_configs

        configs = load_site_configs()
    except Exception:
        configs = []
    pairs: list[tuple[str, str]] = []
    for config in configs:
        if not getattr(config, "enabled", True):
            continue
        name = str(getattr(config, "site_name", "") or "")
        seeds = [str(seed) for seed in (getattr(config, "seed_urls", None) or ()) if seed]
        if not name or not seeds:
            continue
        seed = seeds[0]
        if include_onion or not _is_onion(seed):
            pairs.append((name, seed))
    if pairs:
        return pairs
    # No sites.yaml on this machine (e.g. a fresh checkout): fall back to the
    # built-in table so ``--all`` still exercises the documented sources.
    for key in profiles.BUILTIN_DEFAULTS:
        if key == "default":
            continue
        seed = _default_seed(key)
        if include_onion or not _is_onion(seed):
            pairs.append((key, seed))
    return pairs


def format_report(results: Iterable[ProbeResult]) -> str:
    rows = list(results)
    if not rows:
        return "no probe results"
    lines = [result.line() for result in rows]
    ok = sum(1 for result in rows if result.ok)
    lines.append(f"{ok}/{len(rows)} route(s) served content")
    return "\n".join(lines)


def _print_clearance(urls: Iterable[str]) -> None:
    for url in urls:
        host = httpfetch.host_key(url)
        for line in clearance.describe(host):
            print(line)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="access_bypass.probe",
                                     description="Probe access routes for a source URL")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--site", help="site key from sites.yaml")
    target.add_argument("--url", help="arbitrary URL to probe")
    target.add_argument("--all", action="store_true", help="probe every enabled site seed")
    target.add_argument("--list", action="store_true", help="list site keys and their profiles")
    parser.add_argument("--route", action="append", choices=ROUTES,
                        help="restrict to one route (repeatable)")
    parser.add_argument("--timeout", type=float, default=40.0)
    parser.add_argument("--no-browser", action="store_true", help="skip the browser route")
    parser.add_argument("--include-onion", action="store_true",
                        help="also probe .onion seeds (needs a running Tor SOCKS proxy)")
    parser.add_argument("--json", action="store_true", help="emit JSON lines")
    parser.add_argument("--clearance", metavar="URL", action="append", default=[],
                        help="also print stored clearance cookies for URL")
    args = parser.parse_args(argv)

    if args.list:
        print("site           profile")
        for line in profiles.describe_profiles():
            print(line)
        return 0

    routes = tuple(args.route) if args.route else ROUTES
    results: list[ProbeResult] = []
    if args.url:
        results.extend(probe_url(args.url, profile=profiles.profile_for(url=args.url),
                                 routes=_routes_for(args.url, routes), timeout=args.timeout,
                                 allow_browser=not args.no_browser))
    else:
        targets = _seed_sites(include_onion=args.include_onion)
        if args.site:
            targets = [item for item in targets if item[0] == args.site] or [(args.site, _default_seed(args.site))]
        for site, seed in targets:
            results.extend(probe_url(seed, site=site, profile=profiles.profile_for(site, url=seed),
                                     routes=_routes_for(seed, routes), timeout=args.timeout,
                                     allow_browser=not args.no_browser))
    if args.json:
        import json

        for result in results:
            print(json.dumps(result.__dict__, ensure_ascii=False))
    else:
        print(format_report(results))
        _print_clearance([result.url for result in results] + list(args.clearance))
    return 0 if any(result.ok for result in results) else 1


def _routes_for(url: str, routes: Sequence[str]) -> tuple[str, ...]:
    """Drop routes that cannot work for the scheme/transport of ``url``."""

    if not _is_onion(url):
        return tuple(routes)
    return tuple(route for route in routes if route != "impersonate")


def _default_seed(site: str) -> str:
    payload = profiles.BUILTIN_DEFAULTS.get(site) or {}
    hosts = payload.get("hosts") or ()
    if hosts:
        host = str(hosts[0])
        return f"http://{host}/" if host.endswith(".onion") else f"https://{host}/"
    return f"https://{site}/"


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
