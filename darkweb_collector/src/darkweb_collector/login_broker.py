"""One place to keep forum logins alive across every credential-protected source.

The crawler already knows how to *use* a session: ``source_sessions`` stores a
Playwright storage state per site and replays it from both the browser and the
HTTP route.  What it never had was a way to *obtain* one, so every restricted
source needed a human to paste cookies by hand and to notice when they expired.

This module closes that loop:

* credentials live in one directory (``<data_root>/credentials/<site>.json``),
  encrypted with Windows DPAPI when available so a copied file is useless on
  another account/machine;
* logging in is a real browser session against the source's own form, so the
  session it produces carries whatever clearance cookies the CDN handed out;
* the resulting storage state is committed through ``source_sessions``, which
  means every existing adapter picks it up with no extra wiring;
* ``probe`` re-opens a member-only page and reports whether the stored session
  is still accepted, which is what the console and the keepalive job ask.

Nothing here logs a password.  Failures report the site, the step, and the
observable reason (captcha, wrong credentials, redirect back to the form).
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.wintypes
import datetime
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from darkweb_collector.runtime import user_data_root

logger = logging.getLogger(__name__)

CREDENTIALS_DIRNAME = "credentials"
LOGIN_VERSION = 1

# MyBB and XenForo both name their login inputs predictably; the defaults below
# are what those two products actually ship, and a site can override any of
# them in its credential record without a code change.
DEFAULT_ENGINES: dict[str, dict[str, str]] = {
    "mybb": {
        "login_path": "/member.php?action=login",
        "username_selector": "input[name=username]",
        "password_selector": "input[name=password]",
        "submit_selector": "input[name=submit], form input[type=submit], form button[type=submit]",
        "success_selector": "a[href*='member.php?action=logout'], a[href*='action=logout']",
        "probe_path": "/usercp.php",
    },
    "xenforo": {
        "login_path": "/login/",
        "username_selector": "input[name=login]",
        "password_selector": "input[name=password]",
        "submit_selector": "button[type=submit], .button--primary",
        "success_selector": "a[href*='/logout/'], a[href*='logout']",
        "probe_path": "/account/",
    },
    "generic": {
        "login_path": "/login",
        "username_selector": "input[type=text], input[name=username], input[name=login], input[name=email]",
        "password_selector": "input[type=password]",
        "submit_selector": "button[type=submit], input[type=submit]",
        "success_selector": "a[href*='logout']",
        "probe_path": "/",
    },
}

# Sites whose forum software is known; everything else falls back to the
# generic form shape rather than being refused a login attempt.
SITE_ENGINES = {
    "darkforums": "mybb",
    "breachforums": "mybb",
    "cracked": "mybb",
    "leakforum": "mybb",
    "raidforums": "mybb",
    "spear": "mybb",
    "pwnfrm": "mybb",
    "xforums": "xenforo",
}

CAPTCHA_HINTS = ("captcha", "recaptcha", "hcaptcha", "turnstile")

# Sites behind these vendors answer a headless browser differently depending on
# the browser build, so the login flow prefers the real Chrome channel there.
CAPPED_PROTECTIONS = frozenset({"cloudflare", "ddos-guard", "akamai", "incapsula", "datadome"})


class LoginError(RuntimeError):
    """A login attempt could not produce a usable session."""

    def __init__(self, message: str, *, step: str = "", needs_human: bool = False) -> None:
        super().__init__(message)
        self.step = step
        self.needs_human = needs_human


@dataclass(frozen=True)
class Credentials:
    site_name: str
    username: str
    password: str
    login_url: str = ""
    engine: str = ""
    username_selector: str = ""
    password_selector: str = ""
    submit_selector: str = ""
    success_selector: str = ""
    probe_url: str = ""
    notes: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def engine_name(self) -> str:
        return (self.engine or SITE_ENGINES.get(self.site_name) or "generic").strip().lower()


@dataclass(frozen=True)
class LoginReport:
    site_name: str
    ok: bool
    status: str
    step: str = ""
    detail: str = ""
    needs_human: bool = False
    elapsed_ms: int = 0
    cookie_count: int = 0
    state_path: str = ""
    user_agent: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"site_name": self.site_name, "ok": self.ok, "status": self.status, "step": self.step,
                "detail": self.detail, "needs_human": self.needs_human, "elapsed_ms": self.elapsed_ms,
                "cookie_count": self.cookie_count, "state_path": self.state_path,
                "user_agent": self.user_agent}


def credentials_root() -> Path:
    return user_data_root() / CREDENTIALS_DIRNAME


def credentials_path(site_name: str) -> Path:
    safe = re.sub(r"[^a-z0-9._-]+", "-", str(site_name).strip().lower()).strip("-.") or "site"
    return credentials_root() / f"{safe}.json"


# --- Windows DPAPI -----------------------------------------------------------
# Credentials on disk should be useless when copied to another machine account.
# DPAPI binds the blob to the current user; on other platforms we fall back to
# plain JSON and say so in the record so nobody assumes more protection.
_DPAPI_PREFIX = "dpapi:"


def dpapi_available() -> bool:
    return sys.platform.startswith("win")


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi_call(function: str, payload: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _DataBlob(len(payload), ctypes.cast(ctypes.create_string_buffer(payload), ctypes.POINTER(ctypes.c_char)))
    blob_out = _DataBlob()
    ok = getattr(crypt32, function)(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise LoginError(f"DPAPI {function} failed (error {kernel32.GetLastError()})", step="credentials")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def protect_secret(value: str) -> str:
    if not value:
        return ""
    if not dpapi_available():
        return value
    return _DPAPI_PREFIX + base64.b64encode(_dpapi_call("CryptProtectData", value.encode("utf-8"))).decode("ascii")


def unprotect_secret(value: str) -> str:
    if not value:
        return ""
    if not value.startswith(_DPAPI_PREFIX):
        return value
    if not dpapi_available():
        raise LoginError("this credential record was encrypted on Windows; DPAPI is unavailable here", step="credentials")
    raw = base64.b64decode(value[len(_DPAPI_PREFIX):])
    return _dpapi_call("CryptUnprotectData", raw).decode("utf-8")


# --- credential records ------------------------------------------------------


def load_credentials(site_name: str) -> Credentials | None:
    path = credentials_path(site_name)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise LoginError(f"unreadable credential record {path}: {exc}", step="credentials") from exc
    if not isinstance(payload, dict):
        raise LoginError(f"credential record {path} is not an object", step="credentials")
    password = ""
    if payload.get("password"):
        password = unprotect_secret(str(payload["password"]))
    elif payload.get("password_dpapi"):
        password = unprotect_secret(_DPAPI_PREFIX + str(payload["password_dpapi"]))
    known = {"site_name", "username", "password", "password_dpapi", "login_url", "engine", "username_selector",
             "password_selector", "submit_selector", "success_selector", "probe_url", "notes", "version", "saved_at"}
    return Credentials(
        site_name=str(payload.get("site_name") or site_name),
        username=str(payload.get("username") or ""),
        password=password,
        login_url=str(payload.get("login_url") or ""),
        engine=str(payload.get("engine") or ""),
        username_selector=str(payload.get("username_selector") or ""),
        password_selector=str(payload.get("password_selector") or ""),
        submit_selector=str(payload.get("submit_selector") or ""),
        success_selector=str(payload.get("success_selector") or ""),
        probe_url=str(payload.get("probe_url") or ""),
        notes=str(payload.get("notes") or ""),
        extra={key: value for key, value in payload.items() if key not in known},
    )


def save_credentials(site_name: str, *, username: str, password: str, login_url: str = "", engine: str = "",
                     probe_url: str = "", notes: str = "", protect: bool | None = None, **overrides: Any) -> Path:
    path = credentials_path(site_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    use_dpapi = dpapi_available() if protect is None else protect
    record: dict[str, Any] = {
        "version": LOGIN_VERSION,
        "site_name": site_name,
        "username": username,
        "password": protect_secret(password) if use_dpapi else password,
        "login_url": login_url,
        "engine": engine,
        "probe_url": probe_url,
        "notes": notes,
        "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    record.update({key: value for key, value in overrides.items() if value not in (None, "")})
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def delete_credentials(site_name: str) -> bool:
    path = credentials_path(site_name)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False


def configured_sites() -> list[str]:
    root = credentials_root()
    if not root.is_dir():
        return []
    return sorted(path.stem for path in root.glob("*.json"))


# --- login flow --------------------------------------------------------------

_LOGIN_HTML_READY = """
(() => {
  const form = document.querySelector('form');
  const password = document.querySelector('input[type=password]');
  return Boolean(form && password && document.readyState !== 'loading');
})()
"""

# A login page that carries a captcha cannot be driven headlessly; recognising
# it up front turns a silent timeout into an actionable "needs a human" state.
_CAPTCHA_PROBE = """
() => {
  const selectors = ['input[name*=captcha i]', 'img[src*=captcha i]', 'div.g-recaptcha', 'div.h-captcha',
                     'iframe[src*=recaptcha]', 'iframe[src*=hcaptcha]', 'div[class*=cf-turnstile]'];
  return selectors.filter((selector) => document.querySelector(selector));
}
"""


def _resolve_login_url(credentials: Credentials, config) -> str:
    if credentials.login_url:
        return credentials.login_url
    base = ""
    if config is not None:
        seeds = list(getattr(config, "seed_urls", ()) or ())
        if seeds:
            base = str(seeds[0])
    if not base:
        raise LoginError("no login URL configured and the site has no seed URL", step="resolve")
    parsed = urlsplit(base)
    return f"{parsed.scheme}://{parsed.netloc}"


def _looks_like_login_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(token in path for token in ("login", "member", "signin", "sign-in", "account"))


def _login_targets(credentials: Credentials, config) -> tuple[str, str]:
    """Return ``(login_url, probe_url)`` for this source.

    Notes files usually record the forum front page, not the login form, so a
    generic entry point is upgraded to the engine's login path instead of
    guessing that the homepage hosts the form.
    """
    engine = DEFAULT_ENGINES.get(credentials.engine_name(), DEFAULT_ENGINES["generic"])
    base_url = _resolve_login_url(credentials, config)
    parsed = urlsplit(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    login_url = base_url if _looks_like_login_page(base_url) else f"{origin}{engine['login_path']}"
    probe_url = credentials.probe_url or f"{origin}{engine['probe_path']}"
    return login_url, probe_url


def _default_selector(credentials: Credentials, field_name: str) -> str:
    engine = DEFAULT_ENGINES.get(credentials.engine_name(), DEFAULT_ENGINES["generic"])
    explicit = getattr(credentials, field_name, "")
    return explicit or engine[field_name]


def _await_login_form(page, credentials: Credentials, *, profile, deadline: float) -> None:
    """Wait for the login form, clearing a CDN interstitial on the way.

    The login entry point sits behind the same Cloudflare managed challenge as
    the forum itself, so a plain ``wait_for_selector`` times out on a page that
    only needs one click to become the form.
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    from darkweb_collector.access_bypass import challenge, detect

    selector = _default_selector(credentials, "password_selector")
    attempted = False
    last_reason = ""
    while time.monotonic() < deadline:
        try:
            page.wait_for_selector(selector, timeout=3000)
            return
        except PlaywrightTimeoutError:
            pass
        if attempted:
            page.wait_for_timeout(1500)
            continue
        attempted = True
        try:
            html = page.content()
        except Exception:  # pragma: no cover - navigation in flight
            html = ""
        signal = detect.classify_html(html) if html else None
        if signal is not None and signal.is_challenge:
            logger.info("login: clearing %s interstitial", signal.describe())
            result = challenge.solve(page, lambda: page.content(), profile=profile,
                                     deadline=min(deadline, time.monotonic() + 40))
            last_reason = result.reason or ""
            logger.info("login: interstitial result solved=%s reason=%s", result.solved, last_reason)
            page.wait_for_timeout(1200)
        else:
            page.wait_for_timeout(1500)
    raise LoginError(f"login form never appeared ({last_reason or 'no challenge to clear'})", step="navigate")


_LOGGED_IN_PROBE = """
(username) => {
  const name = (username || '').trim().toLowerCase();
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  const href = (a) => (a.getAttribute('href') || '');
  if (anchors.some((a) => /action=logout/i.test(href(a)))) return 'logout';
  const profile = anchors.find((a) => /member\\.php\\?action=profile/i.test(href(a))
    && (a.textContent || '').trim().toLowerCase() === name);
  if (profile) return 'profile';
  return '';
}
"""


def _wait_for_login(page, credentials: Credentials, success_selector: str, *, timeout_ms: int = 15000) -> bool:
    """Wait until the page proves the session is signed in.

    Themes disagree about the logout link: some hide it in a dropdown, some
    render it as ``member.php?action=logout&uid=``, and a few (bf.st) only show
    the profile link plus the username. Checking the profile link keeps those
    logins from being reported as failures after they actually worked.
    """
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        try:
            if page.query_selector(success_selector):
                return True
            if page.evaluate(_LOGGED_IN_PROBE, credentials.username):
                return True
        except Exception:  # pragma: no cover - navigation races
            pass
        page.wait_for_timeout(400)
    return False


def _login_user_agent(profile) -> str:
    """Return the user agent the login browser should present.

    Playwright advertises ``HeadlessChrome`` by default, and several WAFs
    (BreachForums among them) answer that with a flat 403 before serving any
    challenge -- the same request with a normal Chrome UA loads fine.
    """
    from darkweb_collector.access_bypass.headers import identity_for

    header_profile = getattr(profile, "header_profile", "") or "chrome"
    impersonate = getattr(profile, "impersonate", "") or ""
    try:
        return identity_for(header_profile, impersonate=impersonate).user_agent
    except Exception:  # pragma: no cover - defensive, identity_for is total
        return identity_for("chrome").user_agent


def _login_with_playwright(credentials: Credentials, *, login_url: str, probe_url: str, headless: bool,
                           timeout_seconds: float, proxy_server: str | None) -> tuple[dict, str]:
    """Drive the source's own login form and return (storage_state, user_agent)."""
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    from darkweb_collector.access_bypass.stealth import apply_to_context, context_kwargs, launch_kwargs, plan_for
    from darkweb_collector.access_bypass.profiles import profile_for

    profile = profile_for(credentials.site_name, url=login_url) if login_url else None
    user_agent = _login_user_agent(profile)
    engine = "chromium"
    plan = plan_for("full", engine=engine, headless=headless)
    launch_options = {**launch_kwargs(plan, headless=headless)}
    channel = getattr(profile, "browser_channel", "") if profile is not None else ""
    if not channel and profile is not None and getattr(profile, "protection", "") in CAPPED_PROTECTIONS:
        # The bundled headless shell is the first thing a CDN fingerprints; a
        # real Chrome channel is worth one extra launch attempt.
        channel = "chrome"
    if channel:
        launch_options["channel"] = channel
    with sync_playwright() as playwright:
        browser = None
        error: Exception | None = None
        for attempt in ([launch_options, {key: value for key, value in launch_options.items() if key != "channel"}]
                        if channel else [launch_options]):
            try:
                browser = playwright.chromium.launch(**attempt)
                break
            except Exception as exc:  # pragma: no cover - depends on installed browsers
                error = exc
        if browser is None:
            raise LoginError(f"could not start a browser: {error}", step="launch") from error
        try:
            context_options = context_kwargs(plan, user_agent=user_agent, locale="en-US")
            context = browser.new_context(**context_options)
            apply_to_context(context, plan)
            page = context.new_page()
            try:
                page.goto(login_url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
            except PlaywrightTimeoutError as exc:
                raise LoginError(f"login entry point did not load: {login_url}", step="navigate") from exc
            _await_login_form(page, credentials, profile=profile,
                              deadline=time.monotonic() + timeout_seconds)
            captcha = page.evaluate(_CAPTCHA_PROBE)
            if captcha:
                raise LoginError(f"login page asks for {', '.join(captcha)}", step="captcha", needs_human=True)
            try:
                page.fill(_default_selector(credentials, "username_selector"), credentials.username)
                page.fill(_default_selector(credentials, "password_selector"), credentials.password)
            except Exception as exc:
                raise LoginError(f"could not fill the login form: {exc}", step="fill") from exc
            try:
                with page.expect_navigation(timeout=timeout_seconds * 1000, wait_until="domcontentloaded"):
                    page.click(_default_selector(credentials, "submit_selector"), timeout=15000)
            except PlaywrightTimeoutError:
                # Some themes submit with XHR and never navigate; fall through to
                # the success check, which is what actually matters.
                logger.debug("login submit produced no navigation for %s", credentials.site_name)
            success_selector = _default_selector(credentials, "success_selector")
            if not _wait_for_login(page, credentials, success_selector, timeout_ms=15000):
                body = ""
                try:
                    body = page.inner_text("body")[:400]
                except Exception:  # pragma: no cover - page may be torn down
                    body = ""
                raise LoginError(f"login did not stick (still no logout link). Page said: {body!r}",
                                 step="verify")
            if probe_url:
                try:
                    page.goto(probe_url, timeout=timeout_seconds * 1000, wait_until="domcontentloaded")
                except PlaywrightTimeoutError as exc:
                    raise LoginError(f"member page {probe_url} did not load", step="probe") from exc
                if not _wait_for_login(page, credentials, success_selector, timeout_ms=15000):
                    raise LoginError(f"member page {probe_url} bounced back to the login form", step="probe")
            state = context.storage_state()
            return state, str(page.evaluate("navigator.userAgent"))
        finally:
            browser.close()


from darkweb_collector.source_sessions import (  # noqa: E402  (kept below the browser import on purpose)
    persist_browser_session,
    session_revision,
    session_state_path,
    session_status,
)


def site_config(site_name: str):
    """Load a SiteConfig by name, tolerating a console that only has credentials."""
    from darkweb_collector.config import load_site_configs

    for config in load_site_configs():
        if getattr(config, "site_name", "") == site_name:
            return config
    return None


def login(site_name: str, *, config=None, headless: bool = True, timeout_seconds: float = 75.0,
          proxy_server: str | None = None) -> LoginReport:
    """Log in with the stored credentials and commit the resulting session."""
    started = time.monotonic()
    credentials = load_credentials(site_name)
    if credentials is None:
        return LoginReport(site_name, False, "no_credentials", "credentials", "no credential record for this site")
    if not credentials.username or not credentials.password:
        return LoginReport(site_name, False, "no_credentials", "credentials", "credential record is missing a username or password")
    if config is None:
        config = site_config(site_name)
    state_path = session_state_path(site_name, getattr(config, "extras", None) or {})
    try:
        base_url = _resolve_login_url(credentials, config)
        login_url, probe_url = _login_targets(credentials, config)
        state, user_agent = _login_with_playwright(
            credentials, login_url=login_url, probe_url=probe_url, headless=headless,
            timeout_seconds=timeout_seconds, proxy_server=proxy_server)
        revision = session_revision(state_path)
        committed = persist_browser_session(state, state_path, url=base_url, proxy_server=proxy_server,
                                           user_agent=user_agent, engine="chromium", expected_revision=revision)
        elapsed = int((time.monotonic() - started) * 1000)
        logger.info("login site=%s ok=%s cookies=%d elapsed_ms=%d", site_name, committed,
                    len(state.get("cookies", [])), elapsed)
        return LoginReport(site_name, True, "logged_in", "", "session stored", False, elapsed,
                           len(state.get("cookies", [])), str(state_path), user_agent)
    except LoginError as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        logger.warning("login site=%s failed step=%s needs_human=%s detail=%s", site_name, exc.step, exc.needs_human, exc)
        return LoginReport(site_name, False, "needs_human" if exc.needs_human else "failed", exc.step, str(exc),
                           exc.needs_human, elapsed, 0, str(state_path))
    except Exception as exc:  # pragma: no cover - browser failures are environmental
        elapsed = int((time.monotonic() - started) * 1000)
        logger.warning("login site=%s crashed: %s", site_name, exc, exc_info=True)
        return LoginReport(site_name, False, "failed", "unexpected", f"{type(exc).__name__}: {exc}", False,
                           elapsed, 0, str(state_path))


def import_session_state(site_name: str, payload: dict, *, config=None, proxy_server: str | None = None) -> LoginReport:
    """Adopt a storage state produced by a real, human-driven login.

    Sites that gate their login form behind a managed challenge or a captcha
    cannot be logged into headlessly; a session exported from a real browser is
    the supported answer.  The envelope carries the user agent that produced the
    cookies because Cloudflare ties clearance to it.
    """
    started = time.monotonic()
    state = payload.get("storage_state") if isinstance(payload.get("storage_state"), dict) else payload
    user_agent = str(payload.get("user_agent") or "")
    if config is None:
        config = site_config(site_name)
    extras = getattr(config, "extras", None) or {}
    state_path = session_state_path(site_name, extras)
    if not isinstance(state, dict) or not isinstance(state.get("cookies"), list) or not state.get("cookies"):
        return LoginReport(site_name, False, "invalid_state", "import", "no cookies in the supplied storage state")
    if not user_agent:
        from darkweb_collector.access_bypass.headers import identity_for

        user_agent = identity_for("chrome").user_agent
    seeds = list(getattr(config, "seed_urls", ()) or ())
    credentials = None
    try:
        credentials = load_credentials(site_name)
    except LoginError:
        credentials = None
    url = (credentials.login_url if credentials and credentials.login_url else (seeds[0] if seeds else "")) or "https://localhost/"
    revision = session_revision(state_path)
    committed = persist_browser_session(state, state_path, url=url, proxy_server=proxy_server,
                                        user_agent=user_agent, engine="chromium", expected_revision=revision)
    elapsed = int((time.monotonic() - started) * 1000)
    cookies = len([cookie for cookie in state.get("cookies", []) if isinstance(cookie, dict)])
    logger.info("import_state site=%s cookies=%d committed=%s", site_name, cookies, committed)
    return LoginReport(site_name, True, "imported", "import",
                       "session stored" if committed else "a newer session replaced the imported one",
                       False, elapsed, cookies, str(state_path), user_agent)


def probe(site_name: str, *, config=None, proxy_server: str | None = None) -> dict:
    """Report whether the stored session is still inside its freshness window."""
    if config is None:
        config = site_config(site_name)
    extras = getattr(config, "extras", None) or {}
    state_path = session_state_path(site_name, extras)
    seeds = list(getattr(config, "seed_urls", ()) or ())
    credentials = None
    try:
        credentials = load_credentials(site_name)
    except LoginError:
        credentials = None
    url = (credentials.login_url if credentials and credentials.login_url else (seeds[0] if seeds else ""))
    if not url:
        # Without a URL we cannot verify anything; still distinguish "never had
        # a session" from "has a file we cannot judge", which is what the
        # console shows.
        exists = state_path.exists()
        state = login_state(site_name)
        return {"site_name": site_name, "status": "unverified" if exists else "missing",
                "detail": "no URL known for this site", "has_credentials": bool(credentials),
                "cookie_count": 0, "age_seconds": 0.0, "path": str(state_path),
                "max_age_seconds": None, "origin": "", "user_agent": "", "browser_engine": "",
                "verified_at": "", "revision": "",
                "busy": state["busy"], "last_result": state["last"]}
    info = session_status(state_path, url, proxy_server)
    state = login_state(site_name)
    info.update({"site_name": site_name, "has_credentials": bool(credentials),
                 "username": credentials.username if credentials else "",
                 "busy": state["busy"], "last_result": state["last"]})
    return info


def status_all() -> list[dict]:
    """Every login-capable site, including the ones still missing an account.

    Listing only the configured sites hid the very action the operator needs —
    adding credentials — so the console shows the full engine map instead.
    """
    names = sorted(set(SITE_ENGINES) | set(configured_sites()))
    return [probe(name) for name in names]


def login_all(*, headless: bool = True) -> list[LoginReport]:
    return [login(name, headless=headless) for name in configured_sites()]


# --- background logins -------------------------------------------------------
#
# Driving a browser through a login takes 10-75 seconds, so the console cannot
# wait on the HTTP response: the request would time out and every control would
# stay disabled with nothing to show for it.  Each site therefore gets a
# worker thread, and the status endpoint reports `busy` while it runs.
_LOGIN_LOCK = threading.Lock()
_LOGIN_STATE: dict[str, dict[str, Any]] = {}


def _set_login_state(site_name: str, **fields: Any) -> None:
    with _LOGIN_LOCK:
        _LOGIN_STATE.setdefault(site_name, {}).update(fields)


def login_state(site_name: str) -> dict:
    """Whether a background login is running for this site, and its last result."""
    with _LOGIN_LOCK:
        entry = _LOGIN_STATE.get(site_name) or {}
        return {"busy": bool(entry.get("busy")), "last": entry.get("last"),
                "started_at": float(entry.get("started_at") or 0.0)}


def busy_sites() -> list[str]:
    with _LOGIN_LOCK:
        return sorted(name for name, entry in _LOGIN_STATE.items() if entry.get("busy"))


def _run_login(site_name: str, headless: bool) -> None:
    report: LoginReport
    try:
        report = login(site_name, headless=headless)
    except Exception as exc:  # pragma: no cover - defensive, login() reports its own failures
        logger.exception("background login crashed for %s", site_name)
        report = LoginReport(site_name, False, "failed", "internal", str(exc))
    _set_login_state(site_name, busy=False, last=report.as_dict(), finished_at=time.time())
    logger.info("background login site=%s ok=%s status=%s", site_name, report.ok, report.status)


def start_login(site_name: str, *, headless: bool = True) -> bool:
    """Start a login for one site on a worker thread.

    Returns ``False`` when that site already has a login in flight, so a double
    click cannot stack two browsers against the same account.
    """
    with _LOGIN_LOCK:
        entry = _LOGIN_STATE.setdefault(site_name, {})
        if entry.get("busy"):
            return False
        entry.update({"busy": True, "started_at": time.time(), "last": None})
    thread = threading.Thread(target=_run_login, args=(site_name, headless),
                              name=f"login-{site_name}", daemon=True)
    thread.start()
    return True


def start_login_all(*, headless: bool = True) -> list[str]:
    """Queue a login for every configured site, one after another."""
    names = configured_sites()
    queued: list[str] = []
    with _LOGIN_LOCK:
        for name in names:
            if not (_LOGIN_STATE.setdefault(name, {}).get("busy")):
                queued.append(name)

    def worker() -> None:
        for name in queued:
            if start_login(name, headless=headless):
                while login_state(name)["busy"]:
                    time.sleep(1.0)

    threading.Thread(target=worker, name="login-all", daemon=True).start()
    return queued


# --- CLI ---------------------------------------------------------------------


# Hosts that map onto a collector site key.  Keeping the table explicit means an
# import cannot accidentally create a site the scheduler does not know.
SITE_HOSTS = {
    "darkforums.as": "darkforums",
    "raidforums.im": "raidforums",
    "bf.st": "breachforums",
    "breachforums.st": "breachforums",
    "xforums.st": "xforums",
    "leakforum.io": "leakforum",
    "cracked.st": "cracked",
    "spear.st": "spear",
    "spear.cx": "spear",
    "pwnforums.st": "pwnfrm",
    "pwnfrm.st": "pwnfrm",
}


def import_notes_file(path: str | Path, *, protect: bool | None = None) -> list[str]:
    """Import ``网址：<url>`` / ``账密：<user>/<password>`` pairs from a notes file.

    The desktop notes people actually keep look like this, so the broker accepts
    that shape instead of asking anyone to hand-edit JSON.  Returns the site
    keys that were written; unknown hosts are skipped and reported in the log.
    """
    notes = Path(path)
    imported: list[str] = []
    pending_url = ""
    for raw in notes.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        url_match = re.search(r"https?://[^\s，,；;]+", line)
        if url_match and ("网址" in line or "URL" in line.upper() or "http" in line):
            pending_url = url_match.group(0).rstrip("）)")
            continue
        credentials_match = re.search(r"账密[:：]\s*(\S+?)\s*[/／]\s*(\S+)", line)
        if not credentials_match or not pending_url:
            continue
        username, password = credentials_match.group(1).strip(), credentials_match.group(2).strip()
        host = (urlsplit(pending_url).hostname or "").lower()
        host = host[4:] if host.startswith("www.") else host
        site = SITE_HOSTS.get(host)
        if not site:
            logger.warning("import: no collector site for %s; skipped", host)
            pending_url = ""
            continue
        save_credentials(site, username=username, password=password, login_url=pending_url, protect=protect)
        imported.append(site)
        pending_url = ""
    logger.info("import: wrote %d credential record(s): %s", len(imported), ", ".join(imported))
    return imported


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="darkweb_collector.login_broker",
                                     description="Keep forum logins alive for credential-protected sources.")
    parser.add_argument("action", choices=["status", "login", "login-all", "set", "delete", "sites", "import",
                                           "import-state"])
    parser.add_argument("site", nargs="?", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--login-url", default="")
    parser.add_argument("--engine", default="")
    parser.add_argument("--no-headless", action="store_true")
    parser.add_argument("--state-file", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.action == "sites":
        print("\n".join(configured_sites()))
        return 0
    if args.action == "import":
        if not args.site:
            parser.error("import requires the path to a notes file")
        imported = import_notes_file(args.site)
        print("\n".join(imported))
        return 0 if imported else 1
    if args.action == "import-state":
        if not (args.site and args.state_file):
            parser.error("import-state requires SITE and --state-file PATH")
        payload = json.loads(Path(args.state_file).read_text(encoding="utf-8"))
        report = import_session_state(args.site, payload)
        print(json.dumps(report.as_dict(), ensure_ascii=False, indent=2) if args.json else report.detail)
        return 0 if report.ok else 1
    if args.action == "set":
        if not (args.site and args.username and args.password):
            parser.error("set requires SITE --username --password")
        path = save_credentials(args.site, username=args.username, password=args.password,
                                login_url=args.login_url, engine=args.engine)
        print(f"saved {path}")
        return 0
    if args.action == "delete":
        print("deleted" if delete_credentials(args.site) else "not found")
        return 0
    if args.action == "status":
        rows = status_all() if not args.site else [probe(args.site)]
        if args.json:
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            for row in rows:
                print(f"{row['site_name']:<14} {row['status']:<9} cookies={row.get('cookie_count', 0):<3} "
                      f"age={row.get('age_seconds', 0):.0f}s creds={row.get('has_credentials')}")
        return 0
    reports = [login(args.site, headless=not args.no_headless)] if args.action == "login" else login_all(
        headless=not args.no_headless)
    if args.json:
        print(json.dumps([report.as_dict() for report in reports], ensure_ascii=False, indent=2))
    else:
        for report in reports:
            print(f"{report.site_name:<14} {report.status:<11} {report.detail}")
    return 0 if all(report.ok for report in reports) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
