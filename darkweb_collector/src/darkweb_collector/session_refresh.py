"""Keep the login sessions fresh without an operator in the loop.

A browser session is only replayed while it is younger than
``source_sessions.MAX_SESSION_AGE_SECONDS`` (6 hours) — older cookies are the
exact thing that made Cloudflare answer a hard 403 for days.  The cost of that
rule is that every site needs a new login once or twice a day, and doing that by
hand for eight sites is precisely the chore the login broker was meant to
remove.

This module is the missing clock: a small background loop that looks at each
site's session age, and — when it is about to fall out of the freshness window —
drives the broker's own login for it.  Sites whose login page cannot be passed
by an automated browser (captcha, challenge, drag puzzle) come back as
``needs_human``; the loop records that and stops retrying for a few hours so the
collector never spends its request budget fighting a wall.

Nothing here touches the database or the crawl queue: the only state is one JSON
file next to the other access-bypass state, and the only side effect is the
session file the collector already knows how to use.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable

from darkweb_collector import login_broker
from darkweb_collector.runtime import user_data_root

logger = logging.getLogger(__name__)

STATE_FILENAME = "session-refresh.json"
DEFAULT_REFRESH_AFTER_SECONDS = 4 * 3600
DEFAULT_POLL_SECONDS = 600.0
DEFAULT_FAILURE_COOLDOWN_SECONDS = 30 * 60
HUMAN_COOLDOWN_SECONDS = 6 * 3600
_FRESH_STATUSES = frozenset({"valid", "expiring"})


def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("ignoring invalid %s=%r", name, raw)
        return default
    return value if value > 0 else default


def refresh_after_seconds() -> float:
    return _env_float("DARKWEB_SESSION_REFRESH_AFTER", float(DEFAULT_REFRESH_AFTER_SECONDS))


def poll_seconds() -> float:
    return _env_float("DARKWEB_SESSION_REFRESH_POLL", DEFAULT_POLL_SECONDS)


def failure_cooldown_seconds() -> float:
    return _env_float("DARKWEB_SESSION_REFRESH_COOLDOWN", float(DEFAULT_FAILURE_COOLDOWN_SECONDS))


def state_path() -> Path:
    return user_data_root() / "access-bypass" / STATE_FILENAME


def _read_state() -> dict[str, dict[str, Any]]:
    path = state_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        logger.warning("session refresh state is unreadable: %s", path)
        return {}
    entries = payload.get("sites") if isinstance(payload, dict) else None
    return entries if isinstance(entries, dict) else {}


def _write_state(entries: dict[str, dict[str, Any]]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"version": 1, "sites": entries}, ensure_ascii=False, indent=2, sort_keys=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(body, encoding="utf-8")
    os.replace(temporary, path)


def _entry(entries: dict[str, dict[str, Any]], site_name: str) -> dict[str, Any]:
    current = entries.get(site_name)
    return dict(current) if isinstance(current, dict) else {}


def _update_entry(site_name: str, **fields: Any) -> dict[str, Any]:
    entries = _read_state()
    entry = _entry(entries, site_name)
    entry.update(fields)
    entries[site_name] = entry
    _write_state(entries)
    return entry


def _sites_to_consider() -> list[str]:
    names = set(login_broker.configured_sites())
    names.update(login_broker.busy_sites())
    return sorted(names)


def plan(site_name: str, *, now: float | None = None, entries: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Decide whether this site's session needs a login right now."""
    now = time.time() if now is None else now
    entries = _read_state() if entries is None else entries
    entry = _entry(entries, site_name)
    status = login_broker.probe(site_name)
    age = float(status.get("age_seconds") or 0.0)
    state = str(status.get("status") or "missing")
    has_credentials = bool(status.get("has_credentials"))
    refresh_after = refresh_after_seconds()
    reason = ""
    if not has_credentials:
        reason = "no_credentials"
    elif state in {"missing", "expired", "invalid_state"}:
        reason = state
    elif state in _FRESH_STATUSES and age >= refresh_after:
        reason = "aging"
    next_attempt = float(entry.get("next_attempt") or 0.0)
    due = bool(reason) and reason != "no_credentials" and now >= next_attempt
    return {
        "site_name": site_name,
        "status": state,
        "age_seconds": round(age, 1),
        "refresh_after_seconds": refresh_after,
        "has_credentials": has_credentials,
        "reason": reason,
        "due": due,
        "next_attempt": next_attempt,
        "last_status": str(entry.get("last_status") or ""),
        "last_attempt": float(entry.get("last_attempt") or 0.0),
    }


def refresh_site(
    site_name: str,
    *,
    reason: str = "",
    now: float | None = None,
    headless: bool = True,
    login: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run one login attempt and remember how it went."""
    now = time.time() if now is None else now
    runner = login or login_broker.login
    started = time.time()
    try:
        report = runner(site_name, headless=headless)
        payload = report.as_dict() if hasattr(report, "as_dict") else dict(report or {})
    except Exception as exc:  # noqa: BLE001 - a broken login must not kill the loop
        logger.warning("session refresh for %s raised %s", site_name, type(exc).__name__)
        payload = {"site_name": site_name, "ok": False, "status": "failed", "detail": f"{type(exc).__name__}: {exc}"}
    ok = bool(payload.get("ok"))
    needs_human = bool(payload.get("needs_human"))
    if ok:
        cooldown = max(60.0, refresh_after_seconds() * 0.75)
    elif needs_human:
        cooldown = HUMAN_COOLDOWN_SECONDS
    else:
        cooldown = failure_cooldown_seconds()
    _update_entry(
        site_name,
        last_attempt=now,
        last_status=str(payload.get("status") or ("ok" if ok else "failed")),
        last_detail=str(payload.get("detail") or "")[:400],
        last_reason=reason,
        next_attempt=now + cooldown,
        elapsed_ms=int((time.time() - started) * 1000),
    )
    logger.info(
        "session refresh %s: status=%s reason=%s cooldown=%.0fs",
        site_name, payload.get("status"), reason, cooldown,
    )
    return payload


def refresh_due(
    *,
    now: float | None = None,
    login: Callable[..., Any] | None = None,
    sites: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Refresh every session that is due; safe to call from a timer."""
    now = time.time() if now is None else now
    entries = _read_state()
    busy = set(login_broker.busy_sites())
    refreshed: list[str] = []
    skipped_busy: list[str] = []
    skipped_idle: list[str] = []
    failed: list[str] = []
    for site_name in (sorted(sites) if sites is not None else _sites_to_consider()):
        if site_name in busy:
            skipped_busy.append(site_name)
            continue
        item = plan(site_name, now=now, entries=entries)
        if not item["due"]:
            if item["reason"] in {"no_credentials"} or not item["reason"]:
                skipped_idle.append(site_name)
            continue
        result = refresh_site(site_name, reason=item["reason"], now=now, login=login)
        if result.get("ok"):
            refreshed.append(site_name)
        else:
            failed.append(site_name)
        entries = _read_state()
    return {
        "refreshed": refreshed,
        "failed": failed,
        "skipped_busy": skipped_busy,
        "skipped_idle": skipped_idle,
    }


def request_refresh(site_name: str, *, reason: str = "failure") -> bool:
    """Bring a site's next attempt forward — used when a crawl just failed."""
    if not site_name:
        return False
    entry = _entry(_read_state(), site_name)
    _update_entry(site_name, next_attempt=0.0, last_reason=reason)
    return bool(entry) or True


def schedule(*, now: float | None = None) -> list[dict[str, Any]]:
    now = time.time() if now is None else now
    entries = _read_state()
    return [plan(site_name, now=now, entries=entries) for site_name in _sites_to_consider()]


_worker_lock = threading.Lock()
_worker_stop: threading.Event | None = None
_worker_thread: threading.Thread | None = None


def _worker_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            summary = refresh_due()
            if summary["refreshed"] or summary["failed"]:
                logger.info("session refresh cycle: %s", summary)
        except Exception:  # noqa: BLE001 - the loop must survive one bad site
            logger.exception("session refresh cycle failed")
        if stop_event.wait(poll_seconds()):
            break


def start_worker() -> None:
    global _worker_stop, _worker_thread
    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return
        stop_event = threading.Event()
        thread = threading.Thread(target=_worker_loop, args=(stop_event,), name="session-refresh", daemon=True)
        _worker_stop = stop_event
        _worker_thread = thread
        thread.start()


def stop_worker() -> None:
    global _worker_stop, _worker_thread
    with _worker_lock:
        if _worker_stop is not None:
            _worker_stop.set()
        _worker_stop = None
        _worker_thread = None
