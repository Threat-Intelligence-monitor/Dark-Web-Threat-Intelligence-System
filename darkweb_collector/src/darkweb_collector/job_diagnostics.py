from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from darkweb_collector.models import SiteConfig


DEFAULT_FAILURE_COOLDOWN_SECONDS = 30 * 60
DEFAULT_FAILURE_THRESHOLD = 3


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def classify_error(message: str | None) -> str:
    lowered = (message or "").lower()
    if not lowered:
        return ""
    category = lowered.split(":", 1)[0]
    if category in {"unavailable", "auth_required", "restricted", "blocked", "rate_limited", "network",
                    "timeout", "parse", "unknown", "artifact", "infrastructure", "retry_budget"}:
        return category
    if (
        "cannot switch to a different thread" in lowered
        or "greenlet" in lowered
        or "playwright" in lowered
        or "browser has been closed" in lowered
        or "target page, context or browser has been closed" in lowered
    ):
        return "browser_runtime"
    if "timeout" in lowered or "timed out" in lowered or "time-out" in lowered:
        return "timeout"
    if (
        "checking your browser" in lowered
        or "verify you are human" in lowered
        or "cloudflare" in lowered
        or "captcha" in lowered
        or "forbidden" in lowered
        or "403" in lowered
    ):
        return "site_blocked"
    if (
        "proxy" in lowered
        or "socks" in lowered
        or "curl fetch failed" in lowered
        or "connection refused" in lowered
        or "could not resolve" in lowered
        or "network is unreachable" in lowered
    ):
        return "proxy"
    if (
        "parse" in lowered
        or "parser" in lowered
        or "invalid detail html" in lowered
        or "invalid payload" in lowered
        or "missing required" in lowered
    ):
        return "parse"
    return "unknown"


def failure_threshold(config: SiteConfig) -> int:
    try:
        return max(int(config.extras.get("failure_threshold", DEFAULT_FAILURE_THRESHOLD)), 1)
    except (TypeError, ValueError):
        return DEFAULT_FAILURE_THRESHOLD


def failure_cooldown_seconds(config: SiteConfig) -> int:
    try:
        return max(int(config.extras.get("failure_cooldown_seconds", DEFAULT_FAILURE_COOLDOWN_SECONDS)), 1)
    except (TypeError, ValueError):
        return DEFAULT_FAILURE_COOLDOWN_SECONDS


def consecutive_failures(rows: list[dict[str, Any]]) -> int:
    count = 0
    for row in rows:
        status = str(row.get("status") or "")
        if status == "succeeded":
            break
        if status == "failed":
            count += 1
            continue
        if status in {"running", "enqueued", "stale"}:
            continue
        break
    return count


def failure_cooldown_until(config: SiteConfig, rows: list[dict[str, Any]]) -> datetime | None:
    if consecutive_failures(rows) < failure_threshold(config):
        return None
    latest_failure = next(
        (
            row
            for row in rows
            if str(row.get("status") or "") == "failed"
        ),
        None,
    )
    if latest_failure is None:
        return None
    marker = parse_dt(latest_failure.get("finished_at") or latest_failure.get("started_at"))
    if marker is None:
        return None
    return marker + timedelta(seconds=failure_cooldown_seconds(config))


def is_in_failure_cooldown(
    config: SiteConfig,
    rows: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> bool:
    until = failure_cooldown_until(config, rows)
    if until is None:
        return False
    return (now or datetime.now(timezone.utc)) < until
