"""Persisted edge-clearance cookies (``cf_clearance`` and friends).

Cloudflare binds a clearance cookie to the client it was issued to: the same
IP, the same user-agent *family*, and a document that passed the challenge.
Replaying a ``cf_clearance`` harvested by a Firefox run inside a Chrome request
is treated as a stolen cookie, so slots are keyed by UA family **and** proxy and
are dropped as soon as either changes.

Nothing here is a challenge solver.  It is the memory that makes an expensive
browser solve pay off for the cheap HTTP route afterwards.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib
import tempfile
import time
from typing import Any, Iterable, Mapping

from darkweb_collector.access_bypass.detect import clearance_cookie_names

#: Bumped when the on-disk schema changes; older files are ignored.
JAR_VERSION = 1
#: Cookies kept per (host, UA family, proxy) slot.
MAX_COOKIES_PER_SLOT = 12
#: Slots kept per host before the oldest is evicted.
MAX_SLOTS_PER_HOST = 4
#: A clearance older than this is never trusted even if the cookie claims a
#: longer expiry (edges rotate their challenge far more often than that).
MAX_TRUSTED_AGE_SECONDS = 6 * 3600.0


def _utc_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat()


def ua_family(user_agent: str | None) -> str:
    """Coarse UA family used to bind a clearance cookie to its client."""

    value = (user_agent or "").lower()
    if not value:
        return ""
    if "edg/" in value:
        return "edge"
    if "firefox/" in value:
        return "firefox"
    if "chrome/" in value or "chromium/" in value:
        return "chrome"
    if "safari/" in value and "version/" in value:
        return "safari"
    return "other"


def proxy_tag(proxy_server: str | None) -> str:
    """Stable, non-reversible tag for the egress path a cookie was bound to."""

    value = (proxy_server or "").strip().lower()
    if not value:
        return "direct"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    scheme = value.split("://", 1)[0] if "://" in value else "proxy"
    return f"{scheme}:{digest}"


def state_root() -> pathlib.Path:
    """Directory that holds every clearance jar (inside the collector data root)."""

    from darkweb_collector.runtime import user_data_root

    return user_data_root() / "access-bypass"


def _host_dir(host: str) -> pathlib.Path:
    safe = (host or "unknown").strip().lower().replace(":", "_").replace("/", "_")
    return state_root() / safe


def jar_path(host: str) -> pathlib.Path:
    return _host_dir(host) / "clearance.json"


@dataclass
class ClearanceSlot:
    """One (host, UA family, proxy) clearance record."""

    host: str
    ua_family: str
    proxy: str
    user_agent: str = ""
    cookies: list[dict[str, Any]] = field(default_factory=list)
    obtained_at: float = 0.0
    expires_at: float = 0.0
    source: str = ""
    challenge: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "ua_family": self.ua_family,
            "proxy": self.proxy,
            "user_agent": self.user_agent,
            "cookies": self.cookies,
            "obtained_at": self.obtained_at,
            "expires_at": self.expires_at,
            "source": self.source,
            "challenge": self.challenge,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ClearanceSlot":
        return cls(
            host=str(payload.get("host") or ""),
            ua_family=str(payload.get("ua_family") or ""),
            proxy=str(payload.get("proxy") or "direct"),
            user_agent=str(payload.get("user_agent") or ""),
            cookies=[dict(item) for item in payload.get("cookies") or [] if isinstance(item, Mapping)],
            obtained_at=float(payload.get("obtained_at") or 0.0),
            expires_at=float(payload.get("expires_at") or 0.0),
            source=str(payload.get("source") or ""),
            challenge=str(payload.get("challenge") or ""),
        )

    def fresh(self, now: float) -> bool:
        return self.expires_at > now and bool(self.cookies)

    def cookie_header(self) -> str:
        return "; ".join(
            f"{cookie.get('name')}={cookie.get('value')}"
            for cookie in self.cookies
            if cookie.get("name")
        )


def _read_jar(host: str) -> list[ClearanceSlot]:
    path = jar_path(host)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(raw, dict) or int(raw.get("version") or 0) != JAR_VERSION:
        return []
    slots = []
    for item in raw.get("slots") or []:
        if isinstance(item, Mapping):
            slot = ClearanceSlot.from_dict(item)
            if slot.host and slot.cookies:
                slots.append(slot)
    return slots


def _write_jar(host: str, slots: Iterable[ClearanceSlot]) -> None:
    path = jar_path(host)
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(slots, key=lambda slot: slot.obtained_at, reverse=True)[:MAX_SLOTS_PER_HOST]
    payload = {"version": JAR_VERSION, "host": host, "slots": [slot.to_dict() for slot in ordered]}
    fd, tmp_name = tempfile.mkstemp(prefix=".clearance-", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _domain_matches(cookie_domain: str, host: str) -> bool:
    domain = (cookie_domain or "").strip().lower().lstrip(".")
    host = (host or "").strip().lower()
    if not domain or not host:
        return True
    return host == domain or host.endswith("." + domain)


def _cookie_expiry(cookie: Mapping[str, Any]) -> float:
    try:
        return float(cookie.get("expires") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def select_slot(cookies: Iterable[Mapping[str, Any]], *, user_agent: str = "",
                proxy_server: str = "") -> ClearanceSlot | None:
    """Build a slot from freshly observed cookies, or ``None`` if unusable."""

    payload = [dict(cookie) for cookie in cookies if isinstance(cookie, Mapping)]
    names = clearance_cookie_names(payload)
    if not names:
        return None
    now = time.time()
    selected = {
        str(cookie.get("name") or "").lower()
        for cookie in payload
        if str(cookie.get("name") or "").lower() in {name.lower() for name in names}
    }
    kept: list[dict[str, Any]] = []
    for cookie in payload:
        if str(cookie.get("name") or "").lower() not in selected:
            continue
        expires = _cookie_expiry(cookie)
        if 0 < expires <= now:
            # An already-expired clearance cookie cannot pass anything; storing
            # it would make the HTTP route replay a dead value forever.
            continue
        kept.append(cookie)
        if len(kept) >= MAX_COOKIES_PER_SLOT:
            break
    if not kept:
        return None
    explicit = [expiry for expiry in (_cookie_expiry(cookie) for cookie in kept) if expiry > now]
    issued = min(explicit) if explicit else now + MAX_TRUSTED_AGE_SECONDS
    return ClearanceSlot(
        host="",
        ua_family=ua_family(user_agent),
        proxy=proxy_tag(proxy_server),
        user_agent=(user_agent or "")[:256],
        cookies=kept,
        obtained_at=now,
        expires_at=min(issued, now + MAX_TRUSTED_AGE_SECONDS),
    )


def record(host: str, cookies: Iterable[Mapping[str, Any]], *, user_agent: str = "",
           proxy_server: str = "", source: str = "", challenge: str = "") -> ClearanceSlot | None:
    """Persist clearance cookies for ``host`` and return the stored slot."""

    if not host:
        return None
    slot = select_slot(cookies, user_agent=user_agent, proxy_server=proxy_server)
    if slot is None:
        return None
    slot = replace(slot, host=host, source=source[:32], challenge=challenge[:32])
    existing = _read_jar(host)
    merged = [item for item in existing
              if not (item.ua_family == slot.ua_family and item.proxy == slot.proxy)]
    merged.append(slot)
    _write_jar(host, merged)
    return slot


def slot_for(host: str, *, user_agent: str = "", proxy_server: str = "",
             now: float | None = None) -> ClearanceSlot | None:
    """Return a usable clearance slot for this host/client, if one exists."""

    moment = time.time() if now is None else now
    family = ua_family(user_agent)
    tag = proxy_tag(proxy_server)
    candidates = [
        slot for slot in _read_jar(host)
        if slot.fresh(moment) and slot.ua_family == family and slot.proxy == tag
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda slot: slot.expires_at)


def cookies_for(host: str, *, user_agent: str = "", proxy_server: str = "",
                now: float | None = None) -> list[dict[str, Any]]:
    """Clearance cookies to replay for ``host`` (empty when none is usable)."""

    slot = slot_for(host, user_agent=user_agent, proxy_server=proxy_server, now=now)
    return list(slot.cookies) if slot else []


def invalidate(host: str, *, user_agent: str = "", proxy_server: str = "") -> bool:
    """Drop the slot that was just rejected.  Returns True when one was removed."""

    if not host:
        return False
    family = ua_family(user_agent)
    tag = proxy_tag(proxy_server)
    existing = _read_jar(host)
    kept = [slot for slot in existing if not (slot.ua_family == family and slot.proxy == tag)]
    if len(kept) == len(existing):
        return False
    _write_jar(host, kept)
    return True


def purge_expired(host: str, *, now: float | None = None) -> int:
    """Delete expired slots for ``host``; returns how many were removed."""

    moment = time.time() if now is None else now
    existing = _read_jar(host)
    kept = [slot for slot in existing if slot.expires_at > moment]
    if len(kept) != len(existing):
        _write_jar(host, kept)
    return len(existing) - len(kept)


def describe(host: str) -> list[str]:
    """Human-readable one-liner per slot, for the probe report."""

    lines = []
    now = time.time()
    for slot in _read_jar(host):
        remaining = max(0.0, slot.expires_at - now)
        state = "fresh" if slot.fresh(now) else "expired"
        lines.append(
            f"{host} [{slot.ua_family}/{slot.proxy}] {state} "
            f"ttl={int(remaining)}s cookies="
            + ",".join(str(cookie.get("name")) for cookie in slot.cookies)
            + (f" source={slot.source}" if slot.source else "")
            + (f" at={_utc_iso(slot.obtained_at)}" if slot.obtained_at else "")
        )
    return lines
