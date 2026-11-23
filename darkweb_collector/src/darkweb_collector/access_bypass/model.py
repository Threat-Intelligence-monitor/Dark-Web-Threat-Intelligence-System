"""Data model for the access-bypass layer.

The collector talks to sources that sit behind an anti-automation edge
(Cloudflare, DDoS-Guard, Akamai, Imperva, hCaptcha/reCAPTCHA gates).  The
modules in :mod:`darkweb_collector.access_bypass` keep every piece of that
handling in one place so adapters do not grow their own ad-hoc retry loops.

``BypassProfile`` is the per-source policy.  A profile is data, never code:
it is loaded from ``bypass_profiles.yaml`` (JSON syntax is accepted, matching
``sites.yaml``) and can be overridden from a site's ``bypass`` extras block.

``ProtectionSignal`` is the machine-readable verdict for one response, and
``BypassOutcome`` records how a request was actually served.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
from typing import Any, Mapping

#: Challenge families the challenge resolver knows how to drive.
CHALLENGE_KINDS = frozenset({
    "managed",          # Cloudflare managed challenge (Turnstile widget)
    "turnstile",        # explicit Cloudflare Turnstile widget
    "js",               # Cloudflare JavaScript / "I'm Under Attack" interstitial
    "ddos-guard",       # DDoS-Guard JS check
    "akamai",           # Akamai Bot Manager JS sensor
    "incapsula",        # Imperva/Incapsula JS challenge
    "image-captcha",    # classic image captcha behind a login/entry form
    "unknown",
})

#: Routes a request may be served through, cheapest first.
ROUTES = ("clearance", "impersonate", "curl", "browser")

#: Stealth levels accepted by :mod:`darkweb_collector.access_bypass.stealth`.
STEALTH_LEVELS = frozenset({"none", "basic", "full"})

#: HTTP strategies accepted by :mod:`darkweb_collector.access_bypass.httpfetch`.
HTTP_STRATEGIES = frozenset({"impersonate", "curl", "browser", "auto"})


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _as_float(value: Any, default: float, *, minimum: float | None = None,
              maximum: float | None = None) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    if minimum is not None:
        number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def _as_int(value: Any, default: int, *, minimum: int | None = None,
            maximum: int | None = None) -> int:
    return int(_as_float(value, float(default), minimum=minimum, maximum=maximum))


def _as_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(str(part).strip() for part in value if str(part).strip())
    return ()


@dataclass(frozen=True)
class BypassProfile:
    """Per-source policy for getting past an anti-automation edge.

    Every field has a conservative default so a profile can be a two-line
    entry in the config file.  ``key`` is the stable identifier used for
    state directories and diagnostics.
    """

    key: str = "default"
    #: Host patterns (``darkforums.as``, ``*.onion``) this profile applies to.
    hosts: tuple[str, ...] = ()
    #: Expected edge vendor: cloudflare | ddos-guard | akamai | incapsula | none | unknown.
    protection: str = "unknown"
    #: cheapest route to try first: impersonate | curl | browser.
    http_strategy: str = "auto"
    #: curl_cffi impersonation target (``chrome``, ``chrome136``, ``safari``, ``firefox``).
    impersonate: str = "chrome"
    #: Header set to synthesize on the HTTP route.
    header_profile: str = "chrome"
    #: Playwright engine for the browser route.
    browser_engine: str = "chromium"
    #: Playwright ``channel`` (``chrome``/``msedge``) to reuse an installed browser.
    browser_channel: str = ""
    #: Fingerprint hardening level for the browser route.
    stealth: str = "full"
    #: How long the challenge resolver may spend on one page.
    challenge_wait_seconds: float = 25.0
    #: Allow pointer movement / widget clicks while solving a challenge.
    challenge_interactive: bool = True
    #: Lifetime of persisted clearance cookies (cf_clearance & friends).
    clearance_ttl_seconds: float = 1800.0
    #: Jittered pacing applied before each request from this source.
    min_interval_seconds: float = 1.5
    max_interval_seconds: float = 4.5
    #: Source content sits behind an authenticated session.
    login_wall: bool = False
    #: Free-form operator note surfaced in diagnostics.
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _as_text(self.key, "default") or "default")
        object.__setattr__(self, "hosts", tuple(host.lower() for host in self.hosts if host))
        protection = _as_text(self.protection, "unknown").lower()
        object.__setattr__(self, "protection", protection)
        strategy = _as_text(self.http_strategy, "auto").lower()
        if strategy not in HTTP_STRATEGIES:
            strategy = "auto"
        object.__setattr__(self, "http_strategy", strategy)
        object.__setattr__(self, "impersonate", _as_text(self.impersonate, "chrome"))
        object.__setattr__(self, "header_profile", _as_text(self.header_profile, "chrome").lower())
        engine = _as_text(self.browser_engine, "chromium").lower()
        object.__setattr__(self, "browser_engine", engine if engine in {"chromium", "firefox", "webkit"} else "chromium")
        object.__setattr__(self, "browser_channel", _as_text(self.browser_channel))
        stealth = _as_text(self.stealth, "full").lower()
        object.__setattr__(self, "stealth", stealth if stealth in STEALTH_LEVELS else "full")
        object.__setattr__(self, "challenge_wait_seconds",
                           _as_float(self.challenge_wait_seconds, 25.0, minimum=0.0, maximum=180.0))
        object.__setattr__(self, "challenge_interactive", _as_bool(self.challenge_interactive, True))
        object.__setattr__(self, "clearance_ttl_seconds",
                           _as_float(self.clearance_ttl_seconds, 1800.0, minimum=0.0, maximum=86400.0))
        minimum = _as_float(self.min_interval_seconds, 1.5, minimum=0.0, maximum=120.0)
        maximum = _as_float(self.max_interval_seconds, max(4.5, minimum), minimum=0.0, maximum=300.0)
        if maximum < minimum:
            maximum = minimum
        object.__setattr__(self, "min_interval_seconds", minimum)
        object.__setattr__(self, "max_interval_seconds", maximum)
        object.__setattr__(self, "login_wall", _as_bool(self.login_wall, False))
        object.__setattr__(self, "notes", _as_text(self.notes))

    # -- construction -----------------------------------------------------
    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None, *, key: str = "default") -> "BypassProfile":
        """Build a profile from a config mapping, ignoring unknown keys."""

        if not isinstance(payload, Mapping):
            return cls(key=key)
        known = {field_name for field_name in cls.__dataclass_fields__ if field_name != "key"}
        values = {name: payload[name] for name in known if name in payload}
        values["hosts"] = _as_tuple(payload.get("hosts"))
        values["key"] = _as_text(payload.get("key"), key) or key
        return cls(**values)

    def merged(self, overrides: Mapping[str, Any] | None) -> "BypassProfile":
        """Return a copy with selected fields replaced (site-level overrides)."""

        if not overrides:
            return self
        known = set(self.__dataclass_fields__)
        values = {name: overrides[name] for name in overrides if name in known and name != "key"}
        if "hosts" in values:
            values["hosts"] = _as_tuple(values["hosts"])
        return replace(self, **values) if values else self

    # -- derived views ----------------------------------------------------
    @property
    def wants_clearance_cookies(self) -> bool:
        return self.protection in {"cloudflare", "ddos-guard", "akamai", "incapsula"} or bool(self.hosts)

    @property
    def browser_route_enabled(self) -> bool:
        return self.http_strategy in {"auto", "browser"} or self.protection != "none"

    def describe(self) -> str:
        parts = [f"profile={self.key}", f"protection={self.protection}", f"strategy={self.http_strategy}"]
        if self.impersonate:
            parts.append(f"impersonate={self.impersonate}")
        if self.browser_channel:
            parts.append(f"channel={self.browser_channel}")
        if self.login_wall:
            parts.append("login_wall")
        return " ".join(parts)


@dataclass(frozen=True)
class ProtectionSignal:
    """Machine-readable verdict for one response.

    ``kind`` is the scheduling category (it maps onto
    :class:`darkweb_collector.collection_errors.CollectionFailure` kinds),
    while ``vendor``/``challenge`` say which widget answered so the next
    request can pick the right route.
    """

    kind: str = "none"
    vendor: str = ""
    challenge: str = ""
    status: int = 0
    evidence: tuple[str, ...] = ()
    retry_after: float = 0.0

    @property
    def is_block(self) -> bool:
        return self.kind in {"challenge", "login", "rate-limit", "forbidden", "restricted"}

    @property
    def is_challenge(self) -> bool:
        return self.kind == "challenge"

    @property
    def needs_browser(self) -> bool:
        """True when only a real browser can clear this response."""

        if self.kind != "challenge":
            return False
        return self.challenge in CHALLENGE_KINDS

    def describe(self) -> str:
        if self.kind == "none":
            return "no protection detected"
        label = self.vendor or "edge"
        if self.challenge:
            label = f"{label}/{self.challenge}"
        if self.status:
            label = f"{label} (HTTP {self.status})"
        return label


@dataclass
class BypassOutcome:
    """How one request was served, for diagnostics and the probe report."""

    route: str = "impersonate"
    status: int = 0
    html: str = ""
    signal: ProtectionSignal = field(default_factory=ProtectionSignal)
    resolved: bool = True
    elapsed_ms: int = 0
    clearance: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "status": self.status,
            "resolved": self.resolved,
            "elapsed_ms": self.elapsed_ms,
            "vendor": self.signal.vendor,
            "challenge": self.signal.challenge,
            "signal": self.signal.kind,
            "evidence": list(self.signal.evidence),
            "clearance_cookies": sorted(self.clearance.get("cookie_names", ())),
            "notes": list(self.notes),
        }
