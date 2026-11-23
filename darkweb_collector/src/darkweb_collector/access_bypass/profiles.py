"""Which bypass profile applies to a site, a host, or one URL.

Resolution order (last wins):

1. the built-in table below — every registered source in ``sites.yaml`` has an
   entry, so a site works without any configuration change;
2. ``darkweb_collector/bypass_profiles.yaml`` (same key or a host entry), which
   operators edit to add a site or to relax a limit;
3. the site's own ``sites.yaml`` entry under ``access_bypass: {...}``, so a
   per-site override lives next to the rest of that site's settings.

The file is parsed as JSON first (``config.py`` does the same); PyYAML is not a
dependency of the collector and the shipped file is JSON-compatible YAML.
"""

from __future__ import annotations

from functools import lru_cache
import json
import os
import pathlib
from typing import Any, Mapping

from darkweb_collector.access_bypass.httpfetch import host_key
from darkweb_collector.access_bypass.model import BypassProfile

#: Environment switch: ``ACCESS_BYPASS_DISABLE=1`` forces the plain-curl path
#: and no stealth, which is the pre-change behaviour (used by the ops rollback).
DISABLE_ENV = "ACCESS_BYPASS_DISABLE"

#: Protections observed or plausible per registered source.  ``notes`` records
#: *why* a value is what it is; keep them when editing.
BUILTIN_DEFAULTS: dict[str, dict[str, Any]] = {
    "default": {
        "protection": "unknown",
        "http_strategy": "auto",
        "impersonate": "chrome",
        "header_profile": "chrome",
        "stealth": "full",
        "challenge_wait_seconds": 25.0,
        "challenge_interactive": True,
        "clearance_ttl_seconds": 1800.0,
        "min_interval_seconds": 1.5,
        "max_interval_seconds": 4.5,
        "notes": "fallback for any host without a specific profile",
    },
    "darkforums": {
        "hosts": ["darkforums.as"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "header_profile": "chrome",
        "browser_engine": "chromium",
        "stealth": "full",
        "challenge_wait_seconds": 30.0,
        "clearance_ttl_seconds": 1800.0,
        "notes": "Cloudflare managed challenge on a white-labelled page "
                 "('Checking your browser | DarkForums'); TLS impersonation passes, "
                 "login-only sections report auth_required",
    },
    "cracked": {
        "hosts": ["cracked.st"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "browser_engine": "chromium",
        "stealth": "full",
        "challenge_wait_seconds": 20.0,
        "notes": "Cloudflare in front of MyBB; plain HTTP already passes, keep "
                 "impersonation for the logged-in sections",
    },
    "breachforums": {
        "hosts": ["bf.st", "breachforums.st", "breached.st"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "stealth": "full",
        "challenge_wait_seconds": 25.0,
        "notes": "Cloudflare; the domain rotates between bf.st and mirrors",
    },
    "spear": {
        "hosts": ["spear.cx"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "stealth": "full",
        "challenge_wait_seconds": 25.0,
    },
    "leakforum": {
        "hosts": ["leakforum.io"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "stealth": "full",
        "challenge_wait_seconds": 25.0,
    },
    "raidforums": {
        "hosts": ["raidforums.im"],
        "protection": "ddos-guard",
        "impersonate": "chrome",
        "stealth": "full",
        "challenge_wait_seconds": 30.0,
        "challenge_interactive": True,
        "notes": "DDoS-Guard issues a JS cookie challenge; the browser route "
                 "passes it, the HTTP route only after the cookie is stored",
    },
    "xforums": {
        "hosts": ["xforums.st"],
        "protection": "cloudflare",
        "impersonate": "chrome",
        "browser_engine": "chromium",
        "stealth": "full",
        "challenge_wait_seconds": 25.0,
        "notes": "XenForo behind Cloudflare; unauthenticated /forums/ answers 302 "
                 "to a login redirect, which is auth_required and not a block",
    },
    "changan": {
        "hosts": ["cabyceogpsji73sske5nvo45mdrkbz4m3qd3iommf3zaaa6izg3j2cqd.onion"],
        "protection": "tor",
        "http_strategy": "curl",
        "browser_engine": "firefox",
        "browser_channel": "",
        "stealth": "basic",
        "challenge_wait_seconds": 15.0,
        "challenge_interactive": False,
        "notes": "onion service; exit-node style blocking does not apply, keep the "
                 "browser light so the Tor circuit is not re-rolled for nothing",
    },
    "dragonforce": {
        "hosts": ["dragonforce.onion"],
        "protection": "tor",
        "http_strategy": "curl",
        "browser_engine": "firefox",
        "stealth": "basic",
        "challenge_wait_seconds": 15.0,
        "challenge_interactive": False,
    },
    "pwnfrm": {
        "hosts": [],
        "protection": "tor",
        "http_strategy": "curl",
        "browser_engine": "firefox",
        "stealth": "basic",
        "challenge_interactive": False,
        "notes": "MyBB onion mirror; disabled in sites.yaml, cookie auth via env",
    },
    "chaos": {
        "hosts": ["hptqq2o2qjva7lcaaq67w36jihzivkaitkexorauw7b2yul2z6zozpqd.onion"],
        "protection": "tor",
        "http_strategy": "curl",
        "browser_engine": "firefox",
        "stealth": "basic",
        "challenge_interactive": False,
    },
    "lynx": {
        "hosts": ["lynxblogtwatfsrwj3oatpejwxk5bngqcd5f7s26iskagfu7ouaomjad.onion"],
        "protection": "tor",
        "http_strategy": "curl",
        "browser_engine": "firefox",
        "stealth": "basic",
        "challenge_interactive": False,
    },
}

PROFILE_FILENAME = "bypass_profiles.yaml"


def bypass_disabled() -> bool:
    return os.environ.get(DISABLE_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def profiles_path() -> pathlib.Path:
    override = os.environ.get("DARKWEB_COLLECTOR_BYPASS_FILE")
    if override:
        return pathlib.Path(override)
    from darkweb_collector.runtime import project_root

    return project_root() / PROFILE_FILENAME


def _read_file(path: pathlib.Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    text = text.strip()
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except ValueError:
        try:
            import yaml  # type: ignore

            payload = yaml.safe_load(text)
        except Exception:
            return {}
    return payload if isinstance(payload, dict) else {}


def _file_signature(path: pathlib.Path) -> tuple[str, float]:
    try:
        stat = path.stat()
    except OSError:
        return ("", 0.0)
    return (str(path), stat.st_mtime)


@lru_cache(maxsize=4)
def _load_file_cached(path_str: str, mtime: float) -> dict[str, Any]:
    return _read_file(pathlib.Path(path_str))


def load_file_profiles() -> dict[str, Any]:
    """Parsed ``bypass_profiles.yaml`` (empty dict when absent/invalid)."""

    path = profiles_path()
    path_str, mtime = _file_signature(path)
    if not path_str:
        return {}
    return _load_file_cached(path_str, mtime)


def _split_overrides(payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Separate ``profiles`` (by site key) from ``hosts`` (by host)."""

    profiles = payload.get("profiles") if isinstance(payload.get("profiles"), Mapping) else {}
    hosts = payload.get("hosts") if isinstance(payload.get("hosts"), Mapping) else {}
    # Shorthand: top-level keys that are not ``profiles``/``hosts`` are treated
    # as site keys, so the file stays readable for a single override.
    inline = {
        key: value for key, value in payload.items()
        if key not in {"profiles", "hosts", "version"} and isinstance(value, Mapping)
    }
    merged = {**inline, **dict(profiles)}
    return merged, dict(hosts)


@lru_cache(maxsize=32)
def _base_profile(key: str) -> BypassProfile:
    payload = BUILTIN_DEFAULTS.get(key) or BUILTIN_DEFAULTS["default"]
    return BypassProfile.from_mapping(payload, key=key)


def _builtin_hosts() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for key, payload in BUILTIN_DEFAULTS.items():
        for host in payload.get("hosts") or ():
            mapping[str(host).lower()] = key
    return mapping


def profile_for(
    site_key: str | None = None,
    *,
    url: str = "",
    extras: Mapping[str, Any] | None = None,
    use_file: bool = True,
) -> BypassProfile:
    """Resolve the effective profile for a site key / URL.

    ``extras`` is the site's ``sites.yaml`` dictionary; only its
    ``access_bypass`` entry is used, so callers can pass ``config.extras``
    unchanged.
    """

    key = (site_key or "").strip().lower()
    host = host_key(url)
    if not key and host:
        key = _builtin_hosts().get(host, "")
    profile = _base_profile(key or "default")
    if host and not profile.hosts:
        profile = profile.merged({"hosts": [host]})

    if use_file:
        profiles, host_overrides = _split_overrides(load_file_profiles())
        if key and isinstance(profiles.get(key), Mapping):
            profile = profile.merged(profiles[key])
        if host and isinstance(host_overrides.get(host), Mapping):
            profile = profile.merged(host_overrides[host])

    if extras:
        override = extras.get("access_bypass") if isinstance(extras, Mapping) else None
        if isinstance(override, Mapping):
            profile = profile.merged(override)

    if bypass_disabled():
        profile = profile.merged({"stealth": "none", "http_strategy": "curl",
                                  "challenge_interactive": False, "notes": "bypass disabled by env"})
    return profile


def profile_for_host(host: str) -> BypassProfile:
    key = _builtin_hosts().get((host or "").strip().lower(), "")
    return profile_for(key or None, url=f"https://{host}/" if host else "")


def describe_profiles() -> list[str]:
    """One line per effective site profile, for ``--list`` and the docs."""

    lines = []
    for key in BUILTIN_DEFAULTS:
        if key == "default":
            continue
        profile = profile_for(key)
        hosts = ",".join(profile.hosts) or "-"
        lines.append(f"{key:14s} {hosts:60s} {profile.describe()}")
    return lines


def reload() -> None:
    """Drop cached file content (tests, or after editing the profile file)."""

    _load_file_cached.cache_clear()
    _base_profile.cache_clear()


__all__ = [
    "BUILTIN_DEFAULTS",
    "DISABLE_ENV",
    "bypass_disabled",
    "describe_profiles",
    "load_file_profiles",
    "profile_for",
    "profile_for_host",
    "profiles_path",
    "reload",
]
