"""Per-host politeness.

The collector has a request budget, but a budget alone does not look human: a
burst of six requests in two seconds then silence is a bot signature, and it is
also what earns the 429 that stops the run for half an hour.  This module adds

* a jittered minimum interval between two requests to the same host, and
* a penalty window after the host explicitly asked us to slow down
  (``429``/``503`` with or without ``Retry-After``).

State is a small JSON file per data root so that several worker processes
sharing a data root respect the same pace.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import pathlib
import random
import tempfile
import time
from typing import Any, Mapping

PACING_VERSION = 1
DEFAULT_MIN_INTERVAL = 1.5
DEFAULT_MAX_INTERVAL = 4.5
#: Fallback penalty when a host rejects without ``Retry-After``.
DEFAULT_PENALTY_SECONDS = 120.0
#: Cap so a hostile ``Retry-After`` cannot park a host for days.
MAX_PENALTY_SECONDS = 3600.0


def _root() -> pathlib.Path:
    from darkweb_collector.access_bypass.clearance import state_root

    return state_root()


def _path() -> pathlib.Path:
    return _root() / "pacing.json"


def _load() -> dict[str, Any]:
    try:
        raw = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"version": PACING_VERSION, "hosts": {}}
    if not isinstance(raw, dict) or int(raw.get("version") or 0) != PACING_VERSION:
        return {"version": PACING_VERSION, "hosts": {}}
    if not isinstance(raw.get("hosts"), dict):
        raw["hosts"] = {}
    return raw


def _save(payload: Mapping[str, Any]) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".pacing-", suffix=".json", dir=str(path.parent))
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


@dataclass(frozen=True)
class PaceEntry:
    last_request: float = 0.0
    penalty_until: float = 0.0
    last_status: int = 0

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any] | None) -> "PaceEntry":
        payload = payload or {}
        return cls(
            last_request=float(payload.get("last_request") or 0.0),
            penalty_until=float(payload.get("penalty_until") or 0.0),
            last_status=int(payload.get("last_status") or 0),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_request": round(self.last_request, 3),
            "penalty_until": round(self.penalty_until, 3),
            "last_status": self.last_status,
        }


def _normalise_interval(min_interval: float, max_interval: float) -> tuple[float, float]:
    low = max(0.0, float(min_interval or 0.0))
    high = max(low, float(max_interval or low))
    return low, high


def _jitter(low: float, high: float) -> float:
    if high <= low:
        return low
    # Bias towards the lower half: a human keeps a rhythm, they do not
    # uniformly sprinkle the maximum delay.
    return random.uniform(low, low + (high - low) * 0.6)


def due_at(host: str, *, min_interval: float = DEFAULT_MIN_INTERVAL,
           max_interval: float = DEFAULT_MAX_INTERVAL,
           next_gap: float | None = None) -> float:
    """Epoch at which the next request to ``host`` may start."""

    low, high = _normalise_interval(min_interval, max_interval)
    if not host or (low <= 0 and high <= 0):
        return 0.0
    entry = PaceEntry.from_mapping(_load()["hosts"].get(host.strip().lower()))
    gap = _jitter(low, high) if next_gap is None else max(0.0, float(next_gap))
    return max(entry.penalty_until, entry.last_request + gap)


def wait(host: str, *, min_interval: float = DEFAULT_MIN_INTERVAL,
         max_interval: float = DEFAULT_MAX_INTERVAL, deadline: float | None = None,
         next_gap: float | None = None) -> float:
    """Sleep until the host is due.  Returns the seconds actually slept.

    A ``deadline`` (epoch) caps the sleep: the caller's request timeout is the
    hard limit, and a truncated sleep is reported by the return value being
    smaller than the computed delay.
    """

    delay = due_at(host, min_interval=min_interval, max_interval=max_interval,
                   next_gap=next_gap) - time.time()
    if delay <= 0:
        return 0.0
    if deadline is not None:
        delay = min(delay, max(0.0, deadline - time.time()))
    if delay <= 0:
        return 0.0
    time.sleep(delay)
    return delay


def mark_request(host: str, *, status: int = 0) -> None:
    """Record that a request to ``host`` just started/completed."""

    if not host:
        return
    key = host.strip().lower()
    payload = _load()
    entry = PaceEntry.from_mapping(payload["hosts"].get(key))
    payload["hosts"][key] = PaceEntry(
        last_request=time.time(),
        penalty_until=entry.penalty_until,
        last_status=int(status or entry.last_status),
    ).to_dict()
    _save(payload)


def penalise(host: str, *, seconds: float = 0.0, status: int = 429) -> float:
    """Park ``host`` for a while after it asked us to slow down."""

    if not host:
        return 0.0
    penalty = DEFAULT_PENALTY_SECONDS if seconds <= 0 else float(seconds)
    penalty = min(MAX_PENALTY_SECONDS, max(5.0, penalty))
    key = host.strip().lower()
    payload = _load()
    entry = PaceEntry.from_mapping(payload["hosts"].get(key))
    until = max(entry.penalty_until, time.time() + penalty)
    payload["hosts"][key] = PaceEntry(
        last_request=entry.last_request,
        penalty_until=until,
        last_status=int(status or entry.last_status),
    ).to_dict()
    _save(payload)
    return max(0.0, until - time.time())


def remaining_penalty(host: str) -> float:
    """Seconds left in the current penalty window (0 when free)."""

    if not host:
        return 0.0
    entry = PaceEntry.from_mapping(_load()["hosts"].get(host.strip().lower()))
    return max(0.0, entry.penalty_until - time.time())


def clear(host: str) -> None:
    """Forget all pacing state for ``host`` (used by the probe/tests)."""

    if not host:
        return
    key = host.strip().lower()
    payload = _load()
    if key in payload["hosts"]:
        del payload["hosts"][key]
        _save(payload)
