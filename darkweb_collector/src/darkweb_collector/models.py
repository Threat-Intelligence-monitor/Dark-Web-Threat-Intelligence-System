from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


VALID_FETCH_MODES = {"tor_http", "browser"}
VALID_PROFILES = {"hot", "warm", "cold"}
VALID_BROWSER_QUEUES = {"browser_render", "browser_public", "browser_onion"}
PROFILE_INTERVALS_SECONDS = {
    "hot": 10 * 60,
    "warm": 60 * 60,
    "cold": 6 * 60 * 60,
}


@dataclass(frozen=True)
class SiteConfig:
    site_name: str
    enabled: bool
    seed_urls: tuple[str, ...]
    seed_fetch_mode: str
    detail_fetch_mode: str
    profile: str
    max_topics_per_run: int
    max_detail_pages_per_run: int
    cooldown_seconds: int
    output_dir: Path
    dedupe_window_minutes: int
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def profile_interval_seconds(self) -> int:
        return PROFILE_INTERVALS_SECONDS[self.profile]

    @property
    def effective_interval_seconds(self) -> int:
        return max(self.profile_interval_seconds, self.cooldown_seconds)

    @property
    def fetch_timeout_seconds(self) -> int:
        return int(self.extras.get("fetch_timeout_seconds", 90))

    @property
    def render_wait_seconds(self) -> int:
        return int(self.extras.get("render_wait_seconds", 8))

    @property
    def uses_browser(self) -> bool:
        return self.seed_fetch_mode == "browser" or self.detail_fetch_mode == "browser"

    @property
    def browser_queue(self) -> str:
        return str(self.extras.get("browser_queue") or "browser_render").strip()

    @property
    def max_concurrent_details(self) -> int:
        return max(1, int(self.extras.get("max_concurrent_details", 1)))

    @property
    def detail_slot_ttl_seconds(self) -> int:
        default_ttl = max(900, self.fetch_timeout_seconds * 4)
        return max(60, int(self.extras.get("detail_slot_ttl_seconds", default_ttl)))

    @property
    def detail_slot_retry_seconds(self) -> int:
        return max(1, int(self.extras.get("detail_slot_retry_seconds", 5)))

    @property
    def recent_pages_per_run(self) -> int:
        return int(self.extras.get("recent_pages_per_run", 1))

    @property
    def backfill_pages_per_run(self) -> int:
        return int(self.extras.get("backfill_pages_per_run", 5))

    @property
    def frontier_max_pending(self) -> int:
        return int(self.extras.get("frontier_max_pending", 500))

    @property
    def frontier_dispatch_window(self) -> int:
        return 2 * self.max_concurrent_details

    @property
    def frontier_lease_seconds(self) -> int:
        return max(3600, self.detail_slot_ttl_seconds)

    @property
    def failure_cooldown_seconds(self) -> int:
        return int(self.extras.get("failure_cooldown_seconds", 30 * 60))


@dataclass(frozen=True)
class RunContext:
    job_id: str
    job_type: str
    queue_name: str
    target: str
    started_at_utc: str
    force: bool = False
    attempt: int = 0


@dataclass
class SeedResult:
    site_name: str
    collected_at_utc: str
    payload: dict[str, Any]
    raw_html_by_url: dict[str, str]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetailTask:
    site_name: str
    target_url: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "site_name": self.site_name,
            "target_url": self.target_url,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DetailTask":
        return cls(
            site_name=str(payload["site_name"]),
            target_url=str(payload["target_url"]),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass
class DetailResult:
    site_name: str
    target_url: str
    payload: dict[str, Any]
    raw_html: str | None
    screenshot_png: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
