from __future__ import annotations

from typing import Protocol

from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig


class SiteAdapter(Protocol):
    site_name: str

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        ...

    def plan_details(self, seed_result: SeedResult, config: SiteConfig) -> list[DetailTask]:
        ...

    def collect_detail(self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext) -> DetailResult | None:
        ...

    def persist(
        self,
        config: SiteConfig,
        run_ctx: RunContext,
        seed_result: SeedResult | None = None,
        detail_results: list[DetailResult] | None = None,
        connection=None,
    ) -> None:
        ...
