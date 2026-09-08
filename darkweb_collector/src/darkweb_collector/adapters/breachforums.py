from __future__ import annotations

from darkweb_collector.adapters.darkforums import DarkforumsAdapter, _section_name
from darkweb_collector.adapters.pagination import collect_forum_seed
from darkweb_collector.models import RunContext, SeedResult, SiteConfig
from darkweb_collector.sites.breachforums import parse_breachforums_detail, parse_breachforums_list


def _breachforums_section(url: str) -> str:
    section = _section_name(url)
    return "sellers_place" if section == "leaks_market" else section


class BreachforumsAdapter(DarkforumsAdapter):
    site_name = "breachforums"
    list_parser = staticmethod(parse_breachforums_list)
    detail_parser = staticmethod(parse_breachforums_detail)
    detail_screenshot_selectors = ("#posts .post",)

    @staticmethod
    def _is_valid_detail_payload(detail: dict) -> bool:
        return bool(str(detail.get("content") or "").strip())

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        return collect_forum_seed(self, config, self.list_parser, _breachforums_section)
