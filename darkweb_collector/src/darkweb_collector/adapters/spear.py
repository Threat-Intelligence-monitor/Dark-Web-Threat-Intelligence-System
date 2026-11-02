from __future__ import annotations

from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.sites.spear import parse_spear_detail, parse_spear_list


class SpearAdapter(DarkforumsAdapter):
    site_name = "spear"
    list_parser = staticmethod(parse_spear_list)
    detail_parser = staticmethod(parse_spear_detail)
    detail_screenshot_selectors = ("#posts .post-article", "#posts .post")
