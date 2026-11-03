from __future__ import annotations

from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.sites.leakforum import parse_leakforum_detail, parse_leakforum_list


class LeakforumAdapter(DarkforumsAdapter):
    site_name = "leakforum"
    list_parser = staticmethod(parse_leakforum_list)
    detail_parser = staticmethod(parse_leakforum_detail)
    detail_screenshot_selectors = ("#posts .post-article", "#posts .post")
