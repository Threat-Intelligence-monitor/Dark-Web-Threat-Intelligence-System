from __future__ import annotations

from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.forum_rate_limit import source_request_scope


class PublicForumAdapter(DarkforumsAdapter):
    terminal_failure_kinds = DarkforumsAdapter.terminal_failure_kinds | {"blocked", "auth_required"}

    def _fetch_html(self, url, config, mode):
        with source_request_scope(self.site_name):
            return super()._fetch_html(url, config, mode)

    def collect_detail(self, detail_task, config, run_ctx):
        with source_request_scope(self.site_name):
            return super().collect_detail(detail_task, config, run_ctx)
