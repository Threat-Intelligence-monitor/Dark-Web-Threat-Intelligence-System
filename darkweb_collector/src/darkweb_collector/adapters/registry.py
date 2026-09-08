from __future__ import annotations

from darkweb_collector.adapters.base import SiteAdapter
from darkweb_collector.adapters.breachforums import BreachforumsAdapter
from darkweb_collector.adapters.changan import ChanganAdapter
from darkweb_collector.adapters.chaos import ChaosAdapter
from darkweb_collector.adapters.cracked import CrackedAdapter
from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.adapters.dragonforce import DragonforceAdapter
from darkweb_collector.adapters.lynx import LynxAdapter
from darkweb_collector.adapters.pwnfrm import PwnfrmAdapter
from darkweb_collector.adapters.raidforums import RaidforumsAdapter


ADAPTERS: dict[str, SiteAdapter] = {
    ChanganAdapter.site_name: ChanganAdapter(),
    DragonforceAdapter.site_name: DragonforceAdapter(),
    DarkforumsAdapter.site_name: DarkforumsAdapter(),
    CrackedAdapter.site_name: CrackedAdapter(),
    BreachforumsAdapter.site_name: BreachforumsAdapter(),
    PwnfrmAdapter.site_name: PwnfrmAdapter(),
    RaidforumsAdapter.site_name: RaidforumsAdapter(),
    ChaosAdapter.site_name: ChaosAdapter(),
    LynxAdapter.site_name: LynxAdapter(),
}


def list_adapters() -> list[str]:
    return sorted(ADAPTERS)


def get_adapter(site_name: str) -> SiteAdapter:
    try:
        return ADAPTERS[site_name]
    except KeyError as exc:
        known = ", ".join(list_adapters())
        raise ValueError(f"unknown adapter '{site_name}', available adapters: {known}") from exc
