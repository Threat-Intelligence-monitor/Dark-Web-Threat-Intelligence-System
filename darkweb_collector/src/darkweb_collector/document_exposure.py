from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from html import escape, unescape
from html.parser import HTMLParser
import json
import logging
import os
from pathlib import Path
import re
from threading import Lock
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, parse_qsl, quote_plus, urlencode, unquote, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from darkweb_collector.code_monitoring import (
    _derived_search_terms_from_profile,
    _find_domain_anchor_matches,
    _metadata_enterprise_profile,
)
from darkweb_collector.db import (
    add_document_hit_review,
    delete_exposure_watchlist,
    ensure_netdisk_source_health_records,
    get_db_connection,
    get_document_hit,
    get_code_watchlist,
    get_exposure_watchlist,
    insert_exposure_scan_run,
    insert_document_hit_snapshot,
    list_document_hit_reviews,
    list_document_hit_snapshots,
    list_document_hits,
    list_code_watchlists,
    list_exposure_scan_runs,
    list_exposure_watch_terms,
    list_exposure_watchlists,
    list_netdisk_source_health,
    list_netdisk_source_states,
    replace_exposure_watch_terms,
    reset_netdisk_source_states,
    update_document_hit_snapshot_files,
    update_document_hit_last_snapshot,
    upsert_document_hit,
    upsert_exposure_watchlist,
    upsert_netdisk_source_health,
    upsert_netdisk_source_state,
)
from darkweb_collector.detail_i18n import translate_event_title_cached, translate_event_title_live
from darkweb_collector.document_exposure_browser import (
    NetdiskShareUnavailable,
    fetch_aliyundrive_share_file_entries,
    fetch_baidupan_share_file_entries,
    fetch_page_artifacts_with_session,
    fetch_quark_share_file_entries,
)
from darkweb_collector.document_exposure_platforms import (
    PLATFORMS,
    ExposurePlatform,
    get_exposure_platform,
    monitored_domains,
    platform_from_url,
)
from darkweb_collector.document_exposure_sessions import (
    build_platform_session_payloads,
    platform_storage_state_path,
)
from darkweb_collector.runtime import output_root
from darkweb_collector.utils import dump_json, dump_text, safe_stem


logger = logging.getLogger("darkweb_collector.document_exposure")
SHANGHAI_TZ = timezone(timedelta(hours=8))
_DOCUMENT_EXPOSURE_PAYLOAD_CACHE_LOCK = Lock()
_DOCUMENT_EXPOSURE_PAYLOAD_CACHE_TTL_SECONDS = 3600.0
_DOCUMENT_EXPOSURE_PAYLOAD_CACHE: dict[tuple[Any, ...], tuple[float, list[dict[str, Any]]]] = {}
SENSITIVE_KEYWORDS = (
    "内部",
    "机密",
    "报价",
    "投标",
    "方案",
    "合同",
    "客户",
    "通讯录",
    "账号",
    "密码",
    "源代码",
    "运维",
    "财务",
    "名录",
    "清单",
)
SENSITIVE_CONTEXT_SIGNALS = (
    "leak",
    "leaked",
    "leaks",
    "leakage",
    "breach",
    "breached",
    "exposed",
    "exposure",
    "disclosure",
    "confidential",
    "internal",
    "secret",
    "password",
    "credential",
    "database",
    "source code",
    "customer",
    "employee",
    "supplier",
    "contract",
    "quotation",
    "bid",
    "tender",
    "file",
    "files",
    "document",
    "documents",
    "泄露",
    "泄漏",
    "泄密",
    "外泄",
    "被泄露",
    "数据泄露",
    "文件泄露",
    "内部",
    "机密",
    "保密",
    "敏感",
    "密码",
    "账号",
    "凭据",
    "数据库",
    "源代码",
    "客户",
    "员工",
    "供应商",
    "合同",
    "报价",
    "招标",
    "投标",
    "通讯录",
    "名单",
    "清单",
    "财务",
    "设计文件",
)
FILE_NAME_EXTENSIONS = r"pdf|docx?|xlsx?|pptx?|zip|rar|7z|csv|txt|jpe?g|png|gif|webp|bmp|mov|mp4|m4v|avi|mkv|mp3|m4a|wav"
FILE_NAME_RE = re.compile(rf"\b[\w\-. ]+\.(?:{FILE_NAME_EXTENSIONS})\b", re.IGNORECASE)
LOOSE_FILE_NAME_RE = re.compile(rf"[^\n\r|｜<>\"']{{1,180}}\.(?:{FILE_NAME_EXTENSIONS})", re.IGNORECASE)
SHARE_LINK_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
FILE_SIZE_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(?:KB|MB|GB|TB|KiB|MiB|GiB|TiB)\b", re.IGNORECASE)
NETDISK_FILE_ENTRY_RE = re.compile(
    r"(?:^|\s)file[:：]\s*(.*?)(?=\s+file[:：]|\s+(?:分享时间|入库时间|资源密码|资源类型|分享用户|问题反馈|相似推荐|最新资源)\b|$)",
    re.IGNORECASE,
)
NETDISK_FILE_SUFFIX_RE = re.compile(rf"\.(?:{FILE_NAME_EXTENSIONS})\b", re.IGNORECASE)
NETDISK_NUMBERED_ENTRY_RE = re.compile(
    r"(?:^|\s)(\d{1,3}(?:[.．、](?!\d)\s*|(?=【)).{1,80}?)(?=\s+\d{1,3}(?:[.．、](?!\d)|(?=【))|\s+(?:文件大小|数量|反馈|分享时间|入库时间|资源密码|资源类型|分享用户)|$)",
    re.IGNORECASE,
)
NETDISK_DIRECTORY_COUNT_RE = re.compile(r"(?:数量|文件数量)[:：\s]*(\d{1,5})")
NETDISK_PREVIEW_STOP_MARKERS = ("问题反馈", "相似推荐", "最新资源", "扫码获取资源", "选择举报类型", "复制链接", "进入网盘")
PREVIEW_TEXT_LIMIT = 4000
PANHUB_BASE_ENV_NAMES = ("PANHUB_API_BASE", "PANHUB_BASE_URL")
PANHUB_TOKEN_ENV_NAMES = ("PANHUB_AUTH_TOKEN", "PANHUB_TOKEN")
_NETDISK_DETAIL_CACHE: dict[str, tuple[str, list[dict[str, Any]]]] = {}
HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


@dataclass(frozen=True)
class DiscoverySource:
    key: str
    label: str
    search_url_template: str
    category: str
    fetch_mode: str = "html"


DISCOVERY_SOURCES: tuple[DiscoverySource, ...] = (
    DiscoverySource("panhub", "PanHub", "panhub://search?kw={query}", "netdisk_search", "panhub_api"),
    DiscoverySource("xiaobaipan", "小白盘", "https://www.xiaobaipan.com/s/{query}.html", "netdisk_search"),
    DiscoverySource("xiaobudian", "小不点搜索", "https://www.xiaoso.net/search?wd={query}", "netdisk_search"),
    DiscoverySource("lingfengyun", "凌风云", "https://www.lingfengyun.com/search?q={query}", "netdisk_search"),
    DiscoverySource("pikasoo", "皮卡搜索", "https://www.pikasoo.top/search/?pan=all&type=doc&q={query}", "netdisk_search"),
    DiscoverySource("lzpanx", "懒盘搜索", "https://www.lzpanx.com/search?q={query}", "netdisk_search"),
    DiscoverySource("esoua", "爱搜", "https://www.esoua.com/search?q={query}", "netdisk_search"),
    DiscoverySource("dalipan", "大力盘", "https://www.dalipan.com/search?keyword={query}", "netdisk_search"),
    DiscoverySource("pandashi", "盘大师", "https://www.pandashi8.com/search?keyword={query}", "netdisk_search"),
    DiscoverySource("panyq", "盘友圈", "https://panyq.com/search?keyword={query}", "netdisk_search"),
    DiscoverySource("baidu_wenku", "百度文库直搜", "https://wenku.baidu.com/search?word={query}", "document_library"),
    DiscoverySource("docin", "豆丁直搜", "https://www.docin.com/search.do?nkey={query}", "document_library"),
    DiscoverySource("doc88", "道客巴巴直搜", "https://www.doc88.com/search?q={query}", "document_library"),
    DiscoverySource("book118", "原创力直搜", "https://max.book118.com/search.html?q={query}", "document_library"),
    DiscoverySource("iask_share", "爱问共享直搜", "https://ishare.iask.sina.com.cn/search.php?key={query}", "document_library"),
    DiscoverySource("renrendoc", "人人文库", "https://www.renrendoc.com/search.html?keyword={query}", "document_library"),
    DiscoverySource("jinchutou", "金锄头文库", "https://so.jinchutou.com/search.html?keyword={query}", "document_library"),
    DiscoverySource("mbalib_doc", "MBA智库文档", "https://doc.mbalib.com/search?q={query}", "document_library"),
    DiscoverySource("wenku_360", "360文库", "https://wenku.so.com/s?q={query}", "document_library"),
    DiscoverySource("tencent_wenku", "腾讯文库", "https://wenku.docs.qq.com/search?keyword={query}", "document_library"),
    DiscoverySource("quark_doc", "夸克文档", "https://doc.quark.cn/search?keyword={query}", "document_library"),
    DiscoverySource("taodocs", "淘豆网", "https://www.taodocs.com/search.html?q={query}", "document_library"),
    DiscoverySource("doczj", "文档之家", "https://www.doczj.com/search.html?q={query}", "document_library"),
    DiscoverySource("souhong_wenku", "搜弘文库", "https://mwenku.chochina.com/search?q={query}", "document_library"),
)

NETDISK_DEFAULT_SOURCE_KEYS = ("pikasoo", "lzpanx", "esoua", "pandashi")
NETDISK_OPTIONAL_SOURCE_KEYS = ("panhub",)
NETDISK_FALLBACK_SOURCE_KEYS = ("xiaobaipan", "xiaobudian", "lingfengyun", "dalipan", "panyq")
DOCUMENT_LIBRARY_DEFAULT_SOURCE_KEYS = (
    "renrendoc",
    "jinchutou",
    "mbalib_doc",
    "wenku_360",
    "tencent_wenku",
    "quark_doc",
    "taodocs",
    "doczj",
    "souhong_wenku",
)
DOCUMENT_LIBRARY_RESTRICTED_SOURCE_KEYS = ("baidu_wenku", "docin", "doc88", "book118", "iask_share")
NETDISK_PAGINATED_SOURCE_KEYS = {"pikasoo", "lzpanx", "esoua", "pandashi"}
NETDISK_SEARCH_PAGE_SAFETY_CAP = 20
NETDISK_SOURCE_NOTES = {
    "pikasoo": "公开文档搜索页，当前可免登录解析，默认优先扫描",
    "lzpanx": "公开搜索页，详情页可免登录解析",
    "esoua": "公开搜索页，详情页可免登录解析",
    "pandashi": "公开搜索页，当前未触发登录但结果较少",
    "panhub": "配置 PANHUB_API_BASE 后参与扫描",
    "xiaobaipan": "当前搜索页返回 404，默认不扫描",
    "xiaobudian": "当前触发登录拦截，默认不扫描",
    "lingfengyun": "当前触发登录拦截，默认不扫描",
    "dalipan": "当前搜索页返回 404，默认不扫描",
    "panyq": "当前触发验证码/安全验证，默认不扫描",
}
DOCUMENT_LIBRARY_SOURCE_NOTES = {
    "renrendoc": "公开文档列表和详情页可匿名访问，默认扫描",
    "jinchutou": "公开文档搜索和详情页可匿名访问，默认扫描",
    "mbalib_doc": "管理类文档资源丰富，默认扫描公开搜索和详情页",
    "wenku_360": "公开文库搜索入口，默认低频扫描",
    "tencent_wenku": "公开文库入口，默认采集公开预览线索",
    "quark_doc": "公开文档入口，默认采集公开预览线索",
    "taodocs": "公开分类和详情页可匿名访问，默认扫描",
    "doczj": "公开文档列表和详情页可匿名访问，默认扫描",
    "souhong_wenku": "偏企业报告和 HR 文档，默认扫描",
    "baidu_wenku": "登录和风控较重，默认不扫描",
    "docin": "登录和付费限制较多，默认不扫描",
    "doc88": "登录和付费限制较多，默认不扫描",
    "book118": "登录、付费和采集限制较多，默认不扫描",
    "iask_share": "老站稳定性不确定，默认不扫描",
}
NETDISK_SCAN_MODE_ENV = "NETDISK_SCAN_MODE"
NETDISK_SCAN_MODE_LEGACY = "legacy"
NETDISK_SCAN_MODE_INCREMENTAL = "incremental"
DOCUMENT_LIBRARY_INCLUDE_RESTRICTED_ENV = "DARKWEB_DOCUMENT_LIBRARY_INCLUDE_RESTRICTED_SOURCES"
DEFAULT_SOURCE_FAMILIES = ["netdisk_aggregator", "document_library"]
SUPPORTED_SOURCE_FAMILIES = set(DEFAULT_SOURCE_FAMILIES)
DEFAULT_PAGE_LIMIT = 4
DOCUMENT_LIBRARY_DEFAULT_PAGE_LIMIT = 10
DEFAULT_FILE_TYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "7z", "txt", "csv"]
SOURCE_FAMILY_LABELS = {
    "netdisk_aggregator": "网盘监测",
    "document_library": "文库监测",
    "other": "其他来源",
}


ACCESS_STATE_LABELS = {
    "public": "公开访问",
    "login_required": "需要登录",
    "captcha": "需要验证码",
    "removed": "链接失效",
    "forbidden": "拒绝访问",
    "unknown": "待确认",
}
REVIEW_STATUS_LABELS = {
    "new": "未处理",
    "triaged": "处理中",
    "confirmed": "已确认",
    "false_positive": "误报",
    "closed": "已关闭",
}


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").replace("\u00a0", " ").split()).strip()


def _strip_html(value: str) -> str:
    return _normalize_text(re.sub(r"<[^>]+>", " ", unescape(str(value or ""))))


def _canonical_title(value: str) -> str:
    return re.sub(r"\s+", " ", _normalize_text(value)).lower()


def _sanitize_url(value: str) -> str:
    return str(value or "").strip()


def _public_document_output_root() -> Path:
    path = output_root() / "document_exposure"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _query_output_dir(watchlist_name: str, source_key: str, term: str) -> Path:
    root = _public_document_output_root() / safe_stem(watchlist_name, "watchlist") / safe_stem(source_key, "source") / safe_stem(term, "term")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _public_output_url(path: Path) -> str:
    base = output_root().resolve()
    try:
        relative = path.resolve().relative_to(base)
    except ValueError:
        return path.resolve().as_uri()
    return f"/collector-output/{relative.as_posix()}"


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _parse_json(value: Any, default: Any) -> Any:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except Exception:
        return default


def _watchlist_metadata(payload: dict[str, Any] | None) -> dict[str, Any]:
    data = _parse_json((payload or {}).get("metadata_json"), {})
    return data if isinstance(data, dict) else {}


def _exposure_enterprise_profile(
    connection, watchlist: dict[str, Any], terms: list[dict[str, Any]], code_watchlists=None,
) -> tuple[dict[str, Any], int | None]:
    metadata = _watchlist_metadata(watchlist)
    linked_id = metadata.get("code_watchlist_id")
    if linked_id is not None:
        owner = get_code_watchlist(connection, int(linked_id))
        if owner is None or not owner.get("enabled"):
            return {}, int(linked_id)
    else:
        owners = code_watchlists if code_watchlists is not None else list_code_watchlists(connection)
        matches = [item for item in owners
                   if _normalize_text(item.get("name")) == _normalize_text(watchlist.get("name"))
                   and _normalize_text(item.get("organization_name")) == _normalize_text(watchlist.get("organization_name"))]
        owner = matches[0] if len(matches) == 1 else None
        if owner is not None:
            linked_id = int(owner["id"])
            if not owner.get("enabled"):
                return {}, linked_id
    if owner is not None:
        # Supplemental product/project words must never become enterprise aliases.
        profile = _metadata_enterprise_profile(
            _watchlist_metadata(owner), organization_name=str(owner.get("organization_name") or ""), terms=[],
        )
    else:
        identity_terms = [item for item in terms if item.get("term_type") in {"company_name", "domain"}]
        profile = _metadata_enterprise_profile(
            {}, organization_name=str(watchlist.get("organization_name") or ""), terms=identity_terms,
        )
    return profile, int(linked_id) if linked_id is not None else None


def _enterprise_search_terms(profile: dict[str, Any]) -> list[dict[str, Any]]:
    identity = {**profile, "internal_system_keywords": []}
    identity["root_domains"] = list(profile.get("root_domains") or []) + [
        value[2:] for value in profile.get("trusted_subdomain_patterns") or [] if value.startswith("*.")
    ]
    excluded = {_normalize_text(value).casefold() for value in profile.get("negative_aliases") or []}
    return [row for row in _derived_search_terms_from_profile(identity)
            if _normalize_text(row["term"]).casefold() not in excluded]


def _exposure_search_configuration(connection, watchlist, terms, code_watchlists=None) -> dict[str, Any]:
    profile, linked_id = _exposure_enterprise_profile(connection, watchlist, terms, code_watchlists)
    derived = _enterprise_search_terms(profile)
    queries = list(derived)
    seen = {row["term"].casefold() for row in derived}
    for extension in terms:
        value = _normalize_text(extension.get("term"))
        if not value or not bool(extension.get("enabled", True)) or value.casefold() in seen:
            continue
        for identity in derived:
            query = f"{identity['term']} {value}"
            if query.casefold() in seen:
                continue
            seen.add(query.casefold())
            queries.append({**extension, "term": query, "extension_term": value,
                            "identity_term": identity["term"], "source": "profile_extension"})
    return {"enterprise_profile": profile, "code_watchlist_id": linked_id,
            "derived_terms": derived, "effective_terms": queries}


def _is_seed_placeholder_watchlist(payload: dict[str, Any] | None) -> bool:
    item = payload or {}
    return (
        _normalize_text(item.get("name") or item.get("watchlist_name") or item.get("watchlistName")) == "默认监测对象"
        and _normalize_text(item.get("organization_name") or item.get("organizationName")) == "示例企业"
    )


def _watchlist_public_identity(
    payload: dict[str, Any] | None,
    terms: list[dict[str, Any]] | None = None,
) -> tuple[str, str]:
    item = payload or {}
    name = _normalize_text(item.get("name") or item.get("watchlist_name") or item.get("watchlistName"))
    organization = _normalize_text(item.get("organization_name") or item.get("organizationName"))
    if not _is_seed_placeholder_watchlist(item):
        return name, organization
    rows = [
        row if isinstance(row, dict) else {"term": row, "term_type": ""}
        for row in (terms or [])
        if not isinstance(row, dict) or bool(row.get("enabled", True))
    ]
    for term_type in ("company_name", "domain"):
        value = next(
            (
                _normalize_text(row.get("term"))
                for row in rows
                if _normalize_text(row.get("term_type")) == term_type
                and _normalize_text(row.get("term")) not in {"示例企业", "example.com"}
            ),
            "",
        )
        if value:
            return value, value
    fallback = next(
        (
            _normalize_text(row.get("term"))
            for row in rows
            if _normalize_text(row.get("term")) not in {"", "示例企业", "example.com", "内部"}
        ),
        "",
    )
    if fallback:
        return fallback, fallback
    return "", ""


def _is_seed_placeholder_hit(payload: dict[str, Any] | None, matched_terms: list[dict[str, Any]]) -> bool:
    if not _is_seed_placeholder_watchlist(payload):
        return False
    return any(_normalize_text(item.get("term")) == "示例企业" for item in matched_terms if isinstance(item, dict))


def _source_family_for_source(source: DiscoverySource | None = None, platform_type: str | None = None) -> str:
    category = str((source.category if source is not None else platform_type) or "").strip().lower()
    if category == "netdisk_search":
        return "netdisk_aggregator"
    if category == "document_library":
        return "document_library"
    if category == "netdisk_share":
        return "netdisk_aggregator"
    return "other"


def _normalize_source_families(value: Any, *, default_when_empty: bool = True) -> list[str]:
    items = _parse_json(value, value)
    if isinstance(items, str):
        items = [part.strip() for part in items.split(",")]
    if not isinstance(items, list):
        items = []
    seen: set[str] = set()
    rows: list[str] = []
    for item in items:
        normalized = _normalize_text(item)
        if normalized in SUPPORTED_SOURCE_FAMILIES and normalized not in seen:
            seen.add(normalized)
            rows.append(normalized)
    if rows:
        return rows
    return list(DEFAULT_SOURCE_FAMILIES) if default_when_empty else []


def _default_page_limit_for_source_families(source_families: Any) -> int:
    families = _normalize_source_families(source_families)
    if families == ["document_library"]:
        return DOCUMENT_LIBRARY_DEFAULT_PAGE_LIMIT
    return DEFAULT_PAGE_LIMIT


def _include_unstable_netdisk_sources() -> bool:
    return _normalize_text(os.getenv("DARKWEB_NETDISK_INCLUDE_UNSTABLE_SOURCES")).lower() in {"1", "true", "yes"}


def _include_restricted_document_library_sources() -> bool:
    return _normalize_text(os.getenv(DOCUMENT_LIBRARY_INCLUDE_RESTRICTED_ENV)).lower() in {"1", "true", "yes"}


def netdisk_source_policy(source_key: str) -> dict[str, Any]:
    key = _normalize_text(source_key)
    note = NETDISK_SOURCE_NOTES.get(key, "")
    if key in NETDISK_DEFAULT_SOURCE_KEYS:
        return {
            "scan_tier": "primary",
            "scan_enabled": True,
            "scan_priority": NETDISK_DEFAULT_SOURCE_KEYS.index(key) + 1,
            "scan_note": note,
        }
    if key in NETDISK_OPTIONAL_SOURCE_KEYS:
        enabled = key == "panhub" and bool(_first_env_value(PANHUB_BASE_ENV_NAMES))
        return {
            "scan_tier": "optional",
            "scan_enabled": enabled,
            "scan_priority": 50 + NETDISK_OPTIONAL_SOURCE_KEYS.index(key) + 1,
            "scan_note": note,
        }
    if key in NETDISK_FALLBACK_SOURCE_KEYS:
        return {
            "scan_tier": "fallback",
            "scan_enabled": _include_unstable_netdisk_sources(),
            "scan_priority": 100 + NETDISK_FALLBACK_SOURCE_KEYS.index(key) + 1,
            "scan_note": note,
        }
    return {}


def document_library_source_policy(source_key: str) -> dict[str, Any]:
    key = _normalize_text(source_key)
    note = DOCUMENT_LIBRARY_SOURCE_NOTES.get(key, "")
    if key in DOCUMENT_LIBRARY_DEFAULT_SOURCE_KEYS:
        return {
            "scan_tier": "primary",
            "scan_enabled": True,
            "scan_priority": DOCUMENT_LIBRARY_DEFAULT_SOURCE_KEYS.index(key) + 1,
            "scan_note": note,
        }
    if key in DOCUMENT_LIBRARY_RESTRICTED_SOURCE_KEYS:
        return {
            "scan_tier": "restricted",
            "scan_enabled": _include_restricted_document_library_sources(),
            "scan_priority": 100 + DOCUMENT_LIBRARY_RESTRICTED_SOURCE_KEYS.index(key) + 1,
            "scan_note": note,
        }
    return {}


def _netdisk_scan_mode() -> str:
    value = _normalize_text(os.getenv(NETDISK_SCAN_MODE_ENV)).lower()
    if value == NETDISK_SCAN_MODE_INCREMENTAL:
        return NETDISK_SCAN_MODE_INCREMENTAL
    return NETDISK_SCAN_MODE_LEGACY


def _source_key_rows(source_family: str | None = None) -> list[dict[str, str]]:
    selected_family = _normalize_text(source_family)
    return [
        {"source_key": source.key, "source_label": source.label}
        for source in DISCOVERY_SOURCES
        if not selected_family or _source_family_for_source(source) == selected_family
    ]


def _netdisk_source_key_rows() -> list[dict[str, str]]:
    return _source_key_rows("netdisk_aggregator")


def _source_label(source_key: str) -> str:
    key = _normalize_text(source_key)
    for source in DISCOVERY_SOURCES:
        if source.key == key:
            return source.label
    return key


def _netdisk_source_label(source_key: str) -> str:
    return _source_label(source_key)


def ensure_source_health_defaults(source_family: str | None = None) -> None:
    with get_db_connection() as connection:
        ensure_netdisk_source_health_records(connection, _source_key_rows(source_family), _now_utc_iso())
        connection.commit()


def ensure_netdisk_source_health_defaults() -> None:
    ensure_source_health_defaults("netdisk_aggregator")


def _ordered_discovery_sources(source_families: list[str] | None = None) -> list[DiscoverySource]:
    selected = set(_normalize_source_families(source_families, default_when_empty=False)) if source_families else None
    sources: list[DiscoverySource] = []
    for source in DISCOVERY_SOURCES:
        source_family = _source_family_for_source(source)
        if selected is not None and source_family not in selected:
            continue
        if source_family == "netdisk_aggregator":
            policy = netdisk_source_policy(source.key)
            if policy and not policy.get("scan_enabled"):
                continue
        if source_family == "document_library":
            policy = document_library_source_policy(source.key)
            if policy and not policy.get("scan_enabled"):
                continue
        sources.append(source)

    if selected == {"netdisk_aggregator"}:
        return sorted(sources, key=lambda item: netdisk_source_policy(item.key).get("scan_priority", 999))
    if selected == {"document_library"}:
        return sorted(sources, key=lambda item: document_library_source_policy(item.key).get("scan_priority", 999))
    return sources


def _netdisk_detail_fetch_default(source_families: list[str], configured_default: Any) -> bool:
    if source_families == ["netdisk_aggregator"]:
        return False
    return bool(configured_default)


def _candidate_limit_for_source(source_family: str, selected_page_limit: int) -> int | None:
    if source_family == "netdisk_aggregator":
        return None
    return selected_page_limit


def _replace_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = [(name, item) for name, item in parse_qsl(parsed.query, keep_blank_values=True) if name != key]
    params.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(params)))


def _source_search_page_url(source: DiscoverySource, first_url: str, page: int) -> str:
    if page <= 1:
        return first_url
    if source.category == "netdisk_search" and source.key in NETDISK_PAGINATED_SOURCE_KEYS:
        return _replace_query_param(first_url, "page", str(page))
    return first_url


def _source_search_page_urls(
    source: DiscoverySource,
    first_url: str,
    page_numbers: list[int] | None = None,
) -> list[tuple[int, str]]:
    if page_numbers is not None:
        seen_pages: set[int] = set()
        rows: list[tuple[int, str]] = []
        for page_number in page_numbers:
            page = max(1, int(page_number or 1))
            if page in seen_pages:
                continue
            seen_pages.add(page)
            rows.append((page, _source_search_page_url(source, first_url, page)))
        return rows
    if source.fetch_mode == "panhub_api":
        return [(1, first_url)]
    if source.category == "netdisk_search" and source.key in NETDISK_PAGINATED_SOURCE_KEYS:
        return [
            (page, _source_search_page_url(source, first_url, page))
            for page in range(1, NETDISK_SEARCH_PAGE_SAFETY_CAP + 1)
        ]
    return [(1, first_url)]


def _netdisk_incremental_page_numbers(source: DiscoverySource, state: dict[str, Any] | None) -> list[int]:
    if source.fetch_mode == "panhub_api" or source.key not in NETDISK_PAGINATED_SOURCE_KEYS:
        return [1]
    page_window_size = max(1, int((state or {}).get("page_window_size") or 4))
    next_page = max(1, int((state or {}).get("next_page") or 1))
    next_page = min(next_page, NETDISK_SEARCH_PAGE_SAFETY_CAP)
    pages = [1]
    for page in range(next_page, min(NETDISK_SEARCH_PAGE_SAFETY_CAP, next_page + page_window_size - 1) + 1):
        if page not in pages:
            pages.append(page)
    return pages


def _netdisk_candidate_signature(urls: list[str]) -> str:
    normalized = sorted({_normalize_text(url) for url in urls if _normalize_text(url)})
    return json.dumps(normalized, ensure_ascii=False)[:1000]


def _netdisk_error_status(error_text: str) -> str:
    lowered = _normalize_text(error_text).lower()
    if "login_required" in lowered:
        return "login_required"
    if "captcha" in lowered or "security_verification" in lowered:
        return "captcha"
    if "rate_limited" in lowered or "too many" in lowered or "429" in lowered:
        return "rate_limited"
    return "error"


def _source_health_payload(source: DiscoverySource, error_text: str, updated_at: str) -> dict[str, Any]:
    status = _netdisk_error_status(error_text) if error_text else "healthy"
    payload: dict[str, Any] = {
        "source_key": source.key,
        "updated_at": updated_at,
        "status": status,
    }
    if error_text:
        payload.update(
            {
                "error_delta": 1,
                "last_error_at": updated_at,
                "last_error": error_text,
                "login_required_delta": 1 if status == "login_required" else 0,
                "captcha_delta": 1 if status == "captcha" else 0,
                "rate_limited_delta": 1 if status == "rate_limited" else 0,
            }
        )
    else:
        payload.update({"success_delta": 1, "last_success_at": updated_at})
    return payload


def _source_scan_stat(source: DiscoverySource) -> dict[str, Any]:
    return {
        "source": source.key,
        "sourceLabel": source.label,
        "pagesScanned": 0,
        "lastPage": 0,
        "lastUrl": "",
        "candidateCount": 0,
        "hitCount": 0,
        "errorCount": 0,
        "terms": {},
    }


def _term_scan_stat(term: str) -> dict[str, Any]:
    return {
        "term": term,
        "pagesScanned": 0,
        "lastPage": 0,
        "lastUrl": "",
        "candidateCount": 0,
        "hitCount": 0,
        "errorCount": 0,
    }


def _record_source_page_scan(
    source_stats: dict[str, dict[str, Any]],
    source: DiscoverySource,
    term: str,
    *,
    page: int,
    page_url: str,
    candidate_count: int = 0,
    hit_count: int = 0,
    error_count: int = 0,
) -> None:
    stat = source_stats.setdefault(source.key, _source_scan_stat(source))
    term_stats = stat.setdefault("terms", {})
    term_stat = term_stats.setdefault(term, _term_scan_stat(term))
    for target in (stat, term_stat):
        target["pagesScanned"] = int(target.get("pagesScanned") or 0) + 1
        target["lastPage"] = page
        target["lastUrl"] = page_url
        target["candidateCount"] = int(target.get("candidateCount") or 0) + int(candidate_count or 0)
        target["hitCount"] = int(target.get("hitCount") or 0) + int(hit_count or 0)
        target["errorCount"] = int(target.get("errorCount") or 0) + int(error_count or 0)


def _record_source_hits(
    source_stats: dict[str, dict[str, Any]],
    source: DiscoverySource,
    term: str,
    hit_count: int = 1,
) -> None:
    stat = source_stats.setdefault(source.key, _source_scan_stat(source))
    term_stat = stat.setdefault("terms", {}).setdefault(term, _term_scan_stat(term))
    for target in (stat, term_stat):
        target["hitCount"] = int(target.get("hitCount") or 0) + int(hit_count or 0)


def _record_source_errors(
    source_stats: dict[str, dict[str, Any]],
    source: DiscoverySource,
    term: str,
    error_count: int = 1,
) -> None:
    stat = source_stats.setdefault(source.key, _source_scan_stat(source))
    term_stat = stat.setdefault("terms", {}).setdefault(term, _term_scan_stat(term))
    for target in (stat, term_stat):
        target["errorCount"] = int(target.get("errorCount") or 0) + int(error_count or 0)


def _source_stats_payload(source_stats: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for stat in source_stats.values():
        terms = stat.get("terms") if isinstance(stat.get("terms"), dict) else {}
        rows.append(
            {
                **{key: value for key, value in stat.items() if key != "terms"},
                "terms": list(terms.values()),
            }
        )
    return rows


def _normalize_file_types(value: Any) -> list[str]:
    items = _parse_json(value, value)
    if isinstance(items, str):
        items = [part.strip() for part in items.split(",")]
    if not isinstance(items, list):
        items = []
    seen: set[str] = set()
    rows: list[str] = []
    for item in items:
        normalized = _normalize_text(item).lower().lstrip(".")
        if normalized and normalized not in seen:
            seen.add(normalized)
            rows.append(normalized)
    return rows or list(DEFAULT_FILE_TYPES)


def _normalized_source_policies(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_policies = metadata.get("source_policies")
    if not isinstance(raw_policies, dict):
        raw_policies = {}
    shared_file_types = _normalize_file_types(metadata.get("file_types"))
    shared_detail_fetch = bool(metadata.get("detail_fetch", True))

    def policy(source_family: str) -> dict[str, Any]:
        value = raw_policies.get(source_family)
        if not isinstance(value, dict):
            value = {}
        result: dict[str, Any] = {
            "file_types": _normalize_file_types(value.get("file_types") or shared_file_types),
            "detail_fetch": bool(value.get("detail_fetch", shared_detail_fetch)),
        }
        if source_family == "document_library":
            try:
                candidate_limit = int(value.get("candidate_limit") or metadata.get("page_limit") or DOCUMENT_LIBRARY_DEFAULT_PAGE_LIMIT)
            except (TypeError, ValueError):
                candidate_limit = DOCUMENT_LIBRARY_DEFAULT_PAGE_LIMIT
            result["candidate_limit"] = max(1, min(200, candidate_limit))
        return result

    return {
        "netdisk_aggregator": policy("netdisk_aggregator"),
        "document_library": policy("document_library"),
    }


def _format_day_bucket(value: str | None) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text[:10]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(SHANGHAI_TZ).date().isoformat()


def _discovery_source_label(source_key: str | None) -> str:
    key = _normalize_text(source_key)
    for item in DISCOVERY_SOURCES:
        if item.key == key:
            return item.label
    return key


def _platform_label(platform_key: str | None, discovery_source_key: str | None = None) -> str:
    key = _normalize_text(platform_key)
    if key in PLATFORMS:
        return get_exposure_platform(key).label
    return key or _discovery_source_label(discovery_source_key)


def _extract_access_code(*texts: Any) -> str:
    for item in texts:
        text = _normalize_text(item)
        if not text.lower().startswith(("http://", "https://")):
            continue
        params = parse_qs(urlparse(text).query)
        for key in ("pwd", "password", "code", "pass", "p"):
            for value in params.get(key, []):
                code = _normalize_text(value)
                if re.fullmatch(r"[A-Za-z0-9]{3,10}", code):
                    return code
    patterns = (
        re.compile(r"(?i)(?:提取码|访问码|口令|密码|code)[:：\s]*([A-Za-z0-9]{3,10})"),
        re.compile(r"(?i)(?:提取|访问)\s*[:：]?\s*([A-Za-z0-9]{3,10})"),
    )
    haystack = " ".join(_normalize_text(item) for item in texts if _normalize_text(item))
    if not haystack:
        return ""
    for pattern in patterns:
        match = pattern.search(haystack)
        if match:
            return _normalize_text(match.group(1))
    return ""


def _primary_file_name(file_names: list[str], title: str) -> str:
    for name in file_names:
        normalized = _normalize_text(name)
        if normalized:
            return normalized
    return _normalize_text(title)


def _select_netdisk_primary_file(
    file_names: list[str],
    file_sizes: list[str],
    title: str,
    matched_terms: list[dict[str, Any]],
) -> tuple[str, str]:
    normalized_files = [_normalize_text(item) for item in file_names if _normalize_text(item)]
    normalized_sizes = [_normalize_text(item) for item in file_sizes]
    title_text = _normalize_text(title)

    def size_at(index: int) -> str:
        return normalized_sizes[index] if index < len(normalized_sizes) else ""

    if title_text and _file_type_from_name(title_text):
        for index, name in enumerate(normalized_files):
            if name.lower() == title_text.lower():
                return title_text, size_at(index)
        return title_text, ""

    tokens = _file_relevance_tokens(title_text, matched_terms)
    if tokens:
        for index, name in enumerate(normalized_files):
            if _contains_relevance_token(name, tokens):
                return name, size_at(index)

    primary_name = _primary_file_name(normalized_files, title_text)
    if primary_name:
        for index, name in enumerate(normalized_files):
            if name == primary_name:
                return primary_name, size_at(index)
    return primary_name, ""


def _file_type_from_name(name: str) -> str:
    text = _normalize_text(name)
    if "." not in text:
        return ""
    suffix = text.rsplit(".", 1)[-1].lower()
    return suffix if re.fullmatch(rf"(?:{FILE_NAME_EXTENSIONS})", suffix, re.IGNORECASE) else ""


def _matches_file_type(file_names: list[str], file_types: list[str]) -> bool:
    if not file_types:
        return True
    lowered_types = {item.lower().lstrip(".") for item in file_types if item}
    if not lowered_types:
        return True
    if not file_names:
        return True
    if not any(_file_type_from_name(name) for name in file_names):
        return True
    for name in file_names:
        suffix = name.lower().rsplit(".", 1)[-1] if "." in name else ""
        if suffix and suffix in lowered_types:
            return True
    return False


def _extract_file_sizes(text: str) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for match in FILE_SIZE_RE.findall(str(text or "")):
        normalized = _normalize_text(match)
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            results.append(normalized)
    return results[:30]


def _format_file_size_bytes(value: Any) -> str:
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return ""
    if size <= 0:
        return ""
    units = ("B", "KB", "MB", "GB", "TB")
    index = 0
    while size >= 1024 and index < len(units) - 1:
        size /= 1024
        index += 1
    if index == 0:
        return f"{int(size)} {units[index]}"
    return f"{size:.2f} {units[index]}".rstrip("0").rstrip(".")


def _clean_candidate_url(value: str) -> str:
    text = unescape(str(value or "")).strip()
    text = text.rstrip(".,;!?)）】』」。，；、")
    return _sanitize_url(text)


def _candidate_url_variants(url: str) -> list[str]:
    cleaned = _clean_candidate_url(url)
    if not cleaned:
        return []
    variants = [cleaned]
    parsed = urlparse(cleaned)
    query = parse_qs(parsed.query)
    for key in ("url", "u", "target", "link", "redirect", "to", "href"):
        for value in query.get(key, []):
            for candidate in _redirect_value_variants(value):
                if candidate.startswith("http") and candidate not in variants:
                    variants.append(candidate)
    return variants


def _redirect_value_variants(value: str) -> list[str]:
    decoded = _clean_candidate_url(unquote(str(value or "")))
    rows = [decoded] if decoded else []
    base64_candidates = [decoded]
    if decoded.startswith("a1") and len(decoded) > 2:
        base64_candidates.append(decoded[2:])
    for item in base64_candidates:
        try:
            padded = item + "=" * (-len(item) % 4)
            text = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", "ignore")
        except Exception:
            continue
        candidate = _clean_candidate_url(text)
        if candidate.startswith("http") and candidate not in rows:
            rows.append(candidate)
    return rows


def _netdisk_share_path_id(url: str, marker: str) -> str:
    segments = [segment for segment in urlparse(str(url or "")).path.split("/") if segment]
    for index, segment in enumerate(segments[:-1]):
        if segment == marker:
            return _normalize_text(segments[index + 1])
    return ""


def _netdisk_url_resource_fingerprint(platform_key: str, url: str) -> str:
    platform = _normalize_text(platform_key)
    if platform == "aliyundrive_share":
        folder_id = _netdisk_share_path_id(url, "folder")
        if folder_id:
            return f"{platform}:folder:{folder_id.lower()}"
        file_id = _netdisk_share_path_id(url, "file")
        if file_id:
            return f"{platform}:file:{file_id.lower()}"
    return ""


def _netdisk_file_resource_fingerprint(
    platform_key: str,
    title: str,
    file_names: list[str],
    file_sizes: list[str],
    file_entries: list[dict[str, Any]],
) -> str:
    rows: list[dict[str, Any]] = []
    if file_entries:
        for item in file_entries:
            name = _normalize_text(item.get("name"))
            path = _normalize_text(item.get("path")) or name
            if not name and not path:
                continue
            rows.append(
                {
                    "name": name.lower(),
                    "path": path.lower(),
                    "size": _normalize_text(item.get("size") or item.get("size_text")),
                    "is_dir": bool(item.get("is_dir") or item.get("isDir")),
                }
            )
    else:
        for index, name in enumerate(file_names):
            normalized_name = _normalize_text(name)
            if not normalized_name:
                continue
            rows.append(
                {
                    "name": normalized_name.lower(),
                    "path": normalized_name.lower(),
                    "size": _normalize_text(file_sizes[index] if index < len(file_sizes) else ""),
                    "is_dir": False,
                }
            )
    if not rows:
        return ""
    payload = {
        "title": _canonical_title(title),
        "files": sorted(rows, key=lambda item: (item["path"], item["name"], item["size"], str(item["is_dir"]))),
    }
    digest = hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()[:24]
    return f"{_normalize_text(platform_key)}:files:{digest}"


def _netdisk_resource_fingerprint(
    platform_key: str,
    url: str,
    title: str,
    file_names: list[str],
    file_sizes: list[str],
    file_entries: list[dict[str, Any]],
) -> str:
    return _netdisk_url_resource_fingerprint(platform_key, url) or _netdisk_file_resource_fingerprint(
        platform_key,
        title,
        file_names,
        file_sizes,
        file_entries,
    )


def _build_file_list(
    file_names: list[str],
    file_sizes: list[str] | None = None,
    file_entries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if file_entries:
        rows: list[dict[str, Any]] = []
        for item in file_entries:
            name = _normalize_text(item.get("name"))
            if not name:
                continue
            rows.append(
                {
                    "name": name,
                    "size": _normalize_text(item.get("size_text") or item.get("size")),
                    "path": _normalize_text(item.get("path")) or name,
                    "isDir": bool(item.get("is_dir") or item.get("isDir")),
                    "source": _normalize_text(item.get("source")),
                    "inferred": bool(item.get("inferred")),
                }
            )
        if rows:
            return rows
    sizes = file_sizes or []
    return [
        {"name": name, "size": sizes[index] if index < len(sizes) else "", "path": name}
        for index, name in enumerate(file_names)
    ]


def _detail_file_row_from_raw(file_row: dict[str, Any]) -> dict[str, Any] | None:
    file_name = _normalize_text(file_row.get("name") or file_row.get("path"))
    file_path = _normalize_text(file_row.get("path") or file_name)
    if not file_name:
        return None
    is_dir = bool(
        file_row.get("isDir")
        or file_row.get("is_dir")
        or str(file_row.get("type") or "").lower() in {"folder", "dir", "directory"}
    )
    return {
        "name": file_name,
        "path": file_path,
        "size": _normalize_text(file_row.get("size") or file_row.get("size_text")),
        "type": "folder" if is_dir else _file_type_from_name(file_name),
        "isDir": is_dir,
        "source": _normalize_text(file_row.get("source")),
        "inferred": bool(file_row.get("inferred")),
    }


def _append_detail_file_rows(file_list: list[dict[str, Any]], seen_files: set[str], rows: list[dict[str, Any]]) -> None:
    for file_row in rows:
        normalized = _detail_file_row_from_raw(file_row)
        if not normalized:
            continue
        dedupe_key = f"{normalized['name']}|{normalized['path']}"
        if dedupe_key in seen_files:
            continue
        seen_files.add(dedupe_key)
        file_list.append(normalized)


def _fallback_file_rows_from_payload(
    raw_payload: dict[str, Any],
    latest_snapshot: dict[str, Any],
    title: str,
) -> list[dict[str, Any]]:
    if _normalize_text((raw_payload or {}).get("access_state")) in {"removed", "forbidden"}:
        return []
    file_entries = _parse_json((raw_payload or {}).get("file_entries"), [])
    if isinstance(file_entries, list) and file_entries:
        return _build_file_list([], [], [item for item in file_entries if isinstance(item, dict)])

    file_sizes = [
        _normalize_text(item)
        for item in _parse_json((raw_payload or {}).get("file_sizes"), [])
        if _normalize_text(item)
    ]
    preview_text = _normalize_text(
        (raw_payload or {}).get("preview_text")
        or (latest_snapshot or {}).get("previewText")
        or (latest_snapshot or {}).get("ocrText")
    )
    preview_entries = _build_netdisk_preview_file_entries(preview_text, title, file_sizes)
    if preview_entries:
        return _build_file_list([], [], preview_entries)

    file_names = [
        _normalize_text(item)
        for item in _parse_json((raw_payload or {}).get("file_names"), [])
        if _normalize_text(item)
    ]
    if not file_names and preview_text:
        file_names = _extract_netdisk_preview_file_names(preview_text)
    return _build_file_list(file_names, file_sizes, [])


def _wrap_flat_netdisk_file_list(file_list: list[dict[str, Any]], title: str) -> list[dict[str, Any]]:
    root_name = _normalize_text(title)
    if len(file_list) <= 1 or not root_name or _file_type_from_name(root_name):
        return file_list
    if any("/" in _normalize_text(item.get("path")).strip("/") for item in file_list):
        return file_list
    if any(_normalize_text(item.get("name")) == root_name for item in file_list):
        return file_list
    root = {"name": root_name, "path": root_name, "size": "", "type": "folder", "isDir": True}
    children = [
        {
            **item,
            "path": f"{root_name}/{_normalize_text(item.get('path') or item.get('name'))}",
        }
        for item in file_list
    ]
    return [root, *children]


def _file_list_meta(file_list: list[dict[str, Any]], platform: str) -> dict[str, Any]:
    if not file_list:
        return {"quality": "none", "label": "未解析", "inferred": False}
    sources = {_normalize_text(item.get("source")) for item in file_list if _normalize_text(item.get("source"))}
    if "share_listing" in sources:
        return {"quality": "share_listing", "label": "真实目录", "inferred": False}
    if platform == "baidupan_share" and any("/" in _normalize_text(item.get("path")).strip("/") for item in file_list):
        return {"quality": "share_listing", "label": "真实目录", "inferred": False}
    if "aggregator_preview" in sources:
        return {"quality": "aggregator_preview", "label": "摘要提取", "inferred": True}
    if "matched_preview" in sources:
        return {"quality": "matched_preview", "label": "命中证据", "inferred": True}
    if "title_fallback" in sources:
        return {"quality": "title_fallback", "label": "标题推断", "inferred": True}
    return {"quality": "file_names", "label": "文件清单", "inferred": False}


def _file_relevance_tokens(title: str, matched_terms: list[dict[str, Any]]) -> list[str]:
    tokens: list[str] = []
    for item in matched_terms:
        term = _normalize_text(item.get("term"))
        if len(term) >= 2:
            tokens.append(term)
    title_text = _normalize_text(title)
    if title_text:
        if _file_type_from_name(title_text):
            tokens.append(title_text)
            tokens.append(title_text.rsplit(".", 1)[0])
    results: list[str] = []
    seen: set[str] = set()
    for token in tokens:
        normalized = token.lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            results.append(normalized)
    return results


def _contains_relevance_token(text: str, tokens: list[str]) -> bool:
    haystack = _normalize_text(text).lower()
    compact_haystack = re.sub(r"\s+", "", haystack)
    for token in tokens:
        compact_token = re.sub(r"\s+", "", token)
        if token in haystack or (compact_token and compact_token in compact_haystack):
            return True
    return False


def _filter_relevant_file_list(
    file_list: list[dict[str, Any]],
    title: str,
    matched_terms: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    tokens = _file_relevance_tokens(title, matched_terms)
    if not file_list or not tokens:
        return file_list
    relevant_paths: set[str] = set()
    for item in file_list:
        haystack = f"{_normalize_text(item.get('name'))} {_normalize_text(item.get('path'))}"
        if _contains_relevance_token(haystack, tokens):
            path = _normalize_text(item.get("path") or item.get("name"))
            if path:
                relevant_paths.add(path)
    if not relevant_paths:
        title_text = _normalize_text(title)
        if _file_type_from_name(title_text):
            return [
                {
                    "name": title_text,
                    "path": title_text,
                    "size": "",
                    "type": _file_type_from_name(title_text),
                    "isDir": False,
                    "source": "title_fallback",
                    "inferred": True,
                }
            ]
        return file_list
    filtered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in file_list:
        path = _normalize_text(item.get("path") or item.get("name"))
        if not path:
            continue
        include = path in relevant_paths
        include = include or any(path.startswith(f"{relevant}/") or relevant.startswith(f"{path}/") for relevant in relevant_paths)
        if include and path.lower() not in seen:
            seen.add(path.lower())
            filtered.append(item)
    return filtered or file_list


def _file_list_has_relevant_entry(
    file_list: list[dict[str, Any]],
    title: str,
    matched_terms: list[dict[str, Any]],
) -> bool:
    tokens = _file_relevance_tokens(title, matched_terms)
    if not file_list or not tokens:
        return False
    for item in file_list:
        haystack = f"{_normalize_text(item.get('name'))} {_normalize_text(item.get('path'))}"
        if _contains_relevance_token(haystack, tokens):
            return True
    return False


def _matched_preview_file_rows(
    raw_payload: dict[str, Any],
    latest_snapshot: dict[str, Any],
    title: str,
    matched_terms: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    tokens = _file_relevance_tokens(title, matched_terms)
    if not tokens:
        return []
    preview_texts: list[str] = []
    seen_texts: set[str] = set()

    def add_preview_text(value: Any) -> None:
        text = _normalize_text(value)
        if text and text not in seen_texts:
            seen_texts.add(text)
            preview_texts.append(text)

    add_preview_text((raw_payload or {}).get("preview_text"))
    candidate = (raw_payload or {}).get("candidate")
    if isinstance(candidate, dict):
        add_preview_text(candidate.get("preview_text"))
        add_preview_text(candidate.get("content"))
        add_preview_text(candidate.get("note"))
    add_preview_text((latest_snapshot or {}).get("previewText"))
    add_preview_text((latest_snapshot or {}).get("ocrText"))

    rows: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    title_text = _normalize_text(title)
    for text in preview_texts:
        for name in _extract_netdisk_preview_file_names(text):
            if not _contains_relevance_token(name, tokens):
                continue
            key = name.lower()
            if key in seen_names:
                continue
            seen_names.add(key)
            path = name
            if title_text and not _file_type_from_name(title_text) and "/" not in name:
                path = f"{title_text}/{name}"
            rows.append(
                {
                    "name": name,
                    "path": path,
                    "size": "",
                    "type": _file_type_from_name(name),
                    "isDir": False,
                    "source": "matched_preview",
                    "inferred": True,
                }
            )
    return rows


def _prepend_missing_file_rows(
    file_list: list[dict[str, Any]],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not rows:
        return file_list
    existing_keys: set[str] = set()
    for item in file_list:
        for value in (item.get("name"), item.get("path")):
            normalized = _normalize_text(value).lower()
            if normalized:
                existing_keys.add(normalized)
    prepend_rows: list[dict[str, Any]] = []
    for row in rows:
        row_keys = {
            _normalize_text(row.get("name")).lower(),
            _normalize_text(row.get("path")).lower(),
        }
        row_keys.discard("")
        if row_keys & existing_keys:
            continue
        existing_keys.update(row_keys)
        prepend_rows.append(row)
    return [*prepend_rows, *file_list]


class _AnchorParser(HTMLParser):
    def __init__(self, *, include_noscript: bool = False) -> None:
        super().__init__()
        self.anchors: list[dict[str, str]] = []
        self._skipped_tags = {"script", "style"} if include_noscript else {"script", "style", "noscript"}
        self._in_script = False
        self._current_href = ""
        self._current_text: list[str] = []
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._skipped_tags:
            self._in_script = True
            return
        if self._in_script:
            return
        if tag == "a":
            attr_map = dict(attrs)
            self._current_href = str(attr_map.get("href") or "")
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in self._skipped_tags:
            self._in_script = False
            return
        if self._in_script:
            return
        if tag == "a":
            href = _sanitize_url(self._current_href)
            text = _normalize_text("".join(self._current_text))
            if href:
                self.anchors.append({"href": href, "text": text})
            self._current_href = ""
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            return
        text = _normalize_text(data)
        if not text:
            return
        self._text_parts.append(text)
        if self._current_href:
            self._current_text.append(text)

    @property
    def text(self) -> str:
        return _normalize_text(" ".join(self._text_parts))


class _PikasooResultParser(HTMLParser):
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._in_script = False
        self._current: dict[str, Any] | None = None
        self._item_div_depth = 0
        self._capture_stack: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._in_script = True
            return
        if self._in_script:
            return
        attr_map = dict(attrs)
        classes = set(_normalize_text(attr_map.get("class")).split())
        if tag == "div" and "search-item" in classes and self._current is None:
            self._current = {"href": "", "title": [], "description": [], "note": [], "text": []}
            self._item_div_depth = 1
            self._capture_stack = []
            return
        if self._current is None:
            return
        if tag == "div":
            self._item_div_depth += 1
        href = _sanitize_url(attr_map.get("href") or "")
        if tag == "a" and href and not self._current["href"]:
            self._current["href"] = href
        capture = self._capture_stack[-1] if self._capture_stack else None
        if tag in {"h1", "h2", "h3"} and "search-title" in classes:
            capture = "title"
        elif tag == "div" and "search-des" in classes:
            capture = "description"
        elif tag == "div" and "search-note" in classes:
            capture = "note"
        if tag not in self._VOID_TAGS:
            self._capture_stack.append(capture)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"}:
            self._in_script = False
            return
        if self._in_script or self._current is None:
            return
        if tag not in self._VOID_TAGS and self._capture_stack:
            self._capture_stack.pop()
        if tag == "div":
            self._item_div_depth -= 1
            if self._item_div_depth <= 0:
                self._finish_current()

    def handle_data(self, data: str) -> None:
        if self._in_script or self._current is None:
            return
        text = _normalize_text(data)
        if not text:
            return
        self._current["text"].append(text)
        capture = self._capture_stack[-1] if self._capture_stack else None
        if capture:
            self._current[capture].append(text)

    def _finish_current(self) -> None:
        if self._current is None:
            return
        self.results.append(
            {
                "href": _sanitize_url(self._current.get("href") or ""),
                "title": _normalize_text(" ".join(self._current.get("title") or [])),
                "description": _normalize_text(" ".join(self._current.get("description") or [])),
                "note": _normalize_text(" ".join(self._current.get("note") or [])),
                "text": _normalize_text(" ".join(self._current.get("text") or [])),
            }
        )
        self._current = None
        self._item_div_depth = 0
        self._capture_stack = []


class _LzpanxResultParser(HTMLParser):
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._in_script = False
        self._current: dict[str, Any] | None = None
        self._item_div_depth = 0
        self._capture_stack: list[str | None] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self._in_script = True
            return
        if self._in_script:
            return
        attr_map = dict(attrs)
        classes = set(_normalize_text(attr_map.get("class")).split())
        if tag == "div" and "search-item" in classes and self._current is None:
            self._current = {"href": "", "title": [], "description": [], "text": []}
            self._item_div_depth = 1
            self._capture_stack = []
            return
        if self._current is None:
            return
        if tag == "div":
            self._item_div_depth += 1
        href = _sanitize_url(attr_map.get("href") or "")
        if tag == "a" and "search-item-title" in classes and href:
            self._current["href"] = href
        capture = self._capture_stack[-1] if self._capture_stack else None
        if "search-item-title" in classes:
            capture = "title"
        elif "search-item-info" in classes:
            capture = "description"
        if tag not in self._VOID_TAGS:
            self._capture_stack.append(capture)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"}:
            self._in_script = False
            return
        if self._in_script or self._current is None:
            return
        if tag not in self._VOID_TAGS and self._capture_stack:
            self._capture_stack.pop()
        if tag == "div":
            self._item_div_depth -= 1
            if self._item_div_depth <= 0:
                self._finish_current()

    def handle_data(self, data: str) -> None:
        if self._in_script or self._current is None:
            return
        text = _normalize_text(data)
        if not text:
            return
        self._current["text"].append(text)
        capture = self._capture_stack[-1] if self._capture_stack else None
        if capture:
            self._current[capture].append(text)

    def _finish_current(self) -> None:
        if self._current is None:
            return
        self.results.append(
            {
                "href": _sanitize_url(self._current.get("href") or ""),
                "title": _normalize_text(" ".join(self._current.get("title") or [])),
                "description": _strip_html(" ".join(self._current.get("description") or [])),
                "text": _strip_html(" ".join(self._current.get("text") or [])),
            }
        )
        self._current = None
        self._item_div_depth = 0
        self._capture_stack = []


def _fetch_html(url: str, *, timeout: int = 30) -> str:
    request = Request(url, headers=HTTP_HEADERS)
    for attempt in range(2):
        try:
            with urlopen(request, timeout=timeout) as response:  # noqa: S310
                return response.read().decode("utf-8", errors="replace")
        except HTTPError:
            raise
        except URLError:
            if attempt:
                raise
            time.sleep(0.5)
    return ""


def _first_env_value(names: tuple[str, ...]) -> str:
    for name in names:
        value = _normalize_text(os.getenv(name))
        if value:
            return value.rstrip("/")
    return ""


def _api_auth_token(names: tuple[str, ...]) -> str:
    for name in names:
        value = _normalize_text(os.getenv(name))
        if value:
            return value
    return ""


def _post_json_api(url: str, payload: dict[str, Any], *, token: str = "", timeout: int = 45) -> dict[str, Any]:
    headers = {
        **HTTP_HEADERS,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:  # noqa: S310
        text = response.read().decode("utf-8", errors="replace")
    data = json.loads(text or "{}")
    return data if isinstance(data, dict) else {}


def _unwrap_search_response(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    if isinstance(data, dict):
        return data
    return payload


def _api_candidate_title(row: dict[str, Any], fallback: str) -> str:
    for key in ("note", "work_title", "title", "name", "content"):
        value = _normalize_text(row.get(key))
        if value:
            return value
    return fallback


def _append_api_candidate(
    candidates: list[dict[str, Any]],
    seen: set[str],
    *,
    source: DiscoverySource,
    cloud_type: str,
    row: dict[str, Any],
    fallback_title: str,
) -> None:
    raw_url = _normalize_text(row.get("url"))
    for candidate_url in _candidate_url_variants(raw_url):
        platform = platform_from_url(candidate_url)
        if platform is None or platform.platform_type != "netdisk_share":
            continue
        if candidate_url in seen:
            return
        seen.add(candidate_url)
        title = _api_candidate_title(row, fallback_title)
        evidence_title = next((_normalize_text(row.get(key)) for key in ("work_title", "title", "name")
                               if _normalize_text(row.get(key))), "")
        password = _normalize_text(row.get("password") or row.get("pwd") or row.get("code"))
        candidates.append(
            {
                "url": candidate_url,
                "title": title or candidate_url,
                "title_is_fallback": not bool(evidence_title),
                "evidence_title": evidence_title,
                "source": source.key,
                "source_detail": _normalize_text(row.get("source") or row.get("channel") or cloud_type),
                "share_code": password,
                "cloud_type": cloud_type,
                "source_datetime": _normalize_text(row.get("datetime")),
                "preview_text": _normalize_text(row.get("content") or row.get("note") or title),
            }
        )
        return


def _parse_netdisk_api_candidates(source: DiscoverySource, payload: dict[str, Any], fallback_title: str) -> list[dict[str, Any]]:
    data = _unwrap_search_response(payload)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    merged = data.get("merged_by_type")
    if isinstance(merged, dict):
        for cloud_type, rows in merged.items():
            if isinstance(rows, dict):
                rows = rows.get("links") or rows.get("items") or rows.get("results") or []
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, dict):
                    _append_api_candidate(
                        candidates,
                        seen,
                        source=source,
                        cloud_type=str(cloud_type),
                        row=row,
                        fallback_title=fallback_title,
                    )
    results = data.get("results")
    if isinstance(results, list):
        for result in results:
            if not isinstance(result, dict):
                continue
            links = result.get("links")
            if not isinstance(links, list):
                continue
            for link in links:
                if not isinstance(link, dict):
                    continue
                row = {
                    **link,
                    "note": link.get("work_title") or result.get("title") or result.get("content"),
                    "content": result.get("content") or "",
                    "datetime": link.get("datetime") or result.get("datetime"),
                    "source": result.get("channel") or result.get("source"),
                }
                _append_api_candidate(
                    candidates,
                    seen,
                    source=source,
                    cloud_type=str(link.get("type") or ""),
                    row=row,
                    fallback_title=fallback_title,
                )
    return candidates


def _fetch_netdisk_api_candidates(source: DiscoverySource, term: str) -> list[dict[str, Any]]:
    if source.fetch_mode != "panhub_api":
        return []
    base_url = _first_env_value(PANHUB_BASE_ENV_NAMES)
    token = _api_auth_token(PANHUB_TOKEN_ENV_NAMES)
    if not base_url:
        return []
    payload = _post_json_api(
        f"{base_url}/api/search",
        {
            "kw": term,
            "res": "merge",
            "src": "all",
        },
        token=token,
    )
    return _parse_netdisk_api_candidates(source, payload, term)


def _detect_search_block_reason(source: DiscoverySource, html: str, url: str) -> str:
    lowered = f"{html}\n{url}".lower()
    if "安全验证" in html or "captcha" in lowered or "verify you are human" in lowered:
        return f"{source.key}:captcha_or_security_verification"
    if "登录" in html or "sign in" in lowered or "passport.baidu.com" in lowered:
        return f"{source.key}:login_required"
    if "网络不给力" in html or "稍后重试" in html:
        return f"{source.key}:search_temporarily_unavailable"
    return ""


def _load_storage_state_path(platform_key: str) -> str | None:
    rows = {row["platform"]: row for row in build_platform_session_payloads()}
    row = rows.get(platform_key)
    if not row or not row.get("configured"):
        return None
    path = platform_storage_state_path(platform_key)
    return str(path) if path.exists() else None


def _compact_match_text(value: str) -> str:
    return re.sub(r"\s+", "", _normalize_text(value).lower())


def _contains_context_token(haystack: str, compact_haystack: str, token: str) -> bool:
    normalized = _normalize_text(token).lower()
    if not normalized:
        return False
    compact_token = re.sub(r"\s+", "", normalized)
    if not compact_token:
        return False
    if re.fullmatch(r"[a-z0-9_.-]+", normalized):
        return bool(re.search(rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])", haystack))
    return normalized in haystack or compact_token in compact_haystack


def _matched_terms(
    title: str,
    preview_text: str,
    file_names: list[str],
    terms: list[dict[str, Any]],
    *,
    organization_name: str = "",
    enterprise_profile: dict[str, Any] | None = None,
    evidence_units: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    profile = enterprise_profile if enterprise_profile is not None else _metadata_enterprise_profile(
        {}, organization_name=organization_name,
        terms=[row for row in terms if row.get("term_type") in {"company_name", "domain"}],
    )
    identities = _enterprise_search_terms(profile)
    if not identities:
        return []
    units = evidence_units if evidence_units is not None else [
        {"title": title, "preview_text": preview_text},
        *({"title": name} for name in file_names),
    ]
    matches = []
    seen: set[str] = set()
    guarded = {_normalize_text(value).casefold() for value in profile.get("short_alias_guard") or []}
    official = {_normalize_text(value).casefold() for value in profile.get("official_names") or []}
    for unit in units:
        haystack = " ".join([str(unit.get("title") or ""), str(unit.get("preview_text") or ""),
                             " ".join(unit.get("file_names") or [])]).lower()
        compact_haystack = _compact_match_text(haystack)

        def occurs(row):
            value = _normalize_text(row.get("term"))
            if row.get("term_type") == "domain":
                return bool(_find_domain_anchor_matches(haystack, value))
            return _contains_context_token(haystack, compact_haystack, value)

        identity_hits = [row for row in identities if occurs(row)]
        if not any(row.get("term_type") == "domain" or row["term"].casefold() in official
                   or row["term"].casefold() not in guarded for row in identity_hits):
            continue
        entities = [row["term"] for row in identity_hits]
        for term in terms:
            value = _normalize_text(term.get("term"))
            if not value or value.casefold() in seen or not bool(term.get("enabled", True)) or not occurs(term):
                continue
            seen.add(value.casefold())
            matches.append(
                {
                    "term": value,
                    "term_type": str(term.get("term_type") or "custom"),
                    "weight": int(term.get("weight") or 0),
                    "match_type": "enterprise_identity" if term.get("source") == "enterprise_profile" else "enterprise_and_extension",
                    "matched_entities": entities,
                    "matched_file": _normalize_text(unit.get("title")),
                }
            )
    return matches


class _DocumentBodyParser(HTMLParser):
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
    _SKIP_TAGS = {"script", "style", "noscript", "template", "nav", "header", "footer", "aside", "form", "iframe", "object"}
    _SKIP_WORDS = {"nav", "header", "footer", "aside", "recommend", "recommended", "recommendation", "recommendations", "related", "search", "sidebar"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.scopes = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        labels = " ".join(str(attrs.get(key) or "") for key in ("id", "class", "role"))
        words = set(re.sub(r"([a-z])([A-Z])", r"\1 \2", labels).lower().replace("_", "-").replace("-", " ").split())
        style = re.sub(r"\s+", "", str(attrs.get("style") or "")).lower()
        blocked = bool(self.stack and self.stack[-1][1]) or tag in self._SKIP_TAGS
        blocked = blocked or bool(words & self._SKIP_WORDS) or any(word in labels for word in ("推荐", "相关", "搜索"))
        blocked = blocked or "hidden" in attrs or str(attrs.get("aria-hidden") or "").lower() == "true"
        blocked = blocked or "display:none" in style or "visibility:hidden" in style
        priority = 0
        if not blocked:
            if "articlebody" in str(attrs.get("itemprop") or "").lower().split():
                priority = 3
            elif tag == "article":
                priority = 2
            elif tag == "main" or "main" in str(attrs.get("role") or "").lower().split():
                priority = 1
        scope = None
        if priority:
            scope = len(self.scopes)
            self.scopes.append({"priority": priority, "parts": [], "closed": False})
        if tag not in self._VOID_TAGS:
            self.stack.append((tag, blocked, scope))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                scope = self.stack[index][2]
                if scope is not None:
                    self.scopes[scope]["closed"] = True
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not self.stack or self.stack[-1][1]:
            return
        for _, _, scope in self.stack:
            if scope is not None:
                self.scopes[scope]["parts"].append(data)


def _document_evidence_text(html: str) -> str:
    parser = _DocumentBodyParser()
    parser.feed(str(html or ""))
    parser.close()
    scopes = [scope for scope in parser.scopes if scope["closed"] and _normalize_text(" ".join(scope["parts"]))]
    if not scopes:
        return ""
    priority = max(scope["priority"] for scope in scopes)
    selected = [scope for scope in scopes if scope["priority"] == priority]
    # Sibling articles/main regions may describe different files. Do not join them.
    return _normalize_text(" ".join(selected[0]["parts"])) if len(selected) == 1 else ""


def _document_url_identity(url: str) -> tuple[str, str, tuple[tuple[str, str], ...]] | None:
    try:
        parsed = urlparse(str(url or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.port not in {None, 80, 443}:
            return None
        query = tuple(sorted((key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
                             if not key.lower().startswith("utm_") and key.lower() not in {"spm", "from"}))
        return parsed.hostname.lower(), unquote(parsed.path).rstrip("/") or "/", query
    except ValueError:
        return None


def _document_is_detail_url(url: str, platform: ExposurePlatform) -> bool:
    identity = _document_url_identity(url)
    if identity is None:
        return False
    host, path, query = identity
    domains = getattr(platform, "domains", ())
    if not any(host == domain or host.endswith("." + domain) for domain in domains):
        return False
    path = path.lower()
    if path == "/" or any(key.lower() in {"q", "query", "keyword", "keywords", "word", "wd", "nkey", "search", "key"} for key, _ in query):
        return False
    if re.search(r"(?:^|/)(?:index|home|search|so|s|category|categories|catalog|class|list|tag|tags|login|user|auth|passport)(?:[./_-]|$)", path):
        return False
    if NETDISK_FILE_SUFFIX_RE.search(path) and NETDISK_FILE_SUFFIX_RE.search(path).end() == len(path):
        return True
    # Conservative resource forms; unknown routes remain candidates, not file evidence.
    return bool(re.search(r"/(?:p[-/]|view/|paper/|doc/|document/|f/|html/|detail/|details/).+", path)
                or re.search(r"/[^/]*\d[^/]*\.(?:html?|shtml)$", path)
                or any(key.lower() in {"id", "docid", "document_id", "paperid"} and value for key, value in query))


def _document_match_units(detail: dict[str, Any], candidate: dict[str, Any]) -> list[dict[str, Any]]:
    platform = detail.get("platform")
    platform_type = getattr(platform, "platform_type", "")
    if platform_type == "netdisk_share":
        entries = detail.get("evidence_file_entries", detail.get("file_entries")) or []
        units = []
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("source") != "share_listing" or entry.get("inferred") is not False:
                continue
            if entry.get("is_dir") or entry.get("isDir"):
                continue
            name = _normalize_text(entry.get("name"))
            path = _normalize_text(entry.get("path")) or name
            if not name or not path or path.casefold() in seen:
                continue
            seen.add(path.casefold())
            units.append({"title": name, "preview_text": "", "file_names": [path]})
        if entries:
            return units
        title = _normalize_text(candidate.get("evidence_title", candidate.get("title")))
        suffixes = list(NETDISK_FILE_SUFFIX_RE.finditer(title))
        if (candidate.get("title_is_fallback") is False and len(suffixes) == 1
                and suffixes[0].end() == len(title) and not re.search(r"[\r\n,，;；|｜<>?]", str(candidate.get("evidence_title", candidate.get("title")) or ""))
                and not title.lower().startswith(("http://", "https://"))):
            return [{"title": title, "preview_text": "", "file_names": [title]}]
        return []
    if platform_type != "document_library":
        return []
    requested_url = str(candidate.get("url") or "")
    page_url = str(detail.get("page_url") or requested_url)
    source_url = str(candidate.get("_source_url") or detail.get("source_url") or "")
    if not _document_is_detail_url(page_url, platform) or not _document_is_detail_url(requested_url, platform):
        return []
    if _document_url_identity(page_url) != _document_url_identity(requested_url):
        return []
    if source_url and _document_url_identity(page_url) == _document_url_identity(source_url):
        return []
    title = _normalize_text(candidate.get("title")) if candidate.get("title_is_fallback") is False else ""
    text = _normalize_text(detail.get("document_text"))
    if not title and not text:
        return []
    return [{"title": title, "preview_text": text, "file_names": []}]


def _score_document_hit(title: str, preview_text: str, file_names: list[str], matches: list[dict[str, Any]], access_state: str) -> tuple[int, int, str]:
    confidence_score = 0
    risk_score = 0
    if matches:
        confidence_score += min(50, sum(int(item.get("weight") or 0) for item in matches))
    if file_names:
        confidence_score += min(20, len(file_names) * 3)
    if title:
        confidence_score += 10
    if preview_text:
        confidence_score += 10
    if access_state == "public":
        confidence_score += 10
    signal_text = " ".join([title, preview_text, " ".join(file_names)])
    sensitive_hits = [
        token
        for token in (*SENSITIVE_KEYWORDS, *SENSITIVE_CONTEXT_SIGNALS)
        if _contains_context_token(signal_text.lower(), _compact_match_text(signal_text), str(token))
    ]
    risk_score = confidence_score + min(30, len(sensitive_hits) * 8)
    if len(file_names) >= 3:
        risk_score += 10
    if any(name.lower().endswith((".zip", ".rar", ".7z")) for name in file_names):
        risk_score += 8
    risk_score = min(100, risk_score)
    severity = "high" if risk_score >= 75 else "medium" if risk_score >= 45 else "low"
    return min(100, confidence_score), risk_score, severity


def _detect_access_state(platform: ExposurePlatform, html: str, url: str) -> str:
    lowered = f"{html}\n{url}".lower()
    if any(token.lower() in lowered for token in ("验证", "captcha", "安全验证", "verify you are human")):
        return "captcha"
    if any(token.lower() in lowered for token in platform.login_indicators):
        return "login_required"
    if any(token in lowered for token in ("已失效", "链接不存在", "页面不存在", "404", "已删除", "不存在")):
        return "removed"
    if any(token in lowered for token in ("无权访问", "forbidden", "403")):
        return "forbidden"
    return "public"


NETDISK_REMOVED_TOKENS = (
    "not found",
    "link expired",
    "share expired",
    "file not found",
    "链接不存在",
    "链接已失效",
    "分享已失效",
    "分享不存在",
    "文件不存在",
    "文件已删除",
    "页面不存在",
    "资源不存在",
    "已被删除",
    "已失效",
)
NETDISK_FORBIDDEN_TOKENS = (
    "forbidden",
    "无权访问",
    "禁止访问",
    "访问受限",
    "资源违规",
    "涉嫌违规",
    "违规内容",
)
NETDISK_CAPTCHA_TOKENS = (
    "captcha",
    "verify you are human",
    "安全验证",
    "验证码",
    "人机验证",
    "访问验证",
)


def _detect_netdisk_link_validity_state(html: str, url: str) -> str:
    parser = _AnchorParser()
    try:
        parser.feed(html or "")
    except Exception:
        pass
    visible_text = parser.text or _normalize_text(html)
    lowered = f"{visible_text}\n{url}".lower()
    if not lowered.strip():
        return "unknown"
    if any(token.lower() in lowered for token in NETDISK_CAPTCHA_TOKENS):
        return "captcha"
    if any(token.lower() in lowered for token in NETDISK_REMOVED_TOKENS):
        return "removed"
    if any(token.lower() in lowered for token in NETDISK_FORBIDDEN_TOKENS):
        return "forbidden"
    return "public"


def _probe_netdisk_link_access_state(url: str) -> str:
    try:
        html = _fetch_html(url, timeout=12)
    except HTTPError as exc:
        if exc.code in {404, 410}:
            return "removed"
        if exc.code in {401, 403}:
            return "forbidden"
        return "unknown"
    except Exception:
        return "unknown"
    return _detect_netdisk_link_validity_state(html, url)


def _refresh_legacy_netdisk_access_state(row: dict[str, Any]) -> dict[str, Any]:
    if row.get("platform_type") != "netdisk_share":
        return row
    if (_normalize_text(row.get("access_state")) or "unknown") != "unknown":
        return row
    raw_payload = _parse_json(row.get("raw_json"), {})
    raw_payload = raw_payload if isinstance(raw_payload, dict) else {}
    if _normalize_text(raw_payload.get("validated_at")):
        return row

    state = _probe_netdisk_link_access_state(str(row.get("canonical_url") or ""))
    if state == "unknown":
        return row

    now = _now_utc_iso()
    raw_payload["access_state"] = state
    raw_payload["validated_at"] = now
    raw_json = _json_dumps(raw_payload)
    with get_db_connection() as connection:
        connection.execute(
            "UPDATE document_hits SET access_state = ?, raw_json = ? WHERE id = ?",
            (state, raw_json, int(row["id"])),
        )
        if row.get("last_snapshot_id"):
            connection.execute(
                "UPDATE document_hit_snapshots SET access_state = ?, raw_json = ? WHERE id = ?",
                (state, raw_json, int(row["last_snapshot_id"])),
            )
        connection.commit()

    row["access_state"] = state
    row["raw_json"] = raw_json
    return row


def _clean_netdisk_preview_text(text: str) -> str:
    cleaned = _normalize_text(text)
    stop_indexes = [cleaned.find(marker) for marker in NETDISK_PREVIEW_STOP_MARKERS if cleaned.find(marker) > 0]
    if stop_indexes:
        cleaned = cleaned[: min(stop_indexes)]
    return _normalize_text(cleaned)


def _clean_extracted_file_name(value: str) -> str:
    text = _normalize_text(value)
    text = re.sub(r"(?i)^file[:：]\s*", "", text)
    text = re.sub(r"^[A-Za-z]{0,6}\d{1,10}\s*[|｜]\s*", "", text)
    match = re.search(rf"(.+?\.(?:{FILE_NAME_EXTENSIONS}))\b", text, re.IGNORECASE)
    if match:
        text = match.group(1)
    text = text.strip(" \t\r\n,，;；|｜-—:：")
    return _normalize_text(text)


def _extract_netdisk_preview_file_names(text: str) -> list[str]:
    resource_text = _clean_netdisk_preview_text(text)
    results: list[str] = []
    seen: set[str] = set()
    for match in NETDISK_FILE_ENTRY_RE.finditer(resource_text):
        candidate = _clean_extracted_file_name(match.group(1))
        if not NETDISK_FILE_SUFFIX_RE.search(candidate):
            continue
        key = candidate.lower()
        if key not in seen:
            seen.add(key)
            results.append(candidate)
    return results[:30] if results else _extract_file_names(resource_text, [])


def _extract_netdisk_preview_count(text: str) -> int:
    match = NETDISK_DIRECTORY_COUNT_RE.search(_normalize_text(text))
    if not match:
        return 0
    try:
        return int(match.group(1))
    except ValueError:
        return 0


def _clean_preview_directory_name(value: str) -> str:
    text = _normalize_text(value)
    text = text.replace("......", "")
    text = re.sub(r"\s*(?:文件大小|数量|反馈|分享时间|入库时间|资源密码|资源类型|分享用户).*$", "", text)
    text = text.strip(" \t\r\n,，;；|｜-—:：")
    if "http://" in text or "https://" in text:
        return ""
    if NETDISK_FILE_SUFFIX_RE.search(text):
        return ""
    if any(marker in text for marker in ("文件来源于", "打开此分享", "扫码获取资源", "问题反馈")):
        return ""
    return _normalize_text(text)


def _extract_netdisk_preview_directory_names(text: str, title: str = "") -> list[str]:
    resource_text = _clean_netdisk_preview_text(text)
    for marker in ("文件大小", "数量", "反馈", "分享时间", "入库时间", "资源密码", "资源类型", "分享用户"):
        index = resource_text.find(marker)
        if index > 0:
            resource_text = resource_text[:index]
            break
    normalized_title = _normalize_text(title)
    results: list[str] = []
    seen: set[str] = set()
    for match in NETDISK_NUMBERED_ENTRY_RE.finditer(resource_text):
        candidate = _clean_preview_directory_name(match.group(1))
        if not candidate or candidate == normalized_title:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append(candidate)
    return results[:80]


def _build_netdisk_preview_file_entries(
    preview_text: str,
    title: str,
    file_sizes: list[str] | None = None,
) -> list[dict[str, Any]]:
    title = _normalize_text(title)
    sizes = file_sizes or _extract_file_sizes(preview_text)
    file_names = _extract_netdisk_preview_file_names(preview_text)
    directory_names = _extract_netdisk_preview_directory_names(preview_text, title)
    entries: list[dict[str, Any]] = []

    if directory_names and title:
        entries.append({"name": title, "path": title, "size": sizes[0] if sizes else "", "is_dir": True, "source": "aggregator_preview", "inferred": True})
        entries.extend({"name": name, "path": f"{title}/{name}", "size": "", "is_dir": True, "source": "aggregator_preview", "inferred": True} for name in directory_names)
        return entries

    if file_names:
        if len(file_names) > 1 and title and not _file_type_from_name(title):
            entries.append({"name": title, "path": title, "size": sizes[0] if len(sizes) == 1 else "", "is_dir": True, "source": "aggregator_preview", "inferred": True})
            entries.extend(
                {
                    "name": name,
                    "path": f"{title}/{name}",
                    "size": sizes[index] if index < len(sizes) and len(sizes) == len(file_names) else "",
                    "is_dir": False,
                    "source": "aggregator_preview",
                    "inferred": True,
                }
                for index, name in enumerate(file_names)
            )
            return entries
        return [
            {"name": name, "path": name, "size": sizes[index] if index < len(sizes) else "", "is_dir": False, "source": "aggregator_preview", "inferred": True}
            for index, name in enumerate(file_names)
        ]

    if title:
        is_dir = bool(_extract_netdisk_preview_count(preview_text) > 1 and not _file_type_from_name(title))
        entries.append({"name": title, "path": title, "size": sizes[0] if sizes else "", "is_dir": is_dir, "source": "title_fallback", "inferred": True})
    return entries


def _normalize_share_listing_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in entries:
        name = _normalize_text(item.get("name"))
        path = _normalize_text(item.get("path")) or name
        if not name or path.lower() in seen:
            continue
        seen.add(path.lower())
        size = int(item.get("size") or 0)
        results.append(
            {
                "name": name,
                "path": path,
                "size": _format_file_size_bytes(size),
                "size_text": _format_file_size_bytes(size),
                "is_dir": bool(item.get("is_dir")),
                "depth": int(item.get("depth") or 0),
                "source": "share_listing",
                "inferred": False,
            }
        )
    return results


def _netdisk_file_entries_from_baidupan(url: str, share_code: str) -> list[dict[str, Any]]:
    return _normalize_share_listing_entries(
        fetch_baidupan_share_file_entries(url, access_code=share_code, max_depth=3, max_items=120)
    )


def _netdisk_file_entries_from_aliyundrive(url: str, share_code: str) -> list[dict[str, Any]]:
    return _normalize_share_listing_entries(
        fetch_aliyundrive_share_file_entries(url, access_code=share_code, max_depth=4, max_items=120)
    )


def _netdisk_file_entries_from_quark(url: str, share_code: str) -> list[dict[str, Any]]:
    return _normalize_share_listing_entries(
        fetch_quark_share_file_entries(url, access_code=share_code, max_depth=4, max_items=120)
    )


def _extract_file_names(text: str, anchors: list[dict[str, str]]) -> list[str]:
    results: list[str] = []
    seen: set[str] = set()
    for pattern in (FILE_NAME_RE, LOOSE_FILE_NAME_RE):
        for match in pattern.finditer(text):
            normalized = _clean_extracted_file_name(match.group(0))
            if normalized and normalized.lower() not in seen:
                seen.add(normalized.lower())
                results.append(normalized)
    for item in anchors:
        label = _normalize_text(item.get("text"))
        if not label:
            continue
        if FILE_NAME_RE.search(label) and label.lower() not in seen:
            seen.add(label.lower())
            results.append(label)
    return results[:30]


def _parse_pikasoo_candidates(source: DiscoverySource, html: str, requested_url: str) -> list[dict[str, Any]]:
    parser = _PikasooResultParser()
    parser.feed(html)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in parser.results:
        absolute = urljoin(requested_url, item.get("href") or "")
        selected_url = ""
        selected_platform: ExposurePlatform | None = None
        for variant in _candidate_url_variants(absolute):
            platform = platform_from_url(variant)
            if platform is None or platform.platform_type != "netdisk_share":
                continue
            selected_url = variant
            selected_platform = platform
            break
        if not selected_url or selected_url in seen:
            continue
        seen.add(selected_url)
        title = _normalize_text(item.get("title")) or selected_url
        preview_text = _normalize_text(" ".join([title, item.get("description") or "", item.get("note") or ""]))
        share_code = _extract_access_code(title, preview_text, selected_url)
        candidates.append(
            {
                "url": selected_url,
                "title": title,
                "source": source.key,
                "source_detail": selected_platform.label if selected_platform else "",
                "share_code": share_code,
                "preview_text": preview_text or title,
                "file_sizes": _extract_file_sizes(preview_text),
            }
        )
    return candidates


def _netdisk_links_from_html(
    *,
    source: DiscoverySource,
    html: str,
    page_url: str,
    fallback_title: str,
    fallback_preview: str,
) -> list[dict[str, Any]]:
    parser = _AnchorParser(include_noscript=True)
    parser.feed(html)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_items = [
        {"href": item["href"], "text": item.get("text") or ""}
        for item in parser.anchors
    ]
    raw_items.extend(
        {"href": match.group(0), "text": match.group(0)}
        for match in SHARE_LINK_RE.finditer(parser.text)
    )
    for item in raw_items:
        absolute = urljoin(page_url, item["href"])
        selected_url = ""
        selected_platform: ExposurePlatform | None = None
        for variant in _candidate_url_variants(absolute):
            platform = platform_from_url(variant)
            if platform is None or platform.platform_type != "netdisk_share":
                continue
            selected_url = variant
            selected_platform = platform
            break
        if not selected_url or selected_url in seen:
            continue
        seen.add(selected_url)
        preview_text = _normalize_text(" ".join([fallback_preview, parser.text]))
        title = fallback_title or _normalize_text(item.get("text")) or selected_url
        share_code = _extract_access_code(title, preview_text, selected_url)
        candidates.append(
            {
                "url": selected_url,
                "title": title,
                "source": source.key,
                "source_detail": selected_platform.label if selected_platform else "",
                "share_code": share_code,
                "preview_text": preview_text or title,
                "file_sizes": _extract_file_sizes(preview_text),
            }
        )
    return candidates


def _parse_lzpanx_candidates(source: DiscoverySource, html: str, requested_url: str) -> list[dict[str, Any]]:
    parser = _LzpanxResultParser()
    parser.feed(html)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in parser.results[:10]:
        detail_path = _sanitize_url(item.get("href") or "")
        if not detail_path:
            continue
        detail_url = urljoin(requested_url, detail_path)
        fallback_title = _normalize_text(item.get("title")) or detail_url
        fallback_preview = _normalize_text(" ".join([fallback_title, item.get("description") or ""]))
        try:
            detail_html = _fetch_html(detail_url, timeout=20)
        except Exception as exc:
            logger.debug("lzpanx detail fetch failed: %s %s", detail_url, exc)
            continue
        for candidate in _netdisk_links_from_html(
            source=source,
            html=detail_html,
            page_url=detail_url,
            fallback_title=fallback_title,
            fallback_preview=fallback_preview,
        ):
            if candidate["url"] in seen:
                continue
            seen.add(candidate["url"])
            candidates.append(candidate)
    return candidates


def _parse_candidates_from_html(source: DiscoverySource, html: str, requested_url: str) -> list[dict[str, Any]]:
    if source.key == "pikasoo":
        pikasoo_candidates = _parse_pikasoo_candidates(source, html, requested_url)
        if pikasoo_candidates:
            return pikasoo_candidates
    if source.key in {"lzpanx", "esoua"}:
        return _parse_lzpanx_candidates(source, html, requested_url)

    parser = _AnchorParser()
    parser.feed(html)
    allowed_domains = monitored_domains(module="document_exposure")
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    raw_items = [
        {"href": item["href"], "text": item.get("text") or ""}
        for item in parser.anchors
    ]
    raw_items.extend(
        {"href": match.group(0), "text": match.group(0)}
        for match in SHARE_LINK_RE.finditer(parser.text)
    )
    for item in raw_items:
        absolute = urljoin(requested_url, item["href"])
        selected_url = ""
        selected_platform: ExposurePlatform | None = None
        for variant in _candidate_url_variants(absolute):
            platform = platform_from_url(variant)
            host = urlparse(variant).netloc.lower()
            if source.category == "netdisk_search":
                if platform is None or platform.platform_type != "netdisk_share":
                    continue
            elif source.category == "document_library":
                if platform is None or platform.platform_type != "document_library":
                    continue
            else:
                if not any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains):
                    continue
            selected_url = variant
            selected_platform = platform
            break
        if not selected_url:
            continue
        absolute = selected_url
        if not absolute.startswith("http"):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        title = _normalize_text(item.get("text")) or absolute
        share_code = _extract_access_code(title, absolute)
        candidates.append(
            {
                "url": absolute,
                "title": title,
                "source": source.key,
                "source_detail": selected_platform.label if selected_platform else "",
                "share_code": share_code,
                "preview_text": title,
            }
        )
    return candidates


def _build_search_urls(term: str, source_families: list[str] | None = None) -> list[tuple[DiscoverySource, str]]:
    encoded = quote_plus(term)
    return [(source, source.search_url_template.format(query=encoded)) for source in _ordered_discovery_sources(source_families)]


def _search_candidates_for_source(source: DiscoverySource, url: str, term: str) -> list[dict[str, Any]]:
    if source.fetch_mode == "panhub_api":
        return _fetch_netdisk_api_candidates(source, term)
    search_html = _fetch_html(url, timeout=30)
    block_reason = _detect_search_block_reason(source, search_html, url)
    if block_reason:
        raise RuntimeError(block_reason)
    candidates = _parse_candidates_from_html(source, search_html, url)
    for candidate in candidates:
        title = _normalize_text(candidate.get("title"))
        candidate.setdefault("title_is_fallback", not title or title == candidate.get("url"))
    return candidates


def _search_candidate_pages_for_source(
    source: DiscoverySource,
    first_url: str,
    term: str,
    source_family: str,
    selected_page_limit: int,
    *,
    errors: list[str],
    source_stats: dict[str, dict[str, Any]],
    watchlist_id: int | None = None,
    scan_mode: str = NETDISK_SCAN_MODE_LEGACY,
    netdisk_state: dict[str, Any] | None = None,
    state_updates: list[dict[str, Any]] | None = None,
    health_updates: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    page_seen_urls: set[str] = set()
    candidate_limit = _candidate_limit_for_source(source_family, selected_page_limit)
    max_pages = max(1, int(selected_page_limit or 1)) if source_family == "netdisk_aggregator" else None
    page_urls = _source_search_page_urls(source, first_url)
    if source_family == "netdisk_aggregator" and scan_mode == NETDISK_SCAN_MODE_INCREMENTAL:
        page_urls = _source_search_page_urls(source, first_url, _netdisk_incremental_page_numbers(source, netdisk_state))
        max_pages = None
    scanned_pages: list[int] = []
    usable_candidate_urls: list[str] = []
    error_text = ""
    last_page_empty = False
    last_page_repeated = False
    last_non_empty_page = 0
    for page_index, (page_number, page_url) in enumerate(page_urls, start=1):
        if max_pages is not None and page_index > max_pages:
            break
        scanned_pages.append(page_number)
        try:
            candidates = _search_candidates_for_source(source, page_url, term)
            if candidate_limit is not None:
                candidates = candidates[:candidate_limit]
        except Exception as exc:
            error_text = f"{source.key}:p{page_number}:{term}:{exc}"
            errors.append(error_text)
            _record_source_page_scan(
                source_stats,
                source,
                term,
                page=page_number,
                page_url=page_url,
                error_count=1,
            )
            break

        candidate_urls = {
            _normalize_text(candidate.get("url"))
            for candidate in candidates
            if _normalize_text(candidate.get("url"))
        }
        repeated_page = page_number > 1 and bool(candidate_urls) and not (candidate_urls - page_seen_urls)
        last_page_repeated = repeated_page
        usable_candidates = [] if repeated_page else candidates
        last_page_empty = not bool(usable_candidates)
        _record_source_page_scan(
            source_stats,
            source,
            term,
            page=page_number,
            page_url=page_url,
            candidate_count=len(usable_candidates),
        )
        if not usable_candidates:
            break
        page_seen_urls.update(candidate_urls)
        usable_candidate_urls.extend(_normalize_text(candidate.get("url")) for candidate in usable_candidates)
        last_non_empty_page = page_number
        rows.extend({**candidate, "_source_url": page_url} for candidate in usable_candidates)
        if source_family != "netdisk_aggregator":
            break
    if source_family == "netdisk_aggregator" and state_updates is not None and watchlist_id is not None:
        previous_next_page = max(1, int((netdisk_state or {}).get("next_page") or 1))
        page_window_size = max(1, int((netdisk_state or {}).get("page_window_size") or selected_page_limit or 4))
        if source.fetch_mode == "panhub_api" or source.key not in NETDISK_PAGINATED_SOURCE_KEYS:
            next_page = 1
        elif scanned_pages:
            if scan_mode == NETDISK_SCAN_MODE_INCREMENTAL and (error_text or last_page_empty):
                next_page = previous_next_page
                if last_non_empty_page >= previous_next_page:
                    next_page = last_non_empty_page + 1
            else:
                next_page = max(scanned_pages) + 1
            next_page = min(NETDISK_SEARCH_PAGE_SAFETY_CAP, max(1, next_page))
        else:
            next_page = previous_next_page
        updated_at = _now_utc_iso()
        consecutive_empty_pages = (
            int((netdisk_state or {}).get("consecutive_empty_pages") or 0) + 1
            if last_page_empty
            else 0
        )
        consecutive_repeated_pages = (
            int((netdisk_state or {}).get("consecutive_repeated_pages") or 0) + 1
            if last_page_repeated
            else 0
        )
        health_payload = _source_health_payload(source, error_text, updated_at)
        state_updates.append(
            {
                "watchlist_id": int(watchlist_id),
                "source_key": source.key,
                "term": term,
                "source_family": source_family,
                "next_page": next_page,
                "last_scanned_page": max(scanned_pages) if scanned_pages else 0,
                "page_window_size": page_window_size,
                "consecutive_empty_pages": consecutive_empty_pages,
                "consecutive_repeated_pages": consecutive_repeated_pages,
                "last_candidate_signature": _netdisk_candidate_signature(usable_candidate_urls),
                "last_success_at": "" if error_text else updated_at,
                "last_error_at": updated_at if error_text else "",
                "last_error": error_text,
                "backoff_until": "",
                "created_at": updated_at,
                "updated_at": updated_at,
                "_health": health_payload,
            }
        )
    elif source_family == "document_library" and health_updates is not None:
        health_updates.append(_source_health_payload(source, error_text, _now_utc_iso()))
    return rows


def _detail_payload_from_page(
    *,
    platform: ExposurePlatform,
    detail_url: str,
    source_query: str,
    source_url: str,
) -> dict[str, Any]:
    storage_state = _load_storage_state_path(platform.key) if platform.requires_login else None
    artifacts = fetch_page_artifacts_with_session(
        detail_url,
        storage_state_path=storage_state,
        wait_seconds=4,
        timeout_seconds=45,
    )
    html = artifacts["html"]
    parser = _AnchorParser()
    parser.feed(html)
    preview_text = parser.text[:PREVIEW_TEXT_LIMIT]
    document_text = _document_evidence_text(html)[:PREVIEW_TEXT_LIMIT]
    file_names = _extract_file_names(preview_text, parser.anchors)
    file_sizes = _extract_file_sizes(preview_text)
    access_state = _detect_access_state(platform, html, str(artifacts["url"]))
    share_code = _extract_access_code(detail_url, preview_text, html)
    return {
        "platform": platform,
        "page_url": str(artifacts["url"]),
        "page_title": _normalize_text(artifacts["title"]) or _normalize_text(platform.label),
        "html": html,
        "screenshot_png": artifacts["screenshot_png"],
        "preview_text": preview_text,
        "document_text": document_text,
        "ocr_text": preview_text,
        "file_names": file_names,
        "file_sizes": file_sizes,
        "share_code": share_code,
        "share_type": "password_share" if share_code else "public_share",
        "access_state": access_state,
        "source_query": source_query,
        "source_url": source_url,
    }


def _write_snapshot_files(
    watchlist_name: str,
    platform_key: str,
    term: str,
    page_title: str,
    html: str,
    screenshot_png: bytes | None,
    payload: dict[str, Any],
) -> tuple[Path, Path | None]:
    base_dir = _query_output_dir(watchlist_name, platform_key, term)
    stem = safe_stem(page_title or platform_key, "detail")
    html_path = base_dir / f"{stem}.html"
    dump_text(html_path, html)
    screenshot_path = None
    if screenshot_png:
        screenshot_path = base_dir / f"{stem}.png"
        screenshot_path.parent.mkdir(parents=True, exist_ok=True)
        screenshot_path.write_bytes(screenshot_png)
    dump_json(base_dir / f"{stem}.json", payload)
    return html_path, screenshot_path


def _mirror_html_from_hit_payload(
    *,
    watchlist_name: str,
    platform_key: str,
    platform_label: str,
    page_title: str,
    page_url: str,
    source_url: str,
    source_query: str,
    access_state: str,
    preview_text: str,
    matched_terms: list[dict[str, Any]],
    file_list: list[dict[str, Any]],
    payload: dict[str, Any],
) -> str:
    def cell(label: str, value: Any) -> str:
        return f"<tr><th>{escape(label)}</th><td>{escape(str(value or ''))}</td></tr>"

    term_rows = "".join(
        f"<li>{escape(str(item.get('term') or ''))} <span>{escape(str(item.get('term_type') or ''))}</span></li>"
        for item in matched_terms
        if _normalize_text(item.get("term"))
    )
    file_rows = "".join(
        "<tr>"
        f"<td>{escape(str(item.get('name') or ''))}</td>"
        f"<td>{escape(str(item.get('path') or item.get('name') or ''))}</td>"
        f"<td>{escape(str(item.get('size') or ''))}</td>"
        f"<td>{escape(str(item.get('source') or ''))}</td>"
        "</tr>"
        for item in file_list
    )
    metadata_json = escape(json.dumps(payload, ensure_ascii=False, indent=2))
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>{escape(page_title or platform_label or platform_key)}</title>
  <style>
    body {{ margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f5f7fb; }}
    main {{ max-width: 1120px; margin: 0 auto; padding: 32px 24px; }}
    h1 {{ margin: 0 0 8px; font-size: 24px; }}
    section {{ margin-top: 18px; padding: 18px; border: 1px solid #dbe3f1; border-radius: 12px; background: #fff; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ padding: 10px 12px; border-bottom: 1px solid #edf1f7; text-align: left; vertical-align: top; }}
    th {{ width: 160px; color: #667085; font-weight: 600; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
    ul {{ margin: 0; padding-left: 18px; }}
    .muted {{ color: #667085; }}
  </style>
</head>
<body>
  <main>
    <p class="muted">Document exposure mirror snapshot</p>
    <h1>{escape(page_title or page_url)}</h1>
    <section>
      <table>
        {cell("Watchlist", watchlist_name)}
        {cell("Platform", platform_label or platform_key)}
        {cell("Access state", access_state)}
        {cell("Source query", source_query)}
        {cell("Source URL", source_url)}
        {cell("Page URL", page_url)}
      </table>
    </section>
    <section>
      <h2>Matched terms</h2>
      <ul>{term_rows or "<li>None</li>"}</ul>
    </section>
    <section>
      <h2>Preview text</h2>
      <pre>{escape(preview_text or "")}</pre>
    </section>
    <section>
      <h2>File list</h2>
      <table>
        <thead><tr><th>Name</th><th>Path</th><th>Size</th><th>Source</th></tr></thead>
        <tbody>{file_rows or '<tr><td colspan="4">No parsed files</td></tr>'}</tbody>
      </table>
    </section>
    <section>
      <h2>Raw metadata</h2>
      <pre>{metadata_json}</pre>
    </section>
  </main>
</body>
</html>"""


def _list_from_payload(value: Any) -> list[Any]:
    parsed = _parse_json(value, value)
    return parsed if isinstance(parsed, list) else []


def _ensure_netdisk_snapshot_mirror(
    *,
    row: dict[str, Any],
    watchlist: dict[str, Any] | None,
    snapshot: dict[str, Any],
    matched_terms: list[dict[str, Any]],
    raw_payload: dict[str, Any],
) -> str:
    html_path_raw = _normalize_text(snapshot.get("html_path"))
    if html_path_raw and Path(html_path_raw).exists():
        return html_path_raw

    platform_key = str(row.get("platform") or "")
    platform = get_exposure_platform(platform_key) if platform_key in PLATFORMS else None
    file_list = _list_from_payload(snapshot.get("file_list_json"))
    if not file_list:
        file_list = _build_file_list(
            [_normalize_text(item) for item in _list_from_payload(raw_payload.get("file_names")) if _normalize_text(item)],
            [_normalize_text(item) for item in _list_from_payload(raw_payload.get("file_sizes")) if _normalize_text(item)],
            [item for item in _list_from_payload(raw_payload.get("file_entries")) if isinstance(item, dict)],
        )

    page_title = _normalize_text(snapshot.get("page_title")) or _normalize_text(row.get("title")) or platform_key
    page_url = _normalize_text(snapshot.get("page_url")) or _normalize_text(row.get("canonical_url"))
    source_query = _normalize_text(snapshot.get("source_query")) or _normalize_text(raw_payload.get("source_query"))
    source_url = _normalize_text(snapshot.get("source_url")) or _normalize_text(raw_payload.get("source_url"))
    preview_text = _normalize_text(snapshot.get("preview_text") or snapshot.get("ocr_text") or raw_payload.get("preview_text"))
    access_state = _normalize_text(snapshot.get("access_state")) or _normalize_text(row.get("access_state")) or "unknown"
    mirror_html = _mirror_html_from_hit_payload(
        watchlist_name=str((watchlist or {}).get("name") or row.get("watchlist_id") or "watchlist"),
        platform_key=platform_key,
        platform_label=platform.label if platform else platform_key,
        page_title=page_title,
        page_url=page_url,
        source_url=source_url,
        source_query=source_query,
        access_state=access_state,
        preview_text=preview_text,
        matched_terms=matched_terms,
        file_list=[item for item in file_list if isinstance(item, dict)],
        payload=raw_payload,
    )
    html_path, _ = _write_snapshot_files(
        str((watchlist or {}).get("name") or row.get("watchlist_id") or "watchlist"),
        platform_key or "netdisk",
        source_query or "mirror",
        page_title,
        mirror_html,
        None,
        raw_payload,
    )
    return str(html_path)


def ensure_default_watchlist() -> dict[str, Any]:
    with get_db_connection() as connection:
        existing = list_exposure_watchlists(connection)
        if existing:
            watchlist = existing[0]
            terms = list_exposure_watch_terms(connection, int(watchlist["id"]))
            metadata = _watchlist_metadata(watchlist)
            source_families = _normalize_source_families(metadata.get("source_families"))
            return {
                **watchlist,
                "terms": terms,
                "source_families": source_families,
                "file_types": metadata.get("file_types") or list(DEFAULT_FILE_TYPES),
                "page_limit": int(metadata.get("page_limit") or _default_page_limit_for_source_families(source_families)),
                "detail_fetch": bool(metadata.get("detail_fetch", True)),
                "source_policies": _normalized_source_policies(metadata),
            }
        return {
            "id": None,
            "name": "",
            "organization_name": "",
            "enabled": False,
            "notes": "",
            "metadata_json": _json_dumps(
                {
                    "source_families": DEFAULT_SOURCE_FAMILIES,
                    "file_types": DEFAULT_FILE_TYPES,
                    "page_limit": 4,
                    "detail_fetch": True,
                }
            ),
            "created_at": "",
            "updated_at": "",
            "terms": [],
            "source_families": list(DEFAULT_SOURCE_FAMILIES),
            "file_types": list(DEFAULT_FILE_TYPES),
            "page_limit": 4,
            "detail_fetch": True,
            "source_policies": _normalized_source_policies(
                {"file_types": DEFAULT_FILE_TYPES, "page_limit": 4, "detail_fetch": True}
            ),
        }


def list_watchlists_payload() -> list[dict[str, Any]]:
    ensure_default_watchlist()
    with get_db_connection() as connection:
        rows = list_exposure_watchlists(connection)
        code_watchlists = list_code_watchlists(connection)
        terms_by_watchlist = {
            int(row["id"]): list_exposure_watch_terms(connection, int(row["id"]))
            for row in rows
        }
        preferred_identities = {
            _watchlist_public_identity(row, terms_by_watchlist[int(row["id"])])
            for row in rows
            if not _is_seed_placeholder_watchlist(row)
        }
        payloads = []
        for row in rows:
            terms = terms_by_watchlist[int(row["id"])]
            public_name, public_organization = _watchlist_public_identity(row, terms)
            if _is_seed_placeholder_watchlist(row) and (
                not public_name or (public_name, public_organization) in preferred_identities
            ):
                continue
            metadata = _watchlist_metadata(row)
            source_families = _normalize_source_families(metadata.get("source_families"))
            source_policies = _normalized_source_policies(metadata)
            payloads.append(
                {
                    **row,
                    "name": public_name,
                    "organization_name": public_organization,
                    "terms": terms,
                    **_exposure_search_configuration(connection, row, terms, code_watchlists),
                    "source_families": source_families,
                    "file_types": metadata.get("file_types") or list(DEFAULT_FILE_TYPES),
                    "page_limit": int(metadata.get("page_limit") or _default_page_limit_for_source_families(source_families)),
                    "detail_fetch": bool(metadata.get("detail_fetch", True)),
                    "source_policies": source_policies,
                }
            )
        return payloads


def save_watchlist_payload(payload: dict[str, Any]) -> dict[str, Any]:
    now = _now_utc_iso()
    source_families = _normalize_source_families(payload.get("source_families"))
    source_policies = _normalized_source_policies(
        {
            "source_policies": payload.get("source_policies"),
            "file_types": payload.get("file_types"),
            "page_limit": payload.get("page_limit"),
            "detail_fetch": payload.get("detail_fetch", True),
        }
    )
    page_limit = int(source_policies["document_library"]["candidate_limit"])
    file_types = list(dict.fromkeys(
        source_policies["netdisk_aggregator"]["file_types"]
        + source_policies["document_library"]["file_types"]
    ))
    detail_fetch = all(
        bool(source_policies[source_family]["detail_fetch"])
        for source_family in source_families
        if source_family in source_policies
    )
    with get_db_connection() as connection:
        existing = get_exposure_watchlist(connection, int(payload["id"])) if payload.get("id") else None
        metadata = _watchlist_metadata(existing)
        linked_id = payload.get("code_watchlist_id")
        if linked_id is None:
            linked_id = metadata.get("code_watchlist_id")
        if linked_id is not None:
            if get_code_watchlist(connection, int(linked_id)) is None:
                raise ValueError("linked monitoring object not found")
            metadata["code_watchlist_id"] = int(linked_id)
        watchlist_id = upsert_exposure_watchlist(
            connection,
            {
                "id": payload.get("id"),
                "name": payload.get("name"),
                "organization_name": payload.get("organization_name"),
                "enabled": payload.get("enabled", True),
                "notes": payload.get("notes", ""),
                "metadata_json": _json_dumps(
                    {
                        **metadata,
                        "source_families": source_families,
                        "file_types": file_types,
                        "page_limit": page_limit,
                        "detail_fetch": detail_fetch,
                        "source_policies": source_policies,
                    }
                ),
                "created_at": payload.get("created_at") or now,
                "updated_at": now,
            },
        )
        rows = payload.get("terms") or []
        replace_exposure_watch_terms(
            connection,
            watchlist_id,
            [
                {
                    "term": row.get("term"),
                    "term_type": row.get("term_type"),
                    "weight": row.get("weight", 10),
                    "enabled": row.get("enabled", True),
                    "created_at": now,
                    "updated_at": now,
                }
                for row in rows
            ],
        )
        connection.commit()
        watchlist = get_exposure_watchlist(connection, watchlist_id)
        metadata = _watchlist_metadata(watchlist or {})
        saved_source_families = _normalize_source_families(metadata.get("source_families"))
        saved_source_policies = _normalized_source_policies(metadata)
        saved_terms = list_exposure_watch_terms(connection, watchlist_id)
        return {
            **(watchlist or {}),
            "terms": saved_terms,
            **_exposure_search_configuration(connection, watchlist or {}, saved_terms),
            "source_families": saved_source_families,
            "file_types": metadata.get("file_types") or list(DEFAULT_FILE_TYPES),
            "page_limit": int(metadata.get("page_limit") or _default_page_limit_for_source_families(saved_source_families)),
            "detail_fetch": bool(metadata.get("detail_fetch", True)),
            "source_policies": saved_source_policies,
        }


def delete_watchlist_payload(watchlist_id: int) -> dict[str, Any]:
    with get_db_connection() as connection:
        watchlist = get_exposure_watchlist(connection, int(watchlist_id))
        if watchlist is None:
            raise ValueError(f"watchlist not found: {watchlist_id}")
        delete_exposure_watchlist(connection, int(watchlist_id))
        connection.commit()
    return {"id": int(watchlist_id), "deleted": True}


def scan_watchlist_once(
    watchlist_id: int,
    *,
    max_candidates_per_term: int = 6,
    source_families: list[str] | None = None,
    file_types: list[str] | None = None,
    page_limit: int | None = None,
    detail_fetch: bool | None = None,
    document_library_candidate_limit: int | None = None,
) -> dict[str, Any]:
    ensure_default_watchlist()
    started_at = _now_utc_iso()
    with get_db_connection() as connection:
        watchlist = get_exposure_watchlist(connection, watchlist_id)
        if watchlist is None:
            raise ValueError(f"watchlist not found: {watchlist_id}")
        if not bool(watchlist.get("enabled")):
            return {"watchlist_id": watchlist_id, "scanned_terms": 0, "candidates": 0, "hits": 0, "message": "watchlist disabled"}
        supplemental_terms = list_exposure_watch_terms(connection, watchlist_id)
        search_configuration = _exposure_search_configuration(connection, watchlist, supplemental_terms)
        terms = search_configuration["effective_terms"]
    watchlist_meta = _watchlist_metadata(watchlist)
    source_policies = _normalized_source_policies(watchlist_meta)
    explicit_source_family_request = bool(source_families)
    selected_source_families = _normalize_source_families(
        source_families or watchlist_meta.get("source_families"),
        default_when_empty=not explicit_source_family_request,
    )
    selected_file_types = _normalize_file_types(file_types or watchlist_meta.get("file_types"))
    watchlist_source_families = _normalize_source_families(watchlist_meta.get("source_families"))
    if not selected_source_families:
        return {
            "watchlist_id": watchlist_id,
            "watchlist_name": watchlist["name"],
            "scanned_terms": 0,
            "candidates": 0,
            "hits": 0,
            "errors": ["unsupported source family"],
            "source_families": [],
            "file_types": selected_file_types,
            "page_limit": page_limit or max_candidates_per_term or DEFAULT_PAGE_LIMIT,
            "detail_fetch": bool(detail_fetch if detail_fetch is not None else True),
            "netdisk_scan_mode": NETDISK_SCAN_MODE_LEGACY,
            "source_stats": [],
            "message": "no supported source families selected",
        }
    use_watchlist_page_limit = not source_families or selected_source_families == watchlist_source_families
    configured_page_limit = page_limit or (watchlist_meta.get("page_limit") if use_watchlist_page_limit else None)
    selected_page_limit = int(
        configured_page_limit
        or (
            _default_page_limit_for_source_families(selected_source_families)
            if selected_source_families == ["document_library"]
            else max_candidates_per_term or DEFAULT_PAGE_LIMIT
        )
    )
    selected_detail_fetch = bool(
        detail_fetch
        if detail_fetch is not None
        else _netdisk_detail_fetch_default(selected_source_families, watchlist_meta.get("detail_fetch", True))
    )
    selected_netdisk_scan_mode = (
        _netdisk_scan_mode()
        if "netdisk_aggregator" in selected_source_families
        else NETDISK_SCAN_MODE_LEGACY
    )
    netdisk_states_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    netdisk_state_updates: list[dict[str, Any]] = []
    source_health_updates: list[dict[str, Any]] = []
    if "netdisk_aggregator" in selected_source_families:
        ensure_netdisk_source_health_defaults()
        with get_db_connection() as connection:
            netdisk_states_by_key = {
                (str(row.get("source_key") or ""), str(row.get("term") or "")): row
                for row in list_netdisk_source_states(connection, watchlist_id=int(watchlist["id"]))
            }
    for source_family in ("document_library",):
        if source_family in selected_source_families:
            ensure_source_health_defaults(source_family)

    total_candidates = 0
    total_hits = 0
    errors: list[str] = []
    source_stats: dict[str, dict[str, Any]] = {}
    seen_candidate_urls: set[str] = set()
    seen_resource_fingerprints: set[str] = set()
    now = _now_utc_iso()
    for term_row in terms:
        term = _normalize_text(term_row.get("term"))
        if not term:
            continue
        for source, url in _build_search_urls(term, selected_source_families):
            source_family = _source_family_for_source(source)
            if source_family not in selected_source_families:
                continue
            source_policy = source_policies.get(source_family, {})
            source_page_limit = selected_page_limit
            if page_limit is None and source_family == "document_library":
                source_page_limit = int(source_policy.get("candidate_limit") or selected_page_limit)
            if source_family == "document_library" and document_library_candidate_limit is not None:
                source_page_limit = document_library_candidate_limit
            source_file_types = selected_file_types if file_types is not None else _normalize_file_types(
                source_policy.get("file_types") or selected_file_types
            )
            source_detail_fetch = selected_detail_fetch if detail_fetch is not None else bool(
                source_policy.get("detail_fetch", selected_detail_fetch)
            )
            candidates = _search_candidate_pages_for_source(
                source,
                url,
                term,
                source_family,
                source_page_limit,
                errors=errors,
                source_stats=source_stats,
                watchlist_id=int(watchlist["id"]),
                scan_mode=selected_netdisk_scan_mode,
                netdisk_state=netdisk_states_by_key.get((source.key, term)),
                state_updates=netdisk_state_updates,
                health_updates=source_health_updates,
            )
            total_candidates += len(candidates)
            for candidate in candidates:
                candidate_url = _normalize_text(candidate.get("url"))
                if not candidate_url or candidate_url in seen_candidate_urls:
                    continue
                seen_candidate_urls.add(candidate_url)
                candidate_source_url = _normalize_text(candidate.get("_source_url")) or url
                detail_platform = platform_from_url(candidate["url"])
                if detail_platform is None:
                    continue
                candidate_resource_fingerprint = (
                    _netdisk_url_resource_fingerprint(detail_platform.key, candidate_url)
                    if detail_platform.platform_type == "netdisk_share"
                    else ""
                )
                if candidate_resource_fingerprint and candidate_resource_fingerprint in seen_resource_fingerprints:
                    continue
                try:
                    should_fetch_detail = source_detail_fetch and detail_platform.platform_type != "netdisk_share"
                    if should_fetch_detail:
                        detail = _detail_payload_from_page(
                            platform=detail_platform,
                            detail_url=candidate["url"],
                            source_query=term,
                            source_url=candidate_source_url,
                            )
                    else:
                        raw_candidate_preview = _normalize_text(candidate.get("preview_text") or candidate.get("title"))
                        candidate_file_names = [
                            _normalize_text(item)
                            for item in (candidate.get("file_names") or [])
                            if _normalize_text(item)
                        ]
                        share_code = _normalize_text(candidate.get("share_code")) or _extract_access_code(
                            candidate.get("url"),
                            candidate.get("title"),
                            candidate.get("preview_text"),
                        )
                        file_entries: list[dict[str, Any]] = []
                        access_state_override = ""
                        if detail_platform.key == "baidupan_share":
                            try:
                                file_entries = _netdisk_file_entries_from_baidupan(candidate["url"], share_code)
                            except NetdiskShareUnavailable as exc:
                                access_state_override = exc.state
                            except Exception as exc:
                                errors.append(f"baidupan_file_list:{candidate['url']}:{exc}")
                                _record_source_errors(source_stats, source, term)
                        elif detail_platform.key == "aliyundrive_share":
                            try:
                                file_entries = _netdisk_file_entries_from_aliyundrive(candidate["url"], share_code)
                            except NetdiskShareUnavailable as exc:
                                access_state_override = exc.state
                            except Exception as exc:
                                errors.append(f"aliyundrive_file_list:{candidate['url']}:{exc}")
                                _record_source_errors(source_stats, source, term)
                        elif detail_platform.key == "quark_share":
                            try:
                                file_entries = _netdisk_file_entries_from_quark(candidate["url"], share_code)
                            except NetdiskShareUnavailable as exc:
                                access_state_override = exc.state
                            except Exception as exc:
                                errors.append(f"quark_file_list:{candidate['url']}:{exc}")
                                _record_source_errors(source_stats, source, term)
                        preview_file_entries = (
                            []
                            if file_entries or detail_platform.platform_type != "netdisk_share" or access_state_override in {"removed", "forbidden"}
                            else _build_netdisk_preview_file_entries(
                                raw_candidate_preview,
                                _normalize_text(candidate.get("title")) or candidate["url"],
                                candidate.get("file_sizes") or [],
                            )
                        )
                        if file_entries:
                            preview_parts = [candidate.get("title") or candidate["url"]]
                            preview_parts.extend(
                                _normalize_text(item.get("path") or item.get("name"))
                                for item in file_entries
                                if _normalize_text(item.get("path") or item.get("name"))
                            )
                            candidate_preview = _normalize_text(" ".join(preview_parts))[:PREVIEW_TEXT_LIMIT]
                        elif access_state_override in {"removed", "forbidden"}:
                            candidate_preview = ""
                        elif detail_platform.platform_type == "netdisk_share":
                            candidate_preview = _clean_netdisk_preview_text(raw_candidate_preview)
                        else:
                            candidate_preview = raw_candidate_preview
                        access_state = access_state_override or (
                            _probe_netdisk_link_access_state(candidate["url"])
                            if detail_platform.platform_type == "netdisk_share"
                            else "unknown"
                        )
                        detail = {
                            "platform": detail_platform,
                            "page_url": candidate["url"],
                            "page_title": _normalize_text(candidate.get("title")) or candidate["url"],
                            "html": "",
                            "screenshot_png": b"",
                            "preview_text": candidate_preview,
                            "ocr_text": candidate_preview,
                            "file_names": (
                                [item["name"] for item in (file_entries or preview_file_entries) if _normalize_text(item.get("name"))]
                                if file_entries or preview_file_entries
                                else
                                _extract_netdisk_preview_file_names(raw_candidate_preview)
                                if detail_platform.platform_type == "netdisk_share" and access_state_override not in {"removed", "forbidden"}
                                else candidate_file_names or _extract_file_names(candidate_preview, [])
                            ),
                            "file_sizes": (
                                [item["size"] for item in (file_entries or preview_file_entries) if _normalize_text(item.get("size"))]
                                if file_entries or preview_file_entries
                                else [] if access_state_override in {"removed", "forbidden"} else candidate.get("file_sizes") or _extract_file_sizes(candidate_preview)
                            ),
                            "file_entries": file_entries or preview_file_entries,
                            "evidence_file_entries": file_entries,
                            "share_code": share_code,
                            "share_type": "password_share" if share_code else "public_share",
                            "access_state": access_state,
                            "source_query": term,
                            "source_url": candidate_source_url,
                        }
                except Exception as exc:
                    errors.append(f"{detail_platform.key}:{candidate['url']}:{exc}")
                    _record_source_errors(source_stats, source, term)
                    continue
                candidate_text = " ".join(
                    _normalize_text(value)
                    for value in (
                        candidate.get("title"),
                        candidate.get("preview_text"),
                        candidate.get("source_detail"),
                    )
                    if _normalize_text(value)
                )
                is_unavailable_share = (
                    detail_platform.platform_type == "netdisk_share"
                    and _normalize_text(detail.get("access_state")) in {"removed", "forbidden"}
                )
                if not detail.get("file_names") and not is_unavailable_share:
                    detail["file_names"] = (
                        _extract_netdisk_preview_file_names(candidate_text)
                        if detail_platform.platform_type == "netdisk_share"
                        else _extract_file_names(candidate_text, [])
                    )
                detail["file_sizes"] = [] if is_unavailable_share else detail.get("file_sizes") or _extract_file_sizes(candidate_text)
                detail["share_code"] = _normalize_text(detail.get("share_code") or candidate.get("share_code"))
                if not detail["share_code"]:
                    detail["share_code"] = _extract_access_code(
                        candidate.get("title"),
                        candidate.get("preview_text"),
                        candidate.get("url"),
                        detail.get("preview_text"),
                    )
                detail["share_type"] = "password_share" if detail["share_code"] else "public_share"
                if not is_unavailable_share and not _matches_file_type(detail["file_names"], source_file_types):
                    continue
                resource_fingerprint = (
                    _netdisk_resource_fingerprint(
                        detail_platform.key,
                        detail["page_url"],
                        detail["page_title"],
                        detail["file_names"],
                        detail.get("file_sizes") or [],
                        detail.get("file_entries") or [],
                    )
                    if detail_platform.platform_type == "netdisk_share"
                    else ""
                )
                if resource_fingerprint and resource_fingerprint in seen_resource_fingerprints:
                    continue
                matches = _matched_terms(
                    detail["page_title"],
                    detail["preview_text"],
                    detail["file_names"],
                    [{**term_row, "term": term_row["extension_term"]}]
                    if term_row.get("extension_term") else search_configuration["derived_terms"] + supplemental_terms,
                    organization_name=str(watchlist.get("organization_name") or ""),
                    enterprise_profile=search_configuration["enterprise_profile"],
                    evidence_units=_document_match_units(detail, candidate),
                )
                if not matches:
                    continue
                confidence_score, risk_score, severity = _score_document_hit(
                    detail["page_title"],
                    detail["preview_text"],
                    detail["file_names"],
                    matches,
                    detail["access_state"],
                )
                raw_payload = {
                    "candidate": candidate,
                    "page_url": detail["page_url"],
                    "source_query": term,
                    "source_url": candidate_source_url,
                    "file_names": detail["file_names"],
                    "file_sizes": detail.get("file_sizes") or [],
                    "file_entries": detail.get("file_entries") or [],
                    "share_code": detail.get("share_code") or "",
                    "share_type": detail.get("share_type") or "public_share",
                    "source_detail": _normalize_text(candidate.get("source_detail")),
                    "source_datetime": _normalize_text(candidate.get("source_datetime")),
                    "cloud_type": _normalize_text(candidate.get("cloud_type")),
                    "preview_text": detail["preview_text"],
                    "access_state": detail["access_state"],
                    "validated_at": now if detail_platform.platform_type == "netdisk_share" else "",
                    "resource_fingerprint": resource_fingerprint,
                }
                with get_db_connection() as connection:
                    hit_id = upsert_document_hit(
                        connection,
                        {
                            "watchlist_id": int(watchlist["id"]),
                            "platform": detail_platform.key,
                            "platform_type": detail_platform.platform_type,
                            "discovery_source": source.key,
                            "canonical_url": detail["page_url"],
                            "normalized_title": _canonical_title(detail["page_title"]),
                            "resource_fingerprint": resource_fingerprint,
                            "title": detail["page_title"],
                            "access_state": detail["access_state"],
                            "confidence_score": confidence_score,
                            "risk_score": risk_score,
                            "severity": severity,
                            "matched_terms_json": _json_dumps(matches),
                            "file_count": len(detail["file_names"]),
                            "share_owner": "",
                            "disclosure_time": "",
                            "first_seen_at": now,
                            "last_seen_at": now,
                            "raw_json": _json_dumps(raw_payload),
                        },
                    )
                    html_path = ""
                    screenshot_path = ""
                    file_list_payload = _build_file_list(
                        detail["file_names"],
                        detail.get("file_sizes") or [],
                        detail.get("file_entries") or [],
                    )
                    snapshot_html = str(detail.get("html") or "").strip()
                    if not snapshot_html:
                        snapshot_html = _mirror_html_from_hit_payload(
                            watchlist_name=str(watchlist["name"]),
                            platform_key=detail_platform.key,
                            platform_label=detail_platform.label,
                            page_title=detail["page_title"],
                            page_url=detail["page_url"],
                            source_url=candidate_source_url,
                            source_query=term,
                            access_state=detail["access_state"],
                            preview_text=detail["preview_text"],
                            matched_terms=matches,
                            file_list=file_list_payload,
                            payload=raw_payload,
                        )
                    html_path_obj, screenshot_path_obj = _write_snapshot_files(
                        str(watchlist["name"]),
                        detail_platform.key,
                        term,
                        detail["page_title"],
                        snapshot_html,
                        detail.get("screenshot_png") or None,
                        raw_payload,
                    )
                    html_path = str(html_path_obj)
                    screenshot_path = str(screenshot_path_obj or "")
                    snapshot_id = insert_document_hit_snapshot(
                        connection,
                        {
                            "hit_id": hit_id,
                            "fetched_at": now,
                            "source_query": term,
                            "source_url": candidate_source_url,
                            "page_url": detail["page_url"],
                            "page_title": detail["page_title"],
                            "html_path": html_path,
                            "screenshot_path": screenshot_path,
                            "ocr_text": detail["ocr_text"],
                            "preview_text": detail["preview_text"],
                            "file_list_json": _json_dumps(file_list_payload),
                            "access_state": detail["access_state"],
                            "matched_terms_json": _json_dumps(matches),
                            "raw_json": _json_dumps(raw_payload),
                        },
                    )
                    update_document_hit_last_snapshot(connection, hit_id, snapshot_id)
                    connection.commit()
                if resource_fingerprint:
                    seen_resource_fingerprints.add(resource_fingerprint)
                _record_source_hits(source_stats, source, term)
                total_hits += 1
    source_stats_payload = _source_stats_payload(source_stats)
    result = {
        "watchlist_id": watchlist_id,
        "watchlist_name": watchlist["name"],
        "scanned_terms": len(terms),
        "candidates": total_candidates,
        "hits": total_hits,
        "errors": errors,
        "source_families": selected_source_families,
        "file_types": selected_file_types,
        "page_limit": selected_page_limit,
        "detail_fetch": selected_detail_fetch,
        "source_policies": source_policies,
        "netdisk_scan_mode": selected_netdisk_scan_mode,
        "source_stats": source_stats_payload,
    }
    finished_at = _now_utc_iso()
    with get_db_connection() as connection:
        for state_update in netdisk_state_updates:
            upsert_netdisk_source_state(
                connection,
                {key: value for key, value in state_update.items() if key != "_health"},
            )
            health_payload = state_update.get("_health")
            if isinstance(health_payload, dict):
                upsert_netdisk_source_health(connection, health_payload)
        for health_payload in source_health_updates:
            upsert_netdisk_source_health(connection, health_payload)
        insert_exposure_scan_run(
            connection,
            {
                "watchlist_id": int(watchlist["id"]),
                "source_families_json": _json_dumps(selected_source_families),
                "requested_terms_json": _json_dumps([_normalize_text(item.get("term")) for item in terms if _normalize_text(item.get("term"))]),
                "candidate_count": total_candidates,
                "hit_count": total_hits,
                "error_count": len(errors),
                "scan_stats_json": _json_dumps(source_stats_payload),
                "status": "failed" if errors and total_hits == 0 else "partial" if errors else "succeeded",
                "errors_json": _json_dumps(errors),
                "started_at": started_at,
                "finished_at": finished_at,
            },
        )
        connection.commit()
    result["started_at"] = started_at
    result["finished_at"] = finished_at
    return result


def _build_document_exposures_payload(
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    access_state: str | None = None,
    source_family: str | None = None,
    limit: int | None = 200,
) -> list[dict[str, Any]]:
    ensure_default_watchlist()
    platform_type_filter = {
        "document_library": "document_library",
        "netdisk_aggregator": "netdisk_share",
    }.get(_normalize_text(source_family))
    with get_db_connection() as connection:
        rows = list_document_hits(
            connection,
            watchlist_id=watchlist_id,
            review_status=review_status,
            platform=platform,
            platform_type=platform_type_filter,
            access_state=access_state,
            limit=limit,
        )
    payloads = []
    refresh_legacy_netdisk_state = source_family == "netdisk_aggregator"
    for row in rows:
        matched_terms = json.loads(str(row.get("matched_terms_json") or "[]"))
        if _is_seed_placeholder_hit(row, matched_terms):
            continue
        if refresh_legacy_netdisk_state:
            row = _refresh_legacy_netdisk_access_state(row)
        public_watchlist_name, public_organization_name = _watchlist_public_identity(row, matched_terms)
        raw_payload = json.loads(str(row.get("raw_json") or "{}"))
        file_names = [
            _normalize_text(item)
            for item in _parse_json((raw_payload or {}).get("file_names"), [])
            if _normalize_text(item)
        ]
        file_sizes = [
            _normalize_text(item)
            for item in _parse_json((raw_payload or {}).get("file_sizes"), [])
            if _normalize_text(item)
        ]
        if row.get("platform_type") == "netdisk_share" and not file_names:
            fallback_rows = _fallback_file_rows_from_payload(raw_payload, {}, str(row.get("title") or ""))
            file_names = [
                _normalize_text(item.get("name"))
                for item in fallback_rows
                if _normalize_text(item.get("name"))
            ]
            if not file_sizes:
                file_sizes = [
                    _normalize_text(item.get("size"))
                    for item in fallback_rows
                    if _normalize_text(item.get("size"))
                ]
        if row.get("platform_type") == "netdisk_share":
            primary_file_name, primary_file_size = _select_netdisk_primary_file(
                file_names,
                file_sizes,
                str(row.get("title") or ""),
                matched_terms,
            )
            if not _file_list_has_relevant_entry(
                [{"name": primary_file_name, "path": primary_file_name}],
                str(row.get("title") or ""),
                matched_terms,
            ):
                matched_preview_rows = _matched_preview_file_rows(
                    raw_payload,
                    {},
                    str(row.get("title") or ""),
                    matched_terms,
                )
                if matched_preview_rows:
                    primary_file_name = _normalize_text(matched_preview_rows[0].get("name")) or primary_file_name
                    primary_file_size = _normalize_text(matched_preview_rows[0].get("size")) or primary_file_size
        else:
            primary_file_name = _primary_file_name(file_names, str(row.get("title") or ""))
            primary_file_size = file_sizes[0] if file_sizes else ""
        share_code = _normalize_text((raw_payload or {}).get("share_code")) or _extract_access_code(
            row.get("title"),
            (raw_payload or {}).get("preview_text"),
            " ".join(file_names),
        )
        platform_key = row.get("platform") or ""
        platform_label = _platform_label(platform_key, row.get("discovery_source"))
        row_source_family = _source_family_for_source(
            platform_type=row.get("platform_type"),
            source=next((item for item in DISCOVERY_SOURCES if item.key == row.get("discovery_source")), None),
        )
        if row_source_family not in SUPPORTED_SOURCE_FAMILIES:
            continue
        payload = {
            "id": int(row["id"]),
            "watchlistId": int(row["watchlist_id"]),
            "watchlistName": public_watchlist_name,
            "organizationName": public_organization_name,
            "platform": platform_key,
            "platformLabel": platform_label,
            "platformType": row.get("platform_type") or "",
            "discoverySource": row.get("discovery_source") or "",
            "discoverySourceLabel": _discovery_source_label(row.get("discovery_source")),
            "sourceDetail": _normalize_text((raw_payload or {}).get("source_detail")),
            "sourceFamily": row_source_family,
            "canonicalUrl": row.get("canonical_url") or "",
            "title": row.get("title") or "",
            "normalizedTitle": row.get("normalized_title") or "",
            "resourceFingerprint": row.get("resource_fingerprint") or (raw_payload or {}).get("resource_fingerprint") or "",
            "accessState": row.get("access_state") or "",
            "accessStateLabel": ACCESS_STATE_LABELS.get(str(row.get("access_state") or ""), str(row.get("access_state") or "")),
            "confidenceScore": int(row.get("confidence_score") or 0),
            "riskScore": int(row.get("risk_score") or 0),
            "severity": row.get("severity") or "low",
            "reviewStatus": row.get("review_status") or "new",
            "reviewStatusLabel": REVIEW_STATUS_LABELS.get(str(row.get("review_status") or "new"), str(row.get("review_status") or "new")),
            "matchedTerms": matched_terms,
            "fileCount": len(file_names) or int(row.get("file_count") or 0),
            "evidenceCount": int(row.get("evidence_count") or 0),
            "shareOwner": row.get("share_owner") or "",
            "primaryFileName": primary_file_name,
            "primaryFileType": _file_type_from_name(primary_file_name),
            "fileSizes": file_sizes,
            "primaryFileSize": primary_file_size,
            "shareCode": share_code,
            "shareType": _normalize_text((raw_payload or {}).get("share_type")) or ("password_share" if share_code else "public_share"),
            "disclosureTime": row.get("disclosure_time") or "",
            "firstSeenAt": row.get("first_seen_at") or "",
            "lastSeenAt": row.get("last_seen_at") or "",
            "lastSnapshotId": row.get("last_snapshot_id"),
            "summary": _normalize_text((raw_payload or {}).get("preview_text") or "")[:280],
        }
        if access_state and payload.get("accessState") != access_state:
            continue
        payloads.append(payload)
    if source_family:
        payloads = [item for item in payloads if item.get("sourceFamily") == source_family]
    return payloads


def _document_exposure_payload_cache_revision() -> tuple[Any, ...]:
    ensure_default_watchlist()
    with get_db_connection() as connection:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM document_hits) AS hit_count,
                (SELECT COALESCE(MAX(id), 0) FROM document_hits) AS max_hit_id,
                (SELECT COALESCE(MAX(last_seen_at), '') FROM document_hits) AS max_hit_seen_at,
                (SELECT COALESCE(MAX(last_snapshot_id), 0) FROM document_hits) AS max_snapshot_id,
                (SELECT COUNT(*) FROM document_hit_reviews) AS review_count,
                (SELECT COALESCE(MAX(id), 0) FROM document_hit_reviews) AS max_review_id,
                (SELECT COALESCE(MAX(updated_at), '') FROM exposure_watchlists) AS watchlist_updated_at,
                (SELECT COUNT(*) FROM exposure_watch_terms) AS term_count,
                (SELECT COALESCE(MAX(updated_at), '') FROM exposure_watch_terms) AS term_updated_at
            """
        ).fetchone()
    if row is None:
        return ()
    fields = (
        "hit_count",
        "max_hit_id",
        "max_hit_seen_at",
        "max_snapshot_id",
        "review_count",
        "max_review_id",
        "watchlist_updated_at",
        "term_count",
        "term_updated_at",
    )
    return tuple(row[field] for field in fields)


def _cached_document_exposure_payloads(source_family: str | None) -> list[dict[str, Any]]:
    normalized_family = _normalize_text(source_family)
    revision = _document_exposure_payload_cache_revision()
    cache_key = (normalized_family, revision)
    now = time.monotonic()
    with _DOCUMENT_EXPOSURE_PAYLOAD_CACHE_LOCK:
        cached = _DOCUMENT_EXPOSURE_PAYLOAD_CACHE.get(cache_key)
        if cached and now - cached[0] <= _DOCUMENT_EXPOSURE_PAYLOAD_CACHE_TTL_SECONDS:
            return [dict(item) for item in cached[1]]
        payloads = _build_document_exposures_payload(source_family=normalized_family or None, limit=None)
        for key in list(_DOCUMENT_EXPOSURE_PAYLOAD_CACHE):
            if key[1] != revision:
                _DOCUMENT_EXPOSURE_PAYLOAD_CACHE.pop(key, None)
        _DOCUMENT_EXPOSURE_PAYLOAD_CACHE[cache_key] = (time.monotonic(), payloads)
        return [dict(item) for item in payloads]


def _document_exposure_matches_query(item: dict[str, Any], query: str) -> bool:
    needle = _normalize_text(query).casefold()
    if not needle:
        return True
    matched_terms = " ".join(
        _normalize_text(term.get("term"))
        for term in (item.get("matchedTerms") or [])
        if isinstance(term, dict)
    )
    haystack = " ".join(
        _normalize_text(value)
        for value in (
            item.get("title"),
            item.get("primaryFileName"),
            item.get("canonicalUrl"),
            item.get("platformLabel"),
            item.get("shareOwner"),
            matched_terms,
        )
    ).casefold()
    return needle in haystack


def _document_exposure_is_recent(item: dict[str, Any], recent_hours: int | None) -> bool:
    if not recent_hours:
        return True
    text = _normalize_text(item.get("lastSeenAt") or item.get("firstSeenAt"))
    if not text:
        return False
    try:
        observed_at = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return False
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    return observed_at >= datetime.now(timezone.utc) - timedelta(hours=max(1, int(recent_hours)))


def list_document_exposures_payload(
    *,
    watchlist_id: int | None = None,
    review_status: str | None = None,
    platform: str | None = None,
    access_state: str | None = None,
    source_family: str | None = None,
    severity: str | None = None,
    recent_hours: int | None = None,
    query: str | None = None,
    offset: int = 0,
    limit: int | None = 200,
) -> list[dict[str, Any]]:
    payloads = _cached_document_exposure_payloads(source_family)
    if watchlist_id is not None:
        payloads = [item for item in payloads if int(item.get("watchlistId") or 0) == int(watchlist_id)]
    if review_status:
        payloads = [item for item in payloads if item.get("reviewStatus") == review_status]
    if platform:
        payloads = [item for item in payloads if item.get("platform") == platform]
    if access_state:
        payloads = [item for item in payloads if item.get("accessState") == access_state]
    if severity:
        payloads = [item for item in payloads if item.get("severity") == severity]
    if recent_hours:
        payloads = [item for item in payloads if _document_exposure_is_recent(item, recent_hours)]
    if query:
        payloads = [item for item in payloads if _document_exposure_matches_query(item, query)]
    start = max(0, int(offset or 0))
    end = start + max(1, int(limit)) if limit else None
    return payloads[start:end]


def list_document_exposures_page_payload(
    *,
    offset: int = 0,
    limit: int = 20,
    **filters: Any,
) -> dict[str, Any]:
    filtered = list_document_exposures_payload(limit=None, **filters)
    safe_limit = min(100, max(1, int(limit)))
    safe_offset = max(0, int(offset))
    return {
        "items": filtered[safe_offset : safe_offset + safe_limit],
        "total": len(filtered),
        "offset": safe_offset,
        "limit": safe_limit,
    }


def build_document_exposure_detail(hit_id: int) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        row = get_document_hit(connection, hit_id)
        if row is None:
            return None
        watchlist = get_exposure_watchlist(connection, int(row["watchlist_id"]))
        matched_terms_for_mirror = json.loads(str(row.get("matched_terms_json") or "[]"))
        if _is_seed_placeholder_hit(watchlist, matched_terms_for_mirror):
            return None
        raw_payload_for_mirror = json.loads(str(row.get("raw_json") or "{}"))
        snapshots = list_document_hit_snapshots(connection, hit_id)
        if row.get("platform_type") == "netdisk_share":
            mirror_updated = False
            if not snapshots:
                fallback_file_list = _build_file_list(
                    [_normalize_text(item) for item in _list_from_payload(raw_payload_for_mirror.get("file_names")) if _normalize_text(item)],
                    [_normalize_text(item) for item in _list_from_payload(raw_payload_for_mirror.get("file_sizes")) if _normalize_text(item)],
                    [item for item in _list_from_payload(raw_payload_for_mirror.get("file_entries")) if isinstance(item, dict)],
                )
                snapshot_id = insert_document_hit_snapshot(
                    connection,
                    {
                        "hit_id": int(hit_id),
                        "fetched_at": row.get("last_seen_at") or _now_utc_iso(),
                        "source_query": raw_payload_for_mirror.get("source_query") or "",
                        "source_url": raw_payload_for_mirror.get("source_url") or "",
                        "page_url": row.get("canonical_url") or raw_payload_for_mirror.get("page_url") or "",
                        "page_title": row.get("title") or "",
                        "html_path": "",
                        "screenshot_path": "",
                        "ocr_text": raw_payload_for_mirror.get("preview_text") or "",
                        "preview_text": raw_payload_for_mirror.get("preview_text") or "",
                        "file_list_json": _json_dumps(fallback_file_list),
                        "access_state": row.get("access_state") or "unknown",
                        "matched_terms_json": row.get("matched_terms_json") or "[]",
                        "raw_json": row.get("raw_json") or "{}",
                    },
                )
                update_document_hit_last_snapshot(connection, int(hit_id), snapshot_id)
                snapshots = list_document_hit_snapshots(connection, hit_id)
                mirror_updated = True
            for snapshot in snapshots:
                html_path_raw = _normalize_text(snapshot.get("html_path"))
                if html_path_raw and Path(html_path_raw).exists():
                    continue
                html_path = _ensure_netdisk_snapshot_mirror(
                    row=row,
                    watchlist=watchlist,
                    snapshot=snapshot,
                    matched_terms=matched_terms_for_mirror,
                    raw_payload=raw_payload_for_mirror,
                )
                update_document_hit_snapshot_files(
                    connection,
                    int(snapshot["id"]),
                    html_path=html_path,
                    screenshot_path=_normalize_text(snapshot.get("screenshot_path")),
                )
                mirror_updated = True
            if mirror_updated:
                connection.commit()
                snapshots = list_document_hit_snapshots(connection, hit_id)
        reviews = list_document_hit_reviews(connection, hit_id)
    matched_terms = matched_terms_for_mirror
    raw_payload = json.loads(str(row.get("raw_json") or "{}"))
    formatted_snapshots = []
    for item in snapshots:
        file_list = json.loads(str(item.get("file_list_json") or "[]"))
        matched_snapshot_terms = json.loads(str(item.get("matched_terms_json") or "[]"))
        html_path_raw = _normalize_text(item.get("html_path"))
        screenshot_path_raw = _normalize_text(item.get("screenshot_path"))
        html_path = Path(html_path_raw) if html_path_raw else None
        screenshot_path = Path(screenshot_path_raw) if screenshot_path_raw else None
        formatted_snapshots.append(
            {
                "id": int(item["id"]),
                "fetchedAt": item.get("fetched_at") or "",
                "sourceQuery": item.get("source_query") or "",
                "sourceUrl": item.get("source_url") or "",
                "pageUrl": item.get("page_url") or "",
                "pageTitle": item.get("page_title") or "",
                "htmlPath": str(html_path or ""),
                "htmlUrl": _public_output_url(html_path) if html_path else "",
                "screenshotPath": str(screenshot_path or ""),
                "screenshotUrl": _public_output_url(screenshot_path) if screenshot_path else "",
                "ocrText": item.get("ocr_text") or "",
                "previewText": item.get("preview_text") or "",
                "fileList": file_list,
                "accessState": item.get("access_state") or "",
                "matchedTerms": matched_snapshot_terms,
            }
        )
    latest_snapshot = formatted_snapshots[0] if formatted_snapshots else {}
    preview_assets: list[dict[str, str]] = []
    if latest_snapshot.get("screenshotUrl"):
        preview_assets.append({"kind": "screenshot", "label": "页面截图", "url": latest_snapshot["screenshotUrl"]})
    if latest_snapshot.get("htmlUrl"):
        preview_assets.append({"kind": "html", "label": "镜像文件", "url": latest_snapshot["htmlUrl"]})
    file_list: list[dict[str, Any]] = []
    seen_files: set[str] = set()
    for snapshot in formatted_snapshots:
        _append_detail_file_rows(file_list, seen_files, snapshot.get("fileList") or [])
    if not file_list and row.get("platform_type") == "netdisk_share":
        _append_detail_file_rows(
            file_list,
            seen_files,
            _fallback_file_rows_from_payload(raw_payload, latest_snapshot, str(row.get("title") or "")),
        )
    if row.get("platform_type") == "netdisk_share":
        file_list = _wrap_flat_netdisk_file_list(file_list, str(row.get("title") or ""))
    platform_key = row.get("platform") or ""
    preview_text = _normalize_text(
        latest_snapshot.get("previewText")
        or latest_snapshot.get("ocrText")
        or (raw_payload or {}).get("preview_text")
    )
    share_code = _normalize_text((raw_payload or {}).get("share_code")) or _extract_access_code(
        preview_text,
        row.get("title"),
        " ".join(file_row.get("name") or "" for file_row in file_list),
    )
    live_access_state = ""
    file_list_meta = _file_list_meta(file_list, str(platform_key))
    needs_live_listing = row.get("platform_type") == "netdisk_share" and (
        file_list_meta.get("quality") != "share_listing"
        or not _file_list_has_relevant_entry(file_list, str(row.get("title") or ""), matched_terms)
    )
    if needs_live_listing:
        cache_key = f"{platform_key}|{row.get('canonical_url') or ''}|{share_code}"
        cached_state, cached_entries = _NETDISK_DETAIL_CACHE.get(cache_key, ("", []))
        if cached_state:
            live_access_state = cached_state
            file_list = []
        elif cached_entries:
            file_list = []
            seen_files = set()
            _append_detail_file_rows(file_list, seen_files, _build_file_list([], [], cached_entries))
        else:
            try:
                live_entries: list[dict[str, Any]] = []
                if platform_key == "baidupan_share":
                    live_entries = _netdisk_file_entries_from_baidupan(
                        str(row.get("canonical_url") or ""),
                        share_code,
                    )
                elif platform_key == "aliyundrive_share":
                    live_entries = _netdisk_file_entries_from_aliyundrive(
                        str(row.get("canonical_url") or ""),
                        share_code,
                    )
                elif platform_key == "quark_share":
                    live_entries = _netdisk_file_entries_from_quark(
                        str(row.get("canonical_url") or ""),
                        share_code,
                    )
                if live_entries:
                    _NETDISK_DETAIL_CACHE[cache_key] = ("", live_entries)
                    file_list = []
                    seen_files = set()
                    _append_detail_file_rows(file_list, seen_files, _build_file_list([], [], live_entries))
            except NetdiskShareUnavailable as exc:
                live_access_state = exc.state
                _NETDISK_DETAIL_CACHE[cache_key] = (exc.state, [])
                file_list = []
            except Exception:
                pass
    if row.get("platform_type") == "netdisk_share" and _file_list_meta(file_list, str(platform_key)).get("quality") == "share_listing":
        file_list = _filter_relevant_file_list(file_list, str(row.get("title") or ""), matched_terms)
    detail_access_state = live_access_state or str(row.get("access_state") or "")
    if (
        row.get("platform_type") == "netdisk_share"
        and detail_access_state not in {"removed", "forbidden"}
        and not _file_list_has_relevant_entry(file_list, str(row.get("title") or ""), matched_terms)
    ):
        file_list = _prepend_missing_file_rows(
            file_list,
            _matched_preview_file_rows(raw_payload, latest_snapshot, str(row.get("title") or ""), matched_terms),
        )
    file_list_meta = _file_list_meta(file_list, str(platform_key))
    discovery_source_key = row.get("discovery_source") or ""
    discovery_source = next((item for item in DISCOVERY_SOURCES if item.key == discovery_source_key), None)
    source_family = _source_family_for_source(
        platform_type=row.get("platform_type"),
        source=discovery_source,
    )
    source_family_label = SOURCE_FAMILY_LABELS.get(source_family, source_family)
    platform_label = _platform_label(platform_key, discovery_source_key)
    risk_reasons: list[str] = []
    if matched_terms:
        matched_names = [
            _normalize_text(item.get("term"))
            for item in matched_terms[:4]
            if _normalize_text(item.get("term"))
        ]
        if matched_names:
            risk_reasons.append(f"命中监测词：{', '.join(matched_names)}")
    if file_list:
        risk_reasons.append(f"关联文件 {len(file_list)} 个")
    if detail_access_state == "public":
        risk_reasons.append("目标页面可公开访问")
    elif detail_access_state == "login_required":
        risk_reasons.append("目标页面需要登录复核")
    public_watchlist_name, public_organization_name = _watchlist_public_identity(watchlist, matched_terms)
    public_watchlist = {**(watchlist or {})}
    if _is_seed_placeholder_watchlist(watchlist):
        public_watchlist["name"] = public_watchlist_name
        public_watchlist["organization_name"] = public_organization_name
    return {
        "id": int(row["id"]),
        "watchlist": public_watchlist,
        "watchlistId": int(row["watchlist_id"]),
        "watchlistName": public_watchlist_name,
        "organizationName": public_organization_name,
        "platform": row.get("platform") or "",
        "platformLabel": platform_label,
        "platformType": row.get("platform_type") or "",
        "discoverySource": row.get("discovery_source") or "",
        "discoverySourceLabel": discovery_source.label if discovery_source else discovery_source_key,
        "sourceFamily": source_family,
        "sourceFamilyLabel": source_family_label,
        "canonicalUrl": row.get("canonical_url") or "",
        "title": translate_event_title_live(row.get("title")),
        "originalTitle": row.get("title") or "",
        "normalizedTitle": row.get("normalized_title") or "",
        "resourceFingerprint": row.get("resource_fingerprint") or (raw_payload or {}).get("resource_fingerprint") or "",
        "accessState": detail_access_state,
        "accessStateLabel": ACCESS_STATE_LABELS.get(detail_access_state, detail_access_state),
        "confidenceScore": int(row.get("confidence_score") or 0),
        "riskScore": int(row.get("risk_score") or 0),
        "severity": row.get("severity") or "",
        "reviewStatus": row.get("review_status") or "",
        "matchedTerms": matched_terms,
        "fileCount": len(file_list),
        "evidenceCount": int(row.get("evidence_count") or 0),
        "shareOwner": row.get("share_owner") or "",
        "disclosureTime": row.get("disclosure_time") or "",
        "firstSeenAt": row.get("first_seen_at") or "",
        "lastSeenAt": row.get("last_seen_at") or "",
        "rawPayload": raw_payload,
        "latestSnapshot": latest_snapshot,
        "previewAssets": preview_assets,
        "fileList": file_list,
        "fileListMeta": file_list_meta,
        "shareMeta": {
            "shareUrl": row.get("canonical_url") or "",
            "shareCode": share_code,
            "shareType": _normalize_text((raw_payload or {}).get("share_type")) or ("password_share" if share_code else "public_share"),
            "shareOwner": row.get("share_owner") or "",
            "accessState": detail_access_state,
            "accessStateLabel": ACCESS_STATE_LABELS.get(detail_access_state, detail_access_state),
        },
        "sourceResult": {
            "query": latest_snapshot.get("sourceQuery") or (raw_payload or {}).get("source_query") or "",
            "sourceUrl": latest_snapshot.get("sourceUrl") or (raw_payload or {}).get("source_url") or "",
            "pageUrl": latest_snapshot.get("pageUrl") or row.get("canonical_url") or "",
        },
        "documentMeta": {
            "primaryFileName": file_list[0]["name"] if file_list else _primary_file_name(_parse_json((raw_payload or {}).get("file_names"), []), str(row.get("title") or "")),
            "primaryFileType": file_list[0]["type"] if file_list else "",
            "fileCount": len(file_list),
            "evidenceCount": int(row.get("evidence_count") or 0),
        },
        "riskAnalysis": {
            "score": int(row.get("risk_score") or 0),
            "severity": row.get("severity") or "",
            "confidenceScore": int(row.get("confidence_score") or 0),
            "reasons": risk_reasons,
        },
        "snapshots": formatted_snapshots,
        "reviews": reviews,
    }


def add_document_exposure_review(hit_id: int, *, status: str, reviewer: str = "", note: str = "") -> dict[str, Any]:
    with get_db_connection() as connection:
        add_document_hit_review(
            connection,
            {
                "hit_id": int(hit_id),
                "status": status,
                "reviewer": reviewer,
                "note": note,
                "created_at": _now_utc_iso(),
            },
        )
        connection.commit()
    detail = build_document_exposure_detail(hit_id)
    if detail is None:
        raise ValueError(f"document exposure not found: {hit_id}")
    return detail


def build_document_exposure_summary(source_family: str | None = None) -> dict[str, Any]:
    rows = list_document_exposures_payload(limit=None, source_family=source_family)
    high_risk = [row for row in rows if int(row.get("riskScore") or 0) >= 75]
    login_required = [row for row in rows if row.get("accessState") == "login_required"]
    platforms = sorted({row.get("platform") for row in rows if row.get("platform")})
    pending_review = [row for row in rows if str(row.get("reviewStatus") or "new") in {"", "new", "triaged"}]
    watchlists = list_watchlists_payload()
    enabled_term_count = sum(
        1
        for watchlist in watchlists
        for term in (watchlist.get("effective_terms") or [])
        if bool(term.get("enabled"))
    )
    sessions = build_platform_session_payloads(module="document_exposure", manageable_only=True)
    configured_sessions = [row for row in sessions if bool(row.get("configured"))]
    invalid_sessions = [row for row in sessions if str(row.get("status") or "") in {"invalid", "missing", "unavailable"}]
    scan_runs = list_exposure_scan_runs_payload(limit=50)
    if source_family:
        scan_runs = [item for item in scan_runs if source_family in (item.get("sourceFamilies") or [])]
    latest_scan = scan_runs[0] if scan_runs else {}
    today = datetime.now(SHANGHAI_TZ).date()
    trend_counter = {}
    for offset in range(6, -1, -1):
        trend_counter[(today - timedelta(days=offset)).isoformat()] = 0
    platform_distribution: dict[str, int] = {}
    discovery_distribution: dict[str, int] = {}
    risk_distribution = {"high": 0, "medium": 0, "low": 0}
    access_distribution: dict[str, int] = {}
    review_distribution: dict[str, int] = {}
    keyword_top: dict[str, int] = {}
    file_total = 0
    evidence_total = 0
    recent_count = 0
    invalid_count = 0
    public_count = 0
    password_share_count = 0
    for row in rows:
        bucket = _format_day_bucket(row.get("lastSeenAt") or row.get("firstSeenAt"))
        if bucket in trend_counter:
            trend_counter[bucket] += 1
            if bucket == today.isoformat():
                recent_count += 1
        platform_label = _normalize_text(row.get("platformLabel") or row.get("platform") or "未知平台")
        platform_distribution[platform_label] = platform_distribution.get(platform_label, 0) + 1
        discovery_label = _normalize_text(row.get("discoverySourceLabel") or row.get("discoverySource") or platform_label)
        discovery_distribution[discovery_label] = discovery_distribution.get(discovery_label, 0) + 1
        severity = str(row.get("severity") or "low")
        risk_distribution[severity] = risk_distribution.get(severity, 0) + 1
        access_state = str(row.get("accessState") or "unknown")
        access_distribution[access_state] = access_distribution.get(access_state, 0) + 1
        review_state = str(row.get("reviewStatus") or "new")
        review_distribution[review_state] = review_distribution.get(review_state, 0) + 1
        if access_state == "public":
            public_count += 1
        if row.get("shareCode"):
            password_share_count += 1
        if access_state in {"removed", "forbidden"}:
            invalid_count += 1
        file_total += int(row.get("fileCount") or 0)
        evidence_total += int(row.get("evidenceCount") or 0)
        for term in row.get("matchedTerms") or []:
            term_name = _normalize_text(term.get("term"))
            if term_name:
                keyword_top[term_name] = keyword_top.get(term_name, 0) + 1
    return {
        "sourceFamily": source_family or "",
        "sourceFamilyLabel": SOURCE_FAMILY_LABELS.get(source_family or "", "文件监测"),
        "totalHits": len(rows),
        "highRiskCount": len(high_risk),
        "loginRequiredCount": len(login_required),
        "platformCount": len(platforms),
        "platforms": platforms,
        "pendingReviewCount": len(pending_review),
        "configuredSessionCount": len(configured_sessions),
        "invalidSessionCount": len(invalid_sessions),
        "watchlistCount": len(watchlists),
        "enabledTermCount": enabled_term_count,
        "lastScanAt": str(latest_scan.get("finishedAt") or ""),
        "lastCandidateCount": int(latest_scan.get("candidateCount") or 0),
        "lastHitCount": int(latest_scan.get("hitCount") or 0),
        "lastErrorCount": int(latest_scan.get("errorCount") or 0),
        "recentCount": recent_count,
        "publicCount": public_count,
        "passwordShareCount": password_share_count,
        "invalidCount": invalid_count,
        "fileCount": file_total,
        "evidenceCount": evidence_total,
        "trend": [{"date": key, "value": value} for key, value in trend_counter.items()],
        "platformDistribution": [{"name": key, "value": value} for key, value in sorted(platform_distribution.items(), key=lambda item: item[1], reverse=True)],
        "discoveryDistribution": [{"name": key, "value": value} for key, value in sorted(discovery_distribution.items(), key=lambda item: item[1], reverse=True)],
        "riskDistribution": [
            {"key": "high", "label": "高危", "value": risk_distribution.get("high", 0)},
            {"key": "medium", "label": "中危", "value": risk_distribution.get("medium", 0)},
            {"key": "low", "label": "低危", "value": risk_distribution.get("low", 0)},
        ],
        "accessStateDistribution": [
            {"key": key, "label": ACCESS_STATE_LABELS.get(key, key), "value": value}
            for key, value in sorted(access_distribution.items(), key=lambda item: item[1], reverse=True)
        ],
        "reviewDistribution": [
            {"key": key, "label": REVIEW_STATUS_LABELS.get(key, key), "value": value}
            for key, value in sorted(review_distribution.items(), key=lambda item: item[1], reverse=True)
        ],
        "keywordTop": [{"name": key, "value": value} for key, value in sorted(keyword_top.items(), key=lambda item: item[1], reverse=True)[:10]],
        "platformOptions": [
            {
                "value": key,
                "label": next(
                    (
                        str(item.get("platformLabel") or key)
                        for item in rows
                        if item.get("platform") == key
                    ),
                    key,
                ),
            }
            for key in platforms
        ],
    }


def list_exposure_scan_runs_payload(watchlist_id: int | None = None, limit: int | None = 50) -> list[dict[str, Any]]:
    ensure_default_watchlist()
    with get_db_connection() as connection:
        rows = list_exposure_scan_runs(connection, watchlist_id=watchlist_id, limit=limit)
    payloads: list[dict[str, Any]] = []
    for row in rows:
        requested_terms = _parse_json(row.get("requested_terms_json"), [])
        term_rows = [item if isinstance(item, dict) else {"term": item, "term_type": ""} for item in requested_terms]
        if _is_seed_placeholder_hit(row, term_rows):
            continue
        public_name, public_organization = _watchlist_public_identity(row, term_rows)
        payloads.append(
            {
                "id": int(row["id"]),
                "watchlistId": int(row["watchlist_id"]),
                "watchlistName": public_name,
                "organizationName": public_organization,
                "sourceFamilies": _normalize_source_families(row.get("source_families_json"), default_when_empty=False),
                "requestedTerms": requested_terms,
                "candidateCount": int(row.get("candidate_count") or 0),
                "hitCount": int(row.get("hit_count") or 0),
                "errorCount": int(row.get("error_count") or 0),
                "sourceStats": _parse_json(row.get("scan_stats_json"), []),
                "status": str(row.get("status") or "unknown"),
                "errors": _parse_json(row.get("errors_json"), []),
                "startedAt": str(row.get("started_at") or ""),
                "finishedAt": str(row.get("finished_at") or ""),
            }
        )
    return payloads


def _netdisk_state_suggested_pages(row: dict[str, Any]) -> list[int]:
    source = next((item for item in DISCOVERY_SOURCES if item.key == row.get("source_key")), None)
    if source is None:
        return [1]
    return _netdisk_incremental_page_numbers(source, row)


def list_netdisk_source_states_payload(watchlist_id: int | None = None) -> list[dict[str, Any]]:
    ensure_default_watchlist()
    with get_db_connection() as connection:
        rows = list_netdisk_source_states(connection, watchlist_id=watchlist_id)
    payloads: list[dict[str, Any]] = []
    for row in rows:
        term_rows = [{"term": str(row.get("term") or ""), "term_type": ""}]
        if _is_seed_placeholder_hit(row, term_rows):
            continue
        public_name, public_organization = _watchlist_public_identity(row, term_rows)
        payloads.append(
            {
                "id": int(row.get("id") or 0),
                "watchlistId": int(row.get("watchlist_id") or 0),
                "watchlistName": public_name,
                "organizationName": public_organization,
                "sourceKey": str(row.get("source_key") or ""),
                "sourceLabel": _netdisk_source_label(str(row.get("source_key") or "")),
                "term": str(row.get("term") or ""),
                "sourceFamily": str(row.get("source_family") or "netdisk_aggregator"),
                "nextPage": int(row.get("next_page") or 1),
                "lastScannedPage": int(row.get("last_scanned_page") or 0),
                "pageWindowSize": int(row.get("page_window_size") or 4),
                "suggestedPages": _netdisk_state_suggested_pages(row),
                "consecutiveEmptyPages": int(row.get("consecutive_empty_pages") or 0),
                "consecutiveRepeatedPages": int(row.get("consecutive_repeated_pages") or 0),
                "lastCandidateSignature": str(row.get("last_candidate_signature") or ""),
                "lastSuccessAt": str(row.get("last_success_at") or ""),
                "lastErrorAt": str(row.get("last_error_at") or ""),
                "lastError": str(row.get("last_error") or ""),
                "backoffUntil": str(row.get("backoff_until") or ""),
                "updatedAt": str(row.get("updated_at") or ""),
            }
        )
    return payloads


def list_netdisk_source_health_payload(source_family: str | None = None) -> list[dict[str, Any]]:
    normalized_family = _normalize_text(source_family) or None
    ensure_source_health_defaults(normalized_family or "netdisk_aggregator")
    with get_db_connection() as connection:
        rows = list_netdisk_source_health(connection)
    if normalized_family:
        allowed_sources = {
            source.key
            for source in DISCOVERY_SOURCES
            if _source_family_for_source(source) == normalized_family
        }
        rows = [row for row in rows if str(row.get("source_key") or "") in allowed_sources]
    return [
        {
            "sourceKey": str(row.get("source_key") or ""),
            "sourceLabel": _source_label(str(row.get("source_key") or "")),
            "sourceFamily": _source_family_for_source(
                next((source for source in DISCOVERY_SOURCES if source.key == str(row.get("source_key") or "")), None)
            ),
            "enabled": bool(row.get("enabled")),
            "status": str(row.get("status") or "healthy"),
            "successCount": int(row.get("success_count") or 0),
            "errorCount": int(row.get("error_count") or 0),
            "loginRequiredCount": int(row.get("login_required_count") or 0),
            "captchaCount": int(row.get("captcha_count") or 0),
            "rateLimitedCount": int(row.get("rate_limited_count") or 0),
            "consecutiveFailures": int(row.get("consecutive_failures") or 0),
            "lastSuccessAt": str(row.get("last_success_at") or ""),
            "lastErrorAt": str(row.get("last_error_at") or ""),
            "lastError": str(row.get("last_error") or ""),
            "backoffUntil": str(row.get("backoff_until") or ""),
            "updatedAt": str(row.get("updated_at") or ""),
        }
        for row in rows
    ]


def reset_netdisk_source_states_payload(payload: dict[str, Any]) -> dict[str, Any]:
    watchlist_id = payload.get("watchlist_id")
    with get_db_connection() as connection:
        reset_count = reset_netdisk_source_states(
            connection,
            watchlist_id=int(watchlist_id) if watchlist_id else None,
            source_key=_normalize_text(payload.get("source_key")),
            term=_normalize_text(payload.get("term")),
        )
        connection.commit()
    return {"resetCount": reset_count}


def _format_date(value: str | None) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(SHANGHAI_TZ).date().isoformat()


def build_document_exposure_event_records(limit: int | None = None) -> list[dict[str, Any]]:
    rows = list_document_exposures_payload(limit=limit or 200)
    events: list[dict[str, Any]] = []
    for row in rows:
        platform_label = _platform_label(row.get("platform"), row.get("discoverySource"))
        summary = _normalize_text(row.get("summary"))
        events.append(
            {
                "id": f"document:{int(row['id'])}",
                "event_type": "document",
                "normalized_event_type": "document_exposure",
                "raw_source_type": "document_hits",
                "rawSourceTypeLabel": "文件监测命中",
                "disclosureTime": _format_date(row.get("disclosureTime") or row.get("lastSeenAt")),
                "disclosureTimeRaw": row.get("disclosureTime") or row.get("lastSeenAt") or "",
                "disclosureDate": _format_date(row.get("disclosureTime") or row.get("lastSeenAt")),
                "updatedTime": row.get("lastSeenAt") or "",
                "updatedTimeRaw": row.get("lastSeenAt") or "",
                "title": translate_event_title_cached(row.get("title")),
                "originalTitle": row.get("title") or "",
                "category": "文件监测外泄",
                "attacker": platform_label,
                "sourceSite": platform_label,
                "industry": "未知",
                "country": "未知",
                "countryCode": "",
                "macroRegion": "未知",
                "region": "未知",
                "severity": row.get("severity") or "low",
                "victim": row.get("organizationName") or row.get("watchlistName") or "未知实体",
                "riskScore": int(row.get("riskScore") or 0),
                "riskReasons": [
                    f"命中监测词: {', '.join(item.get('term') for item in row.get('matchedTerms', [])[:3] if item.get('term'))}"
                ] if row.get("matchedTerms") else [],
                "monitoringMatches": row.get("matchedTerms") or [],
                "monitoringWeight": int(sum(int(item.get("weight") or 0) for item in row.get("matchedTerms") or [])),
                "monitoringPriority": "high" if int(row.get("riskScore") or 0) >= 75 else "medium" if int(row.get("riskScore") or 0) >= 45 else "low",
                "sampleLinks": [{"url": row.get("canonicalUrl") or "", "kind": row.get("platform") or "document"}] if row.get("canonicalUrl") else [],
                "sampleLinkCount": 1 if row.get("canonicalUrl") else 0,
                "hasSampleEvidence": bool(row.get("evidenceCount")),
                "priorityScore": int(row.get("riskScore") or 0),
                "confidenceScore": int(row.get("confidenceScore") or 0),
                "completenessScore": min(100, 30 + int(row.get("evidenceCount") or 0) * 10 + int(row.get("fileCount") or 0) * 5),
                "summary": summary,
                "reviewStatus": row.get("reviewStatus") or "new",
                "accessState": row.get("accessState") or "unknown",
                "platform": row.get("platform") or "",
                "fileCount": int(row.get("fileCount") or 0),
            }
        )
    return events


def build_document_exposure_event_detail(event_id: str) -> dict[str, Any] | None:
    if not str(event_id or "").startswith("document:"):
        return None
    try:
        hit_id = int(str(event_id).split(":", 1)[1])
    except Exception:
        return None
    detail = build_document_exposure_detail(hit_id)
    if detail is None:
        return None
    platform_key = str(detail.get("platform") or "")
    platform_label = _platform_label(platform_key, detail.get("discoverySource"))
    matched_terms = detail.get("matchedTerms") or []
    snapshot = detail["snapshots"][0] if detail.get("snapshots") else {}
    mirror_resources = []
    if snapshot.get("htmlUrl"):
        mirror_resources.append({"label": "本地HTML快照", "url": snapshot["htmlUrl"]})
    for item in snapshot.get("fileList") or []:
        if isinstance(item, dict) and item.get("name"):
            mirror_resources.append({"label": f"文件: {item['name']}", "url": detail.get("canonicalUrl") or ""})
    screenshot_resources = []
    if snapshot.get("screenshotUrl"):
        screenshot_resources.append({"label": "预览截图", "url": snapshot["screenshotUrl"]})
    return {
        "id": event_id,
        "identifier": event_id,
        "event_type": "document",
        "normalized_event_type": "document_exposure",
        "raw_source_type": "document_hits",
        "raw_source_type_label": "文件监测命中",
        "title": translate_event_title_live(detail.get("title")),
        "original_title": detail.get("originalTitle") or detail.get("title") or "",
        "disclosure_time": _format_date(detail.get("disclosureTime") or detail.get("lastSeenAt")),
        "disclosure_time_raw": detail.get("disclosureTime") or detail.get("lastSeenAt") or "",
        "updated_time": detail.get("lastSeenAt") or "",
        "updated_time_raw": detail.get("lastSeenAt") or "",
        "attacker": platform_label,
        "disclosure_url": detail.get("canonicalUrl") or "",
        "detail_text": snapshot.get("previewText") or snapshot.get("ocrText") or _normalize_text((detail.get("rawPayload") or {}).get("preview_text")),
        "category": "文件监测外泄",
        "source": platform_label,
        "industry": "未知",
        "country": "未知",
        "country_code": "",
        "macro_region": "未知",
        "region": "未知",
        "mirror_resources": mirror_resources,
        "screenshot_resources": screenshot_resources,
        "json_preview_url": "",
        "victim": (detail.get("watchlist") or {}).get("organization_name") or "未知实体",
        "risk_score": int(detail.get("riskScore") or 0),
        "risk_reasons": [
            f"命中监测词: {', '.join(item.get('term') for item in matched_terms[:4] if item.get('term'))}"
        ] if matched_terms else [],
        "risk_breakdown": {
            "total": int(detail.get("riskScore") or 0),
            "segments": [
                {"key": "matching", "label": "匹配度", "score": int(detail.get("confidenceScore") or 0), "max_score": 100, "reasons": []},
            ],
        },
        "rule_risk_breakdown": {},
        "monitoring_matches": matched_terms,
        "monitoring_weight": int(sum(int(item.get("weight") or 0) for item in matched_terms if isinstance(item, dict))),
        "monitoring_priority": "high" if int(detail.get("riskScore") or 0) >= 75 else "medium" if int(detail.get("riskScore") or 0) >= 45 else "low",
        "sample_links": [{"url": detail.get("canonicalUrl") or "", "kind": "document"}] if detail.get("canonicalUrl") else [],
        "has_sample_evidence": bool(detail.get("evidenceCount")),
        "sample_link_count": 1 if detail.get("canonicalUrl") else 0,
        "leak_type": "公开文件暴露",
        "severity": detail.get("severity") or "low",
        "confidence_score": int(detail.get("confidenceScore") or 0),
        "completeness_score": min(100, 30 + int(detail.get("evidenceCount") or 0) * 10 + int(detail.get("fileCount") or 0) * 5),
        "country_source": "unknown",
        "industry_source": "unknown",
        "tag_sources": [],
        "entity_link_evidence": {},
        "summary": snapshot.get("previewText") or "",
        "reviews": detail.get("reviews") or [],
        "access_state": detail.get("accessState") or "unknown",
        "review_status": detail.get("reviewStatus") or "new",
    }
