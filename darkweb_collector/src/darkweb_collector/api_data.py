from __future__ import annotations

from collections import Counter, OrderedDict
from collections.abc import Iterator
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from functools import wraps
from hashlib import sha1
import heapq
import json
import os
from pathlib import Path
import sqlite3
import sys
from threading import Lock
from time import monotonic
from typing import Any
from urllib.parse import unquote, urlsplit

import darkweb_collector.monitoring_rules as monitoring_rules_module
from darkweb_collector.adapters.registry import ADAPTERS
from darkweb_collector.config import get_site_config, load_site_configs
from darkweb_collector.crawl_frontier import frontier_counts, list_page_cursors
from darkweb_collector.detail_i18n import translate_event_detail_text_with_meta
from darkweb_collector.document_exposure import (
    build_document_exposure_event_detail,
    build_document_exposure_event_records,
    build_document_exposure_summary,
)
from darkweb_collector.db import (
    count_normalized_intelligence_events,
    get_db_connection,
    get_normalized_intelligence_cache_state,
    get_site_connectivity_probe_map,
    iter_normalized_intelligence_events,
    iter_vulnerability_records,
    search_normalized_intelligence_events,
)
from darkweb_collector.job_diagnostics import (
    classify_error,
    consecutive_failures,
    failure_cooldown_until,
    failure_threshold,
)
from darkweb_collector.normalized_intelligence import (
    _build_vulnerability_base_event,
    _coerce_bool,
    _format_date as _normalized_disclosure_date,
    _hydrate_event_row,
    _label_source as _normalized_source_label,
    _normalize_label,
    _severity_from_vulnerability,
    build_display_title,
    load_normalized_event_detail,
    normalized_event_to_detail,
    normalized_event_to_list_item,
)
from darkweb_collector.normalization_runtime import get_normalization_runtime_status
from darkweb_collector.queueing import queue_for_detail, queue_for_seed
from darkweb_collector.search_schema import SEARCH_ORDER, event_report_time
from darkweb_collector.runtime import active_release_config, default_db_path, output_root, project_root
from darkweb_collector.sites.darkforums import normalize_darkforums_timestamp
from darkweb_collector.site_auth import site_auth_readiness, site_display_name
from darkweb_collector.utils import safe_stem
from darkweb_collector.vulnerability_i18n import is_translation_error, resolve_vulnerability_summary
from darkweb_collector.worker_supervisor import queue_health_errors


SECTION_LABELS = {
    "databases": "数据库板块",
    "other_leaks": "其他泄露板块",
    "sellers_place": "卖家交易板块",
}

STATUS_LABELS = {
    "published": "已公开",
    "going": "协商中",
    "transferring": "传输中",
    "stopped": "已停止",
}

INDUSTRY_LABELS = {
    "other": "其他",
    "unknown": "未知",
    "government": "政府",
    "finance": "金融",
    "healthcare": "医疗",
    "technology": "科技",
    "military": "军事",
    "agriculture": "农业",
    "retail": "零售",
    "education": "教育",
    "telecommunications": "通信",
    "energy": "能源",
    "transportation": "交通",
    "entertainment": "文娱",
}

INDUSTRY_LABELS.update(
    {
        "public sector": "鏀垮簻",
        "financial services": "閲戣瀺",
        "agriculture and food production": "鍐滀笟",
        "consumer services": "闆跺敭",
        "telecommunication": "閫氫俊",
        "transportation/logistics": "浜ら€?",
        "hospitality and tourism": "鏂囧ū",
        "manufacturing": "鍒堕€犱笟",
        "construction": "鍒堕€犱笟",
        "business services": "鍏朵粬",
    }
)

REGION_LABELS = {
    "unknown": "未知",
    "north_america": "北美",
    "europe": "欧洲",
    "asia": "亚洲",
    "middle_east": "中东",
    "africa": "非洲",
    "oceania": "大洋洲",
    "south_america": "南美",
}

JOB_STATUS_LABELS = {
    "succeeded": "成功",
    "failed": "失败",
    "running": "运行中",
    "enqueued": "已入队",
    "stale": "异常挂起",
    "skipped": "已跳过",
}

RECENT_FAILURE_WINDOW_HOURS = 24
FAILED_JOB_HISTORY_LIMIT = 30
FAILED_JOB_HISTORY_DAYS = 7
STALE_RUNNING_MINUTES = 30
STALE_ENQUEUED_MINUTES = 10
RANSOMWARE_EVENT_LIMIT = 0
RANSOMWARE_SOURCE_QUERY_LIMIT = 0
DATA_LEAK_EVENT_LIMIT = 3000
VULNERABILITY_EVENT_LIMIT = 500
SHANGHAI_TZ = timezone(timedelta(hours=8))

_PAYLOAD_CACHE_LOCK = Lock()
_PAYLOAD_BUILD_LOCK = Lock()
_DASHBOARD_BUILD_LOCK = Lock()
_PAGE_BUILD_LOCK = Lock()
_PAYLOAD_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_PAYLOAD_CACHE_LIMIT = 8
PAYLOAD_CACHE_VERSION = "2026-04-11-executive-country-v2"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _format_dt(value: str | None) -> str:
    dt = _parse_dt(value)
    if dt is None:
        return value or ""
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


def _apply_event_limit(items: list[Any], limit: int | None) -> list[Any]:
    if limit is None:
        return items
    try:
        normalized = int(limit)
    except (TypeError, ValueError):
        return items
    if normalized <= 0:
        return items
    return items[:normalized]


def _format_date(value: str | None) -> str:
    dt = _parse_dt(value)
    if dt is None:
        return (value or "").split(" ", 1)[0]
    return dt.strftime("%Y-%m-%d")


def _weekday_cn(dt: datetime) -> str:
    names = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"]
    return names[dt.weekday()]


def _label_industry(value: str | None) -> str:
    raw = (value or "").strip()
    return INDUSTRY_LABELS.get(raw, raw or "未知")


def _label_industry(value: str | None) -> str:
    raw = (value or "").strip()
    lowered = raw.lower()
    if any(token in raw for token in ("鍒堕",)) or "manufact" in lowered or "construction" in lowered:
        return "制造业"
    if any(token in raw for token in ("鍏朵",)) or "business services" in lowered:
        return "其他"
    if any(token in raw for token in ("闆跺",)) or "consumer services" in lowered or "retail" in lowered:
        return "零售"
    if any(token in raw for token in ("浜ら",)) or "transport" in lowered or "logistics" in lowered:
        return "交通"
    if any(token in raw for token in ("鏂囧",)) or "hospitality" in lowered or "tourism" in lowered or "entertainment" in lowered:
        return "文娱"
    if any(token in raw for token in ("鏀垮",)) or "public sector" in lowered or "government" in lowered:
        return "政府"
    if any(token in raw for token in ("閲戣",)) or "financial services" in lowered or "finance" in lowered:
        return "金融"
    if any(token in raw for token in ("鍖荤",)) or "healthcare" in lowered:
        return "医疗"
    if any(token in raw for token in ("绉戞",)) or "technology" in lowered:
        return "科技"
    if any(token in raw for token in ("鍐滀",)) or "agriculture" in lowered:
        return "农业"
    if any(token in raw for token in ("閫氫",)) or "telecommunication" in lowered:
        return "通信"
    if any(token in raw for token in ("鑳芥",)) or "energy" in lowered:
        return "能源"
    if any(token in raw for token in ("鏁欒",)) or "education" in lowered:
        return "教育"
    return INDUSTRY_LABELS.get(lowered, INDUSTRY_LABELS.get(raw, raw or "鏈煡"))


def _label_region(value: str | None) -> str:
    raw = (value or "").strip()
    return REGION_LABELS.get(raw, raw or "未知")


def _label_source(value: str | None) -> str:
    return _normalized_source_label(value)


def _label_job_status(value: str | None) -> str:
    raw = (value or "").strip()
    return JOB_STATUS_LABELS.get(raw, raw or "未知")


def _event_hash(*parts: str) -> str:
    payload = "|".join((part or "").strip() for part in parts)
    return sha1(payload.encode("utf-8")).hexdigest()[:16]


def _parse_event_id(event_id: str) -> dict[str, str] | None:
    parts = (event_id or "").split(":")
    if len(parts) == 4 and parts[0] == "forum":
        return {
            "event_type": "forum",
            "site_name": parts[1],
            "section": parts[2],
            "hash": parts[3],
        }
    if len(parts) == 3 and parts[0] == "victim":
        return {
            "event_type": "victim",
            "site_name": parts[1],
            "hash": parts[2],
        }
    return None


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _is_recent(value: str | None, hours: int) -> bool:
    dt = _parse_dt(value)
    if dt is None:
        return False
    return dt >= (_now_utc() - timedelta(hours=hours))


def _is_stale_running(started_at: str | None, finished_at: str | None) -> bool:
    if finished_at:
        return False
    started = _parse_dt(started_at)
    if started is None:
        return False
    return started < (_now_utc() - timedelta(minutes=STALE_RUNNING_MINUTES))


def _is_stale_enqueued(enqueued_at: str | None, started_at: str | None, finished_at: str | None) -> bool:
    if started_at or finished_at:
        return False
    enqueued = _parse_dt(enqueued_at)
    if enqueued is None:
        return False
    return enqueued < (_now_utc() - timedelta(minutes=STALE_ENQUEUED_MINUTES))


def _effective_job_status(row: dict[str, Any]) -> str:
    status = row.get("status") or ""
    if status == "enqueued" and _is_stale_enqueued(row.get("enqueued_at"), row.get("started_at"), row.get("finished_at")):
        return "stale"
    if status == "running" and _is_stale_running(row.get("started_at"), row.get("finished_at")):
        return "stale"
    return status


def _job_event_dt(row: dict[str, Any] | None) -> datetime | None:
    if row is None:
        return None
    return _parse_dt(row.get("finished_at") or row.get("started_at") or row.get("enqueued_at"))


def _last_days(days: int = 7) -> list[datetime]:
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days - 1)
    return [start + timedelta(days=index) for index in range(days)]


def _series_from_counter(counter: Counter[str], days: int = 7) -> dict[str, list[Any]]:
    dates = _last_days(days)
    labels = [item.strftime("%m-%d") for item in dates]
    values = [int(counter.get(item.date().isoformat(), 0)) for item in dates]
    return {"labels": labels, "values": values}


def _count_by_day(values: list[str | None]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for raw in values:
        dt = _parse_dt(raw)
        if dt is None:
            continue
        counter[dt.date().isoformat()] += 1
    return counter


def _build_monitoring_status(forum_details: list[dict[str, Any]], crawl_jobs: list[dict[str, Any]]) -> dict[str, str]:
    latest_refresh = ""
    if crawl_jobs:
        latest_refresh = _format_dt(crawl_jobs[0].get("finished_at") or crawl_jobs[0].get("started_at"))
    elif forum_details:
        latest_refresh = _format_dt(forum_details[0].get("fetched_at"))

    site_names = sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
    failed_jobs = sum(
        1 for site_name in site_names if _latest_unresolved_problem_row([row for row in crawl_jobs if row.get("site_name") == site_name]) is not None
    )
    now_local = datetime.now().astimezone()
    return {
        "dateLabel": f"{now_local.strftime('%Y-%m-%d')} {_weekday_cn(now_local)}",
        "subtitle": "基于采集器 SQLite 数据库实时生成的威胁情报视图。",
        "scope": "覆盖论坛详情、受害者记录与爬虫任务审计数据。",
        "statusLabel": "采集状态",
        "statusValue": "采集中" if failed_jobs == 0 else "部分失败",
        "refreshedLabel": "最近刷新",
        "refreshedValue": latest_refresh or "暂无运行记录",
    }


def _recent_problem_rows(crawl_jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in ranked[:limit]:
        list_item = normalized_event_to_list_item(item)
        rows.append(
            {
                "id": item["event_id"],
                "disclosureDate": list_item.get("disclosureDate") or list_item.get("updatedTime", "")[:10],
                "title": list_item.get("title") or build_display_title(item),
                "originalTitle": item.get("title") or "鏈懡鍚嶄簨浠?",
                "sourceSite": list_item.get("sourceSite") or _label_source(item.get("source_site_name")),
                "attacker": item.get("attacker") or "鏈煡",
                "country": list_item.get("country") or "鏈煡",
                "industry": list_item.get("industry") or "鏈煡",
                "riskScore": int(item.get("risk_score") or 0),
                "monitoringWeight": int(list_item.get("monitoringWeight") or 0),
                "monitoringMatches": list_item.get("monitoringMatches") or [],
                "hasSampleEvidence": bool(list_item.get("hasSampleEvidence")),
            }
        )
    return rows
    rows = []
    for item in ranked[:limit]:
        list_item = normalized_event_to_list_item(item)
        rows.append(
            {
                "id": item["event_id"],
                "disclosureDate": list_item.get("disclosureDate") or list_item.get("updatedTime", "")[:10],
                "title": list_item.get("title") or build_display_title(item),
                "originalTitle": item.get("title") or "鏈懡鍚嶄簨浠?",
                "sourceSite": list_item.get("sourceSite") or _label_source(item.get("source_site_name")),
                "attacker": item.get("attacker") or "鏈煡",
                "country": list_item.get("country") or "鏈煡",
                "industry": list_item.get("industry") or "鏈煡",
                "riskScore": int(item.get("risk_score") or 0),
                "monitoringWeight": int(list_item.get("monitoringWeight") or 0),
                "monitoringMatches": list_item.get("monitoringMatches") or [],
                "hasSampleEvidence": bool(list_item.get("hasSampleEvidence")),
            }
        )
    return rows
    return [
        row
        for row in crawl_jobs
        if _effective_job_status(row) in {"failed", "stale"}
        and _is_recent(row.get("finished_at") or row.get("started_at"), RECENT_FAILURE_WINDOW_HOURS)
    ]


def _recent_problem_rows(crawl_jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in crawl_jobs
        if _effective_job_status(row) == "failed"
        and _is_recent(row.get("finished_at") or row.get("started_at"), RECENT_FAILURE_WINDOW_HOURS)
    ]


def _latest_succeeded_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((row for row in rows if row.get("status") == "succeeded"), None)


def _latest_unresolved_problem_row(rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    latest_success_dt = _job_event_dt(_latest_succeeded_row(rows))
    for row in rows:
        if _effective_job_status(row) != "failed":
            continue
        row_dt = _job_event_dt(row)
        if row_dt is None:
            continue
        if not _is_recent(row.get("finished_at") or row.get("started_at"), RECENT_FAILURE_WINDOW_HOURS):
            continue
        if latest_success_dt is not None and row_dt <= latest_success_dt:
            continue
        return row
    return None


def _build_data_leak_events(forum_details: list[dict[str, Any]]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for row in forum_details[:50]:
        event_id = f"forum:{row['site_name']}:{row['section']}:{_event_hash(row['topic_url'])}"
        events.append(
            {
                "id": event_id,
                "disclosureTime": _format_dt(row.get("fetched_at")),
                "title": row.get("title") or row.get("topic_url") or "未命名论坛帖子",
                "category": SECTION_LABELS.get(row.get("section", ""), row.get("section", "未知")),
                "attacker": row.get("attackers") or _label_source(row.get("site_name")),
                "industry": _label_industry(row.get("industry")),
                "region": _label_region(row.get("region")),
                "severity": "high" if row.get("section") == "databases" else "medium",
                "victim": row.get("victims") or "",
            }
        )
    return events


def _build_ransomware_events(victim_rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    events: list[dict[str, str]] = []
    for row in _apply_event_limit(victim_rows, RANSOMWARE_EVENT_LIMIT):
        raw_json = _parse_json(row.get("raw_json"))
        detail_url = row.get("detail_url") or raw_json.get("detail_url") or ""
        event_id = f"victim:{row['site_name']}:{_event_hash(detail_url or row.get('name', ''))}"
        events.append(
            {
                "id": event_id,
                "disclosureTime": _format_dt(row.get("published_at_utc") or row.get("last_seen_at")),
                "title": row.get("display_label") or row.get("name") or "未知受害者",
                "category": STATUS_LABELS.get(row.get("status", ""), row.get("status", "未知")),
                "attacker": _label_source(row.get("site_name")),
                "industry": _label_industry(row.get("industry")),
                "region": _label_region(row.get("region")),
                "severity": "high" if row.get("status") == "published" else "medium",
            }
        )
    return events


def _parse_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}


def _coerce_resource_list(value: Any) -> list[dict[str, str]]:
    if not value:
        return []
    if isinstance(value, list):
        normalized = []
        for item in value:
            if isinstance(item, dict):
                url = str(item.get("url") or "").strip()
                if url:
                    kind = str(item.get("kind") or "").strip()
                    if not kind and Path(url.split("?", 1)[0]).suffix.lower() in {".gif", ".jpg", ".jpeg", ".png", ".webp"}:
                        kind = "image"
                    normalized.append({
                        "label": str(item.get("label") or item.get("name") or ("商品镜像图片" if kind == "image" else url)),
                        "url": url,
                        **({"kind": kind} if kind else {}),
                    })
            elif isinstance(item, str) and item.strip():
                url = item.strip()
                kind = "image" if Path(url.split("?", 1)[0]).suffix.lower() in {".gif", ".jpg", ".jpeg", ".png", ".webp"} else ""
                normalized.append({
                    "label": "商品镜像图片" if kind else url,
                    "url": url,
                    **({"kind": kind} if kind else {}),
                })
        return normalized
    if isinstance(value, str):
        if value.lstrip().startswith("["):
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, list):
                return _coerce_resource_list(decoded)
        items = [item.strip() for item in value.split(",") if item.strip()]
        return _coerce_resource_list(items)
    return []


def _site_output_dir(site_name: str) -> Path | None:
    try:
        return get_site_config(site_name).output_dir
    except Exception:
        legacy_name = safe_stem(site_name, fallback="")
        return (output_root() / legacy_name).resolve() if legacy_name else None


def _public_output_url(path: Path) -> str:
    root = output_root()
    try:
        relative_path = path.resolve().relative_to(root.resolve())
    except ValueError:
        return path.resolve().as_uri()
    return f"/collector-output/{relative_path.as_posix()}"


def _resource_entry(path: Path, label: str) -> dict[str, str]:
    return {
        "label": label,
        "url": _public_output_url(path),
    }


def _forum_output_resources(row_dict: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    output_dir = _site_output_dir(row_dict["site_name"])
    if output_dir is None:
        return [], []
    topic_url = str(row_dict.get("topic_url") or "")
    if not topic_url:
        return [], []
    section = str(row_dict.get("section") or "section")
    artifact_stem = _event_hash(topic_url)[:10]
    detail_dir = output_dir / section / "details"
    resources = []
    screenshots = []
    html_path = detail_dir / f"{artifact_stem}.html"
    json_path = detail_dir / f"{artifact_stem}.json"
    png_path = detail_dir / f"{artifact_stem}.png"
    if html_path.exists():
        resources.append(_resource_entry(html_path, "本地HTML镜像"))
    if json_path.exists():
        resources.append(_resource_entry(json_path, "本地JSON镜像"))
    if png_path.exists():
        screenshots.append(_resource_entry(png_path, "详情截图"))
    return resources, screenshots


def _victim_output_resources(row_dict: dict[str, Any], raw_json: dict[str, Any]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    output_dir = _site_output_dir(row_dict["site_name"])
    if output_dir is None:
        return [], []

    content_hash = str(raw_json.get("content_hash") or row_dict.get("content_hash") or "")
    domain = str(raw_json.get("domain") or row_dict.get("domain") or "")
    name = str(raw_json.get("name") or row_dict.get("name") or "")
    if row_dict["site_name"] in {"dragonforce", "lynx"}:
        artifact_stem = safe_stem(f"{content_hash[:10]}_{name[:30]}")
    else:
        artifact_stem = safe_stem(f"{content_hash[:10]}_{domain or name}")

    detail_dir = output_dir / "details"
    resources = []
    screenshots = []
    html_path = detail_dir / f"{artifact_stem}.html"
    json_path = detail_dir / f"{artifact_stem}.json"
    png_path = detail_dir / f"{artifact_stem}.png"
    if html_path.exists():
        resources.append(_resource_entry(html_path, "本地HTML镜像"))
    if json_path.exists():
        resources.append(_resource_entry(json_path, "本地JSON镜像"))
    if png_path.exists():
        screenshots.append(_resource_entry(png_path, "详情截图"))
    return resources, screenshots


def _build_forum_event_payload(row_dict: dict[str, Any]) -> dict[str, Any]:
    raw_json = _parse_json(row_dict.get("raw_json"))
    attackers = row_dict.get("attackers") or raw_json.get("attackers") or ""
    victims = row_dict.get("victims") or raw_json.get("victims") or ""
    disclosure_time = (
        raw_json.get("published_at_utc")
        or normalize_darkforums_timestamp(
            raw_json.get("timestamp") or row_dict.get("timestamps"),
            collected_at_utc=row_dict.get("fetched_at"),
        )
        or row_dict.get("fetched_at")
    )
    event_id = f"forum:{row_dict['site_name']}:{row_dict['section']}:{_event_hash(str(row_dict['topic_url']))}"
    local_mirror_resources, local_screenshot_resources = _forum_output_resources(row_dict)
    mirror_resources = _coerce_resource_list(row_dict.get("attachments"))
    mirror_resources.extend(local_mirror_resources)
    if row_dict.get("topic_url"):
        mirror_resources.append({"label": "原始披露链接", "url": str(row_dict["topic_url"])})

    return {
        "id": event_id,
        "event_type": "forum",
        "raw_source_type": "forum_details",
        "title": row_dict.get("title") or row_dict.get("topic_url") or "未命名论坛帖子",
        "disclosure_time": _format_dt(disclosure_time),
        "attacker": attackers or _label_source(row_dict.get("site_name")),
        "disclosure_url": row_dict.get("topic_url") or "",
        "detail_text": row_dict.get("content") or "",
        "category": SECTION_LABELS.get(row_dict.get("section", ""), row_dict.get("section", "未知")),
        "source": _label_source(row_dict.get("site_name")),
        "industry": _label_industry(row_dict.get("industry")),
        "region": _label_region(row_dict.get("region")),
        "mirror_resources": mirror_resources,
        "screenshot_resources": local_screenshot_resources,
        "json_preview_url": next((item["url"] for item in mirror_resources if item["url"].endswith(".json")), ""),
        "victim": victims,
    }


def _build_victim_event_payload(row_dict: dict[str, Any]) -> dict[str, Any]:
    raw_json = _parse_json(row_dict.get("raw_json"))
    detail_url = row_dict.get("detail_url") or raw_json.get("detail_url") or ""
    source_url = row_dict.get("source_url") or raw_json.get("source_url") or ""
    disclosure_url = detail_url or source_url
    event_id = f"victim:{row_dict['site_name']}:{_event_hash(str(detail_url or row_dict.get('name', '')))}"
    local_mirror_resources, local_screenshot_resources = _victim_output_resources(row_dict, raw_json)
    mirror_resources = _coerce_resource_list(detail_url)
    mirror_resources.extend(local_mirror_resources)
    screenshot_resources = _coerce_resource_list(raw_json.get("thumbnails"))
    screenshot_resources.extend(local_screenshot_resources)

    return {
        "id": event_id,
        "event_type": "victim",
        "raw_source_type": "victims",
        "title": row_dict.get("display_label") or row_dict.get("name") or "未知受害者",
        "disclosure_time": _format_dt(row_dict.get("published_at_utc") or row_dict.get("fetched_at_utc")),
        "attacker": _label_source(row_dict.get("site_name")),
        "disclosure_url": disclosure_url,
        "detail_text": row_dict.get("text_excerpt") or raw_json.get("description") or "",
        "category": STATUS_LABELS.get(row_dict.get("status", ""), row_dict.get("status", "未知")),
        "source": _label_source(row_dict.get("site_name")),
        "industry": _label_industry(raw_json.get("industry")),
        "region": _label_region(raw_json.get("region")),
        "mirror_resources": mirror_resources,
        "screenshot_resources": screenshot_resources,
        "json_preview_url": next((item["url"] for item in mirror_resources if item["url"].endswith(".json")), ""),
        "victim": row_dict.get("name") or "",
    }


EVENT_SEARCH_TYPES = {
    "all": "",
    "ransomware": "ransomware",
    "data-leak": "data_leak",
    "vulnerability": "vulnerability",
}

_SEARCH_CACHE_TTL = 15.0
_SEARCH_CACHE_LIMIT = 128
_SEARCH_CACHE_LOCK = Lock()
_SEARCH_COUNTS_CACHE: OrderedDict = OrderedDict()
_SEARCH_PAGE_CACHE: OrderedDict = OrderedDict()


def _search_cache_get(cache, key):
    if key is None:
        return None
    with _SEARCH_CACHE_LOCK:
        entry = cache.get(key)
        if entry is None:
            return None
        if monotonic() - entry[0] >= _SEARCH_CACHE_TTL:
            del cache[key]
            return None
        cache.move_to_end(key)
        return deepcopy(entry[1])


def _search_cache_put(cache, key, value):
    if key is None:
        return
    with _SEARCH_CACHE_LOCK:
        cache[key] = (monotonic(), deepcopy(value))
        cache.move_to_end(key)
        while len(cache) > _SEARCH_CACHE_LIMIT:
            cache.popitem(last=False)


def build_event_search_payload(
    *,
    page: int = 1,
    page_size: int = 20,
    query: str = "",
    event_type: str = "all",
    sort: str = "latest",
    timings: dict[str, float] | None = None,
) -> dict[str, Any]:
    started = monotonic()
    if timings is None:
        timings = {}
    database_event_type = EVENT_SEARCH_TYPES[event_type]
    with get_db_connection() as connection:
        timings["connection"] = (monotonic() - started) * 1000
        phase = monotonic()
        identity = getattr(connection, "cache_identity", None)
        # Keep the revision, counts and page within the same database snapshot.
        begin = "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ" if identity and identity[0] == "postgresql" else "BEGIN"
        connection.execute(begin)
        state = get_normalized_intelligence_cache_state(connection)
        timings["revision"] = (monotonic() - phase) * 1000
        counts_key = (
            identity, state["source_signature"], state["refreshed_at"], state["event_count"], query
        ) if identity and state else None
        page_key = (counts_key, event_type, sort, page, page_size) if counts_key else None
        cached = _search_cache_get(_SEARCH_PAGE_CACHE, page_key)
        if cached is not None:
            timings["cache"] = 0.0
            timings["total"] = (monotonic() - started) * 1000
            return cached
        phase = monotonic()
        result = search_normalized_intelligence_events(
            connection, event_type=database_event_type, query=query, sort=sort,
            limit=page_size, page=page,
            counts=_search_cache_get(_SEARCH_COUNTS_CACHE, counts_key),
        )
        timings["query"] = (monotonic() - phase) * 1000
        timings.update(result.get("timings", {}))
        database_counts = result["counts"]
        _search_cache_put(_SEARCH_COUNTS_CACHE, counts_key, database_counts)
        counts = {
            "ransomware": int(database_counts.get("ransomware") or 0),
            "data-leak": int(database_counts.get("data_leak") or 0),
            "vulnerability": int(database_counts.get("vulnerability") or 0),
        }
        counts["all"] = sum(counts.values())
        total = counts[event_type]
        page_count = max(1, (total + page_size - 1) // page_size)
        normalized_page = result["page"]
        phase = monotonic()
        normalized_events = [_hydrate_event_row(row) for row in result["rows"]]

    payload = {
        "items": [normalized_event_to_list_item(item) for item in normalized_events],
        "total": total,
        "page": normalized_page,
        "page_size": page_size,
        "page_count": page_count,
        "has_previous": normalized_page > 1,
        "has_next": normalized_page < page_count,
        "query": query,
        "event_type": event_type,
        "sort": sort,
        "counts": counts,
        "revision": f"{state['source_signature']}:{state['refreshed_at']}" if state else "",
    }
    _search_cache_put(_SEARCH_PAGE_CACHE, page_key, payload)
    timings["hydrate"] = (monotonic() - phase) * 1000
    timings["total"] = (monotonic() - started) * 1000
    return payload


def _iter_detail_rows(connection, query: str, parameters: tuple) -> Iterator[Any]:
    cursor = (connection.iter_rows(query, parameters, batch_size=1)
              if getattr(connection, "backend_name", "") == "postgresql"
              else connection.execute(query, parameters))
    with closing(cursor):
        for row in cursor:
            yield row


def _build_forum_event_detail_by_id(
    connection,
    site_name: str,
    section: str,
    hash_value: str,
    *,
    source_record_id: int = 0,
    source_url: str = "",
) -> dict[str, Any] | None:
    if source_url and _event_hash(source_url) != hash_value:
        source_url = ""
    if not source_record_id and not source_url:
        rows = _iter_detail_rows(
            connection,
            """SELECT id, topic_url FROM forum_details
               WHERE site_name = ? AND section = ? ORDER BY datetime(fetched_at) DESC""",
            (site_name, section),
        )
        with closing(rows):
            for row in rows:
                if _event_hash(str(row["topic_url"] or "")) == hash_value:
                    source_record_id = int(row["id"])
                    source_url = str(row["topic_url"] or "")
                    break
        if not source_record_id:
            return None
    condition = "d.id = ?" if source_record_id else "d.topic_url = ?"
    parameters = (site_name, section, source_record_id or source_url)
    rows = _iter_detail_rows(
        connection,
        f"""
        SELECT d.site_name, d.section, d.topic_url, d.content, d.attachments, d.victims, d.attackers, d.fetched_at, d.raw_json,
               COALESCE(t.title, d.topic_url) AS title,
               COALESCE((SELECT industry FROM forum_victims fv WHERE fv.forum_detail_id = d.id LIMIT 1), 'other') AS industry,
               COALESCE((SELECT region FROM forum_victims fv WHERE fv.forum_detail_id = d.id LIMIT 1), 'unknown') AS region
        FROM forum_details d
        LEFT JOIN forum_topics t
          ON t.site_name = d.site_name
         AND t.section = d.section
         AND t.url = d.topic_url
        WHERE d.site_name = ? AND d.section = ? AND {condition}
        ORDER BY datetime(d.fetched_at) DESC
        LIMIT 1
        """,
        parameters,
    )
    with closing(rows):
        for row in rows:
            row_dict = dict(row)
            if _event_hash(str(row_dict.get("topic_url") or "")) == hash_value:
                return _build_forum_event_payload(row_dict)
    if source_record_id:
        return _build_forum_event_detail_by_id(
            connection, site_name, section, hash_value, source_url=source_url,
        )
    return None


def _build_victim_event_detail_by_id(
    connection,
    site_name: str,
    hash_value: str,
    *,
    source_record_id: int = 0,
    source_url: str = "",
) -> dict[str, Any] | None:
    if source_url and _event_hash(source_url) != hash_value:
        source_url = ""
    if not source_record_id and not source_url:
        rows = _iter_detail_rows(
            connection,
            """
            SELECT v.id, v.detail_url, v.name,
                   CASE WHEN COALESCE(v.detail_url, '') = '' THEN v.raw_json ELSE '' END AS raw_json
            FROM victims v LEFT JOIN victim_details vd ON vd.victim_id = v.id
            WHERE v.site_name = ?
            ORDER BY COALESCE(vd.fetched_at_utc, v.published_at_utc, '') DESC, v.id DESC
            """,
            (site_name,),
        )
        with closing(rows):
            for row in rows:
                row_dict = dict(row)
                detail_url = row_dict.get("detail_url") or _parse_json(row_dict.get("raw_json")).get("detail_url") or ""
                if _event_hash(str(detail_url or row_dict.get("name", ""))) == hash_value:
                    source_record_id = int(row_dict["id"])
                    break
        if not source_record_id:
            return None
    condition = "v.id = ?" if source_record_id else "v.detail_url = ?"
    rows = _iter_detail_rows(
        connection,
        f"""
        SELECT v.site_name, v.source_url, v.name, v.display_label, v.detail_url, v.status, v.published_at_utc, v.raw_json,
               v.last_detail_fetch_status, v.content_hash, v.domain, vd.text_excerpt, vd.page_title, vd.fetched_at_utc
        FROM victims v
        LEFT JOIN victim_details vd
          ON vd.victim_id = v.id
        WHERE v.site_name = ? AND {condition}
        ORDER BY COALESCE(vd.fetched_at_utc, v.published_at_utc, '') DESC, v.id DESC
        LIMIT 1
        """,
        (site_name, source_record_id or source_url),
    )
    with closing(rows):
        for row in rows:
            row_dict = dict(row)
            raw_json = _parse_json(row_dict.get("raw_json"))
            detail_url = row_dict.get("detail_url") or raw_json.get("detail_url") or ""
            event_id = f"victim:{row_dict['site_name']}:{_event_hash(str(detail_url or row_dict.get('name', '')))}"
            if event_id.split(":", 2)[2] == hash_value:
                return _build_victim_event_payload(row_dict)
    if source_record_id or source_url:
        return _build_victim_event_detail_by_id(
            connection, site_name, hash_value, source_url=source_url if source_record_id else "",
        )
    return None


def _load_raw_vulnerability_record(connection, event_id: str) -> dict[str, Any] | None:
    cve_id = str(event_id or "").removeprefix("vuln:").upper()
    with closing(_iter_detail_rows(
        connection,
        """SELECT id, source_name, source_type, cve_id, title, vendor, product, vulnerability_type,
                  severity, cvss, is_exploited, has_poc, patch_available, wide_impact,
                  disclosure_time, affected_versions, summary, advisory_url, reference_urls_json,
                  raw_json, last_seen_at
           FROM vulnerability_records WHERE UPPER(cve_id) = ?
           ORDER BY datetime(disclosure_time) DESC, id DESC LIMIT 1""",
        (cve_id,),
    )) as rows:
        row = next(rows, None)
    return dict(row) if row is not None else None


def _build_raw_event_detail_by_id(connection, event_id: str, source_event: dict[str, Any] | None = None) -> dict[str, Any] | None:
    if str(event_id or "").startswith("vuln:"):
        row = _load_raw_vulnerability_record(connection, event_id)
        return normalized_event_to_detail(_materialize_vulnerability_event(row)) if row is not None else None
    parsed = _parse_event_id(event_id)
    if parsed is None:
        return None
    source_event = source_event or {}
    if parsed["event_type"] == "forum":
        return _build_forum_event_detail_by_id(
            connection,
            site_name=parsed["site_name"],
            section=parsed["section"],
            hash_value=parsed["hash"],
            source_record_id=int(source_event.get("source_record_id") or 0) if source_event.get("raw_source_type") == "forum_details" else 0,
            source_url=str(source_event.get("source_url") or ""),
        )
    if parsed["event_type"] == "victim":
        return _build_victim_event_detail_by_id(
            connection,
            site_name=parsed["site_name"],
            hash_value=parsed["hash"],
            source_record_id=int(source_event.get("source_record_id") or 0) if source_event.get("raw_source_type") == "victims" else 0,
            source_url=str(source_event.get("source_url") or ""),
        )
    return None


def _merge_event_detail_payload(base: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key in ("disclosure_url", "detail_text", "victim"):
        if not merged.get(key) and fallback.get(key):
            merged[key] = fallback[key]
    for key in ("industry", "region"):
        if merged.get(key) in {"", "未知"} and fallback.get(key) not in {"", "未知", None}:
            merged[key] = fallback[key]
    if merged.get("normalized_event_type") == "vulnerability":
        summary, original = resolve_vulnerability_summary(fallback, {"summary": fallback.get("detail_text")})
        if not summary:
            summary, original = resolve_vulnerability_summary(base, {"summary": base.get("detail_text")})
        unavailable = not summary and any(
            item.get("summary_unavailable") or any(is_translation_error(item.get(key)) for key in ("summary", "detail_text", "original_summary"))
            for item in (base, fallback)
        )
        merged.update(detail_text=summary, summary=summary, original_summary=original, summary_unavailable=bool(unavailable))
    for key in ("mirror_resources", "screenshot_resources"):
        resources = {}
        for item in (merged.get(key) or []) + (fallback.get(key) or []):
            url = str(item.get("url") or "")
            if url and url not in resources:
                resources[url] = dict(item)
            elif url and item.get("kind") and not resources[url].get("kind"):
                resources[url]["kind"] = item["kind"]
        merged[key] = list(resources.values())
    if not merged.get("json_preview_url") and fallback.get("json_preview_url"):
        merged["json_preview_url"] = fallback["json_preview_url"]
    merged.setdefault("identifier", merged.get("id") or fallback.get("id") or "")
    return merged


def _annotate_detail_resources(payload: dict[str, Any]) -> dict[str, Any]:
    statuses: dict[str, str] = {}
    root = output_root().resolve()

    def availability(url: str) -> str:
        if not url.startswith("/collector-output/"):
            return ""
        if url not in statuses:
            try:
                path = (root / unquote(urlsplit(url).path).removeprefix("/collector-output/")).resolve()
                relative = path.relative_to(root)
                private = bool(relative.parts and relative.parts[0].casefold() == "platform_sessions")
                statuses[url] = "available" if not private and path.is_file() else "missing"
            except (OSError, RuntimeError, ValueError):
                statuses[url] = "missing"
        return statuses[url]

    for key in ("mirror_resources", "screenshot_resources", "reference_urls", "sample_links"):
        if key not in payload:
            continue
        resources = []
        for item in payload.get(key) or []:
            resource = dict(item) if isinstance(item, dict) else {"url": str(item), "label": str(item)}
            status = availability(str(resource.get("url") or ""))
            if status:
                resource["availability"] = status
            resources.append(resource)
        payload[key] = resources
    preview_status = availability(str(payload.get("json_preview_url") or ""))
    if preview_status:
        payload["json_preview_availability"] = preview_status
    return payload


def build_event_detail(event_id: str, *, translate_detail: bool = False) -> dict[str, Any] | None:
    if str(event_id or "").startswith("document:"):
        payload = build_document_exposure_event_detail(event_id)
        if payload is None:
            return None
        if translate_detail and payload.get("detail_text"):
            translated, applied, error = translate_event_detail_text_with_meta(payload.get("detail_text"))
            payload["detail_text"] = translated
            payload["translation_applied"] = applied
            payload["translation_error"] = error or ""
        return _annotate_detail_resources(payload)
    with get_db_connection() as connection:
        event = load_normalized_event_detail(connection, event_id)
        fallback_payload = _build_raw_event_detail_by_id(connection, event_id, event)
        if event is None:
            payload = fallback_payload
            if payload is None:
                return None
        else:
            enriched_events, _ = monitoring_rules_module.build_monitoring_payload(connection, [event])
            payload = normalized_event_to_detail(enriched_events[0] if enriched_events else event)
            if fallback_payload is not None or payload.get("normalized_event_type") == "vulnerability":
                payload = _merge_event_detail_payload(payload, fallback_payload or {})
        payload.setdefault("identifier", payload.get("id") or event_id)
        if translate_detail and payload.get("normalized_event_type") != "vulnerability":
            translated, applied, error = translate_event_detail_text_with_meta(payload.get("detail_text"))
            payload["detail_text"] = translated
            payload["translation_applied"] = applied
            payload["translation_error"] = error or ""
        return _annotate_detail_resources(payload)


def build_vulnerability_records(
    *,
    severity: str | None = None,
    is_exploited: bool | None = None,
    days: int | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    # Select and deduplicate using scalar fields before loading any source body
    # or translating a summary. Keep the previous source ordering and tie rules.
    with get_db_connection() as connection:
        selected: dict[str, tuple[datetime | None, dict[str, Any]]] = {}
        for row in iter_vulnerability_records(connection, selection_only=True):
            key = _normalize_label(row.get("cve_id")).upper() or "vuln:"
            updated = _parse_dt(event_report_time({
                "event_type": "vulnerability", "disclosure_time": row.get("disclosure_time"),
                "metadata": {"updated_time": row.get("last_seen_at") or row.get("disclosure_time")},
            }))
            current = selected.get(key)
            if current is None or (updated is not None and (current[0] is None or updated >= current[0])):
                selected[key] = (updated, row)

        cutoff = _now_utc() - timedelta(days=days) if days else None
        severity_filter = (severity or "").strip().lower()
        filtered = []
        for _, row in selected.values():
            exploited = _coerce_bool(row.get("is_exploited"))
            if severity_filter and _severity_from_vulnerability(str(row.get("severity") or ""), row.get("cvss"), exploited) != severity_filter:
                continue
            if is_exploited is not None and exploited != bool(is_exploited):
                continue
            disclosed = _parse_dt(_normalized_disclosure_date(row.get("disclosure_time")).replace(" ", "T"))
            if cutoff is not None and (disclosed is None or disclosed < cutoff):
                continue
            filtered.append((disclosed or datetime.min.replace(tzinfo=timezone.utc), int(row["id"])))
        filtered.sort(key=lambda item: item[0], reverse=True)
        if limit is not None:
            filtered = filtered[:limit]
        selected_ids = [record_id for _, record_id in filtered]
        records = {}
        for offset in range(0, len(selected_ids), 500):
            for row in iter_vulnerability_records(connection, record_ids=selected_ids[offset:offset + 500]):
                records[int(row["id"])] = normalized_event_to_list_item(_materialize_vulnerability_event(row))
    return [records[record_id] for record_id in selected_ids if record_id in records]


def build_vulnerability_detail(event_id: str) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        row = _load_raw_vulnerability_record(connection, event_id)
        if row is not None:
            event = _materialize_vulnerability_event(row)
        else:
            event = load_normalized_event_detail(connection, event_id)
    if event is None or event.get("event_type") != "vulnerability":
        return None
    return _annotate_detail_resources(_merge_event_detail_payload(normalized_event_to_detail(event), {}))


def _materialize_vulnerability_event(row: dict[str, Any]) -> dict[str, Any]:
    event = _build_vulnerability_base_event(row)
    severity = str(event.get("severity") or "").lower()
    risk_score = 55
    if severity == "critical":
        risk_score = 85
    elif severity == "high":
        risk_score = 72
    elif severity == "medium":
        risk_score = 58
    if bool((event.get("metadata") or {}).get("is_exploited")):
        risk_score = min(100, risk_score + 10)
    return {
        **event,
        "source": (event.get("metadata") or {}).get("source") or "公开源",
        "risk_score": int(event.get("risk_score") or risk_score),
        "risk_reasons": event.get("risk_reasons") or [],
    }


def _build_summary_cards(
    data_leak_events: list[dict[str, str]],
    ransomware_events: list[dict[str, str]],
    crawl_jobs: list[dict[str, Any]],
    forum_victims: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    site_names = sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
    failed_jobs = sum(
        1 for site_name in site_names if _latest_unresolved_problem_row([row for row in crawl_jobs if row.get("site_name") == site_name]) is not None
    )
    impacted_entities = len([row for row in forum_victims if row.get("victim_name")])

    dashboard_summary = [
        {
            "label": "数据泄露事件",
            "value": str(len(data_leak_events)),
            "description": "已写入 SQLite 的论坛泄露详情数量。",
            "trend": f"{failed_jobs} 个失败任务" if failed_jobs else "运行正常",
            "tone": "warning",
            "icon": "Files",
        },
        {
            "label": "勒索受害者",
            "value": str(len(ransomware_events)),
            "description": "从泄露站点采集器解析出的受害者记录。",
            "trend": "采集链路在线",
            "tone": "danger",
            "icon": "Warning",
        },
        {
            "label": "受影响实体",
            "value": str(impacted_entities),
            "description": "从论坛详情中识别出的受害实体数量。",
            "trend": "来源于受害者实体表",
            "tone": "primary",
            "icon": "OfficeBuilding",
        },
        {
            "label": "爬虫任务",
            "value": str(len(crawl_jobs)),
            "description": "最近记录在任务审计表中的种子页与详情页任务。",
            "trend": "审计链路已开启",
            "tone": "success",
            "icon": "Bell",
        },
    ]

    data_leak_summary = [
        {
            "label": "泄露事件",
            "value": str(len(data_leak_events)),
            "description": "当前已同步到前端的数据泄露详情数量。",
            "trend": "实时来自已接入论坛数据源",
            "tone": "warning",
            "icon": "DocumentRemove",
        },
        {
            "label": "活跃板块",
            "value": str(len({item["category"] for item in data_leak_events})),
            "description": "当前正在贡献数据的论坛板块数量。",
            "trend": "数据库 / 其他泄露 / 卖家交易",
            "tone": "primary",
            "icon": "Files",
        },
        {
            "label": "受害者提及",
            "value": str(impacted_entities),
            "description": "从详情页内容中识别出的受害者实体。",
            "trend": "已启用实体抽取",
            "tone": "success",
            "icon": "UserFilled",
        },
    ]

    ransomware_summary = [
        {
            "label": "受害者记录",
            "value": str(len(ransomware_events)),
            "description": "当前受害者表中的勒索受害者数量。",
            "trend": "为 0 表示相关站点暂未写入数据",
            "tone": "danger",
            "icon": "Warning",
        },
        {
            "label": "活跃来源",
            "value": str(len({item["attacker"] for item in ransomware_events if item["attacker"]})),
            "description": "当前贡献受害者数据的泄露站点数量。",
            "trend": "按站点来源聚合",
            "tone": "warning",
            "icon": "UserFilled",
        },
        {
            "label": "状态种类",
            "value": str(len({item["category"] for item in ransomware_events if item["category"]})),
            "description": "已公开、协商中、传输中等状态种类。",
            "trend": "来源于受害者状态字段",
            "tone": "primary",
            "icon": "TrendCharts",
        },
        {
            "label": "失败任务",
            "value": str(failed_jobs),
            "description": "供运维排查的失败爬虫任务数量。",
            "trend": "来源于任务审计表",
            "tone": "success",
            "icon": "Bell",
        },
    ]

    return dashboard_summary, data_leak_summary, ransomware_summary


def _build_preview_cards(
    data_leak_events: list[dict[str, str]],
    ransomware_events: list[dict[str, str]],
    crawl_jobs: list[dict[str, Any]],
    behavior_payload: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    site_names = sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
    failed_jobs = sum(
        1 for site_name in site_names if _latest_unresolved_problem_row([row for row in crawl_jobs if row.get("site_name") == site_name]) is not None
    )
    return [
        {
            "route": "/ransomware",
            "eyebrow": "模块预览",
            "title": "勒索情报",
            "summary": "聚合受害者表中的受害者记录与泄露站点活动。",
            "highlight": f"{len(ransomware_events)} 条受害者记录",
            "tone": "danger",
            "stats": [
                {"label": "受害者", "value": str(len(ransomware_events))},
                {"label": "来源数", "value": str(len({item['attacker'] for item in ransomware_events if item['attacker']}))},
                {"label": "已公开", "value": str(sum(1 for item in ransomware_events if item['category'] == '已公开'))},
            ],
        },
        {
            "route": "/data-leak",
            "eyebrow": "模块预览",
            "title": "数据泄露情报",
            "summary": "聚合论坛详情记录与标准化泄露事件。",
            "highlight": f"{len(data_leak_events)} 条泄露详情",
            "tone": "warning",
            "stats": [
                {"label": "事件数", "value": str(len(data_leak_events))},
                {"label": "类型数", "value": str(len({item['category'] for item in data_leak_events}))},
                {"label": "地区数", "value": str(len({item['region'] for item in data_leak_events if item['region']}))},
            ],
        },
        {
            "route": "/threat-situation",
            "eyebrow": "模块预览",
            "title": "威胁态势",
            "summary": "从爬虫任务、结构化事件和风险分布构建整体态势视图。",
            "highlight": f"{failed_jobs} 个失败任务",
            "tone": "primary",
            "stats": [
                {"label": "任务数", "value": str(len(crawl_jobs))},
                {"label": "失败数", "value": str(failed_jobs)},
                {"label": "成功数", "value": str(sum(1 for row in crawl_jobs if row.get('status') == 'succeeded'))},
            ],
        },
    ]


def _build_recent_timeline(data_leak_events: list[dict[str, str]], ransomware_events: list[dict[str, str]], crawl_jobs: list[dict[str, Any]]) -> list[dict[str, str]]:
    timeline: list[dict[str, str]] = []
    for event in data_leak_events[:4]:
        timeline.append(
            {
                "time": event["disclosureTime"][-5:] if event["disclosureTime"] else "--:--",
                "module": "数据泄露",
                "title": event["title"],
                "detail": event["category"],
                "tone": "warning",
            }
        )
    for event in ransomware_events[:2]:
        timeline.append(
            {
                "time": event["disclosureTime"][-5:] if event["disclosureTime"] else "--:--",
                "module": "勒索情报",
                "title": event["title"],
                "detail": event["category"],
                "tone": "danger",
            }
        )
    unresolved_rows = []
    for site_name in sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")}):
        row = _latest_unresolved_problem_row([item for item in crawl_jobs if item.get("site_name") == site_name])
        if row is not None:
            unresolved_rows.append(row)
    unresolved_rows.sort(
        key=lambda row: _job_event_dt(row) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    for row in unresolved_rows[:2]:
            timeline.append(
                {
                    "time": _format_dt(row.get("finished_at") or row.get("started_at"))[-5:],
                    "module": "采集任务",
                    "title": f"{row.get('site_name')} {row.get('job_type')} {_label_job_status(_effective_job_status(row))}",
                    "detail": row.get("error_message") or row.get("target") or "任务失败",
                    "tone": "primary",
                }
            )
    return timeline[:8]


def _build_watchlist(crawl_jobs: list[dict[str, Any]], section_counts: Counter[str]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for site_name in sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")}):
        row = _latest_unresolved_problem_row([item for item in crawl_jobs if item.get("site_name") == site_name])
        if row is not None:
            items.append(
                {
                    "module": "采集任务",
                    "title": f"{row.get('site_name')} {row.get('job_type')} {_label_job_status(_effective_job_status(row))}",
                    "note": row.get("error_message") or "请检查代理链路或目标站点可达性",
                    "tone": "danger",
                }
            )
    for section, count in section_counts.most_common(3):
        items.append(
            {
                "module": "数据泄露",
                "title": f"{SECTION_LABELS.get(section, section)}持续活跃",
                "note": f"当前已累计 {count} 条详情记录。",
                "tone": "warning",
            }
        )
    return items[:3]


def _build_situation_alerts(crawl_jobs: list[dict[str, Any]]) -> list[dict[str, str]]:
    unresolved_rows: list[dict[str, Any]] = []
    for site_name in sorted({item.get("site_name") for item in crawl_jobs if item.get("site_name")}):
        row = _latest_unresolved_problem_row([item for item in crawl_jobs if item.get("site_name") == site_name])
        if row is not None:
            unresolved_rows.append(row)
    unresolved_rows.sort(
        key=lambda row: _job_event_dt(row) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return [
        {
            "level": "high",
            "time": _format_dt(row.get("finished_at") or row.get("started_at")),
            "title": f"{_label_source(row.get('site_name'))} {row.get('job_type')} {_label_job_status(_effective_job_status(row))}",
            "description": row.get("error_message") or row.get("target") or "采集任务状态更新",
            "source": _label_source(row.get("site_name")),
        }
        for row in unresolved_rows[:12]
    ]


def _build_country_focus(forum_victims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(_label_region(row.get("region")) for row in forum_victims)
    return [{"name": name, "value": value} for name, value in counts.most_common(6)]


def _build_vulnerability_summary(vulnerability_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exploited_count = sum(1 for item in vulnerability_events if item.get("isExploited"))
    patchable_count = sum(1 for item in vulnerability_events if item.get("patchAvailable"))
    vendor_count = len({item.get("vendor") for item in vulnerability_events if item.get("vendor")})
    return [
        {
            "label": "高危漏洞",
            "value": str(len(vulnerability_events)),
            "description": "已写入标准化事件表的公开源高危漏洞数量。",
            "trend": f"{exploited_count} 条已被利用",
            "tone": "danger",
            "icon": "WarningFilled",
        },
        {
            "label": "已被利用",
            "value": str(exploited_count),
            "description": "公开源披露中已确认存在利用活动的漏洞数量。",
            "trend": "优先进入处置视图",
            "tone": "warning",
            "icon": "Bell",
        },
        {
            "label": "影响厂商",
            "value": str(vendor_count),
            "description": "当前漏洞事件覆盖的重点厂商数量。",
            "trend": "用于识别高频产品族",
            "tone": "primary",
            "icon": "OfficeBuilding",
        },
        {
            "label": "可直接修复",
            "value": str(patchable_count),
            "description": "已明确有补丁或官方修复建议的漏洞数量。",
            "trend": "用于展示修复可执行性",
            "tone": "success",
            "icon": "CircleCheck",
        },
    ]


def _build_vulnerability_rankings(
    vulnerability_events: list[dict[str, Any]],
    field: str,
    limit: int = 6,
    recent_days: int = 30,
) -> list[dict[str, Any]]:
    cutoff = _now_utc() - timedelta(days=recent_days)
    recent_events = [
        item
        for item in vulnerability_events
        if (_parse_dt(str(item.get("disclosureTimeRaw") or item.get("disclosureTime") or "")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff
    ]
    source_events = recent_events or vulnerability_events
    counter = Counter(item.get(field) or "未知" for item in source_events if item.get(field))
    return [{"name": name, "value": value} for name, value in counter.most_common(limit)]


def _build_vulnerability_watchlist(vulnerability_events: list[dict[str, Any]], limit: int = 3) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for item in vulnerability_events[:limit]:
        alerts.append(
            {
                "module": "漏洞预警",
                "title": item.get("title") or item.get("cveId") or "高危漏洞",
                "note": "已被利用，建议优先核查补丁与暴露面。" if item.get("isExploited") else "存在公开 PoC 或高危利用条件，建议尽快研判。",
                "tone": "danger" if item.get("isExploited") else "warning",
            }
        )
    return alerts


def _build_vulnerability_timeline(vulnerability_events: list[dict[str, Any]], limit: int = 2) -> list[dict[str, str]]:
    timeline: list[dict[str, str]] = []
    for item in vulnerability_events[:limit]:
        timeline.append(
            {
                "time": (item.get("disclosureTime") or "--:--")[-5:],
                "module": "漏洞预警",
                "title": item.get("title") or item.get("cveId") or "公开源漏洞",
                "detail": "已被利用" if item.get("isExploited") else (item.get("category") or "公开披露"),
                "tone": "danger" if item.get("isExploited") else "primary",
            }
        )
    return timeline


def _build_vulnerability_alert_stream(vulnerability_events: list[dict[str, Any]], limit: int = 4) -> list[dict[str, str]]:
    alerts: list[dict[str, str]] = []
    for item in vulnerability_events[:limit]:
        alerts.append(
            {
                "level": "critical" if item.get("isExploited") else "high",
                "time": item.get("disclosureTime") or "",
                "title": item.get("title") or item.get("cveId") or "公开源漏洞",
                "description": item.get("summary") or "公开源披露了新的高危漏洞事件。",
                "source": item.get("vendor") or "漏洞预警",
            }
        )
    return alerts


def _keyword_category(title: str, content: str) -> str:
    text = f"{title} {content}".lower()
    if any(keyword in text for keyword in ["password", "credential", "fullz", "account"]):
        return "凭证数据"
    if any(keyword in text for keyword in ["database", "dump", "records", "breach", "leak"]):
        return "数据库"
    if any(keyword in text for keyword in ["document", "passport", "id", "license", "statement"]):
        return "文档证件"
    if any(keyword in text for keyword in ["source code", "code", "repo", "git"]):
        return "源代码"
    return "其他"


def _build_threat_heatmap(data_leak_events: list[dict[str, str]], ransomware_events: list[dict[str, str]], crawl_jobs: list[dict[str, Any]]) -> dict[str, Any]:
    regions = list({item["region"] for item in data_leak_events if item["region"]})[:5] or ["未知"]
    categories = ["数据泄露", "勒索情报", "失败任务"]
    values: list[list[int]] = []
    region_counts = Counter(item["region"] for item in data_leak_events)
    ransom_counts = Counter(item["region"] for item in ransomware_events if item["region"])
    site_names = sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
    failed_jobs = sum(
        1 for site_name in site_names if _latest_unresolved_problem_row([row for row in crawl_jobs if row.get("site_name") == site_name]) is not None
    )
    for region_index, region in enumerate(regions):
        values.append([region_index, 0, int(region_counts.get(region, 0))])
        values.append([region_index, 1, int(ransom_counts.get(region, 0))])
        values.append([region_index, 2, failed_jobs])
    return {"regions": regions, "categories": categories, "values": values}


def _latest_job_marker(connection) -> str:
    row = connection.execute(
        """
        SELECT MAX(COALESCE(finished_at, started_at, enqueued_at)) AS latest
        FROM crawl_jobs
        """
    ).fetchone()
    return str(row["latest"] or "") if row else ""


def _payload_cache_key(connection, namespace: str) -> str:
    cache_state = get_normalized_intelligence_cache_state(connection) or {}
    if namespace.startswith("intelligence:dashboard:"):
        vulnerability_state = connection.execute(
            "SELECT COUNT(*) AS count, MAX(last_seen_at) AS latest FROM vulnerability_records"
        ).fetchone()
        return json.dumps({
            "namespace": namespace,
            "source_signature": cache_state.get("source_signature") or "",
            "refreshed_at": cache_state.get("refreshed_at") or "",
            "event_count": int(cache_state.get("event_count") or 0),
            "vulnerabilities": dict(vulnerability_state) if vulnerability_state else {},
            "minute": int(datetime.now(timezone.utc).timestamp()) // 60,
        }, ensure_ascii=False, sort_keys=True)
    latest_jobs = _latest_job_marker(connection) if namespace == "intelligence" else ""
    document_state = {}
    if namespace in {"events", "intelligence"}:
        row = connection.execute(
            """
            SELECT COUNT(*) AS count, MAX(last_seen_at) AS latest,
                   SUM(risk_score) AS risk_total, SUM(evidence_count) AS evidence_total,
                   SUM(CASE WHEN review_status = 'new' THEN 1 ELSE 0 END) AS new_reviews,
                   SUM(CASE WHEN access_state = 'public' THEN 1 ELSE 0 END) AS public_hits
            FROM document_hits
            """
        ).fetchone()
        document_state = dict(row) if row else {}
    monitoring_state = connection.execute(
        """
        SELECT COUNT(*) AS count, MAX(updated_at) AS latest
        FROM monitoring_keywords
        """
    ).fetchone()
    monitoring_count = int(monitoring_state["count"]) if monitoring_state else 0
    monitoring_latest = str(monitoring_state["latest"] or "") if monitoring_state else ""
    payload = {
        "payload_cache_version": PAYLOAD_CACHE_VERSION,
        "namespace": namespace,
        "source_signature": cache_state.get("source_signature") or "",
        "refreshed_at": cache_state.get("refreshed_at") or "",
        "event_count": int(cache_state.get("event_count") or 0),
        "latest_jobs": latest_jobs,
        "monitoring_keyword_count": monitoring_count,
        "monitoring_keyword_latest": monitoring_latest,
        "document_state": document_state,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _get_cached_payload(namespace: str, cache_key: str) -> Any | None:
    with _PAYLOAD_CACHE_LOCK:
        entry = _PAYLOAD_CACHE.get(namespace)
        if entry and entry.get("key") == cache_key:
            _PAYLOAD_CACHE.move_to_end(namespace)
            return entry.get("payload")
    return None


def _set_cached_payload(namespace: str, cache_key: str, payload: Any) -> None:
    with _PAYLOAD_CACHE_LOCK:
        _PAYLOAD_CACHE[namespace] = {"key": cache_key, "payload": payload}
        _PAYLOAD_CACHE.move_to_end(namespace)
        while len(_PAYLOAD_CACHE) > _PAYLOAD_CACHE_LIMIT:
            _PAYLOAD_CACHE.popitem(last=False)


def _serialize_payload_build(function):
    @wraps(function)
    def build(*args, **kwargs):
        namespace = "intelligence"
        build_lock = _PAYLOAD_BUILD_LOCK
        if function.__name__ == "build_dashboard_payload":
            days = int(args[0] if args else kwargs.get("days", 7))
            namespace = f"intelligence:dashboard:{1 if days <= 1 else 30 if days >= 30 else 7}"
            build_lock = _DASHBOARD_BUILD_LOCK
        elif function.__name__ == "build_intelligence_page_payload":
            page = args[0] if args else kwargs.get("page")
            limit = args[1] if len(args) > 1 else kwargs.get("limit")
            if limit is None:
                limit = DATA_LEAK_EVENT_LIMIT if page == "data-leak" else RANSOMWARE_EVENT_LIMIT
            namespace = f"intelligence:{page}:{limit or 'all'}"
            if limit and 0 < int(limit) <= DATA_LEAK_EVENT_LIMIT:
                build_lock = _PAGE_BUILD_LOCK
        # Cached reads never queue behind another payload's cold build. Cold
        # unbounded payloads still share one lock to bound resident memory.
        with get_db_connection() as connection:
            cache_key = _payload_cache_key(connection, namespace)
            cached = _get_cached_payload(namespace, cache_key)
            if cached is not None:
                return _dashboard_live_payload(connection, cached) if namespace.startswith("intelligence:dashboard:") else cached
        with build_lock:
            return function(*args, **kwargs)

    return build


def _safe_pct(current: int, previous: int) -> int:
    if previous <= 0:
        return 100 if current > 0 else 0
    return round(((current - previous) / previous) * 100)


def _last_n_days(days: int) -> list[datetime]:
    today = datetime.now(timezone.utc).date()
    return [datetime.combine(today - timedelta(days=offset), datetime.min.time(), tzinfo=timezone.utc) for offset in range(days - 1, -1, -1)]


def _build_executive_trend(events: list[dict[str, Any]], days: int = 30) -> dict[str, list[Any]]:
    dates = _last_n_days(days)
    start = dates[0]
    total_counter: Counter[str] = Counter()
    high_counter: Counter[str] = Counter()
    for event in events:
        event_dt = _parse_dt(event.get("disclosure_time"))
        if event_dt is None or event_dt < start:
            continue
        key = event_dt.date().isoformat()
        total_counter[key] += 1
        if int(event.get("risk_score") or 0) >= 60:
            high_counter[key] += 1
    labels = [item.strftime("%m-%d") for item in dates]
    keys = [item.date().isoformat() for item in dates]
    return {
        "labels": labels,
        "total": [int(total_counter.get(key, 0)) for key in keys],
        "highRisk": [int(high_counter.get(key, 0)) for key in keys],
    }


def _build_executive_countries(events: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        country = (event.get("country") or "").strip()
        if not country or country == "未知":
            continue
        grouped.setdefault(country, []).append(event)
    rows: list[dict[str, Any]] = []
    for country, country_events in grouped.items():
        rows.append(
            {
                "name": country,
                "eventCount": len(country_events),
                "highRiskCount": sum(1 for item in country_events if int(item.get("risk_score") or 0) >= 60),
                "averageRiskScore": round(sum(int(item.get("risk_score") or 0) for item in country_events) / len(country_events)),
            }
        )
    rows.sort(key=lambda item: (item["eventCount"], item["highRiskCount"], item["averageRiskScore"]), reverse=True)
    return rows[:limit]


def _build_executive_priority_events(events: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        (
            item
            for item in events
            if (item.get("title") or "").strip() and len((item.get("title") or "").strip()) >= 4
        ),
        key=lambda item: (
            int(item.get("risk_score") or 0),
            _parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return [
        {
            "id": item["event_id"],
            "disclosureDate": _format_date(item.get("disclosure_time")),
            "title": build_display_title(item),
            "originalTitle": item.get("title") or "未命名事件",
            "attacker": item.get("attacker") or "未知",
            "country": item.get("country") or "未知",
            "industry": item.get("industry") or "未知",
            "riskScore": int(item.get("risk_score") or 0),
        }
        for item in ranked[:limit]
    ]


def _build_executive_priority_events(events: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        (
            item
            for item in events
            if (item.get("title") or "").strip() and len((item.get("title") or "").strip()) >= 4
        ),
        key=lambda item: (
            int(item.get("risk_score") or 0),
            _parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    rows = []
    for item in ranked[:limit]:
        list_item = normalized_event_to_list_item(item)
        rows.append(
            {
                "id": item["event_id"],
                "disclosureDate": list_item.get("disclosureDate") or list_item.get("updatedTime", "")[:10],
                "title": list_item.get("title") or build_display_title(item),
                "originalTitle": item.get("title") or "鏈懡鍚嶄簨浠?",
                "sourceSite": list_item.get("sourceSite") or _label_source(item.get("source_site_name")),
                "attacker": item.get("attacker") or "鏈煡",
                "country": list_item.get("country") or "鏈煡",
                "industry": list_item.get("industry") or "鏈煡",
                "riskScore": int(item.get("risk_score") or 0),
                "monitoringWeight": int(list_item.get("monitoringWeight") or 0),
                "monitoringMatches": list_item.get("monitoringMatches") or [],
                "hasSampleEvidence": bool(list_item.get("hasSampleEvidence")),
            }
        )
    return rows


def _build_executive_coverage(events: list[dict[str, Any]]) -> dict[str, int]:
    total = len(events) or 1
    return {
        "countryCoverageRate": round(sum(1 for item in events if (item.get("country") or "").strip() not in {"", "未知"}) / total * 100),
        "regionCoverageRate": round(sum(1 for item in events if (item.get("region") or "").strip() not in {"", "未知"}) / total * 100),
        "industryCoverageRate": round(sum(1 for item in events if (item.get("industry") or "").strip() not in {"", "未知"}) / total * 100),
    }


def _build_executive_cards(events: list[dict[str, Any]], countries: list[dict[str, Any]]) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=30)
    previous_start = now - timedelta(days=60)

    current_events = [item for item in events if (_parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc)) >= current_start]
    previous_events = [
        item
        for item in events
        if previous_start <= (_parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc)) < current_start
    ]
    current_high = [item for item in current_events if int(item.get("risk_score") or 0) >= 60]
    previous_high = [item for item in previous_events if int(item.get("risk_score") or 0) >= 60]
    top_country = countries[0] if countries else {"name": "未知", "eventCount": 0}
    return {
        "totalEvents30d": len(current_events),
        "totalEventsDeltaPct": _safe_pct(len(current_events), len(previous_events)),
        "highRisk30d": len(current_high),
        "highRiskDeltaPct": _safe_pct(len(current_high), len(previous_high)),
        "topCountry": top_country["name"],
        "topCountryEventCount": top_country["eventCount"],
    }


def _hydrate_payload_event(row: dict[str, Any]) -> dict[str, Any]:
    event = _hydrate_event_row(row)
    for key in ("event_metadata_json", "mirror_resources_json", "screenshot_resources_json", "risk_reasons_json"):
        event.pop(key, None)
    event["metadata"] = {sys.intern(key): value for key, value in event["metadata"].items()}
    return event


def _iter_payload_events(connection, *, preview_characters: int | None = 500,
                         event_type: str = "", limit: int | None = None,
                         report_time_since: str | None = None, summary_only: bool = False,
                         event_ids: list[str] | None = None) -> Iterator[dict[str, Any]]:
    options = {"preview_characters": preview_characters, "event_type": event_type,
               "limit": limit, "order_by": SEARCH_ORDER["latest"]}
    if report_time_since is not None:
        options["report_time_since"] = report_time_since
    if summary_only:
        options["summary_only"] = True
    if event_ids is not None:
        options["event_ids"] = event_ids
    rows = iter_normalized_intelligence_events(connection, **options)
    first = next(rows, None)
    if first is not None:
        yield _hydrate_payload_event(first)
    del first
    for row in rows:
        yield _hydrate_payload_event(row)


@_serialize_payload_build
def build_intelligence_page_payload(page: str, limit: int | None = None) -> dict[str, Any]:
    page_config = {
        "ransomware": ("ransomware", "ransomwareEvents", RANSOMWARE_EVENT_LIMIT),
        "data-leak": ("data_leak", "dataLeakEvents", DATA_LEAK_EVENT_LIMIT),
    }
    if page not in page_config:
        raise ValueError(f"unsupported intelligence page: {page}")

    event_type, payload_key, configured_limit = page_config[page]
    event_limit = limit if limit is not None else (configured_limit or None)
    namespace = f"intelligence:{page}:{event_limit or 'all'}"
    with get_db_connection() as connection:
        cache_key = _payload_cache_key(connection, namespace)
        cached_payload = _get_cached_payload(namespace, cache_key)
        if cached_payload is not None:
            return cached_payload
        source_events = list(_iter_payload_events(connection, event_type=event_type, limit=event_limit, summary_only=True))
        total_events = count_normalized_intelligence_events(connection, event_type)

    source_events.sort(
        key=lambda item: _parse_dt(
            str((item.get("metadata") or {}).get("updated_time") or item.get("disclosure_time") or "")
        )
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    source_events = _apply_event_limit(source_events, event_limit or 0)
    common_fields = (
        "id",
        "event_type",
        "normalized_event_type",
        "raw_source_type",
        "disclosureTimeRaw",
        "disclosureDate",
        "updatedTimeRaw",
        "title",
        "category",
        "victim",
        "attacker",
        "sourceSite",
        "industry",
    )
    page_fields = common_fields + (
        ("region", "country")
        if page == "ransomware"
        else ("confidenceScore",)
    )
    events = [
        {key: value for key in page_fields if (value := item.get(key)) is not None}
        for item in (normalized_event_to_list_item(source_event) for source_event in source_events)
    ]
    payload: dict[str, Any] = {payload_key: events, f"{payload_key}Total": total_events}
    if page == "ransomware":
        actors = Counter(item.get("attacker") or "未知" for item in events if item.get("attacker"))
        industries = Counter(item.get("industry") or "未知" for item in events if item.get("industry"))
        payload["ransomwareActorRanking"] = [
            {"name": name, "value": value} for name, value in actors.most_common(6)
        ]
        payload["ransomwareIndustryImpact"] = [
            {"name": name, "value": value} for name, value in industries.most_common(6)
        ]

    _set_cached_payload(namespace, cache_key, payload)
    return payload


def _dashboard_event_datetime(event: dict[str, Any]) -> datetime | None:
    metadata = event.get("metadata") or {}
    return _parse_dt(
        str(
            event.get("updatedTimeRaw")
            or metadata.get("updated_time")
            or event.get("disclosureTimeRaw")
            or event.get("disclosure_time")
            or ""
        )
    )


def _dashboard_is_high_risk(event: dict[str, Any]) -> bool:
    severity = str(event.get("severity") or "").lower()
    return severity in {"critical", "high"} or int(event.get("riskScore") or event.get("risk_score") or 0) >= 60


def _dashboard_daily_trend(
    events: list[dict[str, Any]],
    days: int,
    reference_time: datetime | None = None,
) -> list[int]:
    reference = (reference_time or datetime.now(timezone.utc)).astimezone(SHANGHAI_TZ)
    dates = [reference.date() - timedelta(days=offset) for offset in range(days - 1, -1, -1)]
    counters = {item.isoformat(): 0 for item in dates}
    for event in events:
        event_dt = _dashboard_event_datetime(event)
        if event_dt is None:
            continue
        key = event_dt.astimezone(SHANGHAI_TZ).date().isoformat()
        if key in counters:
            counters[key] += 1
    return [counters[item.isoformat()] for item in dates]


def _dashboard_priority_event(event: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "id",
        "event_type",
        "normalized_event_type",
        "raw_source_type",
        "disclosureTimeRaw",
        "disclosureDate",
        "updatedTimeRaw",
        "title",
        "summary",
        "category",
        "victim",
        "attacker",
        "industry",
        "country",
        "countryCode",
        "region",
        "severity",
        "riskScore",
        "priorityScore",
        "monitoringPriority",
        "monitoringWeight",
        "isExploited",
        "vendor",
        "product",
        "cveId",
    )
    payload = {key: event.get(key) for key in fields if event.get(key) is not None}
    if payload.get("summary"):
        payload["summary"] = str(payload["summary"])[:160]
    return payload


def _dashboard_live_payload(connection, payload: dict[str, Any]) -> dict[str, Any]:
    jobs = [dict(row) for row in connection.execute("""
        SELECT site_name, job_type, status, target, enqueued_at, started_at, finished_at, error_message
        FROM crawl_jobs ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC LIMIT 100
    """).fetchall()]
    latest = connection.execute(
        f"SELECT disclosure_time FROM normalized_intelligence_events ORDER BY {SEARCH_ORDER['latest']} LIMIT 1"
    ).fetchone()
    document_row = connection.execute("""
        SELECT COUNT(*) AS count FROM document_hits WHERE COALESCE(last_seen_at, first_seen_at) >= ?
    """, ((datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(),)).fetchone()
    return {
        **payload,
        "distribution24h": [*payload["distribution24h"][:3], int(document_row["count"] or 0) if document_row else 0],
        "monitoringStatus": _build_monitoring_status(
            [{"fetched_at": latest["disclosure_time"]}] if latest else [], jobs),
    }


def _dashboard_metric_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": event["event_id"], "_normalized": True,
        "updatedTimeRaw": event_report_time(event),
        "disclosureTimeRaw": event.get("disclosure_time") or "",
        "category": event.get("category"), "attacker": event.get("attacker"),
        "country": event.get("country"), "countryCode": event.get("country_code"),
        "region": event.get("region"), "industry": event.get("industry"),
        "severity": event.get("severity"), "riskScore": event.get("risk_score"),
    }


@_serialize_payload_build
def build_dashboard_payload(days: int = 7) -> dict[str, Any]:
    safe_days = 1 if int(days) <= 1 else 30 if int(days) >= 30 else 7
    namespace = f"intelligence:dashboard:{safe_days}"
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=safe_days)
    last_day_cutoff = now - timedelta(hours=24)
    minimum_time = datetime.min.replace(tzinfo=timezone.utc)
    trend, high_trend = Counter(), Counter()
    severity_totals = [0, 0, 0]
    high_count = pending_count = geo_count = geo_score = sequence = 0
    country_map: dict[str, dict[str, Any]] = {}
    industry_map: dict[str, dict[str, Any]] = {}
    priority: list[tuple[Any, ...]] = []

    def add_geo(item):
        nonlocal geo_count, geo_score
        code = str(item.get("countryCode") or "").upper()
        if not code:
            return
        score = int(item.get("riskScore") or 0)
        geo_count += 1
        geo_score += score
        name = item.get("country") if item.get("country") not in {"", "未知", None} else item.get("region")
        if not name or name == "未知":
            return
        current = country_map.setdefault(code, {"name": name, "code": code, "count": 0, "score": 0})
        current["count"] += 1
        current["score"] += score

    def keep_latest(heap, key, item, limit):
        entry = (*key, item)
        if len(heap) < limit:
            heapq.heappush(heap, entry)
        elif key > heap[0][:-1]:
            heapq.heapreplace(heap, entry)

    def add_period(item):
        nonlocal high_count, pending_count, sequence
        event_dt = _dashboard_event_datetime(item)
        day = event_dt.astimezone(SHANGHAI_TZ).date().isoformat() if event_dt else ""
        trend[day] += 1
        if _dashboard_is_high_risk(item):
            high_count += 1
            high_trend[day] += 1
        severity = str(item.get("severity") or "").lower()
        if severity in {"critical", "high", "medium", "low"}:
            severity_totals[0 if severity == "critical" else 1 if severity == "high" else 2] += 1
        pending_count += int(str(item.get("monitoringPriority") or "").lower() in {"critical", "high"}
                             or int(item.get("monitoringWeight") or 0) > 0)
        add_geo(item)
        name = item.get("industry")
        if name and name != "未知":
            current = industry_map.setdefault(str(name), {"name": str(name), "count": 0, "score": 0})
            current["count"] += 1
            current["score"] += int(item.get("riskScore") or 0)
        keep_latest(priority, (int(item.get("priorityScore") or item.get("riskScore") or 0),
                               event_dt or minimum_time, -sequence), item, 20)
        sequence += 1

    def daily(counter, reference=now):
        today = reference.astimezone(SHANGHAI_TZ).date()
        return [counter[(today - timedelta(days=offset)).isoformat()] for offset in range(safe_days - 1, -1, -1)]

    with get_db_connection() as connection:
        cache_key = _payload_cache_key(connection, namespace)
        cached_payload = _get_cached_payload(namespace, cache_key)
        if cached_payload is not None:
            return _dashboard_live_payload(connection, cached_payload)
    vulnerability_all = build_vulnerability_records(limit=VULNERABILITY_EVENT_LIMIT)
    with get_db_connection() as connection:
        type_stats = {}
        for kind in ("ransomware", "data_leak"):
            stats = {"count": 0, "days": Counter(), "ranking": Counter(), "actors": set(),
                     "latest": minimum_time, "last24": 0, "fallback": False}

            def add_ranking(item):
                value = item.get("attacker") if kind == "ransomware" else item.get("category") or "未知"
                if value:
                    stats["ranking"][value] += 1
                if item.get("attacker"):
                    stats["actors"].add(str(item["attacker"]).casefold())

            def add_source(item, event_dt):
                stats["count"] += 1
                if event_dt:
                    stats["days"][event_dt.astimezone(SHANGHAI_TZ).date().isoformat()] += 1
                    stats["latest"] = max(stats["latest"], event_dt)

            for event in _iter_payload_events(connection, event_type=kind, summary_only=True,
                                               report_time_since=cutoff.isoformat(timespec="microseconds")):
                event_dt = _dashboard_event_datetime(event)
                # report_time also repairs invalid source dates. Preserve the
                # dashboard's existing exclusion of an invalid updated_time.
                if event_dt is None or event_dt < cutoff:
                    continue
                add_source(event, event_dt)
                stats["last24"] += int(event_dt >= last_day_cutoff)
                metric = _dashboard_metric_event(event)
                add_ranking(metric)
                add_period(metric)
            if not stats["count"]:
                historical = []
                for index, event in enumerate(_iter_payload_events(connection, event_type=kind, summary_only=True)):
                    event_dt = _dashboard_event_datetime(event)
                    add_source(event, event_dt)
                    keep_latest(historical, (event_dt or minimum_time, -index), _dashboard_metric_event(event), 500)
                for entry in sorted(historical, reverse=True):
                    add_ranking(entry[-1])
                stats["fallback"] = bool(stats["count"])
            type_stats[kind] = stats

        vulnerability_period = [item for item in vulnerability_all
            if (_dashboard_event_datetime(item) or minimum_time) >= cutoff]
        for item in vulnerability_period:
            add_period(item)
        ranked = [entry[-1] for entry in sorted(priority, reverse=True)]
        event_ids = [item["id"] for item in ranked if item.get("_normalized")]
        previews = {event["event_id"]: normalized_event_to_list_item(event)
                    for event in _iter_payload_events(connection, event_ids=event_ids)} if event_ids else {}
        priority_events = [_dashboard_priority_event(previews[item["id"]] if item.get("_normalized") else item)
                           for item in ranked if not item.get("_normalized") or item["id"] in previews]

        map_fallback = not geo_count
        if map_fallback:
            for event in _iter_payload_events(connection, summary_only=True):
                add_geo(_dashboard_metric_event(event))
            for item in vulnerability_all:
                add_geo(item)
        map_fallback = map_fallback and bool(geo_count)

        leak, ransomware = type_stats["data_leak"], type_stats["ransomware"]
        exploited_count = sum(1 for item in vulnerability_period if item.get("isExploited"))
        countries = sorted(({**item, "value": item["count"], "risk": round(item["score"] / item["count"])}
                            for item in country_map.values()), key=lambda item: (-item["count"], -item["risk"]))[:6]
        industries = sorted(({**item, "value": round(item["score"] / item["count"])} for item in industry_map.values()),
                            key=lambda item: (-item["value"], -item["count"]))[:4]
        vulnerability_vendors = Counter(item.get("vendor") for item in vulnerability_period if item.get("vendor"))
        top_leak = leak["ranking"].most_common(1)
        payload = {
            "rangeDays": safe_days,
            "fallback": {"dataLeak": leak["fallback"], "ransomware": ransomware["fallback"], "geo": map_fallback},
            "kpis": [
                {"value": leak["count"], "highlight": f"累计 {leak['count']:,} 条" if leak["fallback"] else
                 (f"{top_leak[0][0]} {top_leak[0][1]:,} 条" if top_leak else "本期无新增"),
                 "trend": daily(leak["days"], leak["latest"] if leak["fallback"] and leak["latest"] != minimum_time else now)},
                {"value": ransomware["count"], "highlight": f"累计 {len(ransomware['actors']):,} 个团伙" if ransomware["fallback"] else f"{len(ransomware['actors']):,} 个活跃团伙",
                 "trend": daily(ransomware["days"], ransomware["latest"] if ransomware["fallback"] and ransomware["latest"] != minimum_time else now)},
                {"value": len(vulnerability_period), "highlight": f"{exploited_count:,} 项已利用", "trend": _dashboard_daily_trend(vulnerability_period, safe_days, now)},
                {"value": high_count, "highlight": f"{high_count:,} 条需优先研判", "trend": daily(high_trend)},
            ],
            "priorityEvents": priority_events,
            "geo": {"averageRisk": round(geo_score / geo_count) if geo_count else 0, "countries": countries},
            "industries": industries,
            "distribution24h": [ransomware["last24"], leak["last24"], sum(1 for item in vulnerability_all if (_dashboard_event_datetime(item) or minimum_time) >= last_day_cutoff), 0],
            "threatTrend": {"labels": [(now.astimezone(SHANGHAI_TZ).date() - timedelta(days=offset)).strftime("%m-%d") for offset in range(safe_days - 1, -1, -1)],
                            "total": daily(trend), "highRisk": daily(high_trend), "severityTotals": severity_totals},
            "statusCounts": [len(countries), len(industries), pending_count],
            "rankings": {
                "ransomwareActors": [{"name": name, "value": value} for name, value in ransomware["ranking"].most_common(6)],
                "sensitiveTypes": [{"name": name, "value": value} for name, value in leak["ranking"].most_common(6)],
                "vulnerabilityVendors": [{"name": name, "value": value} for name, value in vulnerability_vendors.most_common(6)],
            },
        }
        payload = _dashboard_live_payload(connection, payload)
    _set_cached_payload(namespace, cache_key, payload)
    return payload


@_serialize_payload_build
def build_intelligence_payload() -> dict[str, Any]:
    with get_db_connection() as connection:
        cache_key = _payload_cache_key(connection, "intelligence")
        cached_payload = _get_cached_payload("intelligence", cache_key)
        if cached_payload is not None:
            return cached_payload
        normalized_events, monitoring_payload = monitoring_rules_module.build_monitoring_payload(
            connection, _iter_payload_events(connection, preview_characters=None), retain_detail_text=False)
        vulnerability_items = [
            (_parse_dt(str(row.get("last_seen_at") or row.get("disclosure_time") or ""))
             or datetime.min.replace(tzinfo=timezone.utc),
             normalized_event_to_list_item(_materialize_vulnerability_event(row)))
            for row in iter_vulnerability_records(connection)
        ]
        crawl_jobs = [
            dict(row)
            for row in connection.execute(
                """
                SELECT site_name, job_type, status, target, enqueued_at, started_at, finished_at, error_message
                FROM crawl_jobs
                ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
                LIMIT 100
                """
            ).fetchall()
        ]

    def sort_by_disclosure(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return sorted(
            items,
            key=lambda item: _parse_dt(str((item.get("metadata") or {}).get("updated_time") or item.get("disclosure_time") or "")) or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )

    data_leak_source_events = sort_by_disclosure([item for item in normalized_events if item.get("event_type") == "data_leak"])
    ransomware_source_events = sort_by_disclosure([item for item in normalized_events if item.get("event_type") == "ransomware"])
    vulnerability_source_events = [item for _, item in sorted(vulnerability_items, key=lambda item: item[0], reverse=True)]
    document_exposure_events = build_document_exposure_event_records(limit=100)
    document_exposure_summary = build_document_exposure_summary()
    data_leak_events = [normalized_event_to_list_item(item) for item in data_leak_source_events[:DATA_LEAK_EVENT_LIMIT]]
    ransomware_events = [normalized_event_to_list_item(item) for item in _apply_event_limit(ransomware_source_events, RANSOMWARE_EVENT_LIMIT)]
    vulnerability_events = vulnerability_source_events[:VULNERABILITY_EVENT_LIMIT]
    forum_victims = [
        {
            "victim_name": item.get("victim"),
            "industry": item.get("industry"),
            "region": item.get("region"),
        }
        for item in data_leak_source_events
        if item.get("victim") and item.get("victim") != "未知实体"
    ]
    dashboard_summary, data_leak_summary, ransomware_summary = _build_summary_cards(
        data_leak_events, ransomware_events, crawl_jobs, forum_victims
    )
    vulnerability_summary = _build_vulnerability_summary(vulnerability_events)

    data_leak_counter = _count_by_day([row.get("disclosure_time") for row in data_leak_source_events])
    ransomware_counter = _count_by_day([row.get("disclosure_time") for row in ransomware_source_events])
    vulnerability_counter = _count_by_day([row.get("disclosureTimeRaw") for row in vulnerability_source_events])
    data_leak_series = _series_from_counter(data_leak_counter)
    ransomware_series = _series_from_counter(ransomware_counter)
    vulnerability_series = _series_from_counter(vulnerability_counter)
    threat_alert_series = {
        "labels": data_leak_series["labels"],
        "values": [
            int(data_leak_series["values"][index])
            + int(ransomware_series["values"][index])
            + int(vulnerability_series["values"][index])
            for index in range(len(data_leak_series["labels"]))
        ],
    }

    section_counts = Counter(row.get("category") or "unknown" for row in data_leak_events)
    failed_jobs = sum(
        1
        for site_name in sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
        if _latest_unresolved_problem_row([row for row in crawl_jobs if row.get("site_name") == site_name]) is not None
    )
    attack_type_share = [
        {"name": "数据泄露", "value": len(data_leak_events)},
        {"name": "勒索情报", "value": len(ransomware_events)},
        {"name": "漏洞预警", "value": len(vulnerability_events)},
        {"name": "文件监测", "value": len(document_exposure_events)},
        {
            "name": "失败任务",
            "value": failed_jobs,
        },
    ]
    data_leak_keyword_counts = Counter(item.get("category") or "其他" for item in data_leak_events)
    top_industries = Counter(item.get("industry") or "未知" for item in data_leak_source_events if item.get("industry"))
    top_regions = Counter(
        item.get("region") or "未知"
        for item in data_leak_source_events + ransomware_source_events
        if item.get("region")
    )
    top_ransomware_actors = Counter(item.get("attacker") or "未知" for item in ransomware_events if item.get("attacker"))
    top_ransomware_industries = Counter(item.get("industry") or "未知" for item in ransomware_source_events if item.get("industry"))
    vulnerability_vendor_ranking = _build_vulnerability_rankings(vulnerability_events, "vendor")
    vulnerability_product_ranking = _build_vulnerability_rankings(vulnerability_events, "product")
    threat_level_trend = {
        "labels": data_leak_series["labels"],
        "high": ransomware_series["values"],
        "medium": data_leak_series["values"],
        "low": threat_alert_series["values"],
    }
    executive_behavior_events = [item for item in normalized_events if item.get("event_type") != "vulnerability"]
    executive_countries = _build_executive_countries(executive_behavior_events)
    executive_cards = _build_executive_cards(executive_behavior_events, executive_countries)
    executive_trend = _build_executive_trend(normalized_events)
    executive_priority_events = _build_executive_priority_events(normalized_events)
    executive_coverage = _build_executive_coverage(normalized_events)
    preview_cards = _build_preview_cards(data_leak_events, ransomware_events, crawl_jobs, {})
    preview_cards.insert(
        2,
        {
            "route": "/document-exposure",
            "eyebrow": "模块预览",
            "title": "文件监测",
            "summary": "集中查看文档平台与网盘聚合中的疑似企业文件暴露线索。",
            "highlight": f"{document_exposure_summary['highRiskCount']} 条高风险命中",
            "tone": "warning",
            "stats": [
                {"label": "命中数", "value": str(document_exposure_summary["totalHits"])},
                {"label": "高风险", "value": str(document_exposure_summary["highRiskCount"])},
                {"label": "平台数", "value": str(document_exposure_summary["platformCount"])},
            ],
        },
    )
    preview_cards.insert(
        3,
        {
            "route": "/vulnerability-alerts",
            "eyebrow": "模块预览",
            "title": "漏洞预警",
            "summary": "聚合公开源高危漏洞、利用状态与受影响厂商/产品，适合演示应急研判入口。",
            "highlight": f"{sum(1 for item in vulnerability_events if item.get('isExploited'))} 条已被利用",
            "tone": "danger",
            "stats": [
                {"label": "漏洞数", "value": str(len(vulnerability_events))},
                {"label": "厂商数", "value": str(len(vulnerability_vendor_ranking))},
                {"label": "已利用", "value": str(sum(1 for item in vulnerability_events if item.get('isExploited')))},
            ],
        },
    )
    dashboard_watchlist = _build_vulnerability_watchlist(vulnerability_events, limit=2) + _build_watchlist(crawl_jobs, section_counts)
    timeline = _build_vulnerability_timeline(vulnerability_events, limit=2) + _build_recent_timeline(data_leak_events, ransomware_events, crawl_jobs)
    situation_alerts = _build_vulnerability_alert_stream(vulnerability_events, limit=4) + _build_situation_alerts(crawl_jobs)
    dashboard_summary_cards = dashboard_summary + vulnerability_summary[:1]

    payload = {
        "monitoringStatus": _build_monitoring_status(
            [{"fetched_at": item.get("disclosure_time")} for item in normalized_events],
            crawl_jobs,
        ),
        "dashboardSummaryCards": dashboard_summary_cards,
        "modulePreviewCards": preview_cards,
        "dashboardTrendSeries": {
            "labels": data_leak_series["labels"],
            "ransomware": ransomware_series["values"],
            "dataLeak": data_leak_series["values"],
            "vulnerability": vulnerability_series["values"],
            "threatAlerts": threat_alert_series["values"],
        },
        "dashboardCountryFocus": _build_country_focus(forum_victims),
        "crossModuleTimeline": timeline[:8],
        "dashboardWatchlist": dashboard_watchlist[:4],
        "ransomwareSummary": ransomware_summary,
        "ransomwareEvents": ransomware_events,
        "documentExposureSummary": [
            {
                "label": "监测命中",
                "value": str(document_exposure_summary["totalHits"]),
                "description": "来自文档平台与网盘聚合的疑似暴露文件数量。",
                "trend": f"{document_exposure_summary['highRiskCount']} 条高风险",
                "tone": "warning",
                "icon": "Files",
            },
            {
                "label": "待复核",
                "value": str(document_exposure_summary["pendingReviewCount"]),
                "description": "当前仍需人工核验或待进一步确认的命中记录。",
                "trend": f"{document_exposure_summary['loginRequiredCount']} 条需登录复核",
                "tone": "primary",
                "icon": "Document",
            },
            {
                "label": "会话状态",
                "value": str(document_exposure_summary["configuredSessionCount"]),
                "description": "已配置平台会话数量。",
                "trend": f"{document_exposure_summary['invalidSessionCount']} 个异常",
                "tone": "primary",
                "icon": "Lock",
            },
        ],
        "documentExposureEvents": document_exposure_events,
        "dataLeakSummary": data_leak_summary,
        "dataLeakEvents": data_leak_events,
        "vulnerabilitySummary": vulnerability_summary,
        "vulnerabilityEvents": vulnerability_events,
        "vulnerabilityTrend": vulnerability_series,
        "vulnerabilityVendorRanking": vulnerability_vendor_ranking,
        "vulnerabilityProductRanking": vulnerability_product_ranking,
        "threatSituationSummary": {
            "title": "基于标准化情报事件的威胁态势总览",
            "description": "从数据泄露、勒索情报、公开源漏洞和爬虫任务日志中聚合生成当前态势视图。",
            "stats": [
                {"label": "泄露事件", "value": str(len(data_leak_events))},
                {"label": "勒索受害者", "value": str(len(ransomware_events))},
                {"label": "漏洞预警", "value": str(len(vulnerability_events))},
                {"label": "失败任务", "value": str(failed_jobs)},
            ],
        },
        "attackTypeShare": attack_type_share,
        "dataLeakEventTrend": data_leak_series,
        "dataLeakRanking": [
            {"name": name, "value": value}
            for name, value in (top_industries.most_common(5) or section_counts.most_common(5))
        ],
        "regionalThreatComparison": [{"name": name, "value": value} for name, value in top_regions.most_common(6)],
        "ransomwareActorRanking": [{"name": name, "value": value} for name, value in top_ransomware_actors.most_common(6)],
        "ransomwareIndustryImpact": [{"name": name, "value": value} for name, value in top_ransomware_industries.most_common(6)],
        "ransomwareTrend": ransomware_series,
        "sensitiveTypeShare": [{"name": name, "value": value} for name, value in data_leak_keyword_counts.most_common(5)],
        "situationAlerts": situation_alerts[:12],
        "threatHeatmap": _build_threat_heatmap(data_leak_events, ransomware_events, crawl_jobs),
        "threatLevelTrend": threat_level_trend,
        "threatExecutiveCards": executive_cards,
        "threatExecutiveTrend": executive_trend,
        "threatExecutiveCountries": executive_countries,
        "threatExecutivePriorityEvents": executive_priority_events,
        "threatExecutiveCoverage": executive_coverage,
        "routeHeaderMeta": {
            "/": {
                "kicker": "Threat Overview",
                "subtitle": "聚合暗网、公开源漏洞、勒索情报与文件监测线索。",
            },
            "/document-exposure": {
                "kicker": "文件监测",
                "subtitle": "文件监测总览，仅展示监测配置、扫描执行与命中结果三个子模块入口。",
            },
            "/document-exposure/settings": {
                "kicker": "文件监测",
                "subtitle": "统一管理平台会话、监测对象、关键词、来源家族、文件类型与启停状态。",
            },
            "/document-exposure/scans": {
                "kicker": "文件监测",
                "subtitle": "执行文件监测扫描任务并查看最近扫描历史、候选数、命中数和错误数。",
            },
            "/document-exposure/results": {
                "kicker": "文件监测",
                "subtitle": "筛选和复核文档平台与网盘聚合中的疑似文件暴露命中。",
            },
            "/collector-control": {
                "kicker": "Collection Control",
                "subtitle": "统一触发采集任务、同步接口与运行状态查看。",
            },
        },
        **monitoring_payload,
    }
    _set_cached_payload("intelligence", cache_key, payload)
    return payload


def warm_api_payloads() -> None:
    # Warm published views; background publication owns source processing.
    build_intelligence_page_payload("ransomware", limit=500)
    build_intelligence_page_payload("data-leak", limit=500)
    build_dashboard_payload()


def _runtime_db_status() -> dict[str, Any]:
    runtime_db_path = default_db_path()
    source_db_path = Path(os.environ.get("DARKWEB_COLLECTOR_SOURCE_DB_PATH", project_root() / "data" / "collector.db")).expanduser()
    meta_path = Path(os.environ.get("DARKWEB_RUNTIME_DB_META_PATH", f"{runtime_db_path}.meta.json")).expanduser()
    active = active_release_config()
    if active.get("database_engine") == "postgresql":
        schema = str(active.get("database_schema") or "").strip()
        return {
            "database_engine": "postgresql",
            "runtime_db_path": f"PostgreSQL / {schema}" if schema else "PostgreSQL",
            "source_db_path": str(source_db_path),
            "using_runtime_db": True,
            "runtime_db_exists": True,
            "source_db_exists": source_db_path.exists(),
            "runtime_db_updated_at": active.get("activated_at") or "",
            "runtime_db_size_mb": 0,
            "meta_exists": True,
            "prepared_at": active.get("activated_at") or "",
            "copied_counts": {},
            "skipped_tables": {},
            "migration_job_id": active.get("job_id") or "",
        }

    runtime_exists = runtime_db_path.exists()
    source_exists = source_db_path.exists()
    status = {
        "database_engine": "sqlite",
        "runtime_db_path": str(runtime_db_path),
        "source_db_path": str(source_db_path),
        "using_runtime_db": runtime_db_path.resolve() != source_db_path.resolve() if runtime_exists and source_exists else str(runtime_db_path) != str(source_db_path),
        "runtime_db_exists": runtime_exists,
        "source_db_exists": source_exists,
        "runtime_db_updated_at": _format_dt(datetime.fromtimestamp(runtime_db_path.stat().st_mtime, tz=timezone.utc).isoformat()) if runtime_exists else "",
        "runtime_db_size_mb": round(runtime_db_path.stat().st_size / 1024 / 1024, 2) if runtime_exists else 0,
        "meta_exists": meta_path.exists(),
        "prepared_at": "",
        "copied_counts": {},
        "skipped_tables": {},
    }
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
        status["prepared_at"] = _format_dt(meta.get("prepared_at"))
        status["copied_counts"] = meta.get("copied_counts") or {}
        status["skipped_tables"] = meta.get("skipped_tables") or {}
    return status


def build_failed_jobs_payload(page: int = 1, page_size: int = FAILED_JOB_HISTORY_LIMIT, query: str = "", site: str = "") -> dict[str, Any]:
    page = max(1, int(page))
    page_size = min(100, max(1, int(page_size)))
    cutoff = (_now_utc() - timedelta(days=FAILED_JOB_HISTORY_DAYS)).isoformat()
    try:
        configs = load_site_configs()
        config_map = {config.site_name: config for config in configs}
    except Exception:
        config_map = {}
    clauses = ["status = 'failed'", "COALESCE(finished_at, started_at, enqueued_at) >= ?"]
    params: list[Any] = [cutoff]
    if site.strip():
        clauses.append("site_name = ?")
        params.append(site.strip())
    if query.strip():
        # Match literal text, including SQL wildcard characters, across all pages.
        escaped = query.strip().lower().replace("!", "!!").replace("%", "!%").replace("_", "!_")
        pattern = f"%{escaped}%"
        fields = ("site_name", "job_id", "job_type", "queue_name", "target", "error_message")
        search = [f"LOWER(COALESCE({field}, '')) LIKE ? ESCAPE '!'" for field in fields]
        params.extend([pattern] * len(fields))
        aliases = [name for name, config in config_map.items() if query.strip().lower() in site_display_name(config).lower()]
        if aliases:
            search.append("site_name IN (" + ",".join("?" for _ in aliases) + ")")
            params.extend(aliases)
        clauses.append("(" + " OR ".join(search) + ")")
    where = " AND ".join(clauses)
    with get_db_connection() as connection:
        total = int(connection.execute(f"SELECT COUNT(*) FROM crawl_jobs WHERE {where}", tuple(params)).fetchone()[0])
        page = min(page, max(1, (total + page_size - 1) // page_size))
        failed_job_rows = [dict(row) for row in connection.execute(
            f"""SELECT job_id, site_name, job_type, queue_name, target, status,
                       enqueued_at, started_at, finished_at, duration_ms, error_message
                FROM crawl_jobs WHERE {where}
                ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC, job_id DESC
                LIMIT ? OFFSET ?""", tuple(params) + (page_size, (page - 1) * page_size)
        ).fetchall()]
    items = [
        {
            "job_id": row.get("job_id"),
            "site_name": row.get("site_name"),
            "display_name": (
                site_display_name(config_map[row["site_name"]])
                if row.get("site_name") in config_map
                else row.get("site_name")
            ),
            "job_type": row.get("job_type"),
            "queue_name": row.get("queue_name"),
            "target": row.get("target"),
            "status": "failed",
            "enqueued_at": _format_dt(row.get("enqueued_at")),
            "started_at": _format_dt(row.get("started_at")),
            "finished_at": _format_dt(row.get("finished_at") or row.get("started_at")),
            "duration_ms": row.get("duration_ms"),
            "error_message": row.get("error_message") or "",
            "error_category": classify_error(row.get("error_message") or ""),
        }
        for row in failed_job_rows
    ]
    return {
        "failed_job_history": items,
        "failed_job_history_total": total,
        "failed_job_history_limit": page_size,
        "page": page,
        "page_size": page_size,
        "days": FAILED_JOB_HISTORY_DAYS,
    }


def build_jobs_payload() -> dict[str, Any]:
    failure_cutoff = _now_utc() - timedelta(hours=RECENT_FAILURE_WINDOW_HOURS)
    with get_db_connection() as connection:
        detail_yield = [dict(row) for row in connection.execute(
            """SELECT site_name, COUNT(*) AS completed_jobs, SUM(new_count) AS new_count,
                      SUM(updated_count) AS updated_count, SUM(unchanged_count) AS unchanged_count,
                      SUM(CASE WHEN outcome = 'partial' THEN 1 ELSE 0 END) AS artifacts_pending_jobs
               FROM crawl_detail_results WHERE finished_at >= ? GROUP BY site_name""",
            (failure_cutoff.timestamp(),),
        ).fetchall()]
        crawl_jobs = [
            dict(row)
            for row in connection.execute(
                """
                SELECT site_name, job_type, status, queue_name, target, enqueued_at, started_at, finished_at, error_message
                FROM crawl_jobs
                ORDER BY COALESCE(finished_at, started_at, enqueued_at) DESC
                LIMIT 1000
                """
            ).fetchall()
        ]
        forum_detail_counts = {
            row["site_name"]: int(row["count"])
            for row in connection.execute(
                "SELECT site_name, COUNT(*) AS count FROM forum_details GROUP BY site_name"
            ).fetchall()
        }
        victim_counts = {
            row["site_name"]: int(row["count"])
            for row in connection.execute(
                "SELECT site_name, COUNT(*) AS count FROM victims GROUP BY site_name"
            ).fetchall()
        }
        failure_counts_24h = {
            row["site_name"]: int(row["count"])
            for row in connection.execute(
                """
                SELECT site_name, COUNT(*) AS count
                FROM crawl_jobs
                WHERE status = 'failed'
                  AND COALESCE(finished_at, started_at, enqueued_at) >= ?
                GROUP BY site_name
                """,
                (failure_cutoff.isoformat(),),
            ).fetchall()
        }
        vulnerability_count_row = connection.execute(
            "SELECT COUNT(*) AS count, MAX(disclosure_time) AS latest_disclosure_time FROM vulnerability_records"
        ).fetchone()
        connectivity_probe_map = get_site_connectivity_probe_map(connection)
        try:
            frontier_count_map = frontier_counts(connection)
            frontier_cursor_map = list_page_cursors(connection)
        except Exception as exc:
            missing_frontier_table = (
                isinstance(exc, sqlite3.OperationalError) and "no such table:" in str(exc)
                or getattr(exc, "pgcode", None) == "42P01"
            ) and any(name in str(exc) for name in ("crawl_frontier", "crawl_page_cursors"))
            if not missing_frontier_table:
                raise
            connection.rollback()
            frontier_count_map = {}
            frontier_cursor_map = {}

    from darkweb_collector.api_actions import (
        get_browser_runtime_status,
        get_ransomware_sync_status,
        get_vulnerability_sync_status,
    )

    try:
        configured_configs = load_site_configs()
        configured_sites = [config.site_name for config in configured_configs]
        enabled_map = {config.site_name: config.enabled for config in configured_configs}
        config_map = {config.site_name: config for config in configured_configs}
    except Exception:
        configured_sites = sorted({row.get("site_name") for row in crawl_jobs if row.get("site_name")})
        enabled_map = {site_name: True for site_name in configured_sites}
        config_map = {}

    running_jobs = sum(1 for row in crawl_jobs if _effective_job_status(row) == "running")
    stale_jobs = sum(
        1
        for row in crawl_jobs
        if _effective_job_status(row) == "stale" and not row.get("finished_at")
    )

    worker_errors = queue_health_errors()
    site_health = []
    unresolved_problem_rows: list[dict[str, Any]] = []
    for site_name in configured_sites:
        site_rows = [row for row in crawl_jobs if row.get("site_name") == site_name]
        seed_rows = [row for row in site_rows if row.get("job_type") == "seed"]
        latest_seed = next(
            (
                row
                for row in site_rows
                if row.get("job_type") == "seed" and _effective_job_status(row) != "stale"
            ),
            None,
        )
        latest_detail = next(
            (
                row
                for row in site_rows
                if row.get("job_type") == "detail" and _effective_job_status(row) != "stale"
            ),
            None,
        )
        latest_success = next((row for row in site_rows if row.get("status") == "succeeded"), None)
        latest_unresolved_problem = _latest_unresolved_problem_row(site_rows)
        if latest_unresolved_problem is not None:
            unresolved_problem_rows.append(latest_unresolved_problem)
        error_category = classify_error(
            latest_unresolved_problem.get("error_message") if latest_unresolved_problem else ""
        )
        config = config_map.get(site_name)
        dependency_errors = {}
        if config is not None and config.enabled:
            for queue_name in (queue_for_seed(config), queue_for_detail(config)):
                if queue_name in worker_errors:
                    dependency_errors[queue_name] = worker_errors[queue_name]
        worker_error = "；".join(dict.fromkeys(dependency_errors.values()))
        auth = site_auth_readiness(config) if config is not None else {
            "auth_required": False,
            "auth_status": "not_required",
            "auth_platform": "",
            "auth_message": "",
        }
        auth_required = bool(auth["auth_required"])
        auth_waiting = auth["auth_status"] in {"missing", "login_in_progress", "login_required"}
        failure_count = consecutive_failures(seed_rows)
        threshold = failure_threshold(config) if config is not None else 3
        cooldown_until_dt = failure_cooldown_until(config, seed_rows) if config is not None else None
        circuit_breaker_open = cooldown_until_dt is not None and _now_utc() < cooldown_until_dt
        active_cooldown_until_dt = cooldown_until_dt if circuit_breaker_open else None
        active_running = sum(1 for row in site_rows if _effective_job_status(row) == "running")
        active_enqueued = sum(1 for row in site_rows if _effective_job_status(row) == "enqueued")
        failed_jobs_24h = failure_counts_24h.get(site_name, 0)
        connectivity_probe = connectivity_probe_map.get(site_name) or {}
        frontier = frontier_count_map.get(site_name) or {}
        frontier_enabled = bool(getattr(ADAPTERS.get(site_name), "supports_frontier", False))
        frontier_pending = int(frontier.get("pending", 0))
        frontier_inflight = int(frontier.get("inflight", 0))

        latest_seed_dt = _job_event_dt(latest_seed)
        latest_detail_dt = _job_event_dt(latest_detail)
        effective_seed_status = _effective_job_status(latest_seed) if latest_seed else ""
        if (
            effective_seed_status == "stale"
            and latest_seed
            and latest_seed.get("status") == "enqueued"
            and any(
                row.get("queue_name") == latest_seed.get("queue_name")
                and row.get("status") == "running"
                and not row.get("finished_at")
                for row in crawl_jobs
            )
        ):
            effective_seed_status = "enqueued"
        seed_age_minutes = None
        if latest_seed_dt is not None:
            seed_age_minutes = max(0, round((_now_utc() - latest_seed_dt).total_seconds() / 60))
        detail_status = _label_job_status(_effective_job_status(latest_detail)) if latest_detail else "未运行"
        if (
            latest_detail
            and _effective_job_status(latest_detail) in {"failed", "stale"}
            and latest_seed is not None
            and latest_seed.get("status") == "succeeded"
            and latest_seed_dt is not None
            and latest_detail_dt is not None
            and latest_seed_dt > latest_detail_dt
            and latest_unresolved_problem is None
        ):
            detail_status = "未更新"

        site_health.append(
            {
                "site_name": site_name,
                "display_name": site_display_name(config) if config is not None else site_name,
                "enabled": enabled_map.get(site_name, True),
                "seed_urls": list(config.seed_urls) if config is not None else [],
                "seed_fetch_mode": config.seed_fetch_mode if config is not None else "",
                "detail_fetch_mode": config.detail_fetch_mode if config is not None else "",
                "profile": config.profile if config is not None else "",
                "connectivity_available": connectivity_probe.get("available"),
                "connectivity_checked_at": _format_dt(connectivity_probe.get("checked_at")),
                "connectivity_last_success_at": _format_dt(connectivity_probe.get("last_success_at")),
                "connectivity_failure_reason": connectivity_probe.get("failure_reason") or "",
                "connectivity_error": connectivity_probe.get("error") or "",
                "overall_status": (
                    "异常"
                    if worker_error
                    else "待登录"
                    if auth_required and auth_waiting
                    else "会话失效"
                    if auth_required
                    else "异常"
                    if latest_unresolved_problem
                    else "运行中"
                    if active_running
                    else "等待中"
                    if active_enqueued
                    else "正常"
                    if latest_success
                    else "未运行"
                ),
                "seed_status": _label_job_status(_effective_job_status(latest_seed)) if latest_seed else "未运行",
                "detail_status": detail_status,
                "running_jobs": active_running,
                "enqueued_jobs": active_enqueued,
                "frontier": {
                    "enabled": frontier_enabled,
                    "pending": frontier_pending,
                    "inflight": frontier_inflight,
                    "completed": int(frontier.get("completed", 0)),
                    "artifacts_pending": int(frontier.get("artifacts_pending", 0)),
                    "backfill_paused": frontier_enabled and frontier_pending + frontier_inflight >= (
                        config.frontier_max_pending if config is not None else 500
                    ),
                    "backfill_pages_per_run": config.backfill_pages_per_run if config is not None else 5,
                    "page_cursors": frontier_cursor_map.get(site_name) or [],
                },
                "failed_jobs_24h": failed_jobs_24h,
                "last_success_at": _format_dt(latest_success.get("finished_at") if latest_success else None),
                "last_error": (
                    worker_error or (latest_unresolved_problem.get("error_message") if latest_unresolved_problem else "")
                ),
                "worker_error": worker_error,
                "queue_errors": dependency_errors,
                "auth_required": auth_required,
                "auth_status": auth["auth_status"],
                "auth_platform": auth["auth_platform"],
                "auth_message": auth["auth_message"],
                "error_category": error_category,
                "forum_details_count": forum_detail_counts.get(site_name, 0),
                "victims_count": victim_counts.get(site_name, 0),
                "consecutive_failures": failure_count,
                "failure_threshold": threshold,
                "circuit_breaker_open": circuit_breaker_open,
                "failure_cooldown_until": _format_dt(active_cooldown_until_dt.isoformat()) if active_cooldown_until_dt else "",
                "failure_cooldown_until_raw": active_cooldown_until_dt.isoformat() if active_cooldown_until_dt else "",
                "activeSeedJobStatus": effective_seed_status or "",
                "staleSeedDetected": effective_seed_status == "stale",
                "latestSeedJobAgeMinutes": seed_age_minutes,
                "blockingReason": (
                    "worker_unavailable"
                    if worker_error
                    else "auth_required"
                    if auth_required
                    else "failure_cooldown"
                    if circuit_breaker_open
                    else ("active_seed_job" if effective_seed_status in {"running", "enqueued"} else "")
                ),
            }
        )

    unresolved_problem_rows.sort(
        key=lambda row: _job_event_dt(row) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    recent_failures = [
        {
            "site_name": row.get("site_name"),
            "job_type": row.get("job_type"),
            "status": _label_job_status(_effective_job_status(row)),
            "target": row.get("target"),
            "error_message": row.get("error_message") or "",
            "error_category": classify_error(row.get("error_message") or ""),
            "finished_at": _format_dt(row.get("finished_at") or row.get("started_at")),
        }
        for row in unresolved_problem_rows[:20]
    ]
    failed_jobs_24h = sum(failure_counts_24h.values())

    overall_status = "部分失败" if any(item["worker_error"] for item in site_health) else "采集中" if running_jobs > 0 else "部分失败" if recent_failures or stale_jobs > 0 else "正常"
    vulnerability_sync = {
        **get_vulnerability_sync_status(),
        "record_count": int(vulnerability_count_row["count"]) if vulnerability_count_row else 0,
        "latest_disclosure_time": _format_dt(vulnerability_count_row["latest_disclosure_time"]) if vulnerability_count_row else "",
    }
    for key in ("started_at", "last_tick_at", "last_success_at"):
        vulnerability_sync[key] = _format_dt(vulnerability_sync.get(key))
    ransomware_sync = get_ransomware_sync_status()
    for key in ("started_at", "last_tick_at", "last_success_at"):
        ransomware_sync[key] = _format_dt(ransomware_sync.get(key))
    ransomware_sync["latest_disclosure_time"] = _format_dt(ransomware_sync.get("latest_disclosure_time"))
    return {
        "overall_status": overall_status,
        "running_jobs": running_jobs,
        "stale_jobs": stale_jobs,
        "failed_jobs_24h": failed_jobs_24h,
        "detail_yield_24h": {"unit": "raw_detail_records", "by_site": detail_yield},
        "recent_failures": recent_failures,
        **build_failed_jobs_payload(),
        "site_health": site_health,
        "browser_runtime": get_browser_runtime_status(),
        "normalization_runtime": get_normalization_runtime_status(),
        "vulnerability_sync": vulnerability_sync,
        "ransomware_sync": ransomware_sync,
        "runtime_db": _runtime_db_status(),
        "updated_at": _format_dt(_now_utc().isoformat()),
    }
