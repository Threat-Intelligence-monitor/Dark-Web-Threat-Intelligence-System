from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sized
from datetime import datetime, timezone
from hashlib import sha1
import json
import logging
import re
import sys
from threading import Lock
from typing import Any

from darkweb_collector.db import (
    get_db_connection,
    get_normalized_intelligence_cache_state,
    iter_normalized_intelligence_events,
    list_monitoring_keywords,
    replace_monitoring_keywords,
)
from darkweb_collector.normalized_intelligence import _hydrate_event_row, ensure_normalized_intelligence
from darkweb_collector.search_schema import SEARCH_ORDER
from darkweb_collector.utils import utc_now_iso


logger = logging.getLogger(__name__)
DEFAULT_MONITORING_KEYWORDS = [
    {"keyword": "中国", "category": "geo_keywords", "weight": 10, "enabled": True, "match_mode": "contains"},
    {"keyword": "china", "category": "geo_keywords", "weight": 8, "enabled": True, "match_mode": "word_boundary"},
    {"keyword": "政府", "category": "org_keywords", "weight": 12, "enabled": True, "match_mode": "contains"},
    {"keyword": "government", "category": "org_keywords", "weight": 10, "enabled": True, "match_mode": "word_boundary"},
    {"keyword": "能源", "category": "org_keywords", "weight": 10, "enabled": True, "match_mode": "contains"},
    {"keyword": "energy", "category": "org_keywords", "weight": 8, "enabled": True, "match_mode": "word_boundary"},
]
SAMPLE_HINT_WORDS = ("sample", "samples", "proof", "mirror", "preview", "demo", "file", "files", "paste", "download", "link")
URL_RE = re.compile(r"https?://[^\s'\"<>)]+", re.IGNORECASE)
SAMPLE_PREFIX_RE = re.compile(
    r"(?P<label>sample|samples|proof|mirror|preview|demo|file|files|paste|download|link)\s*[:=]\s*(?P<url>https?://[^\s'\"<>)]+)",
    re.IGNORECASE,
)
ASSET_PATTERNS = {
    "凭证": (r"\bcredential\b", r"\baccount\b", r"\bpassword\b", r"\bcookie\b", r"\bmfa\b", "凭证", "账号", "密码"),
    "KYC/PII": (r"\bkyc\b", r"\bpassport\b", r"\bssn\b", r"\bphone\b", r"\bemail\b", "身份证", "护照", "手机号"),
    "数据库": (r"\bdatabase\b", r"\bdump\b", r"\brecords\b", r"\bsql\b", "数据库", "数据表"),
    "源码": (r"\bsource code\b", r"\brepository\b", r"\bgithub\b", r"\bgitlab\b", "源码"),
    "金融数据": (r"\bbank\b", r"\bcredit\b", r"\bbanking\b", r"\bfinance\b", "金融", "银行卡"),
}

_MONITORING_CACHE_LOCK = Lock()
_MONITORING_CACHE_KEY = ""
_MONITORING_CACHE_PAYLOAD: dict[str, Any] = {}


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _event_text(event: dict[str, Any]) -> str:
    parts = [
        event.get("title"),
        event.get("original_title"),
        event.get("detail_text"),
        event.get("victim"),
        event.get("attacker"),
        event.get("industry"),
        event.get("region"),
        event.get("country"),
    ]
    return "\n".join(_normalize_text(item) for item in parts if _normalize_text(item))


def _seed_keywords(connection) -> list[dict[str, Any]]:
    current = list_monitoring_keywords(connection)
    if current:
        return current
    rows = [{**item, "updated_at": utc_now_iso()} for item in DEFAULT_MONITORING_KEYWORDS]
    replace_monitoring_keywords(connection, rows)
    connection.commit()
    return list_monitoring_keywords(connection)


def get_monitoring_keywords() -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        return _seed_keywords(connection)


def save_monitoring_keywords(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_rows = []
    for row in rows:
        keyword = _normalize_text(row.get("keyword"))
        if not keyword:
            continue
        normalized_rows.append(
            {
                "keyword": keyword,
                "category": _normalize_text(row.get("category")) or "custom_keywords",
                "weight": int(row.get("weight") or 0),
                "enabled": bool(row.get("enabled", True)),
                "match_mode": _normalize_text(row.get("match_mode")) or "contains",
                "updated_at": utc_now_iso(),
            }
        )
    with get_db_connection() as connection:
        replace_monitoring_keywords(connection, normalized_rows)
        connection.commit()
        _invalidate_monitoring_cache()
        return list_monitoring_keywords(connection)


def _invalidate_monitoring_cache() -> None:
    global _MONITORING_CACHE_KEY, _MONITORING_CACHE_PAYLOAD
    with _MONITORING_CACHE_LOCK:
        _MONITORING_CACHE_KEY = ""
        _MONITORING_CACHE_PAYLOAD = {}


def _keywords_cache_key(keywords: list[dict[str, Any]]) -> str:
    rows = [
        {
            "keyword": _normalize_text(item.get("keyword")),
            "category": _normalize_text(item.get("category")),
            "weight": int(item.get("weight") or 0),
            "enabled": bool(item.get("enabled")),
            "match_mode": _normalize_text(item.get("match_mode")) or "contains",
            "updated_at": _normalize_text(item.get("updated_at")),
        }
        for item in keywords
    ]
    return sha1(json.dumps(rows, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _monitoring_cache_key(connection, keywords: list[dict[str, Any]]) -> str:
    cache_state = get_normalized_intelligence_cache_state(connection) or {}
    payload = {
        "source_signature": cache_state.get("source_signature") or "",
        "event_count": int(cache_state.get("event_count") or 0),
        "keywords_signature": _keywords_cache_key(keywords),
    }
    return sha1(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def _can_use_global_monitoring_cache(connection, normalized_events: Iterable[dict[str, Any]]) -> bool:
    cache_state = get_normalized_intelligence_cache_state(connection) or {}
    event_count = int(cache_state.get("event_count") or 0)
    try:
        return bool(event_count > 0 and len(normalized_events) == event_count)
    except TypeError:
        return False


def _cached_monitoring_summary(connection) -> dict[str, Any] | None:
    keywords = _seed_keywords(connection)
    cache_key = _monitoring_cache_key(connection, keywords)
    with _MONITORING_CACHE_LOCK:
        if _MONITORING_CACHE_KEY != cache_key:
            return None
        summary = dict((_MONITORING_CACHE_PAYLOAD.get("monitoringConfigurationSummary") or {}))
    return {
        "keywordCount": int(summary.get("keywordCount") or len(keywords)),
        "enabledKeywordCount": int(summary.get("enabledKeywordCount") or 0),
        "highPriorityCount": int(summary.get("highPriorityCount") or 0),
        "sampleEvidenceCount": int(summary.get("sampleEvidenceCount") or 0),
        "eventCount": int((get_normalized_intelligence_cache_state(connection) or {}).get("event_count") or 0),
    }


def _keyword_match_positions(text: str, keyword: str, match_mode: str) -> list[tuple[int, int]]:
    if not text or not keyword:
        return []
    if match_mode == "word_boundary":
        pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])", re.IGNORECASE)
        return [(item.start(), item.end()) for item in pattern.finditer(text)]
    lowered_text = text.lower()
    lowered_keyword = keyword.lower()
    positions: list[tuple[int, int]] = []
    start = 0
    while True:
        index = lowered_text.find(lowered_keyword, start)
        if index == -1:
            break
        positions.append((index, index + len(lowered_keyword)))
        start = index + len(lowered_keyword)
    return positions


def _extract_monitoring_matches(event: dict[str, Any], keywords: list[dict[str, Any]]) -> list[dict[str, Any]]:
    text = _event_text(event)
    matches: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in keywords:
        if not bool(item.get("enabled")):
            continue
        keyword = _normalize_text(item.get("keyword"))
        positions = _keyword_match_positions(text, keyword, _normalize_text(item.get("match_mode")) or "contains")
        if not positions:
            continue
        key = (keyword.lower(), _normalize_text(item.get("category")))
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            {
                "keyword": keyword,
                "category": _normalize_text(item.get("category")) or "custom_keywords",
                "weight": int(item.get("weight") or 0),
                "match_count": len(positions),
            }
        )
    matches.sort(key=lambda row: (int(row["weight"]), int(row["match_count"]), row["keyword"]), reverse=True)
    return matches


def _sample_link_entries(text: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    normalized = _normalize_text(text)

    for match in SAMPLE_PREFIX_RE.finditer(normalized):
        url = match.group("url").strip()
        if url in seen:
            continue
        seen.add(url)
        results.append({"url": url, "kind": match.group("label").lower(), "confidence": "high"})

    for match in URL_RE.finditer(normalized):
        url = match.group(0).strip()
        if url in seen:
            continue
        window_start = max(0, match.start() - 30)
        window = normalized[window_start : min(len(normalized), match.end() + 30)].lower()
        if any(hint in window for hint in SAMPLE_HINT_WORDS):
            seen.add(url)
            results.append({"url": url, "kind": "contextual", "confidence": "medium"})
    return results[:6]


def _asset_sensitivity_score(text: str) -> tuple[int, list[str]]:
    lowered = text.lower()
    best_score = 0
    reasons: list[str] = []
    score_map = {
        "凭证": 15,
        "KYC/PII": 15,
        "数据库": 13,
        "源码": 15,
        "金融数据": 14,
    }
    for label, patterns in ASSET_PATTERNS.items():
        hits = sum(1 for pattern in patterns if re.search(pattern, lowered, re.IGNORECASE))
        if hits <= 0:
            continue
        score = score_map.get(label, 8)
        if score > best_score:
            best_score = score
            reasons = [f"rule:正文疑似包含{label}"]
    return best_score, reasons


def _severity_score(event: dict[str, Any]) -> tuple[int, list[str]]:
    severity = _normalize_text(event.get("severity")).lower()
    score_map = {"critical": 22, "high": 16, "medium": 10, "low": 4}
    score = score_map.get(severity, 8)
    reasons: list[str] = []
    if severity == "critical":
        reasons.append("rule:危害等级为 critical")
    elif severity == "high":
        reasons.append("rule:危害等级为 high")
    if _normalize_text(event.get("leak_type")) in {"凭证泄露", "源代码泄露", "数据库泄露", "勒索披露"}:
        score += 6
        reasons.append(f"rule:命中重点情报类型 {_normalize_text(event.get('leak_type'))}")
    return min(score, 30), reasons[:3]


def _monitoring_score(matches: list[dict[str, Any]]) -> tuple[int, list[str]]:
    total = sum(int(item.get("weight") or 0) for item in matches)
    reasons = [f"rule:命中监测关键词 {item['keyword']}" for item in matches[:4]]
    return min(total, 25), reasons


def _sample_evidence_score(sample_links: list[dict[str, str]], text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if sample_links:
        score += 12
        reasons.append("rule:检测到样本链接")
        if len(sample_links) >= 2:
            score += 4
            reasons.append("rule:检测到多个样本链接")
    lowered = text.lower()
    if any(token in lowered for token in ("credential sample", "records preview", "sample dump", "preview data", "sample:")):
        score += 4
        reasons.append("rule:正文包含样本提示词")
    return min(score, 20), reasons


def _timeliness_score(event: dict[str, Any]) -> tuple[int, list[str]]:
    event_dt = _parse_dt(event.get("disclosure_time"))
    if event_dt is None:
        return 0, []
    hours = (datetime.now(timezone.utc) - event_dt).total_seconds() / 3600
    if hours <= 72:
        return 10, ["rule:事件发生在近 72 小时内"]
    if hours <= 168:
        return 5, ["rule:事件发生在近 7 天内"]
    return 0, []


def _priority_from_weight(weight: int) -> str:
    if weight >= 20:
        return "high"
    if weight >= 10:
        return "medium"
    return "low"


def _with_monitoring(event: dict[str, Any], keywords: list[dict[str, Any]]) -> dict[str, Any]:
    item = {**event, "metadata": dict(event.get("metadata") or {})}
    text = _event_text(item)
    matches = _extract_monitoring_matches(item, keywords)
    monitoring_weight = sum(int(entry.get("weight") or 0) for entry in matches)
    sample_links = _sample_link_entries(text)
    has_sample_evidence = bool(sample_links)
    severity_score, severity_reasons = _severity_score(item)
    monitoring_score, monitoring_reasons = _monitoring_score(matches)
    sample_score, sample_reasons = _sample_evidence_score(sample_links, text)
    asset_score, asset_reasons = _asset_sensitivity_score(text)
    timeliness_score, timeliness_reasons = _timeliness_score(item)
    rule_segments = [
        {"key": "severity", "label": "危害等级分", "score": severity_score, "max_score": 30, "reasons": severity_reasons},
        {"key": "monitoring", "label": "监测命中分", "score": monitoring_score, "max_score": 25, "reasons": monitoring_reasons},
        {"key": "sample_evidence", "label": "样本证据分", "score": sample_score, "max_score": 20, "reasons": sample_reasons},
        {"key": "asset_sensitivity", "label": "资产敏感度分", "score": asset_score, "max_score": 15, "reasons": asset_reasons},
        {"key": "timeliness", "label": "时效性分", "score": timeliness_score, "max_score": 10, "reasons": timeliness_reasons},
    ]
    rule_risk_score = min(sum(int(segment["score"]) for segment in rule_segments), 100)
    sample_evidence_bonus = 0
    if has_sample_evidence:
        sample_evidence_bonus += 40
        if len(sample_links) >= 2:
            sample_evidence_bonus += 10
    priority_score = monitoring_weight * 100 + sample_evidence_bonus + rule_risk_score * 2

    item["monitoring_matches"] = matches
    item["monitoring_weight"] = monitoring_weight
    item["monitoring_priority"] = _priority_from_weight(monitoring_weight)
    item["sample_links"] = sample_links
    item["has_sample_evidence"] = has_sample_evidence
    item["sample_link_count"] = len(sample_links)
    item["rule_risk_breakdown"] = {"total": rule_risk_score, "segments": rule_segments}
    item["rule_risk_score"] = rule_risk_score
    item["priority_score"] = priority_score
    item["risk_score"] = rule_risk_score
    item["risk_breakdown"] = item["rule_risk_breakdown"]

    rule_reasons: list[str] = []
    seen: set[str] = set()
    for segment in rule_segments:
        for reason in segment.get("reasons") or []:
            if reason in seen:
                continue
            seen.add(reason)
            rule_reasons.append(reason)
    item["risk_reasons"] = rule_reasons[:8]
    item["metadata"]["risk_reasons"] = item["risk_reasons"]
    item["metadata"]["rule_risk_breakdown"] = item["rule_risk_breakdown"]
    item["metadata"]["monitoring_matches"] = matches
    item["metadata"]["sample_links"] = sample_links
    return item


def enrich_events(connection, normalized_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keywords = _seed_keywords(connection)
    return enrich_events_with_keywords(normalized_events, keywords)


def enrich_events_with_keywords(
    normalized_events: list[dict[str, Any]],
    keywords: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [_with_monitoring(event, keywords) for event in normalized_events]


def _keyword_stats(enriched_events: list[dict[str, Any]]) -> dict[str, Any]:
    category_counter: Counter[str] = Counter()
    keyword_counter: Counter[str] = Counter()
    keyword_risk_counter: Counter[str] = Counter()
    for event in enriched_events:
        for item in event.get("monitoring_matches") or []:
            category = _normalize_text(item.get("category")) or "custom_keywords"
            keyword = _normalize_text(item.get("keyword"))
            category_counter[category] += 1
            keyword_counter[keyword] += 1
            if int(event.get("rule_risk_score") or 0) >= 60:
                keyword_risk_counter[keyword] += 1
    return {
        "categories": [{"name": key, "value": value} for key, value in category_counter.most_common()],
        "keywords": [
            {
                "keyword": key,
                "hits": value,
                "highRiskHits": int(keyword_risk_counter.get(key, 0)),
            }
            for key, value in keyword_counter.most_common(20)
        ],
    }


def _priority_queue(enriched_events: list[dict[str, Any]], limit: int = 12) -> list[dict[str, Any]]:
    rows = sorted(
        enriched_events,
        key=lambda item: (
            int(item.get("priority_score") or 0),
            int(item.get("rule_risk_score") or 0),
            _parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    payload: list[dict[str, Any]] = []
    for event in rows[:limit]:
        payload.append(
            {
                "id": event.get("event_id"),
                "title": event.get("title") or "",
                "attacker": event.get("attacker") or "未知",
                "victim": event.get("victim") or "未知",
                "sourceSite": event.get("source_site_name") or "",
                "disclosureTime": event.get("disclosure_time") or "",
                "riskScore": int(event.get("rule_risk_score") or 0),
                "priorityScore": int(event.get("priority_score") or 0),
                "monitoringWeight": int(event.get("monitoring_weight") or 0),
                "monitoringPriority": event.get("monitoring_priority") or "low",
                "monitoringMatches": event.get("monitoring_matches") or [],
                "sampleLinkCount": int(event.get("sample_link_count") or 0),
                "hasSampleEvidence": bool(event.get("has_sample_evidence")),
            }
        )
    return payload


def _sample_alerts(enriched_events: list[dict[str, Any]], limit: int = 10) -> list[dict[str, Any]]:
    rows = [event for event in enriched_events if event.get("has_sample_evidence")]
    rows.sort(
        key=lambda item: (
            int(item.get("sample_link_count") or 0),
            int(item.get("rule_risk_score") or 0),
            _parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return [
        {
            "id": event.get("event_id"),
            "title": event.get("title") or "",
            "sourceSite": event.get("source_site_name") or "",
            "riskScore": int(event.get("rule_risk_score") or 0),
            "sampleLinks": event.get("sample_links") or [],
            "sampleLinkCount": int(event.get("sample_link_count") or 0),
            "disclosureTime": event.get("disclosure_time") or "",
        }
        for event in rows[:limit]
    ]


def _priority_alert_stream(enriched_events: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    rows = [event for event in enriched_events if int(event.get("monitoring_weight") or 0) > 0]
    rows.sort(
        key=lambda item: (
            int(item.get("priority_score") or 0),
            _parse_dt(item.get("disclosure_time")) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return [
        {
            "id": event.get("event_id"),
            "title": event.get("title") or "",
            "summary": event["_monitoring_summary"] if "_monitoring_summary" in event else _normalize_text(event.get("detail_text"))[:180],
            "riskScore": int(event.get("rule_risk_score") or 0),
            "monitoringMatches": event.get("monitoring_matches") or [],
            "hasSampleEvidence": bool(event.get("has_sample_evidence")),
            "sourceSite": event.get("source_site_name") or "",
            "disclosureTime": event.get("disclosure_time") or "",
        }
        for event in rows[:limit]
    ]


def build_monitoring_payload(connection, normalized_events: Iterable[dict[str, Any]], *,
                             retain_detail_text: bool = True) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    global _MONITORING_CACHE_KEY, _MONITORING_CACHE_PAYLOAD
    keywords = _seed_keywords(connection)
    use_global_cache = _can_use_global_monitoring_cache(connection, normalized_events)
    streamed = not isinstance(normalized_events, Sized)
    cache_key = _monitoring_cache_key(connection, keywords) if use_global_cache or streamed else ""
    enriched_events = []
    for event in normalized_events:
        item = _with_monitoring(event, keywords)
        if not retain_detail_text:
            item["_monitoring_summary"] = _normalize_text(item.get("detail_text"))[:180]
            item["detail_text"] = str(item.get("detail_text") or "")[:500]
            for key in ("event_metadata_json", "mirror_resources_json", "screenshot_resources_json", "risk_reasons_json"):
                item.pop(key, None)
            for key in ("risk_breakdown", "rule_risk_breakdown"):
                item.pop(key, None)
                item["metadata"].pop(key, None)
            item["metadata"] = {sys.intern(key): value for key, value in item["metadata"].items()}
        enriched_events.append(item)
    payload = {
        "monitoringPriorityQueue": _priority_queue(enriched_events),
        "monitoringKeywordStats": _keyword_stats(enriched_events),
        "sampleEvidenceAlerts": _sample_alerts(enriched_events),
        "monitoringConfigurationSummary": {
            "keywordCount": len(keywords),
            "enabledKeywordCount": sum(1 for row in keywords if bool(row.get("enabled"))),
            "highPriorityCount": sum(1 for event in enriched_events if event.get("monitoring_priority") == "high"),
            "sampleEvidenceCount": sum(1 for event in enriched_events if event.get("has_sample_evidence")),
        },
        "priorityAlertStream": _priority_alert_stream(enriched_events),
    }
    if streamed:
        use_global_cache = (_can_use_global_monitoring_cache(connection, enriched_events)
                            and cache_key == _monitoring_cache_key(connection, keywords))
    if use_global_cache:
        with _MONITORING_CACHE_LOCK:
            _MONITORING_CACHE_KEY = cache_key
            _MONITORING_CACHE_PAYLOAD = dict(payload)
    return enriched_events, payload


def build_monitoring_status() -> dict[str, Any]:
    with get_db_connection() as connection:
        cached = _cached_monitoring_summary(connection)
        if cached is not None:
            return cached
        if get_normalized_intelligence_cache_state(connection) is None:
            ensure_normalized_intelligence(connection, load_events=False)
        events = (_hydrate_event_row(row) for row in iter_normalized_intelligence_events(
            connection, order_by=SEARCH_ORDER["latest"]))
        enriched_events, payload = build_monitoring_payload(connection, events, retain_detail_text=False)
    summary = payload.get("monitoringConfigurationSummary") or {}
    return {
        "keywordCount": int(summary.get("keywordCount") or 0),
        "enabledKeywordCount": int(summary.get("enabledKeywordCount") or 0),
        "highPriorityCount": int(summary.get("highPriorityCount") or 0),
        "sampleEvidenceCount": int(summary.get("sampleEvidenceCount") or 0),
        "eventCount": len(enriched_events),
    }
