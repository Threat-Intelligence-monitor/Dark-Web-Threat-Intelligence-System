from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from darkweb_collector.db import get_db_connection, replace_vulnerability_records
from darkweb_collector.runtime import project_root
from darkweb_collector.vulnerability_i18n import humanize_product_token
from darkweb_collector.vulnerability_i18n import translate_vulnerability_summary_live
from darkweb_collector.vulnerability_i18n import translate_vulnerability_title_live


DEFAULT_SAMPLE_FEED = project_root() / "samples" / "public_vulnerability_feed.json"
DEFAULT_LIVE_LIMIT = 300
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES_API_URL = "https://api.github.com/advisories"
NVD_RECENT_SOURCE_NAME = "nvd_recent"
GITHUB_ADVISORIES_SOURCE_NAME = "github_advisories"
NVD_RECENT_LOOKBACK_DAYS = 30
NVD_RESULTS_PER_PAGE = 500
NVD_ENRICHMENT_CACHE_FILE = project_root() / "data" / "nvd_enrichment_cache.json"
NVD_ENRICHMENT_CACHE_TTL_SECONDS = 24 * 3600
NVD_ENRICHMENT_MAX_WORKERS = 8
GITHUB_ADVISORIES_PER_PAGE = 100
GITHUB_ADVISORIES_MAX_PAGES = 3
HTTP_HEADERS = {
    "User-Agent": "bishe-threat-intel/1.0",
    "Accept": "application/json",
}
URL_RE = re.compile(r"https?://[^\s;]+", re.IGNORECASE)


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_remote_datetime(value: str | None) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _cache_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _load_nvd_enrichment_cache() -> dict[str, Any]:
    path = NVD_ENRICHMENT_CACHE_FILE
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_nvd_enrichment_cache(cache: dict[str, Any]) -> None:
    path = NVD_ENRICHMENT_CACHE_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def _get_cached_nvd_enrichment(cve_id: str, cache: dict[str, Any]) -> dict[str, Any]:
    cached = cache.get(cve_id) or {}
    fetched_at = int(cached.get("fetched_at") or 0)
    if fetched_at and (_cache_timestamp() - fetched_at) < NVD_ENRICHMENT_CACHE_TTL_SECONDS:
        data = cached.get("data")
        if isinstance(data, dict):
            return data
    data = _enrich_from_nvd(cve_id)
    cache[cve_id] = {
        "fetched_at": _cache_timestamp(),
        "data": data,
    }
    return data


def _fetch_json(url: str, *, timeout: int = 20) -> dict[str, Any]:
    request = Request(url, headers=HTTP_HEADERS)
    with urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _fetch_json_with_headers(
    url: str,
    *,
    timeout: int = 20,
    headers: dict[str, str] | None = None,
) -> tuple[Any, Any]:
    request = Request(url, headers={**HTTP_HEADERS, **(headers or {})})
    with urlopen(request, timeout=timeout) as response:
        return json.load(response), response.headers


def _coerce_reference_urls(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return []


def _coerce_versions(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    return []


def _unique_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = str(value or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        deduped.append(cleaned)
    return deduped


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    disclosure_time = str(record.get("disclosure_time") or record.get("published_at") or _now_utc_iso()).strip()
    reference_urls = _unique_strings(_coerce_reference_urls(record.get("reference_urls")))
    advisory_url = str(record.get("advisory_url") or (reference_urls[0] if reference_urls else "")).strip()
    return {
        "source_name": str(record.get("source_name") or "public_feed").strip(),
        "source_type": str(record.get("source_type") or "public").strip(),
        "cve_id": str(record.get("cve_id") or "").strip().upper(),
        "title": str(record.get("title") or "").strip(),
        "vendor": str(record.get("vendor") or "").strip(),
        "product": str(record.get("product") or "").strip(),
        "vulnerability_type": str(record.get("vulnerability_type") or "公开源漏洞").strip(),
        "severity": str(record.get("severity") or "high").strip().lower(),
        "cvss": record.get("cvss"),
        "is_exploited": bool(record.get("is_exploited")),
        "has_poc": bool(record.get("has_poc")),
        "patch_available": bool(record.get("patch_available")),
        "wide_impact": bool(record.get("wide_impact")),
        "disclosure_time": disclosure_time,
        "affected_versions": _coerce_versions(record.get("affected_versions")),
        "summary": str(record.get("summary") or "").strip(),
        "advisory_url": advisory_url,
        "reference_urls": reference_urls,
        "last_seen_at": str(record.get("last_seen_at") or disclosure_time).strip(),
    }


def _load_sample_feed(sample_file: str | Path | None = None) -> list[dict[str, Any]]:
    feed_path = Path(sample_file).expanduser().resolve() if sample_file else DEFAULT_SAMPLE_FEED.resolve()
    payload = json.loads(feed_path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        records = payload.get("records") or []
    else:
        records = payload
    return [_normalize_record(record) for record in records if isinstance(record, dict)]


def _extract_urls(text: str) -> list[str]:
    return _unique_strings(URL_RE.findall(text or ""))


def _pick_cvss(metrics: dict[str, Any]) -> float | None:
    candidates: list[float] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(key) or []:
            cvss_data = item.get("cvssData") or {}
            score = cvss_data.get("baseScore")
            try:
                if score is not None:
                    candidates.append(float(score))
            except (TypeError, ValueError):
                continue
    return max(candidates) if candidates else None


def _pick_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"]).strip()
    for item in cve.get("descriptions") or []:
        if item.get("value"):
            return str(item["value"]).strip()
    return ""


def _format_cpe_range(match: dict[str, Any]) -> str:
    parts: list[str] = []
    criteria = str(match.get("criteria") or "")
    criteria_parts = criteria.split(":")
    product_token = criteria_parts[4] if len(criteria_parts) >= 5 else ""
    if len(criteria_parts) >= 6:
        version = criteria_parts[5]
        if version and version != "*":
            parts.append(version)
    if match.get("versionStartIncluding"):
        parts.append(f">= {match['versionStartIncluding']}")
    if match.get("versionStartExcluding"):
        parts.append(f"> {match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        parts.append(f"<= {match['versionEndIncluding']}")
    if match.get("versionEndExcluding"):
        parts.append(f"< {match['versionEndExcluding']}")
    range_text = " ".join(parts).strip() or criteria
    product_label = humanize_product_token(product_token)
    if product_label and range_text != criteria:
        return f"{product_label}: {range_text}"
    return range_text


def _walk_configuration_nodes(node: dict[str, Any], versions: list[str]) -> None:
    for match in node.get("cpeMatch") or []:
        if not match.get("vulnerable", True):
            continue
        versions.append(_format_cpe_range(match))
    for child in node.get("children") or []:
        _walk_configuration_nodes(child, versions)


def _extract_affected_versions(cve: dict[str, Any]) -> list[str]:
    versions: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            _walk_configuration_nodes(node, versions)
    return _unique_strings(versions)[:8]


def _extract_fixed_version_ranges(summary: str) -> list[str]:
    if not summary:
        return []
    match = re.search(r"fixed in (.+?)(?:\.|$)", summary, flags=re.IGNORECASE)
    if not match:
        return []
    segment = match.group(1).replace(" and ", ", ")
    ranges: list[str] = []
    for part in [item.strip() for item in segment.split(",") if item.strip()]:
        version_match = re.match(r"(.+?)\s+([0-9][0-9A-Za-z._-]*)$", part)
        if not version_match:
            continue
        product_name = humanize_product_token(version_match.group(1))
        fixed_version = version_match.group(2)
        ranges.append(f"{product_name}: < {fixed_version}")
    return _unique_strings(ranges)


def _format_api_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_source_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            value = str(description.get("value") or "").strip()
            if value and value.startswith("CWE-") and value not in cwes:
                cwes.append(value)
    return cwes


def _humanize_vendor_token(value: str | None) -> str:
    raw = str(value or "").strip().replace("_", " ").replace("-", " ")
    if not raw:
        return ""
    return " ".join(part.capitalize() if part.islower() else part for part in raw.split())


def _extract_vendor_product_from_configurations(cve: dict[str, Any]) -> tuple[str, str]:
    configurations = cve.get("configurations") or []

    def walk(node: dict[str, Any]) -> tuple[str, str]:
        for match in node.get("cpeMatch") or []:
            if not match.get("vulnerable", True):
                continue
            criteria = str(match.get("criteria") or "")
            parts = criteria.split(":")
            if len(parts) >= 5:
                vendor = _humanize_vendor_token(parts[3])
                product = humanize_product_token(parts[4])
                if vendor or product:
                    return vendor, product
        for child in node.get("children") or []:
            vendor, product = walk(child)
            if vendor or product:
                return vendor, product
        return "", ""

    for config in configurations:
        for node in config.get("nodes") or []:
            vendor, product = walk(node)
            if vendor or product:
                return vendor, product
    return "", ""


def _github_ecosystem_label(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    mapping = {
        "npm": "npm",
        "pip": "PyPI",
        "maven": "Maven",
        "nuget": "NuGet",
        "composer": "Composer",
        "go": "Go",
        "rust": "Rust",
        "swift": "Swift",
        "actions": "GitHub Actions",
        "other": "Other",
        "pub": "Pub",
        "rubygems": "RubyGems",
    }
    return mapping.get(raw, raw or "")


def _extract_github_cve_id(advisory: dict[str, Any]) -> str:
    cve_id = str(advisory.get("cve_id") or "").strip().upper()
    if cve_id:
        return cve_id
    for identifier in advisory.get("identifiers") or []:
        if str(identifier.get("type") or "").strip().upper() == "CVE":
            value = str(identifier.get("value") or "").strip().upper()
            if value:
                return value
    return ""


def _extract_github_cvss(advisory: dict[str, Any]) -> float | None:
    cvss = advisory.get("cvss") or {}
    score = cvss.get("score")
    try:
        if score is not None:
            return float(score)
    except (TypeError, ValueError):
        pass
    cvss_severities = advisory.get("cvss_severities") or {}
    for key in ("cvss_v4", "cvss_v3"):
        entry = cvss_severities.get(key) or {}
        score = entry.get("score")
        try:
            if score is not None:
                return float(score)
        except (TypeError, ValueError):
            continue
    return None


def _extract_github_references(advisory: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in advisory.get("references") or []:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, dict):
            values.append(str(item.get("url") or "").strip())
    html_url = str(advisory.get("html_url") or "").strip()
    api_url = str(advisory.get("url") or "").strip()
    return _unique_strings(values + ([html_url] if html_url else []) + ([api_url] if api_url else []))


def _parse_link_header_next(link_header: str | None) -> str:
    raw = str(link_header or "").strip()
    if not raw:
        return ""
    for part in raw.split(","):
        if 'rel="next"' not in part:
            continue
        start = part.find("<")
        end = part.find(">", start + 1)
        if start != -1 and end != -1:
            return part[start + 1:end]
    return ""


def _enrich_from_nvd(cve_id: str) -> dict[str, Any]:
    query = urlencode({"cveId": cve_id})
    payload = _fetch_json(f"{NVD_API_URL}?{query}")
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {}
    cve = vulnerabilities[0].get("cve") or {}
    description = _pick_description(cve)
    affected_versions = _extract_affected_versions(cve)
    affected_versions = _unique_strings(affected_versions + _extract_fixed_version_ranges(description))
    vendor, product = _extract_vendor_product_from_configurations(cve)
    return {
        "summary": description,
        "cvss": _pick_cvss(cve.get("metrics") or {}),
        "affected_versions": affected_versions,
        "vendor": vendor,
        "product": product,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


def _derive_vulnerability_type(name: str, cwes: list[str]) -> str:
    lowered = (name or "").lower()
    for keyword, label in (
        ("remote code execution", "远程代码执行"),
        ("command injection", "命令注入"),
        ("sql injection", "SQL 注入"),
        ("use-after-free", "释放后重用"),
        ("authentication bypass", "身份认证绕过"),
        ("privilege escalation", "权限提升"),
        ("deserialization", "反序列化漏洞"),
        ("cross-site scripting", "跨站脚本"),
        ("path traversal", "路径遍历"),
        ("request smuggling", "请求走私"),
        ("memory corruption", "内存破坏"),
    ):
        if keyword in lowered:
            return label
    if cwes:
        return cwes[0]
    return "公开源漏洞"


def _build_record_from_kev(item: dict[str, Any], *, nvd_enrichment: dict[str, Any] | None = None) -> dict[str, Any]:
    cve_id = str(item.get("cveID") or "").strip().upper()
    notes = str(item.get("notes") or "")
    note_urls = _extract_urls(notes)
    nvd_url = (nvd_enrichment or {}).get("nvd_url") or (f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "")
    reference_urls = _unique_strings(note_urls + ([nvd_url] if nvd_url else []))
    required_action = str(item.get("requiredAction") or "").strip()
    summary = str((nvd_enrichment or {}).get("summary") or item.get("shortDescription") or "").strip()
    title = str(item.get("vulnerabilityName") or f"{item.get('vendorProject', '')} {item.get('product', '')}").strip()
    has_poc = any(token in f"{notes} {summary}".lower() for token in ("poc", "proof-of-concept", "proof of concept", "exploit code"))
    affected_versions = (nvd_enrichment or {}).get("affected_versions") or []
    return _normalize_record(
        {
            "source_name": "cisa_kev",
            "source_type": "official",
            "cve_id": cve_id,
            "title": translate_vulnerability_title_live(
                title,
                vendor=str(item.get("vendorProject") or "").strip(),
                product=str(item.get("product") or "").strip(),
            ),
            "vendor": str(item.get("vendorProject") or "").strip(),
            "product": str(item.get("product") or "").strip(),
            "vulnerability_type": _derive_vulnerability_type(
                str(item.get("vulnerabilityName") or ""),
                [str(cwe).strip() for cwe in item.get("cwes") or [] if str(cwe).strip()],
            ),
            "severity": "critical",
            "cvss": (nvd_enrichment or {}).get("cvss"),
            "is_exploited": True,
            "has_poc": has_poc,
            "patch_available": bool(required_action),
            "wide_impact": len(affected_versions) >= 3 or "multiple" in summary.lower() or "multiple" in notes.lower(),
            "disclosure_time": str(item.get("dateAdded") or _now_utc_iso()).strip(),
            "affected_versions": affected_versions,
            "summary": translate_vulnerability_summary_live(summary),
            "advisory_url": next((url for url in reference_urls if "nvd.nist.gov" not in url), "") or (reference_urls[0] if reference_urls else ""),
            "reference_urls": reference_urls,
            "last_seen_at": _now_utc_iso(),
        }
    )


def _build_record_from_nvd_item(item: dict[str, Any], *, source_name: str = NVD_RECENT_SOURCE_NAME) -> dict[str, Any]:
    cve = (item.get("cve") or {}) if isinstance(item, dict) else {}
    cve_id = str(cve.get("id") or "").strip().upper()
    description = _pick_description(cve)
    vendor, product = _extract_vendor_product_from_configurations(cve)
    cvss = _pick_cvss(cve.get("metrics") or {})
    affected_versions = _extract_affected_versions(cve)
    reference_urls = _unique_strings(
        [
            str(reference.get("url") or "").strip()
            for reference in cve.get("references") or []
            if str(reference.get("url") or "").strip()
        ]
    )
    cwes = _extract_cwes(cve)
    severity = "critical" if (cvss is not None and cvss >= 9.0) else "high"
    title = " ".join(part for part in [vendor, product, cve_id] if part).strip() or cve_id
    return _normalize_record(
        {
            "source_name": source_name,
            "source_type": "public",
            "cve_id": cve_id,
            "title": translate_vulnerability_title_live(title, vendor=vendor, product=product),
            "vendor": vendor,
            "product": product,
            "vulnerability_type": _derive_vulnerability_type(description, cwes),
            "severity": severity,
            "cvss": cvss,
            "is_exploited": False,
            "has_poc": False,
            "patch_available": False,
            "wide_impact": len(affected_versions) >= 3,
            "disclosure_time": str(cve.get("published") or _now_utc_iso()).strip(),
            "affected_versions": affected_versions,
            "summary": translate_vulnerability_summary_live(description),
            "advisory_url": reference_urls[0] if reference_urls else f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "reference_urls": _unique_strings(reference_urls + ([f"https://nvd.nist.gov/vuln/detail/{cve_id}"] if cve_id else [])),
            "last_seen_at": str(cve.get("lastModified") or _now_utc_iso()).strip(),
        }
    )


def _build_record_from_github_advisory(
    advisory: dict[str, Any],
    *,
    nvd_enrichment: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    cve_id = _extract_github_cve_id(advisory)
    if not cve_id:
        return None
    vulnerabilities = advisory.get("vulnerabilities") or []
    package = ((vulnerabilities[0] or {}).get("package") or {}) if vulnerabilities else {}
    ecosystem = _github_ecosystem_label(package.get("ecosystem"))
    package_name = str(package.get("name") or "").strip()
    vendor = str((nvd_enrichment or {}).get("vendor") or "").strip() or ecosystem
    product = str((nvd_enrichment or {}).get("product") or "").strip() or package_name or str(advisory.get("ghsa_id") or "").strip()
    if not vendor or not product:
        return None
    cwes = [str(item.get("cwe_id") or "").strip() for item in advisory.get("cwes") or [] if str(item.get("cwe_id") or "").strip()]
    summary = str(advisory.get("summary") or "").strip()
    description = str((nvd_enrichment or {}).get("summary") or advisory.get("description") or summary).strip()
    severity = str(advisory.get("severity") or "high").strip().lower()
    cvss = (nvd_enrichment or {}).get("cvss")
    if cvss in {None, ""}:
        cvss = _extract_github_cvss(advisory)
    references = _extract_github_references(advisory)
    nvd_url = str((nvd_enrichment or {}).get("nvd_url") or "").strip()
    if nvd_url:
        references = _unique_strings(references + [nvd_url])
    patch_available = any((item or {}).get("first_patched_version") for item in vulnerabilities)
    wide_impact = len(vulnerabilities) > 1
    disclosure_time = (
        str(advisory.get("nvd_published_at") or "").strip()
        or str(advisory.get("published_at") or "").strip()
        or str(advisory.get("updated_at") or "").strip()
    )
    return _normalize_record(
        {
            "source_name": GITHUB_ADVISORIES_SOURCE_NAME,
            "source_type": "public",
            "cve_id": cve_id,
            "title": translate_vulnerability_title_live(summary or cve_id, vendor=vendor, product=product),
            "vendor": vendor,
            "product": product,
            "vulnerability_type": _derive_vulnerability_type(description, cwes),
            "severity": severity,
            "cvss": cvss,
            "is_exploited": False,
            "has_poc": False,
            "patch_available": patch_available,
            "wide_impact": wide_impact,
            "disclosure_time": disclosure_time or _now_utc_iso(),
            "affected_versions": [],
            "summary": translate_vulnerability_summary_live(description),
            "advisory_url": references[0] if references else str(advisory.get("html_url") or "").strip(),
            "reference_urls": references,
            "last_seen_at": str(advisory.get("updated_at") or _now_utc_iso()).strip(),
        }
    )


def _fetch_recent_nvd_records(*, limit: int = DEFAULT_LIVE_LIMIT, lookback_days: int = NVD_RECENT_LOOKBACK_DAYS) -> list[dict[str, Any]]:
    end_at = datetime.now(timezone.utc)
    start_at = end_at - timedelta(days=max(1, lookback_days))
    per_severity_limit = max(limit, NVD_RESULTS_PER_PAGE)

    def fetch_severity(severity: str) -> list[dict[str, Any]]:
        params = {
            "pubStartDate": _format_api_datetime(start_at),
            "pubEndDate": _format_api_datetime(end_at),
            "cvssV3Severity": severity,
            "resultsPerPage": str(per_severity_limit),
            "startIndex": "0",
        }
        payload = _fetch_json(f"{NVD_API_URL}?{urlencode(params)}")
        vulnerabilities = payload.get("vulnerabilities") or []
        return [
            _build_record_from_nvd_item(item)
            for item in vulnerabilities
            if isinstance(item, dict) and str((item.get("cve") or {}).get("id") or "").strip()
        ]

    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(fetch_severity, severity): severity for severity in ("CRITICAL", "HIGH")}
        for future in as_completed(futures):
            try:
                records.extend(future.result())
            except Exception:
                continue

    deduped: dict[str, dict[str, Any]] = {}
    for record in records:
        cve_id = record.get("cve_id") or ""
        existing = deduped.get(cve_id)
        if existing is None:
            deduped[cve_id] = record
            continue
        current_dt = _normalize_record(record).get("disclosure_time", "")
        existing_dt = _normalize_record(existing).get("disclosure_time", "")
        deduped[cve_id] = record if current_dt >= existing_dt else existing

    return sorted(
        deduped.values(),
        key=lambda row: str(row.get("disclosure_time") or ""),
        reverse=True,
    )[: max(1, int(limit))]


def _fetch_recent_github_advisories(
    *,
    limit: int = DEFAULT_LIVE_LIMIT,
    lookback_days: int = NVD_RECENT_LOOKBACK_DAYS,
    nvd_cache: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=max(1, lookback_days))).date().isoformat()
    cache = nvd_cache if nvd_cache is not None else _load_nvd_enrichment_cache()

    def fetch_severity(severity: str) -> list[dict[str, Any]]:
        params = {
            "type": "reviewed",
            "severity": severity,
            "sort": "updated",
            "direction": "desc",
            "per_page": str(GITHUB_ADVISORIES_PER_PAGE),
            "modified": f">={cutoff_date}",
        }
        url = f"{GITHUB_ADVISORIES_API_URL}?{urlencode(params)}"
        collected: list[dict[str, Any]] = []
        pages = 0
        while url and pages < GITHUB_ADVISORIES_MAX_PAGES and len(collected) < limit:
            payload, headers = _fetch_json_with_headers(
                url,
                headers={"Accept": "application/vnd.github+json"},
            )
            advisories = payload if isinstance(payload, list) else []
            for advisory in advisories:
                if not isinstance(advisory, dict):
                    continue
                cve_id = _extract_github_cve_id(advisory)
                if not cve_id:
                    continue
                try:
                    nvd_enrichment = _get_cached_nvd_enrichment(cve_id, cache)
                except Exception:
                    nvd_enrichment = {}
                record = _build_record_from_github_advisory(advisory, nvd_enrichment=nvd_enrichment)
                if record is not None:
                    collected.append(record)
                    if len(collected) >= limit:
                        break
            url = _parse_link_header_next(headers.get("Link"))
            pages += 1
        return collected

    records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {executor.submit(fetch_severity, severity): severity for severity in ("critical", "high")}
        for future in as_completed(futures):
            try:
                records.extend(future.result())
            except Exception:
                continue

    deduped: dict[str, dict[str, Any]] = {}
    for record in records:
        cve_id = record.get("cve_id") or ""
        existing = deduped.get(cve_id)
        if existing is None:
            deduped[cve_id] = record
            continue
        current_dt = _parse_source_datetime(record.get("last_seen_at")) or datetime.min.replace(tzinfo=timezone.utc)
        existing_dt = _parse_source_datetime(existing.get("last_seen_at")) or datetime.min.replace(tzinfo=timezone.utc)
        deduped[cve_id] = record if current_dt >= existing_dt else existing

    return sorted(
        deduped.values(),
        key=lambda row: str(row.get("disclosure_time") or ""),
        reverse=True,
    )[: max(1, int(limit))]


def fetch_live_public_vulnerability_feed(*, limit: int = DEFAULT_LIVE_LIMIT) -> list[dict[str, Any]]:
    kev_payload = _fetch_json(KEV_FEED_URL)
    vulnerabilities = kev_payload.get("vulnerabilities") or []
    kev_cutoff = datetime.now(timezone.utc) - timedelta(days=NVD_RECENT_LOOKBACK_DAYS)
    latest_items = sorted(
        [
            item
            for item in vulnerabilities
            if (_parse_source_datetime(item.get("dateAdded")) or datetime.min.replace(tzinfo=timezone.utc)) >= kev_cutoff
        ],
        key=lambda item: str(item.get("dateAdded") or ""),
        reverse=True,
    )[: max(1, int(limit))]
    nvd_cache = _load_nvd_enrichment_cache()
    kev_records: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(NVD_ENRICHMENT_MAX_WORKERS, max(1, len(latest_items)))) as executor:
        futures = {
            executor.submit(
                _get_cached_nvd_enrichment,
                str(item.get("cveID") or "").strip().upper(),
                nvd_cache,
            ): item
            for item in latest_items
            if str(item.get("cveID") or "").strip()
        }
        for future in as_completed(futures):
            item = futures[future]
            try:
                nvd_enrichment = future.result()
            except Exception:
                nvd_enrichment = {}
            kev_records.append(_build_record_from_kev(item, nvd_enrichment=nvd_enrichment))
    try:
        nvd_recent_records = _fetch_recent_nvd_records(limit=max(1, int(limit)))
    except Exception:
        nvd_recent_records = []
    try:
        github_recent_records = _fetch_recent_github_advisories(limit=max(1, int(limit)), nvd_cache=nvd_cache)
    except Exception:
        github_recent_records = []
    _save_nvd_enrichment_cache(nvd_cache)

    kev_cves = {str(item.get("cve_id") or "").strip().upper() for item in kev_records}
    combined = kev_records + [
        item for item in nvd_recent_records if str(item.get("cve_id") or "").strip().upper() not in kev_cves
    ] + [
        item
        for item in github_recent_records
        if str(item.get("cve_id") or "").strip().upper() not in kev_cves
        and str(item.get("cve_id") or "").strip().upper() not in {
            str(row.get("cve_id") or "").strip().upper() for row in nvd_recent_records
        }
    ]
    combined.sort(key=lambda item: str(item.get("disclosure_time") or ""), reverse=True)
    return combined[: max(1, int(limit))]


def load_public_vulnerability_feed(
    sample_file: str | Path | None = None,
    *,
    limit: int = DEFAULT_LIVE_LIMIT,
    prefer_live: bool = True,
) -> tuple[list[dict[str, Any]], str]:
    if sample_file:
        path = Path(sample_file).expanduser().resolve()
        return _load_sample_feed(path), str(path)

    if prefer_live:
        try:
            records = fetch_live_public_vulnerability_feed(limit=limit)
            if records:
                return records, KEV_FEED_URL
        except Exception:
            pass

    return _load_sample_feed(DEFAULT_SAMPLE_FEED), str(DEFAULT_SAMPLE_FEED.resolve())


def sync_public_vulnerability_feed(
    sample_file: str | Path | None = None,
    *,
    limit: int = DEFAULT_LIVE_LIMIT,
    prefer_live: bool = True,
    refresh_normalized: bool = True,
) -> dict[str, Any]:
    records, source = load_public_vulnerability_feed(
        sample_file=sample_file,
        limit=limit,
        prefer_live=prefer_live,
    )
    with get_db_connection() as connection:
        replace_vulnerability_records(connection, records)
        if refresh_normalized:
            from darkweb_collector.normalized_intelligence import ensure_normalized_intelligence

            ensure_normalized_intelligence(connection, force=True, load_events=False)
        connection.commit()
    return {
        "ingested": len(records),
        "source": source,
        "mode": "sample" if sample_file or not source.startswith("http") else "live",
    }
