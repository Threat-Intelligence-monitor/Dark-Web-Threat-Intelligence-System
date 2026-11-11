from __future__ import annotations

import atexit
import json
from pathlib import Path
import re
from threading import Lock, current_thread
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPCookieProcessor, Request, build_opener


_BROWSERS: dict[object, tuple[object, object]] = {}
_BROWSER_LOCK = Lock()
_HTTP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class NetdiskShareUnavailable(RuntimeError):
    def __init__(self, state: str, message: str = "") -> None:
        super().__init__(message or state)
        self.state = state
        self.message = message or state


def _get_browser():
    thread_key = current_thread()
    with _BROWSER_LOCK:
        existing = _BROWSERS.get(thread_key)
        if existing is not None:
            return existing
        from playwright.sync_api import sync_playwright
        from darkweb_collector.browser_temp import ensure_browser_temp

        ensure_browser_temp()
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        _BROWSERS[thread_key] = (playwright, browser)
        return playwright, browser


def close_session_browser(*, all_threads: bool = False) -> None:
    thread_key = current_thread()
    with _BROWSER_LOCK:
        if all_threads:
            pairs = list(_BROWSERS.values())
            _BROWSERS.clear()
        else:
            pair = _BROWSERS.pop(thread_key, None)
            pairs = [pair] if pair is not None else []
    for playwright, browser in pairs:
        try:
            browser.close()
        except Exception:
            pass
        try:
            playwright.stop()
        except Exception:
            pass


def fetch_page_artifacts_with_session(
    url: str,
    *,
    storage_state_path: str | None = None,
    wait_seconds: int = 4,
    timeout_seconds: int = 45,
) -> dict[str, Any]:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    _, browser = _get_browser()

    context_kwargs: dict[str, Any] = {
        "viewport": {"width": 1440, "height": 960},
        "user_agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        ),
        "ignore_https_errors": True,
    }
    candidate = None
    if storage_state_path:
        candidate = Path(storage_state_path)
        if candidate.exists():
            context_kwargs["storage_state"] = str(candidate)

    context = browser.new_context(**context_kwargs)
    page = context.new_page()
    try:
        try:
            page.goto(url, wait_until="networkidle", timeout=timeout_seconds * 1000)
        except PlaywrightTimeoutError:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
        page.wait_for_timeout(wait_seconds * 1000)
        html = page.content()
        return {
            "url": page.url,
            "requested_url": url,
            "title": page.title(),
            "html": html,
            "screenshot_png": b"",
        }
    finally:
        try:
            if candidate is not None:
                context.storage_state(path=str(candidate))
        except Exception:
            pass
        try:
            context.close()
        except Exception:
            pass


def _json_argument_after(text: str, marker: str, start_at: int = 0) -> tuple[dict[str, Any], int] | None:
    marker_index = text.find(marker, start_at)
    if marker_index < 0:
        return None
    start = text.find("{", marker_index)
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                try:
                    payload = json.loads(text[start : index + 1])
                except json.JSONDecodeError:
                    return None
                return (payload, index + 1) if isinstance(payload, dict) else None
    return None


def _baidupan_initial_payload(html: str) -> dict[str, Any]:
    payloads: list[dict[str, Any]] = []
    offset = 0
    while True:
        result = _json_argument_after(html, "locals.mset(", offset)
        if result is None:
            break
        payload, offset = result
        payloads.append(payload)
    for payload in reversed(payloads):
        if isinstance(payload.get("list"), list) or isinstance(payload.get("file_list"), list):
            return payload
    return payloads[-1] if payloads else {}


def fetch_baidupan_share_file_entries(
    url: str,
    *,
    access_code: str = "",
    max_depth: int = 3,
    max_items: int = 120,
    wait_seconds: int = 8,
    timeout_seconds: int = 60,
) -> list[dict[str, Any]]:
    _, browser = _get_browser()
    context = browser.new_context(
        viewport={"width": 1440, "height": 960},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
        ),
        ignore_https_errors=True,
    )
    page = context.new_page()
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
        page.wait_for_timeout(2500)
        body_text = ""
        try:
            body_text = page.locator("body").inner_text(timeout=3000)
        except Exception:
            body_text = ""
        if access_code and ("请输入提取码" in page.title() or "请输入提取码" in body_text):
            inputs = page.locator("input")
            for index in range(inputs.count()):
                candidate = inputs.nth(index)
                try:
                    if candidate.bounding_box(timeout=1000) and (candidate.get_attribute("type") or "text") != "hidden":
                        candidate.fill(access_code, timeout=3000)
                        break
                except Exception:
                    continue
            for selector in (".submit-btn", ".submit-btn-text", "text=提取文件"):
                try:
                    button = page.locator(selector)
                    if button.count():
                        button.first.click(timeout=5000)
                        break
                except Exception:
                    continue
        page.wait_for_timeout(wait_seconds * 1000)
        html = page.content()
        payload = _baidupan_initial_payload(html)
        root_items = payload.get("list") if isinstance(payload.get("list"), list) else payload.get("file_list")
        root_items = root_items if isinstance(root_items, list) else []
        if not root_items:
            return []
        share_uk = str(payload.get("share_uk") or "")
        shareid = str(payload.get("shareid") or "")
        browser_state = page.evaluate(
            """() => {
                const keys = [];
                for (let index = 0; index < localStorage.length; index += 1) {
                    const key = localStorage.key(index);
                    if (key && key.endsWith('_bdclnd')) {
                        keys.push(localStorage.getItem(key));
                    }
                }
                return {
                    sekey: keys.length ? decodeURIComponent(keys[0] || '') : '',
                    share_uk: window.yunData?.share_uk || '',
                    shareid: window.yunData?.shareid || ''
                };
            }"""
        )
        sekey = str(browser_state.get("sekey") or "")
        share_uk = share_uk or str(browser_state.get("share_uk") or "")
        shareid = shareid or str(browser_state.get("shareid") or "")

        def normalize_item(item: dict[str, Any], depth: int) -> dict[str, Any]:
            return {
                "name": str(item.get("server_filename") or item.get("name") or "").strip(),
                "path": str(item.get("path") or "").strip(),
                "size": int(item.get("size") or 0),
                "is_dir": bool(int(item.get("isdir") or 0)),
                "depth": depth,
            }

        entries: list[dict[str, Any]] = []
        queue: list[tuple[dict[str, Any], int]] = [(item, 0) for item in root_items if isinstance(item, dict)]
        while queue and len(entries) < max_items:
            item, depth = queue.pop(0)
            normalized = normalize_item(item, depth)
            if not normalized["name"]:
                continue
            entries.append(normalized)
            if not normalized["is_dir"] or depth >= max_depth or not normalized["path"] or not sekey or not share_uk or not shareid:
                continue
            response = page.evaluate(
                """async (args) => {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), args.timeout_ms);
                    const params = new URLSearchParams({
                        is_from_web: 'true',
                        sekey: args.sekey,
                        uk: String(args.share_uk),
                        shareid: String(args.shareid),
                        web: '1',
                        order: 'other',
                        desc: '1',
                        showempty: '0',
                        page: '1',
                        num: '100',
                        dir: args.path,
                        t: String(Date.now()),
                        channel: 'chunlei',
                        app_id: '250528',
                        bdstoken: '',
                        clienttype: '0'
                    });
                    try {
                        const result = await fetch('/share/list?' + params.toString(), {
                            credentials: 'include',
                            headers: {'X-Requested-With': 'XMLHttpRequest'},
                            signal: controller.signal
                        });
                        return await result.json();
                    } catch (error) {
                        return {errno: -1, error: String(error && error.message ? error.message : error)};
                    } finally {
                        clearTimeout(timer);
                    }
                }""",
                {
                    "sekey": sekey,
                    "share_uk": share_uk,
                    "shareid": shareid,
                    "path": normalized["path"],
                    "timeout_ms": timeout_seconds * 1000,
                },
            )
            if int(response.get("errno", -1)) != 0:
                continue
            for child in response.get("list") or []:
                if isinstance(child, dict):
                    queue.append((child, depth + 1))
        return entries[:max_items]
    finally:
        try:
            context.close()
        except Exception:
            pass


def _read_http_error(exc: HTTPError) -> tuple[dict[str, Any], str]:
    try:
        text = exc.read().decode("utf-8", errors="replace")
    except Exception:
        text = ""
    try:
        payload = json.loads(text or "{}")
    except json.JSONDecodeError:
        payload = {}
    return payload if isinstance(payload, dict) else {}, text


def _unavailable_state_from_payload(payload: dict[str, Any], status_code: int = 0) -> tuple[str, str] | None:
    code = str(payload.get("code") or payload.get("status") or "")
    message = str(payload.get("message") or payload.get("msg") or "")
    lowered = f"{code} {message}".lower()
    if status_code in {404, 410} or code in {"41011", "41012"}:
        return "removed", message
    if status_code in {401, 403}:
        return "forbidden", message
    if any(token in lowered for token in ("not found", "expired", "cancel", "deleted", "invalid share")):
        return "removed", message
    if any(token in lowered for token in ("forbidden", "permission", "unauthorized")):
        return "forbidden", message
    return None


def _json_http_request(
    opener: Any,
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    request_headers = {
        "User-Agent": _HTTP_USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        **(headers or {}),
    }
    body = None
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = Request(url, data=body, headers=request_headers, method=method)
    try:
        with opener.open(request, timeout=timeout_seconds) as response:  # noqa: S310
            text = response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        error_payload, error_text = _read_http_error(exc)
        state = _unavailable_state_from_payload(error_payload, exc.code)
        if state:
            raise NetdiskShareUnavailable(*state) from exc
        raise RuntimeError(error_text or str(exc)) from exc
    data = json.loads(text or "{}")
    if not isinstance(data, dict):
        return {}
    state = _unavailable_state_from_payload(data)
    if state:
        raise NetdiskShareUnavailable(*state)
    return data


def _extract_share_path_id(url: str, marker: str) -> str:
    parsed = urlparse(url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    for index, segment in enumerate(segments[:-1]):
        if segment == marker:
            return segments[index + 1]
    return ""


def _extract_quark_fragment_id(url: str) -> str:
    segments = [segment for segment in urlparse(url).fragment.split("/") if segment]
    for index, segment in enumerate(segments[:-1]):
        if segment == "share":
            return segments[index + 1]
    return ""


def fetch_aliyundrive_share_file_entries(
    url: str,
    *,
    access_code: str = "",
    max_depth: int = 4,
    max_items: int = 120,
    timeout_seconds: int = 20,
) -> list[dict[str, Any]]:
    share_id = _extract_share_path_id(url, "s")
    if not share_id:
        return []
    selected_folder_id = _extract_share_path_id(url, "folder")
    opener = build_opener()
    token_payload = _json_http_request(
        opener,
        "https://api.aliyundrive.com/v2/share_link/get_share_token",
        method="POST",
        payload={"share_id": share_id, "share_pwd": access_code or ""},
        headers={"Referer": url, "Origin": "https://www.aliyundrive.com"},
        timeout_seconds=timeout_seconds,
    )
    token_data = token_payload.get("data") if isinstance(token_payload.get("data"), dict) else token_payload
    share_token = str((token_data or {}).get("share_token") or "")
    if not share_token:
        return []

    def list_parent(parent_file_id: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        marker = ""
        while len(items) < max_items:
            payload = {
                "share_id": share_id,
                "parent_file_id": parent_file_id,
                "limit": 100,
                "order_by": "name",
                "order_direction": "ASC",
            }
            if marker:
                payload["marker"] = marker
            response = _json_http_request(
                opener,
                "https://api.aliyundrive.com/adrive/v2/file/list_by_share",
                method="POST",
                payload=payload,
                headers={
                    "Referer": url,
                    "Origin": "https://www.aliyundrive.com",
                    "x-share-token": share_token,
                },
                timeout_seconds=timeout_seconds,
            )
            batch = response.get("items") if isinstance(response.get("items"), list) else []
            items.extend(item for item in batch if isinstance(item, dict))
            marker = str(response.get("next_marker") or "")
            if not marker or not batch:
                break
        return items[:max_items]

    def normalize_item(item: dict[str, Any], parent_path: str, depth: int) -> dict[str, Any] | None:
        name = str(item.get("name") or item.get("file_name") or "").strip()
        if not name:
            return None
        path = f"{parent_path}/{name}" if parent_path else name
        return {
            "name": name,
            "path": path,
            "size": int(item.get("size") or 0),
            "is_dir": str(item.get("type") or "").lower() == "folder",
            "depth": depth,
            "file_id": str(item.get("file_id") or ""),
        }

    def walk(parent_file_id: str, parent_path: str = "", start_depth: int = 0) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        queue: list[tuple[str, str, int]] = [(parent_file_id, parent_path, start_depth)]
        seen_parents: set[str] = set()
        while queue and len(entries) < max_items:
            current_parent, current_path, depth = queue.pop(0)
            if current_parent in seen_parents or depth > max_depth:
                continue
            seen_parents.add(current_parent)
            for item in list_parent(current_parent):
                normalized = normalize_item(item, current_path, depth)
                if not normalized:
                    continue
                entries.append(normalized)
                if len(entries) >= max_items:
                    break
                if normalized["is_dir"] and normalized["file_id"] and depth < max_depth:
                    queue.append((normalized["file_id"], normalized["path"], depth + 1))
        return entries[:max_items]

    if selected_folder_id:
        selected_entries = walk(selected_folder_id)
        if selected_entries:
            return selected_entries
    return walk("root")


def fetch_quark_share_file_entries(
    url: str,
    *,
    access_code: str = "",
    max_depth: int = 4,
    max_items: int = 120,
    timeout_seconds: int = 20,
) -> list[dict[str, Any]]:
    share_id = _extract_share_path_id(url, "s")
    if not share_id:
        return []
    selected_fragment_id = _extract_quark_fragment_id(url)
    opener = build_opener(HTTPCookieProcessor())
    opener.open(Request(url, headers={"User-Agent": _HTTP_USER_AGENT}), timeout=timeout_seconds)  # noqa: S310
    token_payload = _json_http_request(
        opener,
        "https://pan.quark.cn/1/clouddrive/share/sharepage/token",
        method="POST",
        payload={"pwd_id": share_id, "passcode": access_code or ""},
        headers={"Referer": url, "Origin": "https://pan.quark.cn"},
        timeout_seconds=timeout_seconds,
    )
    token_data = token_payload.get("data") if isinstance(token_payload.get("data"), dict) else {}
    stoken = str(token_data.get("stoken") or token_data.get("st") or "")
    if not stoken:
        return []

    def list_parent(parent_fid: str, *, include_share: bool = False) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        page_size = 100
        while len(items) < max_items:
            params = {
                "pwd_id": share_id,
                "stoken": stoken,
                "pdir_fid": parent_fid,
                "force": "0",
                "_page": str(page),
                "_size": str(page_size),
                "_fetch_banner": "1" if include_share else "0",
                "_fetch_share": "1" if include_share else "0",
                "_fetch_total": "1",
                "fetch_sub_file_cnt": "1",
                "_sort": "",
                "ver": "2",
                "format": "png",
                "support_visit_limit_private_share": "true",
                "fetch_share_full_path": "0",
            }
            query = urlencode(params)
            response = _json_http_request(
                opener,
                f"https://pan.quark.cn/1/clouddrive/share/sharepage/detail?{query}",
                headers={"Referer": url, "Origin": "https://pan.quark.cn"},
                timeout_seconds=timeout_seconds,
            )
            data = response.get("data") if isinstance(response.get("data"), dict) else {}
            batch = data.get("list") if isinstance(data.get("list"), list) else []
            items.extend(item for item in batch if isinstance(item, dict))
            if len(batch) < page_size:
                break
            page += 1
        return items[:max_items]

    def normalize_item(item: dict[str, Any], parent_path: str, depth: int) -> dict[str, Any] | None:
        name = str(item.get("file_name") or item.get("name") or "").strip()
        if not name:
            return None
        path = f"{parent_path}/{name}" if parent_path else name
        return {
            "name": name,
            "path": path,
            "size": int(item.get("size") or 0),
            "is_dir": bool(item.get("dir")) and not bool(item.get("file")),
            "depth": depth,
            "fid": str(item.get("fid") or ""),
            "share_fid_token": str(item.get("share_fid_token") or ""),
        }

    def walk(seed_items: list[dict[str, Any]], parent_path: str = "", start_depth: int = 0) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        queue: list[tuple[str, str, int]] = []
        seen_fids: set[str] = set()
        for item in seed_items:
            normalized = normalize_item(item, parent_path, start_depth)
            if not normalized:
                continue
            entries.append(normalized)
            if normalized["is_dir"] and normalized["fid"] and start_depth < max_depth:
                queue.append((normalized["fid"], normalized["path"], start_depth + 1))
        while queue and len(entries) < max_items:
            fid, current_path, depth = queue.pop(0)
            if fid in seen_fids or depth > max_depth:
                continue
            seen_fids.add(fid)
            for child in list_parent(fid):
                normalized = normalize_item(child, current_path, depth)
                if not normalized:
                    continue
                entries.append(normalized)
                if len(entries) >= max_items:
                    break
                if normalized["is_dir"] and normalized["fid"] and depth < max_depth:
                    queue.append((normalized["fid"], normalized["path"], depth + 1))
        return entries[:max_items]

    root_items = list_parent("0", include_share=True)
    if selected_fragment_id:
        for item in root_items:
            if selected_fragment_id in {str(item.get("fid") or ""), str(item.get("share_fid_token") or "")}:
                return walk([item])
    return walk(root_items)


atexit.register(lambda: close_session_browser(all_threads=True))
