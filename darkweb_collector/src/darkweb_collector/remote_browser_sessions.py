from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import json
import os
from queue import Empty, Full, Queue
import shutil
import socket
import subprocess
from threading import Lock, Thread
import time
from typing import Any
from uuid import uuid4

from darkweb_collector.chaojiying import chaojiying_configured, recognize_captcha, report_recognition_error
from darkweb_collector.db import get_db_connection, upsert_platform_session
from darkweb_collector.document_exposure_platforms import get_exposure_platform
from darkweb_collector.document_exposure_sessions import (
    platform_profile_dir,
    platform_storage_state_path,
    platform_user_data_dir,
)
from darkweb_collector.tor_fetch import browser_proxy_server_for_url, is_onion_url


REMOTE_LOGIN_VIEWPORT = {"width": 1024, "height": 675}
_REMOTE_SESSIONS: dict[str, "RemoteBrowserSession"] = {}
_REMOTE_SESSIONS_LOCK = Lock()

USERNAME_SELECTORS = [
    "input#login_field",
    "input#user_login",
    "input[name='login']",
    "input[name='username']",
    "input[name='user[login]']",
    "input[name='account']",
    "input[name='email']",
    "input[type='email']",
    "input[autocomplete='username']",
    "input[autocomplete='email']",
    "input[placeholder*='账号']",
    "input[placeholder*='用户名']",
    "input[placeholder*='邮箱']",
    "input[placeholder*='Email']",
    "input[placeholder*='Username']",
    "input[type='text']",
]
PASSWORD_SELECTORS = [
    "input#password",
    "input[name='password']",
    "input[type='password']",
    "input[autocomplete='current-password']",
]
CAPTCHA_INPUT_SELECTORS = [
    "input[placeholder*='验证码']",
    "input[aria-label*='验证码']",
    "input[name*='captcha']",
    "input[id*='captcha']",
    "input[name*='verify']",
    "input[id*='verify']",
    "input[name*='code']",
    "input[id*='code']",
]
CAPTCHA_IMAGE_SELECTORS = [
    "img[alt*='验证码']",
    "img[title*='验证码']",
    "img[name*='captcha']",
    "img[id*='captcha']",
    "img[class*='captcha']",
    "img[src*='captcha']",
    "img[src*='verify']",
    "img[src*='checkcode']",
    "img[src*='validcode']",
    "img[src*='authcode']",
]
OTP_SELECTORS = [
    "input[name*='otp']",
    "input[name*='code']",
    "input[id*='otp']",
    "input[id*='code']",
    "input[autocomplete='one-time-code']",
    "input[placeholder*='验证码']",
    "input[placeholder*='验证']",
    "input[placeholder*='code']",
]
SUBMIT_SELECTORS = [
    "button[type='submit']",
    "input[type='submit']",
    "button:has-text('Sign in')",
    "button:has-text('Log in')",
    "button:has-text('登录')",
    "button:has-text('登入')",
    "button:has-text('下一步')",
    "button:has-text('Continue')",
    "button:has-text('Next')",
]


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _find_free_display() -> str:
    for display_number in range(90, 140):
        socket_path = f"/tmp/.X11-unix/X{display_number}"
        if not os.path.exists(socket_path):
            return f":{display_number}"
    raise RuntimeError("no free X display was found for embedded browser")


def _require_linux_embedded_runtime() -> None:
    missing = [name for name in ("Xvfb", "x11vnc") if shutil.which(name) is None]
    if missing:
        raise RuntimeError(
            "embedded browser runtime is missing: "
            + ", ".join(missing)
            + ". Install xvfb and x11vnc on Linux."
        )


def _wait_for_x_display(display: str, process: subprocess.Popen) -> None:
    display_number = display.lstrip(":").split(".", 1)[0]
    socket_path = f"/tmp/.X11-unix/X{display_number}"
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Xvfb exited before the embedded browser display became ready")
        if os.path.exists(socket_path):
            return
        time.sleep(0.1)
    raise RuntimeError("embedded browser display did not become ready")


def _wait_for_tcp_port(port: int, process: subprocess.Popen) -> None:
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError("x11vnc exited before the VNC port became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("embedded browser VNC port did not become ready")


def _terminate_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=4)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


def _browser_child_environment() -> dict[str, str]:
    env = os.environ.copy()
    for name in ("DARKWEB_GITHUB_TOKEN", "DARKWEB_GITHUB_TOKEN_FILE", "GITHUB_TOKEN", "GH_TOKEN"):
        env.pop(name, None)
    return env


def _start_embedded_display(session: "RemoteBrowserSession") -> None:
    _require_linux_embedded_runtime()
    session.display = _find_free_display()
    session.vnc_port = _find_free_tcp_port()
    env = _browser_child_environment()
    env["DISPLAY"] = session.display

    session.xvfb_process = subprocess.Popen(
        [
            "Xvfb",
            session.display,
            "-screen",
            "0",
            f"{REMOTE_LOGIN_VIEWPORT['width']}x{REMOTE_LOGIN_VIEWPORT['height']}x24",
            "-nolisten",
            "tcp",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    _wait_for_x_display(session.display, session.xvfb_process)

    if shutil.which("openbox") is not None:
        session.window_manager_process = subprocess.Popen(
            ["openbox"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        )

    session.vnc_process = subprocess.Popen(
        [
            "x11vnc",
            "-display",
            session.display,
            "-localhost",
            "-nopw",
            "-forever",
            "-shared",
            "-rfbport",
            str(session.vnc_port),
            "-quiet",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    _wait_for_tcp_port(session.vnc_port, session.vnc_process)


def _stop_embedded_display(session: "RemoteBrowserSession") -> None:
    _terminate_process(session.vnc_process)
    _terminate_process(session.window_manager_process)
    _terminate_process(session.xvfb_process)
    session.vnc_process = None
    session.window_manager_process = None
    session.xvfb_process = None


@dataclass
class RemoteBrowserSession:
    session_id: str
    platform: str
    label: str
    login_url: str
    homepage_url: str
    requires_login: bool
    storage_state_path: str
    user_data_dir: str
    created_at: str
    commands: Queue
    thread: Thread | None = None
    display: str = ""
    vnc_port: int = 0
    xvfb_process: subprocess.Popen | None = None
    window_manager_process: subprocess.Popen | None = None
    vnc_process: subprocess.Popen | None = None
    cdp_stream: bool = False
    last_error: str = ""
    last_captcha_pic_id: str = ""
    last_captcha_reported: bool = False


def _state_payload(
    session: RemoteBrowserSession,
    page: Any,
    *,
    include_screenshot: bool = True,
) -> dict[str, Any]:
    title = ""
    url = ""
    screenshot = ""
    try:
        title = str(page.title() or "")
    except Exception:
        title = ""
    try:
        url = str(page.url or "")
    except Exception:
        url = ""
    cdp_stream = bool(getattr(session, "cdp_stream", False))
    if include_screenshot and not cdp_stream:
        try:
            png = page.screenshot(type="png", full_page=False)
            screenshot = "data:image/png;base64," + base64.b64encode(png).decode("ascii")
        except Exception as exc:
            if not session.last_error:
                session.last_error = str(exc)
    return {
        "session_id": session.session_id,
        "platform": session.platform,
        "label": session.label,
        "mode": "embedded_browser" if session.vnc_port or cdp_stream else "headless_control",
        "title": title,
        "url": url,
        "login_url": session.login_url,
        "homepage_url": session.homepage_url,
        "screenshot": screenshot,
        "rfb_ws_path": f"/api/platform-sessions/remote-login/{session.session_id}/rfb" if session.vnc_port else "",
        "stream_ws_path": f"/api/platform-sessions/remote-login/{session.session_id}/stream" if cdp_stream else "",
        "viewport": dict(REMOTE_LOGIN_VIEWPORT),
        "storage_state_path": session.storage_state_path,
        "user_data_dir": session.user_data_dir,
        "created_at": session.created_at,
        "last_error": session.last_error,
        "captcha_recognition_available": chaojiying_configured(),
        "captcha_error_report_available": bool(
            getattr(session, "last_captcha_pic_id", "")
            and not getattr(session, "last_captcha_reported", False)
        ),
    }


def _navigate_remote_page(session: RemoteBrowserSession, page: Any, url: str) -> bool:
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=45000)
    except Exception as exc:
        session.last_error = str(exc)
        return False
    session.last_error = ""
    return True


def _save_platform_session(session: RemoteBrowserSession, account_label: str) -> dict[str, Any]:
    updated_at = _now_utc_iso()
    metadata = {
        "remote_browser_session": True,
        "remote_session_id": session.session_id,
        "remote_browser_mode": "embedded_browser" if session.vnc_port or session.cdp_stream else "headless_control",
        "user_data_dir": session.user_data_dir,
        "saved_at": updated_at,
    }
    with get_db_connection() as connection:
        upsert_platform_session(
            connection,
            {
                "platform": session.platform,
                "account_label": str(account_label or "").strip(),
                "login_url": session.login_url,
                "homepage_url": session.homepage_url,
                "requires_login": session.requires_login,
                "status": "valid" if session.platform == "changan" else "configured",
                "storage_state_path": session.storage_state_path,
                "last_verified_at": updated_at,
                "last_error": "",
                "metadata_json": json.dumps(metadata, ensure_ascii=False),
                "updated_at": updated_at,
            },
        )
        connection.commit()
    return {
        "platform": session.platform,
        "status": "valid" if session.platform == "changan" else "configured",
        "valid": True,
        "storage_state_path": session.storage_state_path,
        "last_verified_at": updated_at,
        "metadata": metadata,
    }


def _validate_session_before_save(session: RemoteBrowserSession, page: Any) -> None:
    if session.platform != "changan":
        return
    probe = page.evaluate(
        """
        async () => {
          const token = String(localStorage.getItem('token') || '').trim();
          if (!token || token.startsWith('noLogin_')) {
            return { valid: false, code: 0, message: '尚未完成账号登录' };
          }
          try {
            const response = await fetch(
              '/api/category/goods?cid=0&page_num=1&page_size=1&order=&order_by=',
              {
                method: 'GET',
                headers: {
                  Accept: 'application/json',
                  Authorization: `Bearer ${token}`,
                },
              },
            );
            const payload = await response.json();
            const code = Number(payload?.code || 0);
            return {
              valid: response.ok && code === 2000,
              code,
              message: String(payload?.msg || ''),
            };
          } catch (error) {
            return { valid: false, code: 0, message: String(error || '会话校验失败') };
          }
        }
        """
    )
    if not isinstance(probe, dict) or not probe.get("valid"):
        code = int((probe or {}).get("code") or 0) if isinstance(probe, dict) else 0
        message = str((probe or {}).get("message") or "尚未进入登录后的站内页面") if isinstance(probe, dict) else "尚未进入登录后的站内页面"
        suffix = f"（接口代码 {code}）" if code else ""
        raise ValueError(f"长安不夜城登录会话校验失败：{message}{suffix}")


def _remote_browser_worker(session: RemoteBrowserSession, startup_queue: Queue) -> None:
    playwright = None
    context = None
    cdp_session = None
    stream_clients: dict[str, Queue] = {}

    def stop_cdp_stream() -> None:
        nonlocal cdp_session
        if cdp_session is None:
            return
        try:
            cdp_session.send("Page.stopScreencast")
        except Exception:
            pass
        try:
            cdp_session.detach()
        except Exception:
            pass
        cdp_session = None

    def publish_frame(event: dict[str, Any]) -> None:
        if cdp_session is None:
            return
        frame_session_id = int(event.get("sessionId") or 0)
        try:
            cdp_session.send("Page.screencastFrameAck", {"sessionId": frame_session_id})
        except Exception:
            pass
        metadata = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
        frame = {
            "type": "frame",
            "data": str(event.get("data") or ""),
            "width": int(metadata.get("deviceWidth") or REMOTE_LOGIN_VIEWPORT["width"]),
            "height": int(metadata.get("deviceHeight") or REMOTE_LOGIN_VIEWPORT["height"]),
        }
        for frame_queue in list(stream_clients.values()):
            try:
                frame_queue.put_nowait(frame)
            except Full:
                try:
                    frame_queue.get_nowait()
                except Empty:
                    pass
                try:
                    frame_queue.put_nowait(frame)
                except Full:
                    pass

    def start_cdp_stream(page: Any) -> None:
        nonlocal cdp_session
        if cdp_session is not None:
            return
        cdp_session = context.new_cdp_session(page)
        cdp_session.on("Page.screencastFrame", publish_frame)
        cdp_session.send("Page.enable")
        cdp_session.send(
            "Page.startScreencast",
            {
                "format": "jpeg",
                "quality": 72,
                "maxWidth": REMOTE_LOGIN_VIEWPORT["width"],
                "maxHeight": REMOTE_LOGIN_VIEWPORT["height"],
                "everyNthFrame": 1,
            },
        )

    try:
        from playwright.sync_api import sync_playwright
        from darkweb_collector.browser_temp import ensure_browser_temp

        ensure_browser_temp()
        playwright = sync_playwright().start()
        browser_env = _browser_child_environment()
        if session.display:
            browser_env["DISPLAY"] = session.display
        launch_kwargs: dict[str, Any] = {
            "headless": not bool(session.display),
            "viewport": dict(REMOTE_LOGIN_VIEWPORT),
            "screen": dict(REMOTE_LOGIN_VIEWPORT),
            "env": browser_env,
            "ignore_https_errors": True,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--disable-dev-shm-usage",
                "--no-sandbox",
                "--window-position=0,0",
                f"--window-size={REMOTE_LOGIN_VIEWPORT['width']},{REMOTE_LOGIN_VIEWPORT['height']}",
            ],
        }
        if is_onion_url(session.login_url or session.homepage_url):
            proxy_server = browser_proxy_server_for_url(session.login_url or session.homepage_url)
            if proxy_server:
                launch_kwargs["proxy"] = {"server": proxy_server}
        context = playwright.chromium.launch_persistent_context(session.user_data_dir, **launch_kwargs)
        page = context.pages[0] if context.pages else context.new_page()
        _navigate_remote_page(session, page, session.login_url or session.homepage_url)
        startup_queue.put(("ok", _state_payload(session, page)))

        while True:
            try:
                command = session.commands.get(timeout=0.04 if stream_clients else None)
            except Empty:
                page.wait_for_timeout(10)
                continue
            op = str(command.get("op") or "")
            payload = command.get("payload") or {}
            response_queue = command["response_queue"]
            should_stop = False
            try:
                if op == "state":
                    result = _state_payload(session, page)
                elif op == "control":
                    result = _apply_remote_action(session, page, payload)
                elif op == "stream_open":
                    if not session.cdp_stream:
                        raise ValueError("CDP browser streaming is not enabled for this session")
                    stream_id = uuid4().hex
                    frame_queue: Queue = Queue(maxsize=2)
                    stream_clients[stream_id] = frame_queue
                    start_cdp_stream(page)
                    result = {"stream_id": stream_id, "frame_queue": frame_queue}
                elif op == "stream_input":
                    _apply_stream_input(page, payload)
                    result = {"accepted": True}
                elif op == "stream_close":
                    stream_clients.pop(str(payload.get("stream_id") or ""), None)
                    if not stream_clients:
                        stop_cdp_stream()
                    result = {"closed": True}
                elif op == "finish":
                    _validate_session_before_save(session, page)
                    context.storage_state(path=session.storage_state_path)
                    result = _save_platform_session(session, str(payload.get("account_label") or ""))
                    should_stop = True
                elif op == "close":
                    result = {"session_id": session.session_id, "platform": session.platform, "status": "closed"}
                    should_stop = True
                else:
                    raise ValueError(f"unsupported remote browser op: {op}")
                response_queue.put(("ok", result))
            except Exception as exc:
                response_queue.put(("error", str(exc)))
            if should_stop:
                break
    except Exception as exc:
        startup_queue.put(("error", str(exc)))
    finally:
        stop_cdp_stream()
        if context is not None:
            try:
                context.storage_state(path=session.storage_state_path)
            except Exception:
                pass
            try:
                context.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                playwright.stop()
            except Exception:
                pass
        _stop_embedded_display(session)


def _apply_stream_input(page: Any, payload: dict[str, Any]) -> None:
    event_type = str(payload.get("type") or "").strip().lower()
    action = str(payload.get("action") or payload.get("event") or "").strip().lower()
    if event_type in {"mouse", "pointer"}:
        x = float(payload.get("x") or 0)
        y = float(payload.get("y") or 0)
        button = str(payload.get("button") or "left").strip().lower()
        if action == "move":
            page.mouse.move(x, y)
        elif action == "down":
            page.mouse.move(x, y)
            page.mouse.down(button=button)
        elif action == "up":
            page.mouse.move(x, y)
            page.mouse.up(button=button)
        elif action == "click":
            page.mouse.click(x, y, button=button)
        elif action == "wheel":
            page.mouse.wheel(
                float(payload.get("deltaX") or payload.get("delta_x") or 0),
                float(payload.get("deltaY") or payload.get("delta_y") or 0),
            )
        else:
            raise ValueError(f"unsupported pointer action: {action}")
    elif event_type == "key":
        key = str(payload.get("key") or "").strip()
        text = str(payload.get("text") or "")
        if text and action == "down" and len(text) == 1:
            page.keyboard.insert_text(text)
            return
        if not key:
            raise ValueError("key is required")
        if action == "down":
            page.keyboard.down(key)
        elif action == "up":
            page.keyboard.up(key)
        elif action == "press":
            page.keyboard.press(key)
        else:
            raise ValueError(f"unsupported key action: {action}")
    elif event_type == "text":
        page.keyboard.insert_text(str(payload.get("text") or ""))
    elif event_type == "navigate":
        url = str(payload.get("url") or "").strip()
        if url:
            page.goto(url, wait_until="domcontentloaded", timeout=45000)
    elif event_type == "reload":
        page.reload(wait_until="domcontentloaded", timeout=45000)
    else:
        raise ValueError(f"unsupported stream input type: {event_type}")


def _apply_remote_action(session: RemoteBrowserSession, page: Any, payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "").strip().lower()
    if action == "click":
        page.mouse.click(float(payload.get("x") or 0), float(payload.get("y") or 0))
    elif action == "type":
        text = str(payload.get("text") or "")
        if text:
            page.keyboard.type(text, delay=20)
    elif action == "key":
        key = str(payload.get("key") or "").strip()
        if key:
            page.keyboard.press(key)
    elif action == "navigate":
        url = str(payload.get("url") or "").strip()
        if url:
            _navigate_remote_page(session, page, url)
    elif action == "wait":
        page.wait_for_timeout(int(payload.get("ms") or 1000))
    elif action == "fill_login_form":
        result = _fill_login_form(page, payload)
        page.wait_for_timeout(500)
        state = _state_payload(session, page)
        state["action_result"] = result
        return state
    elif action == "submit_login_form":
        result = _submit_login_form(page)
        page.wait_for_timeout(1200)
        state = _state_payload(session, page)
        state["action_result"] = result
        return state
    elif action == "solve_captcha":
        result = _solve_captcha(page)
        session.last_captcha_pic_id = str(result.get("pic_id") or "")
        session.last_captcha_reported = False
        page.wait_for_timeout(300)
        state = _state_payload(session, page)
        state["action_result"] = result
        return state
    elif action == "report_captcha_error":
        if not session.last_captcha_pic_id or session.last_captcha_reported:
            raise ValueError("no unreported captcha recognition is available")
        result = report_recognition_error(session.last_captcha_pic_id)
        session.last_captcha_reported = True
        state = _state_payload(session, page)
        state["action_result"] = result
        return state
    else:
        raise ValueError(f"unsupported remote browser action: {action}")
    page.wait_for_timeout(500)
    return _state_payload(session, page)


def _first_editable_locator(page: Any, selectors: list[str]) -> Any | None:
    for selector in selectors:
        try:
            locator = page.locator(selector)
            count = min(locator.count(), 6)
        except Exception:
            continue
        for index in range(count):
            item = locator.nth(index)
            try:
                if item.is_visible() and item.is_enabled():
                    return item
            except Exception:
                continue
    return None


def _first_visible_locator(page: Any, selectors: list[str]) -> tuple[Any, Any] | tuple[None, None]:
    scopes = [page]
    for frame in list(getattr(page, "frames", []) or []):
        if frame is not page:
            scopes.append(frame)
    for scope in scopes:
        for selector in selectors:
            try:
                locator = scope.locator(selector)
                count = min(locator.count(), 8)
            except Exception:
                continue
            for index in range(count):
                item = locator.nth(index)
                try:
                    if item.is_visible():
                        return scope, item
                except Exception:
                    continue
    return None, None


def _fill_first_available(page: Any, selectors: list[str], value: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    locator = _first_editable_locator(page, selectors)
    if locator is None:
        return False
    locator.fill(text)
    return True


def _fill_login_form(page: Any, payload: dict[str, Any]) -> dict[str, Any]:
    username_filled = _fill_first_available(page, USERNAME_SELECTORS, str(payload.get("username") or ""))
    password_filled = _fill_first_available(page, PASSWORD_SELECTORS, str(payload.get("password") or ""))
    otp = str(payload.get("otp") or "")
    otp_filled = _fill_first_available(page, OTP_SELECTORS, otp) if otp else False
    if not username_filled and not password_filled and not otp_filled:
        raise ValueError("no supported login input was found on the current page")
    return {
        "username_filled": username_filled,
        "password_filled": password_filled,
        "otp_filled": otp_filled,
    }


def _solve_captcha(page: Any) -> dict[str, Any]:
    scope, image = _first_visible_locator(page, CAPTCHA_IMAGE_SELECTORS)
    if image is None or scope is None:
        raise ValueError("no supported image captcha was found on the current page")
    captcha_input = _first_editable_locator(scope, CAPTCHA_INPUT_SELECTORS)
    if captcha_input is None:
        raise ValueError("captcha input was not found on the current page")
    image_bytes = image.screenshot(type="png")
    result = recognize_captcha(image_bytes)
    captcha_input.fill(str(result["pic_str"]))
    return {
        "captcha_filled": True,
        "pic_id": str(result.get("pic_id") or ""),
    }


def _submit_login_form(page: Any) -> dict[str, Any]:
    locator = _first_editable_locator(page, SUBMIT_SELECTORS)
    if locator is not None:
        locator.click()
        return {"submitted": True, "method": "button"}
    page.keyboard.press("Enter")
    return {"submitted": True, "method": "enter"}


def _get_remote_session(session_id: str) -> RemoteBrowserSession:
    with _REMOTE_SESSIONS_LOCK:
        session = _REMOTE_SESSIONS.get(str(session_id or "").strip())
    if session is None:
        raise ValueError("remote browser session not found")
    return session


def _call_session(session: RemoteBrowserSession, op: str, payload: dict[str, Any] | None = None) -> Any:
    response_queue: Queue = Queue(maxsize=1)
    session.commands.put({"op": op, "payload": payload or {}, "response_queue": response_queue})
    status, result = response_queue.get(timeout=70)
    if status == "error":
        raise ValueError(str(result))
    return result


def _remove_session_keys(session: RemoteBrowserSession) -> None:
    with _REMOTE_SESSIONS_LOCK:
        _REMOTE_SESSIONS.pop(session.session_id, None)
        current = _REMOTE_SESSIONS.get(session.platform)
        if current is session:
            _REMOTE_SESSIONS.pop(session.platform, None)


def start_remote_browser_login(platform_name: str) -> dict[str, Any]:
    platform = get_exposure_platform(platform_name)
    profile_dir = platform_profile_dir(platform.key)
    profile_dir.mkdir(parents=True, exist_ok=True)
    user_data_dir = platform_user_data_dir(platform.key)
    user_data_dir.mkdir(parents=True, exist_ok=True)
    storage_state_path = platform_storage_state_path(platform.key)
    storage_state_path.parent.mkdir(parents=True, exist_ok=True)

    with _REMOTE_SESSIONS_LOCK:
        previous = _REMOTE_SESSIONS.pop(platform.key, None)
        if previous is not None:
            _REMOTE_SESSIONS.pop(previous.session_id, None)
    if previous is not None:
        try:
            _call_session(previous, "close")
        except Exception:
            pass

    startup_queue: Queue = Queue(maxsize=1)
    session = RemoteBrowserSession(
        session_id=uuid4().hex,
        platform=platform.key,
        label=platform.label,
        login_url=platform.login_url or platform.homepage_url,
        homepage_url=platform.homepage_url,
        requires_login=platform.requires_login,
        storage_state_path=str(storage_state_path),
        user_data_dir=str(user_data_dir),
        created_at=_now_utc_iso(),
        commands=Queue(),
        cdp_stream=os.name == "nt",
    )
    if os.name != "nt":
        try:
            _start_embedded_display(session)
        except Exception:
            _stop_embedded_display(session)
            raise

    thread = Thread(target=_remote_browser_worker, args=(session, startup_queue), daemon=True)
    session.thread = thread
    thread.start()
    status, result = startup_queue.get(timeout=70)
    if status == "error":
        raise ValueError(str(result))
    with _REMOTE_SESSIONS_LOCK:
        _REMOTE_SESSIONS[session.session_id] = session
        _REMOTE_SESSIONS[session.platform] = session
    return result


def get_remote_browser_state(session_id: str) -> dict[str, Any]:
    return _call_session(_get_remote_session(session_id), "state")


def control_remote_browser(session_id: str, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = dict(payload or {})
    body["action"] = action
    return _call_session(_get_remote_session(session_id), "control", body)


def finish_remote_browser_login(session_id: str, account_label: str = "") -> dict[str, Any]:
    session = _get_remote_session(session_id)
    result = _call_session(session, "finish", {"account_label": account_label})
    _remove_session_keys(session)
    return result


def close_remote_browser_login(session_id: str) -> dict[str, Any]:
    session = _get_remote_session(session_id)
    try:
        return _call_session(session, "close")
    finally:
        _remove_session_keys(session)


async def proxy_remote_browser_rfb(session_id: str, websocket: Any) -> None:
    try:
        session = _get_remote_session(session_id)
    except ValueError:
        await websocket.close(code=1008)
        return
    if not session.vnc_port:
        await websocket.close(code=1008)
        return

    protocol_header = str(websocket.headers.get("sec-websocket-protocol") or "")
    subprotocol = "binary" if "binary" in protocol_header else None
    await websocket.accept(subprotocol=subprotocol)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", session.vnc_port)
    except OSError:
        await websocket.close(code=1011)
        return

    async def websocket_to_vnc() -> None:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            data = message.get("bytes")
            if data is None and message.get("text") is not None:
                data = str(message["text"]).encode("latin-1")
            if data:
                writer.write(data)
                await writer.drain()

    async def vnc_to_websocket() -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            await websocket.send_bytes(data)

    tasks = [
        asyncio.create_task(websocket_to_vnc()),
        asyncio.create_task(vnc_to_websocket()),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


async def proxy_remote_browser_stream(session_id: str, websocket: Any) -> None:
    try:
        session = _get_remote_session(session_id)
    except ValueError:
        await websocket.close(code=1008)
        return
    if not session.cdp_stream:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        stream = await asyncio.to_thread(_call_session, session, "stream_open")
    except Exception:
        await websocket.close(code=1011)
        return
    stream_id = str(stream["stream_id"])
    frame_queue: Queue = stream["frame_queue"]
    await websocket.send_json(
        {
            "type": "ready",
            "width": REMOTE_LOGIN_VIEWPORT["width"],
            "height": REMOTE_LOGIN_VIEWPORT["height"],
        }
    )

    async def websocket_to_browser() -> None:
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break
            text = message.get("text")
            if text is None:
                continue
            try:
                payload = json.loads(str(text))
                if not isinstance(payload, dict):
                    raise ValueError("stream input must be a JSON object")
                await asyncio.to_thread(_call_session, session, "stream_input", payload)
            except Exception as exc:
                await websocket.send_json({"type": "error", "message": str(exc)})

    async def browser_to_websocket() -> None:
        while True:
            try:
                frame = frame_queue.get_nowait()
            except Empty:
                await asyncio.sleep(0.015)
                continue
            await websocket.send_json(frame)

    tasks = [
        asyncio.create_task(websocket_to_browser()),
        asyncio.create_task(browser_to_websocket()),
    ]
    try:
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            task.result()
    except Exception:
        pass
    finally:
        try:
            await asyncio.to_thread(_call_session, session, "stream_close", {"stream_id": stream_id})
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass
