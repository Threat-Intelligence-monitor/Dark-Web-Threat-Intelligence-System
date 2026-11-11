from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from threading import Lock
import tempfile
import time
from typing import Any, Iterator
from urllib.parse import urlsplit, urlunsplit

from darkweb_collector.chaojiying import (
    chaojiying_config_status,
    load_chaojiying_credentials,
    recognize_captcha,
    report_recognition_error,
    save_chaojiying_config,
)
from darkweb_collector.db import get_db_connection, get_platform_session, upsert_platform_session
from darkweb_collector.document_exposure_platforms import get_exposure_platform
from darkweb_collector.document_exposure_sessions import (
    platform_profile_dir,
    resolve_platform_storage_state_path,
)
from darkweb_collector.models import SiteConfig
from darkweb_collector.site_auth import site_auth_platform, site_auth_readiness
from darkweb_collector.tor_bridge_control import get_tor_bridge_status, start_tor_bridge
from darkweb_collector.tor_fetch import browser_proxy_server_for_url


CHAOJIYING_CODE_TYPE = "5000"
MAX_CAPTCHA_ATTEMPTS = 3
LOGIN_LOCK_TIMEOUT_SECONDS = 240
LOGIN_LOCK_STALE_SECONDS = 300
FAILED_LOGIN_RETRY_SECONDS = 300
_CONFIG_STATE_LOCK = Lock()
_CONFIG_STATE: dict[str, Any] = {
    "last_validated_at": "",
    "last_validation_success": None,
    "last_error": "",
}


class ChanganAutoLoginConfigError(ValueError):
    pass


class ChanganAutoLoginTestError(RuntimeError):
    pass


@dataclass(frozen=True)
class ChanganAutoLoginCredentials:
    chaojiying_user: str
    changan_username: str
    changan_password: str
    chaojiying_password: str = ""
    chaojiying_pass2: str = ""
    chaojiying_soft_id: str = ""


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _base_url(url: str) -> str:
    parsed = urlsplit(str(url or "").strip())
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def _parse_credentials_file(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8-sig")
    values: dict[str, str] = {}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        for key, value in payload.items():
            values[str(key).strip().upper()] = str(value or "").strip()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        assignment = re.match(r"([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.*)", line)
        if assignment:
            values[assignment.group(1).upper()] = assignment.group(2).strip().strip("\"'")
            continue
        if "超级鹰" in line:
            parts = re.split(r"[:：]", line, maxsplit=1)
            credentials = parts[1].split() if len(parts) == 2 else []
            if len(credentials) == 2:
                values["DARKWEB_CHAOJIYING_USER"] = credentials[0]
                values["DARKWEB_CHAOJIYING_PASSWORD"] = credentials[1]
            continue
        if "长安不夜城" in line:
            parts = re.split(r"[,，]", line, maxsplit=1)
            tail = parts[1].strip() if len(parts) == 2 else ""
            account = re.match(r"([^\s:：]+)\s*[:：]\s*(\S+)", tail)
            if account:
                values["DARKWEB_CHANGAN_USERNAME"] = account.group(1)
                values["DARKWEB_CHANGAN_PASSWORD"] = account.group(2)
    return values


def _credential_value(file_values: dict[str, str], *names: str) -> str:
    for name in names:
        value = str(os.environ.get(name) or file_values.get(name.upper()) or "").strip()
        if value:
            return value
    return ""


def changan_auto_login_config_path() -> Path:
    configured = str(os.environ.get("DARKWEB_CHANGAN_AUTO_LOGIN_CONFIG_FILE") or "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return platform_profile_dir("changan") / "auto_login_credentials.json"


def _load_managed_config(*, required: bool = False) -> dict[str, Any]:
    path = changan_auto_login_config_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            raise ChanganAutoLoginConfigError("尚未通过前端配置长安自动登录")
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ChanganAutoLoginConfigError("长安自动登录配置文件无法读取") from exc
    if not isinstance(payload, dict):
        raise ChanganAutoLoginConfigError("长安自动登录配置文件格式无效")
    return payload


def _credential_file_values() -> dict[str, str]:
    values: dict[str, str] = {}
    managed = _load_managed_config()
    values.update({str(key).strip().upper(): str(value or "").strip() for key, value in managed.items()})

    configured_path = str(os.environ.get("DARKWEB_CHANGAN_AUTO_LOGIN_CREDENTIALS_FILE") or "").strip()
    if configured_path:
        path = Path(configured_path).expanduser().resolve()
        if not path.is_file():
            raise ChanganAutoLoginConfigError("长安自动登录凭据文件不存在")
        if path != changan_auto_login_config_path():
            values.update(_parse_credentials_file(path))
    return values


def _auto_login_enabled() -> bool:
    environment_value = str(os.environ.get("DARKWEB_CHANGAN_AUTO_LOGIN") or "").strip().lower()
    if environment_value:
        return environment_value not in {"0", "false", "no", "off"}
    managed = _load_managed_config()
    return str(managed.get("enabled", True)).strip().lower() not in {"0", "false", "no", "off"}


def load_auto_login_credentials() -> ChanganAutoLoginCredentials:
    file_values = _credential_file_values()
    chaojiying = load_chaojiying_credentials()

    credentials = ChanganAutoLoginCredentials(
        chaojiying_user=chaojiying.user,
        chaojiying_password=chaojiying.password,
        chaojiying_pass2=chaojiying.pass2,
        chaojiying_soft_id=chaojiying.soft_id,
        changan_username=_credential_value(file_values, "DARKWEB_CHANGAN_USERNAME", "CHANGAN_USERNAME"),
        changan_password=_credential_value(file_values, "DARKWEB_CHANGAN_PASSWORD", "CHANGAN_PASSWORD"),
    )
    missing: list[str] = []
    if not credentials.changan_username:
        missing.append("Changan username")
    if not credentials.changan_password:
        missing.append("Changan password")
    if missing:
        raise ValueError(f"automatic-login credentials are incomplete: {', '.join(missing)}")
    return credentials


def changan_auto_login_available(config: SiteConfig) -> bool:
    if site_auth_platform(config) != "changan":
        return False
    try:
        if not _auto_login_enabled():
            return False
        load_auto_login_credentials()
    except (OSError, ValueError):
        return False
    return True


def _managed_config_complete(payload: dict[str, Any]) -> bool:
    return bool(
        str(payload.get("DARKWEB_CHANGAN_USERNAME") or "").strip()
        and str(payload.get("DARKWEB_CHANGAN_PASSWORD") or "").strip()
    )


def _environment_managed() -> bool:
    names = (
        "DARKWEB_CHANGAN_AUTO_LOGIN_CREDENTIALS_FILE",
        "DARKWEB_CHANGAN_USERNAME",
        "DARKWEB_CHANGAN_PASSWORD",
    )
    return any(str(os.environ.get(name) or "").strip() for name in names)


def _session_auto_login_state() -> dict[str, Any]:
    try:
        with get_db_connection() as connection:
            existing = get_platform_session(connection, "changan") or {}
    except Exception:
        return {}
    metadata = _session_metadata(existing)
    automatic_login = metadata.get("automatic_login")
    state = automatic_login if isinstance(automatic_login, dict) else {}
    return {
        "session_status": str(existing.get("status") or ""),
        "last_attempt_at": str(state.get("last_attempt_at") or ""),
        "success": state.get("success"),
        "last_error": str(existing.get("last_error") or ""),
    }


def changan_auto_login_config_status() -> dict[str, Any]:
    config_error = ""
    try:
        managed = _load_managed_config()
        file_values = _credential_file_values()
        changan_username = _credential_value(file_values, "DARKWEB_CHANGAN_USERNAME", "CHANGAN_USERNAME")
        changan_password = _credential_value(file_values, "DARKWEB_CHANGAN_PASSWORD", "CHANGAN_PASSWORD")
    except (OSError, ValueError) as exc:
        managed = {}
        changan_username = ""
        changan_password = ""
        config_error = str(exc)
    provider_status = chaojiying_config_status()
    configured = bool(changan_username and changan_password)
    ready = bool(configured and provider_status.get("configured"))
    try:
        enabled = _auto_login_enabled()
    except (OSError, ValueError) as exc:
        enabled = False
        config_error = config_error or str(exc)

    session_state = _session_auto_login_state()
    with _CONFIG_STATE_LOCK:
        test_state = dict(_CONFIG_STATE)
    last_validated_at = str(test_state.get("last_validated_at") or session_state.get("last_attempt_at") or "")
    last_validation_success = test_state.get("last_validation_success")
    if last_validation_success is None:
        last_validation_success = session_state.get("success")
    last_error = str(test_state.get("last_error") or config_error or session_state.get("last_error") or "")
    return {
        "configured": configured,
        "ready": ready,
        "providerConfigured": bool(provider_status.get("configured")),
        "managedConfigured": _managed_config_complete(managed),
        "managedByEnvironment": _environment_managed(),
        "enabled": enabled,
        "hasChanganUsername": bool(changan_username),
        "hasChanganPassword": bool(changan_password),
        "codeType": CHAOJIYING_CODE_TYPE,
        "lastValidatedAt": last_validated_at,
        "lastValidationSuccess": last_validation_success,
        "sessionStatus": str(session_state.get("session_status") or ""),
        "lastError": last_error,
    }


def _write_managed_config(payload: dict[str, Any]) -> None:
    path = changan_auto_login_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            json.dump(payload, stream, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary_path, path)
        if os.name != "nt":
            path.chmod(0o600)
    except Exception:
        temporary_path.unlink(missing_ok=True)
        raise


def save_changan_auto_login_config(
    *,
    enabled: bool,
    changan_username: str = "",
    changan_password: str = "",
) -> dict[str, Any]:
    existing = _load_managed_config()
    provider_status = chaojiying_config_status()
    if provider_status.get("legacyConfigured") and not provider_status.get("managedConfigured"):
        save_chaojiying_config()
    values = {
        "DARKWEB_CHANGAN_USERNAME": str(changan_username or "").strip()
        or str(existing.get("DARKWEB_CHANGAN_USERNAME") or "").strip(),
        "DARKWEB_CHANGAN_PASSWORD": str(changan_password or "")
        or str(existing.get("DARKWEB_CHANGAN_PASSWORD") or ""),
    }
    if not _managed_config_complete(values):
        raise ChanganAutoLoginConfigError("首次配置必须填写长安账号和长安密码")

    _write_managed_config({"enabled": bool(enabled), **values})
    with _CONFIG_STATE_LOCK:
        _CONFIG_STATE.update({"last_error": ""})
    return changan_auto_login_config_status()


def delete_changan_auto_login_config() -> dict[str, Any]:
    path = changan_auto_login_config_path()
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise ChanganAutoLoginConfigError("长安自动登录配置文件无法删除") from exc
    with _CONFIG_STATE_LOCK:
        _CONFIG_STATE.update({"last_validated_at": "", "last_validation_success": None, "last_error": ""})
    return changan_auto_login_config_status()


def test_changan_auto_login_config(config: SiteConfig) -> dict[str, Any]:
    try:
        credentials = load_auto_login_credentials()
    except ValueError as exc:
        raise ChanganAutoLoginConfigError(str(exc)) from exc
    base_url = _base_url(str(config.extras.get("auth_origin") or config.seed_urls[0]))
    result = perform_changan_login(credentials, base_url=base_url, logout_after=True)
    success = bool(result.get("success") and result.get("authenticated_probe_ok"))
    error = str(result.get("error") or "")[:300]
    with _CONFIG_STATE_LOCK:
        _CONFIG_STATE.update(
            {
                "last_validated_at": _now_utc_iso(),
                "last_validation_success": success,
                "last_error": "" if success else (error or "长安自动登录测试失败"),
            }
        )
    if not success:
        raise ChanganAutoLoginTestError(error or "长安自动登录测试失败")
    return {
        **changan_auto_login_config_status(),
        "testResult": {
            "success": True,
            "gateAttempts": int(result.get("gate_recognition_attempts") or 0),
            "loginAttempts": int(result.get("login_recognition_attempts") or 0),
            "errorReports": int(result.get("gate_error_reports") or 0)
            + int(result.get("login_error_reports") or 0),
        },
    }


def _ensure_tor_connected(timeout_seconds: int = 120) -> None:
    status = get_tor_bridge_status()
    if status.get("connected"):
        return
    start_tor_bridge()
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = get_tor_bridge_status()
        if status.get("connected"):
            return
        if status.get("connection_state") == "error":
            raise RuntimeError(str(status.get("last_error") or "Tor bridge failed to connect"))
        time.sleep(1)
    raise TimeoutError("Tor bridge did not connect within 120 seconds")


def _recognize_changan_captcha(
    page: Any,
    credentials: ChanganAutoLoginCredentials,
    bearer_token: str = "",
) -> dict[str, str]:
    response = page.evaluate(
        """async (token) => {
          const headers = token ? {Authorization: `Bearer ${token}`} : {};
          const result = await fetch('/api/public/captcha', {cache: 'no-store', headers});
          let payload = null;
          try { payload = await result.json(); } catch (_) {}
          return {httpStatus: result.status, payload};
        }""",
        bearer_token,
    )
    payload = response.get("payload") or {}
    data = payload.get("data") or {}
    image_url = str(data.get("digits") or "")
    captcha_id = str(data.get("id") or "")
    if (
        response.get("httpStatus") != 200
        or payload.get("code") != 2000
        or not captcha_id
        or not image_url.startswith("data:image/")
        or "," not in image_url
    ):
        raise ValueError("Changan captcha endpoint returned an invalid image")
    image = base64.b64decode(image_url.split(",", 1)[1], validate=True)
    recognition = recognize_captcha(
        image,
        user=credentials.chaojiying_user,
        password=credentials.chaojiying_password,
        pass2=credentials.chaojiying_pass2,
        soft_id=credentials.chaojiying_soft_id,
        code_type=CHAOJIYING_CODE_TYPE,
    )
    answer = str(recognition.get("pic_str") or "").strip()
    if not answer:
        raise ValueError("Chaojiying returned an empty recognition result")
    return {
        "captcha_id": captcha_id,
        "answer": answer,
        "pic_id": str(recognition.get("pic_id") or ""),
    }


def _report_wrong_captcha(
    pic_id: str,
    credentials: ChanganAutoLoginCredentials,
    result: dict[str, Any],
    key: str,
) -> None:
    try:
        report_recognition_error(
            pic_id,
            user=credentials.chaojiying_user,
            password=credentials.chaojiying_password,
            pass2=credentials.chaojiying_pass2,
            soft_id=credentials.chaojiying_soft_id,
        )
        result[key] = int(result.get(key) or 0) + 1
    except Exception as exc:  # noqa: BLE001
        result[f"{key}_failures"] = int(result.get(f"{key}_failures") or 0) + 1
        result[f"{key}_last_error_type"] = type(exc).__name__


def _token_expiry_hint(token: str) -> str:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return ""
    try:
        encoded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
        raw_expiry = payload.get("expire") or payload.get("exp")
        if isinstance(raw_expiry, (int, float)):
            return datetime.fromtimestamp(float(raw_expiry), timezone.utc).isoformat()
        if isinstance(raw_expiry, str):
            return raw_expiry.strip()
    except Exception:
        pass
    return ""


def perform_changan_login(
    credentials: ChanganAutoLoginCredentials,
    *,
    base_url: str,
    storage_state_path: Path | None = None,
    logout_after: bool = False,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "login_success": False,
        "code_type": CHAOJIYING_CODE_TYPE,
        "tor_connected": False,
        "gate_accepted": False,
        "login_response_ok": False,
        "authenticated_probe_ok": False,
        "gate_recognition_attempts": 0,
        "login_recognition_attempts": 0,
        "session_saved": False,
        "credentials_stored": False,
        "token_stored": False,
        "logout_attempted": False,
        "logout_ok": False,
    }
    browser = None
    context = None
    try:
        _ensure_tor_connected()
        result["tor_connected"] = True
        from playwright.sync_api import sync_playwright
        from darkweb_collector.browser_temp import ensure_browser_temp

        ensure_browser_temp()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                proxy={"server": browser_proxy_server_for_url(base_url)},
            )
            context = browser.new_context()
            page = context.new_page()
            page.goto(f"{base_url}/#/checking", wait_until="domcontentloaded", timeout=90_000)

            gate_token = ""
            for attempt in range(1, MAX_CAPTCHA_ATTEMPTS + 1):
                captcha = _recognize_changan_captcha(page, credentials)
                result["gate_recognition_attempts"] = attempt
                verification = page.evaluate(
                    """async ({captchaId, code}) => {
                      const response = await fetch('/api/loginChecking', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({cid: captchaId, code})
                      });
                      let payload = null;
                      try { payload = await response.json(); } catch (_) {}
                      return {httpStatus: response.status, payload};
                    }""",
                    {"captchaId": captcha["captcha_id"], "code": captcha["answer"]},
                )
                payload = verification.get("payload") or {}
                data = payload.get("data")
                if verification.get("httpStatus") == 200 and payload.get("code") == 2000 and data not in (
                    None,
                    "",
                    "InvalidCaptcha",
                ):
                    gate_token = str(data)
                    break
                if payload.get("code") == 2000 and data in (None, "", "InvalidCaptcha"):
                    _report_wrong_captcha(captcha["pic_id"], credentials, result, "gate_error_reports")
            if not gate_token:
                raise ValueError("Changan entrance captcha was rejected three times")
            result["gate_accepted"] = True

            page.evaluate("token => localStorage.setItem('token', token)", gate_token)
            page.goto(f"{base_url}/#/login", wait_until="domcontentloaded", timeout=90_000)
            login_token = ""
            account: dict[str, Any] | None = None
            last_login_code = 0
            for attempt in range(1, MAX_CAPTCHA_ATTEMPTS + 1):
                captcha = _recognize_changan_captcha(page, credentials, gate_token)
                result["login_recognition_attempts"] = attempt
                login = page.evaluate(
                    """async ({token, name, password, captchaId, code}) => {
                      const response = await fetch('/api/account/login', {
                        method: 'POST',
                        headers: {
                          'Content-Type': 'application/json',
                          Authorization: `Bearer ${token}`
                        },
                        body: JSON.stringify({name, password, code, cid: captchaId})
                      });
                      let payload = null;
                      try { payload = await response.json(); } catch (_) {}
                      return {httpStatus: response.status, payload};
                    }""",
                    {
                        "token": gate_token,
                        "name": credentials.changan_username,
                        "password": credentials.changan_password,
                        "captchaId": captcha["captcha_id"],
                        "code": captcha["answer"],
                    },
                )
                payload = login.get("payload") or {}
                raw_data = payload.get("data") or {}
                data = raw_data if isinstance(raw_data, dict) else {}
                raw_account = data.get("account")
                account = raw_account if isinstance(raw_account, dict) else None
                login_token = str(data.get("token") or "")
                last_login_code = int(payload.get("code") or 0)
                accepted = (
                    login.get("httpStatus") == 200
                    and last_login_code == 2000
                    and bool(login_token)
                    and account is not None
                )
                if last_login_code == 4002:
                    _report_wrong_captcha(captcha["pic_id"], credentials, result, "login_error_reports")
                if accepted or last_login_code != 4002:
                    break
            if not login_token or account is None or last_login_code != 2000:
                result["login_result"] = {
                    4002: "captcha_rejected",
                    4005: "account_not_found",
                    4006: "password_mismatch",
                }.get(last_login_code, "rejected")
                raise ValueError("Changan account login was rejected")
            result["login_response_ok"] = True

            page.evaluate("token => localStorage.setItem('token', token)", login_token)
            account_id = account.get("hid") or account.get("id")
            probe = page.evaluate(
                """async ({token, accountId}) => {
                  const url = accountId
                    ? `/api/account/info?hid=${encodeURIComponent(accountId)}`
                    : '/api/config/';
                  const response = await fetch(url, {
                    headers: {Authorization: `Bearer ${token}`},
                    cache: 'no-store'
                  });
                  let payload = null;
                  try { payload = await response.json(); } catch (_) {}
                  return {httpStatus: response.status, code: payload && payload.code};
                }""",
                {"token": login_token, "accountId": account_id},
            )
            if probe.get("httpStatus") != 200 or probe.get("code") != 2000:
                raise ValueError("Changan authenticated session probe failed")
            result["authenticated_probe_ok"] = True

            result["expires_hint"] = _token_expiry_hint(login_token)
            if storage_state_path is not None:
                storage_state_path.parent.mkdir(parents=True, exist_ok=True)
                context.storage_state(path=str(storage_state_path))
                result["session_saved"] = True
                result["token_stored"] = True
            result["success"] = True
            result["login_success"] = True

            if logout_after:
                result["logout_attempted"] = True
                logout = page.evaluate(
                    """async (token) => {
                      const response = await fetch('/api/account/logout', {
                        method: 'POST',
                        headers: {Authorization: `Bearer ${token}`}
                      });
                      let payload = null;
                      try { payload = await response.json(); } catch (_) {}
                      localStorage.clear();
                      return {httpStatus: response.status, code: payload && payload.code};
                    }""",
                    login_token,
                )
                result["logout_ok"] = logout.get("httpStatus") == 200 and logout.get("code") == 2000
                result["token_stored"] = False
    except Exception as exc:  # noqa: BLE001
        result["error_type"] = type(exc).__name__
        result["error"] = str(exc)[:300]
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
    return result


@contextmanager
def _auto_login_lock(path: Path) -> Iterator[bool]:
    deadline = time.monotonic() + LOGIN_LOCK_TIMEOUT_SECONDS
    descriptor: int | None = None
    path.parent.mkdir(parents=True, exist_ok=True)
    while time.monotonic() < deadline:
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(descriptor, f"{os.getpid()} {_now_utc_iso()}".encode("ascii"))
            break
        except FileExistsError:
            try:
                if time.time() - path.stat().st_mtime > LOGIN_LOCK_STALE_SECONDS:
                    path.unlink()
                    continue
            except OSError:
                pass
            time.sleep(1)
    try:
        yield descriptor is not None
    finally:
        if descriptor is not None:
            os.close(descriptor)
            try:
                path.unlink()
            except OSError:
                pass


def _session_metadata(existing: dict[str, Any]) -> dict[str, Any]:
    raw = existing.get("metadata_json") or "{}"
    try:
        payload = json.loads(raw) if isinstance(raw, str) else raw
    except json.JSONDecodeError:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _recent_failed_login(existing: dict[str, Any]) -> bool:
    automatic_login = _session_metadata(existing).get("automatic_login")
    state = automatic_login if isinstance(automatic_login, dict) else {}
    if state.get("success") is not False:
        return False
    value = str(state.get("last_attempt_at") or "").strip()
    if not value:
        return False
    try:
        attempted_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if attempted_at.tzinfo is None:
        attempted_at = attempted_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < attempted_at + timedelta(seconds=FAILED_LOGIN_RETRY_SECONDS)


def _update_session(
    config: SiteConfig,
    *,
    status: str,
    storage_state_path: Path,
    last_error: str = "",
    expires_hint: str = "",
    result: dict[str, Any] | None = None,
) -> None:
    platform_name = site_auth_platform(config)
    platform = get_exposure_platform(platform_name)
    now = _now_utc_iso()
    with get_db_connection() as connection:
        existing = get_platform_session(connection, platform_name) or {}
        metadata = _session_metadata(existing)
        if result is not None:
            metadata["automatic_login"] = {
                "last_attempt_at": now,
                "success": bool(result.get("success")),
                "code_type": CHAOJIYING_CODE_TYPE,
                "gate_attempts": int(result.get("gate_recognition_attempts") or 0),
                "login_attempts": int(result.get("login_recognition_attempts") or 0),
                "gate_error_reports": int(result.get("gate_error_reports") or 0),
                "login_error_reports": int(result.get("login_error_reports") or 0),
            }
        upsert_platform_session(
            connection,
            {
                "platform": platform_name,
                "account_label": existing.get("account_label", ""),
                "login_url": existing.get("login_url") or platform.login_url,
                "homepage_url": existing.get("homepage_url") or platform.homepage_url,
                "requires_login": True,
                "status": status,
                "storage_state_path": str(storage_state_path),
                "last_verified_at": now,
                "expires_hint": expires_hint or existing.get("expires_hint", ""),
                "last_error": last_error,
                "metadata_json": json.dumps(metadata, ensure_ascii=False),
                "updated_at": now,
            },
        )
        connection.commit()


def recover_changan_session(config: SiteConfig, reason: str = "") -> bool:
    if not changan_auto_login_available(config):
        return False
    profile_dir = platform_profile_dir("changan")
    lock_path = profile_dir / "auto-login.lock"
    with _auto_login_lock(lock_path) as acquired:
        if not acquired:
            return bool(site_auth_readiness(config).get("ready"))
        if site_auth_readiness(config).get("ready"):
            return True
        with get_db_connection() as connection:
            existing = get_platform_session(connection, "changan") or {}
        if _recent_failed_login(existing):
            return False
        storage_state_path = resolve_platform_storage_state_path("changan", existing)
        _update_session(
            config,
            status="login_in_progress",
            storage_state_path=storage_state_path,
            last_error="",
        )
        try:
            credentials = load_auto_login_credentials()
            base_url = _base_url(config.seed_urls[0])
            result = perform_changan_login(
                credentials,
                base_url=base_url,
                storage_state_path=storage_state_path,
            )
        except Exception as exc:  # noqa: BLE001
            result = {
                "success": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:300],
            }
        if result.get("success") and result.get("session_saved"):
            _update_session(
                config,
                status="valid",
                storage_state_path=storage_state_path,
                expires_hint=str(result.get("expires_hint") or ""),
                result=result,
            )
            return True
        error = str(result.get("error") or "automatic Changan login failed")[:300]
        if reason and not error:
            error = str(reason)[:300]
        _update_session(
            config,
            status="invalid",
            storage_state_path=storage_state_path,
            last_error=error,
            result=result,
        )
        return False
