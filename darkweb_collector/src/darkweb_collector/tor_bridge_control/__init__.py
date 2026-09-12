from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import re
import signal
import shutil
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from threading import Event, Lock, RLock, Thread
from typing import Any

import psutil

from darkweb_collector.runtime import default_db_path


SETTINGS_PATH_ENV = "DARKWEB_TOR_BRIDGE_SETTINGS_PATH"
TOR_EXECUTABLE_ENV = "DARKWEB_TOR_EXECUTABLE"
TRANSPORT_EXECUTABLE_ENV = "DARKWEB_TOR_TRANSPORT_EXECUTABLE"
PT_CONFIG_PATH_ENV = "DARKWEB_TOR_PT_CONFIG_PATH"
SETTINGS_FILE = "tor_bridge_settings.json"
RUNTIME_DIR_NAME = "tor_bridge_runtime"
DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050
BRIDGE_MODES = {"snowflake", "obfs4", "webtunnel", "meek_lite", "vanilla", "custom"}
TRANSPORT_MODES = {"snowflake", "obfs4", "webtunnel", "meek_lite"}
BOOTSTRAP_PATTERN = re.compile(r"Bootstrapped\s+(\d{1,3})%\s+\(([^)]+)\):\s*(.*)")
EXIT_IP_CHECK_HOST = "check.torproject.org"
EXIT_IP_CHECK_PATH = "/api/ip"
EXIT_IP_RETRY_SECONDS = 15
EXIT_IP_RECHECK_SECONDS = 60
EXIT_IP_STALE_SECONDS = 90
PACKAGED_PT_CONFIG_PATH = Path(__file__).with_name("pt_config.json")
DEFAULT_SNOWFLAKE_BRIDGES = [
    (
        "Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com "
        "ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
        "stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,"
        "stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn"
    ),
    (
        "Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
        "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
        "url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com "
        "ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,"
        "stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,"
        "stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn"
    ),
]
DEFAULT_SNOWFLAKE_BRIDGE = DEFAULT_SNOWFLAKE_BRIDGES[0]
DEFAULT_OBFS4_BRIDGES = [
    "Bridge obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D "
    "cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
    "Bridge obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 "
    "cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
    "Bridge obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 "
    "cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
    "Bridge obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C "
    "cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
    "Bridge obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 "
    "cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    "Bridge obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 "
    "cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
    "Bridge obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 "
    "cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
]
DEFAULT_OBFS4_BRIDGE = DEFAULT_OBFS4_BRIDGES[0]
DEFAULT_MEEK_LITE_BRIDGES = [
    "Bridge meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org "
    "front=www.phpmyadmin.net utls=HelloRandomizedALPN",
]
DEFAULT_MEEK_LITE_BRIDGE = DEFAULT_MEEK_LITE_BRIDGES[0]
DEFAULT_BUILTIN_BRIDGES = {
    "snowflake": DEFAULT_SNOWFLAKE_BRIDGES,
    "obfs4": DEFAULT_OBFS4_BRIDGES,
    "meek_lite": DEFAULT_MEEK_LITE_BRIDGES,
}
_process_lock = Lock()
_operation_lock = RLock()
_recovery_stop = Event()
_recovery_thread: Thread | None = None
logger = logging.getLogger(__name__)


def _serialized_operation(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        with _operation_lock:
            return function(*args, **kwargs)
    return wrapped


_process: subprocess.Popen | None = None
_last_error = ""
_exit_ip_lock = Lock()
_exit_ip = ""
_exit_ip_checked_at = ""
_exit_ip_error = ""
_exit_ip_checking = False
_exit_ip_last_attempt = 0.0
_exit_ip_last_success = 0.0
_runtime_generation = 0
_builtin_bridge_lock = Lock()
_builtin_bridge_cache_key: tuple[str, int, int] | None = None
_builtin_bridge_cache: dict[str, Any] = {}
_builtin_bridge_last_good: dict[str, Any] = {}


def settings_path() -> Path:
    raw_path = str(os.environ.get(SETTINGS_PATH_ENV) or "").strip()
    if raw_path:
        return Path(raw_path).expanduser().resolve()
    return default_db_path().with_name(SETTINGS_FILE).resolve()


def _default_runtime_dir() -> Path:
    return default_db_path().with_name(RUNTIME_DIR_NAME).resolve()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _string(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _is_executable_file(value: str | Path) -> bool:
    raw_value = _string(value)
    if not raw_value:
        return False
    path = Path(raw_value).expanduser()
    return path.is_file() and os.access(path, os.X_OK)


def _normalize_lines(value: Any) -> list[str]:
    if isinstance(value, str):
        raw_lines = value.splitlines()
    elif isinstance(value, list):
        raw_lines = value
    else:
        raw_lines = []
    lines: list[str] = []
    for item in raw_lines:
        line = _string(item)
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _normalize_bridge_lines(value: Any) -> list[str]:
    lines = []
    for line in _normalize_lines(value):
        if line.lower().startswith("bridge "):
            lines.append(line)
        else:
            lines.append(f"Bridge {line}")
    return lines


def _normalize_settings(payload: dict[str, Any]) -> dict[str, Any]:
    mode = _string(payload.get("bridge_mode")) or "snowflake"
    if mode not in BRIDGE_MODES:
        raise ValueError(f"bridge_mode must be one of {', '.join(sorted(BRIDGE_MODES))}")

    socks_port = _int(payload.get("socks_port"), DEFAULT_SOCKS_PORT)
    if socks_port < 1 or socks_port > 65535:
        raise ValueError("socks_port must be between 1 and 65535")

    data_directory = _string(payload.get("data_directory"))
    return {
        "enabled": bool(payload.get("enabled", False)),
        "recovery_requested": bool(payload.get("recovery_requested", payload.get("enabled", False))),
        "bridge_mode": mode,
        "tor_executable": _string(payload.get("tor_executable")),
        "transport_executable": _string(payload.get("transport_executable")),
        "socks_host": _string(payload.get("socks_host")) or DEFAULT_SOCKS_HOST,
        "socks_port": socks_port,
        "bridge_lines": _normalize_bridge_lines(payload.get("bridge_lines")),
        "extra_torrc_lines": _normalize_lines(payload.get("extra_torrc_lines")),
        "data_directory": data_directory,
        "updated_at": _string(payload.get("updated_at")),
        "last_started_at": _string(payload.get("last_started_at")),
    }


def _load_raw_settings() -> dict[str, Any]:
    path = settings_path()
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def load_tor_bridge_settings() -> dict[str, Any]:
    defaults = {
        "enabled": False,
        "bridge_mode": "snowflake",
        "tor_executable": "",
        "transport_executable": "",
        "socks_host": DEFAULT_SOCKS_HOST,
        "socks_port": DEFAULT_SOCKS_PORT,
        "bridge_lines": [],
        "extra_torrc_lines": [],
        "data_directory": "",
        "updated_at": "",
        "last_started_at": "",
    }
    settings = _normalize_settings({**defaults, **_load_raw_settings()})
    env_tor_executable = _string(os.environ.get(TOR_EXECUTABLE_ENV))
    env_transport_executable = _string(os.environ.get(TRANSPORT_EXECUTABLE_ENV))
    if _is_executable_file(env_tor_executable):
        settings["tor_executable"] = env_tor_executable
    if _is_executable_file(env_transport_executable):
        settings["transport_executable"] = env_transport_executable
    if not settings["tor_executable"]:
        settings["tor_executable"] = detect_tor_executable()
    if not settings["transport_executable"]:
        settings["transport_executable"] = detect_transport_executable(
            settings["tor_executable"],
            _effective_transport_mode(settings),
        )
    return settings


@_serialized_operation
def save_tor_bridge_settings(payload: dict[str, Any]) -> dict[str, Any]:
    previous = load_tor_bridge_settings()
    settings = _normalize_settings({**previous, **payload, "updated_at": _now_iso()})
    bridge_errors = _bridge_mode_errors(settings)
    if bridge_errors:
        raise ValueError(" ".join(bridge_errors))
    runtime_keys = (
        "enabled",
        "bridge_mode",
        "tor_executable",
        "transport_executable",
        "socks_host",
        "socks_port",
        "bridge_lines",
        "extra_torrc_lines",
        "data_directory",
    )
    if any(previous.get(key) != settings.get(key) for key in runtime_keys):
        with _process_lock:
            _terminate_process_locked(previous)
            _reset_exit_ip_state()
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding="utf-8")
    apply_collector_proxy_env(settings)
    return get_tor_bridge_status()


def apply_collector_proxy_env(settings: dict[str, Any] | None = None) -> None:
    current = settings or load_tor_bridge_settings()
    if not current.get("enabled"):
        return
    os.environ["TOR_SOCKS_HOST"] = _string(current.get("socks_host")) or DEFAULT_SOCKS_HOST
    os.environ["TOR_SOCKS_PORT"] = str(_int(current.get("socks_port"), DEFAULT_SOCKS_PORT))


def active_socks_settings() -> tuple[str, int] | None:
    settings = load_tor_bridge_settings()
    if not settings.get("enabled"):
        return None
    return _string(settings.get("socks_host")) or DEFAULT_SOCKS_HOST, _int(settings.get("socks_port"), DEFAULT_SOCKS_PORT)


def _home_candidates() -> list[Path]:
    try:
        home = Path.home()
    except RuntimeError:
        return []
    return [
        home / ".local" / "bin" / "darkweb-tor",
        home / "tor-browser" / "Browser" / "TorBrowser" / "Tor" / "tor",
        home / "Desktop" / "tor-browser" / "Browser" / "TorBrowser" / "Tor" / "tor",
        home / "Downloads" / "tor-browser" / "Browser" / "TorBrowser" / "Tor" / "tor",
    ]


def detect_tor_executable() -> str:
    candidates = _home_candidates()
    for command_name in ("tor.exe", "tor"):
        command_path = shutil.which(command_name)
        if command_path:
            candidates.append(Path(command_path))
    local_app_data = os.environ.get("LOCALAPPDATA")
    user_profile = os.environ.get("USERPROFILE")
    if local_app_data:
        candidates.append(Path(local_app_data) / "Programs" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe")
    if user_profile:
        for parent in ("Desktop", "Downloads", "Documents"):
            candidates.append(Path(user_profile) / parent / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe")
    candidates.extend(
        [
            Path("/usr/bin/tor"),
            Path("/usr/local/bin/tor"),
        ]
    )
    for candidate in candidates:
        if _is_executable_file(candidate):
            return str(candidate.resolve())
    return ""


def detect_transport_executable(tor_executable: str = "", bridge_mode: str = "snowflake") -> str:
    if bridge_mode == "snowflake":
        names = ["snowflake-client.exe", "snowflake-client", "lyrebird.exe", "lyrebird"]
    elif bridge_mode == "obfs4":
        names = ["lyrebird.exe", "lyrebird", "obfs4proxy.exe", "obfs4proxy"]
    elif bridge_mode in {"meek_lite", "webtunnel"}:
        names = ["lyrebird.exe", "lyrebird"]
    else:
        return ""
    tor_path = Path(tor_executable).expanduser() if tor_executable else None
    candidates: list[Path] = []
    try:
        expert_transport_dir = (
            Path.home()
            / ".local"
            / "share"
            / "darkweb-threat-intel"
            / "tor-expert"
            / "current"
            / "tor"
            / "pluggable_transports"
        )
        candidates.extend(expert_transport_dir / name for name in names)
    except RuntimeError:
        pass
    for name in names:
        command_path = shutil.which(name)
        if command_path:
            candidates.append(Path(command_path))
    if tor_path:
        transport_dir = tor_path.parent / "PluggableTransports"
        candidates.extend(transport_dir / name for name in names)
    candidates.extend(Path("/usr/bin") / name for name in names)
    candidates.extend(Path("/usr/local/bin") / name for name in names)
    for candidate in candidates:
        if _is_executable_file(candidate):
            return str(candidate.resolve())
    return ""


def _runtime_paths(settings: dict[str, Any]) -> dict[str, str]:
    runtime_dir = Path(settings.get("data_directory") or _default_runtime_dir()).expanduser().resolve()
    return {
        "data_directory": str(runtime_dir),
        "torrc_path": str(runtime_dir / "torrc"),
        "log_path": str(runtime_dir / "tor.log"),
        "snowflake_log_path": str(runtime_dir / "snowflake.log"),
        "pid_path": str(runtime_dir / "tor.pid"),
    }


def _looks_like_posix_absolute_path(value: str) -> bool:
    return value.startswith("/") and not value.startswith("//")


def _torrc_token(value: str | Path) -> str:
    if isinstance(value, Path):
        text = str(value.expanduser().resolve())
    else:
        raw = _string(value)
        text = raw if _looks_like_posix_absolute_path(raw) else str(Path(raw).expanduser().resolve())
    if any(char.isspace() for char in text):
        return f'"{text}"'
    return text


def _transport_exec_token(settings: dict[str, Any]) -> str:
    raw_transport = _string(settings.get("transport_executable"))
    if _looks_like_posix_absolute_path(raw_transport):
        return _torrc_token(raw_transport)
    transport = Path(_string(settings.get("transport_executable"))).expanduser().resolve()
    tor_executable = Path(_string(settings.get("tor_executable"))).expanduser().resolve()
    token = _torrc_token(transport)
    if not any(char.isspace() for char in token.strip('"')):
        return token
    try:
        relative = transport.relative_to(tor_executable.parent)
    except ValueError:
        return token
    relative_text = str(relative)
    if any(char.isspace() for char in relative_text):
        return token
    return relative_text


def _effective_bridge_lines(settings: dict[str, Any]) -> list[str]:
    lines = list(settings.get("bridge_lines") or [])
    mode = _string(settings.get("bridge_mode"))
    if not lines and mode in DEFAULT_BUILTIN_BRIDGES:
        bridges = refresh_builtin_bridges(settings)["bridges"]
        return list(bridges.get(mode) or DEFAULT_BUILTIN_BRIDGES[mode])
    return lines


def _bridge_line_mode(line: str) -> str:
    parts = _string(line).split()
    if parts and parts[0].lower() == "bridge":
        parts = parts[1:]
    if not parts:
        return ""
    mode = parts[0].lower()
    if mode == "meek":
        mode = "meek_lite"
    return mode if mode in TRANSPORT_MODES else "vanilla"


def _bridge_line_modes(settings: dict[str, Any]) -> set[str]:
    return {mode for line in settings.get("bridge_lines") or [] if (mode := _bridge_line_mode(line))}


def _bridge_mode_errors(settings: dict[str, Any]) -> list[str]:
    modes = _bridge_line_modes(settings)
    if not modes:
        return []
    selected = _string(settings.get("bridge_mode"))
    if selected == "custom":
        if len(modes) > 1:
            return ["Custom bridge lines must use one transport type."]
        return []
    if modes != {selected}:
        actual = ", ".join(sorted(modes))
        return [f"Bridge lines use {actual}, but the selected bridge mode is {selected}."]
    return []


def _effective_transport_mode(settings: dict[str, Any]) -> str:
    selected = _string(settings.get("bridge_mode")) or "snowflake"
    if selected != "custom":
        return selected
    modes = _bridge_line_modes(settings)
    return next(iter(modes)) if len(modes) == 1 else ""


def _pt_config_candidates(settings: dict[str, Any]) -> list[Path]:
    candidates: list[Path] = []
    explicit_path = _string(os.environ.get(PT_CONFIG_PATH_ENV))
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())
    candidates.append(default_db_path().parent / "tor-expert" / "pt_config.json")
    local_app_data = _string(os.environ.get("LOCALAPPDATA"))
    if local_app_data:
        candidates.append(Path(local_app_data) / "DarkWebThreatIntel" / "tor-expert" / "pt_config.json")
    try:
        candidates.append(
            Path.home() / ".local" / "share" / "darkweb-threat-intel" / "tor-expert" / "pt_config.json"
        )
    except RuntimeError:
        pass
    candidates.append(PACKAGED_PT_CONFIG_PATH)
    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        key = os.path.normcase(str(resolved))
        if key not in seen:
            seen.add(key)
            unique.append(resolved)
    return unique


def _read_pt_config(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("bridges"), dict):
        raise ValueError("Tor Browser bridge configuration is invalid")
    return payload


def _parse_pt_config(path: Path) -> dict[str, Any]:
    payload = _read_pt_config(path)
    mode_names = {
        "meek": "meek_lite",
        "meek-azure": "meek_lite",
        "meek_lite": "meek_lite",
        "snowflake": "snowflake",
        "obfs4": "obfs4",
        "webtunnel": "webtunnel",
    }
    bridges: dict[str, list[str]] = {}
    for raw_mode, raw_lines in payload["bridges"].items():
        mode = mode_names.get(_string(raw_mode).lower())
        if not mode:
            continue
        lines = [line for line in _normalize_bridge_lines(raw_lines) if _bridge_line_mode(line) == mode]
        if lines:
            bridges[mode] = lines
    if not bridges:
        raise ValueError("Tor Browser bridge configuration contains no supported bridges")
    source_stat = path.stat()
    recommended_mode = mode_names.get(_string(payload.get("recommendedDefault")).lower(), "")
    return {
        "bridges": bridges,
        "source": "bundled" if path == PACKAGED_PT_CONFIG_PATH else "project_cache",
        "source_path": str(path),
        "updated_at": datetime.fromtimestamp(source_stat.st_mtime, timezone.utc).isoformat(),
        "recommended_mode": recommended_mode,
        "source_error": "",
    }


def _fallback_builtin_bridges(error: str = "") -> dict[str, Any]:
    return {
        "bridges": {mode: list(lines) for mode, lines in DEFAULT_BUILTIN_BRIDGES.items()},
        "source": "bundled_fallback",
        "source_path": "",
        "updated_at": "",
        "recommended_mode": "obfs4",
        "source_error": error,
    }


def refresh_builtin_bridges(
    settings: dict[str, Any] | None = None,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Load the project-owned built-in bridge list when its JSON file changes."""
    global _builtin_bridge_cache, _builtin_bridge_cache_key, _builtin_bridge_last_good
    current = settings or load_tor_bridge_settings()
    candidates = [path for path in _pt_config_candidates(current) if path.is_file()]
    if not candidates:
        return dict(_builtin_bridge_last_good or _fallback_builtin_bridges())
    source = candidates[0]
    source_stat = source.stat()
    cache_key = (os.path.normcase(str(source)), source_stat.st_mtime_ns, source_stat.st_size)
    with _builtin_bridge_lock:
        if not force and cache_key == _builtin_bridge_cache_key and _builtin_bridge_cache:
            return dict(_builtin_bridge_cache)
        try:
            loaded = _parse_pt_config(source)
        except Exception as exc:
            loaded = dict(_builtin_bridge_last_good or _fallback_builtin_bridges())
            loaded["source_error"] = str(exc)
        else:
            _builtin_bridge_last_good = dict(loaded)
        _builtin_bridge_cache_key = cache_key
        _builtin_bridge_cache = dict(loaded)
        return dict(loaded)


def _client_transport_plugin(settings: dict[str, Any], paths: dict[str, str]) -> str:
    mode = _effective_transport_mode(settings)
    if mode not in TRANSPORT_MODES:
        return ""
    transport = _string(settings.get("transport_executable"))
    if not transport:
        return ""
    base = f"ClientTransportPlugin {mode} exec {_transport_exec_token(settings)}"
    if mode == "snowflake":
        if Path(transport).name.lower() in {"lyrebird.exe", "lyrebird"}:
            return base
        return f"{base} -log {_torrc_token(paths['snowflake_log_path'])}"
    return base


def build_torrc(settings: dict[str, Any] | None = None) -> str:
    current = settings or load_tor_bridge_settings()
    paths = _runtime_paths(current)
    lines = [
        "ClientOnly 1",
        f"SocksPort {_string(current.get('socks_host')) or DEFAULT_SOCKS_HOST}:{_int(current.get('socks_port'), DEFAULT_SOCKS_PORT)}",
        f"DataDirectory {_torrc_token(paths['data_directory'])}",
        f"Log notice file {_torrc_token(paths['log_path'])}",
        "AvoidDiskWrites 1",
    ]
    if current.get("enabled"):
        lines.append("UseBridges 1")
        plugin = _client_transport_plugin(current, paths)
        if plugin:
            lines.append(plugin)
        lines.extend(current.get("extra_torrc_lines") or [])
        lines.extend(_effective_bridge_lines(current))
    else:
        lines.append("UseBridges 0")
    return "\n".join(lines) + "\n"


def write_torrc(settings: dict[str, Any] | None = None) -> Path:
    current = settings or load_tor_bridge_settings()
    paths = _runtime_paths(current)
    runtime_dir = Path(paths["data_directory"])
    runtime_dir.mkdir(parents=True, exist_ok=True)
    torrc_path = Path(paths["torrc_path"])
    torrc_path.write_text(build_torrc(current), encoding="utf-8")
    return torrc_path


def _runtime_errors(settings: dict[str, Any]) -> list[str]:
    errors = _bridge_mode_errors(settings)
    tor_executable = _string(settings.get("tor_executable"))
    if not _is_executable_file(tor_executable):
        errors.append("Tor executable was not found. Install tor or Tor Browser, then refresh bridge status.")

    mode = _effective_transport_mode(settings)
    if mode in TRANSPORT_MODES:
        transport_executable = _string(settings.get("transport_executable"))
        if not _is_executable_file(transport_executable):
            errors.append(
                "Tor bridge transport plugin was not found. Install snowflake-client, lyrebird, or obfs4proxy."
            )
        else:
            transport_name = Path(transport_executable).name.lower()
            allowed_names = {
                "snowflake": {"snowflake-client", "snowflake-client.exe", "lyrebird", "lyrebird.exe"},
                "obfs4": {"obfs4proxy", "obfs4proxy.exe", "lyrebird", "lyrebird.exe"},
                "meek_lite": {"lyrebird", "lyrebird.exe"},
                "webtunnel": {"lyrebird", "lyrebird.exe"},
            }[mode]
            if transport_name not in allowed_names:
                if mode in {"meek_lite", "webtunnel"}:
                    errors.append(f"{mode} requires lyrebird; {transport_name} does not support this transport.")
                else:
                    errors.append(f"{transport_name} does not support the selected {mode} transport.")

    if settings.get("enabled") and not _effective_bridge_lines(settings):
        errors.append("No built-in bridge lines are available for the selected bridge mode.")
    return errors


def _validate_start_inputs(settings: dict[str, Any]) -> None:
    errors = _runtime_errors(settings)
    if errors:
        raise RuntimeError(" ".join(errors))


def _process_running() -> bool:
    return _process is not None and _process.poll() is None


def _remove_pid_file(settings: dict[str, Any]) -> None:
    try:
        Path(_runtime_paths(settings)["pid_path"]).unlink(missing_ok=True)
    except OSError:
        pass


def _write_pid_file(settings: dict[str, Any], pid: int) -> None:
    path = Path(_runtime_paths(settings)["pid_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="ascii")


def _pid_matches_runtime(pid: int, settings: dict[str, Any]) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    if os.name == "nt":
        try:
            process = psutil.Process(pid)
            expected_executable = Path(_string(settings.get("tor_executable"))).resolve()
            actual_executable = Path(process.exe()).resolve()
            expected_torrc = Path(_runtime_paths(settings)["torrc_path"]).resolve()
            command = process.cmdline()
        except (OSError, psutil.Error):
            return False
        if os.path.normcase(str(actual_executable)) != os.path.normcase(str(expected_executable)):
            return False
        return any(
            os.path.normcase(str(Path(arg.strip('"')).resolve())) == os.path.normcase(str(expected_torrc))
            for arg in command
            if arg and not arg.startswith("-")
        )
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    expected_torrc = os.fsencode(str(Path(_runtime_paths(settings)["torrc_path"]).resolve()))
    return expected_torrc in command


def _find_external_tor_pid(settings: dict[str, Any]) -> int | None:
    pid_path = Path(_runtime_paths(settings)["pid_path"])
    try:
        saved_pid = int(pid_path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        saved_pid = 0
    if _pid_matches_runtime(saved_pid, settings):
        return saved_pid
    if os.name == "nt":
        _remove_pid_file(settings)
        return None
    for process_dir in Path("/proc").glob("[0-9]*"):
        try:
            pid = int(process_dir.name)
        except ValueError:
            continue
        if _pid_matches_runtime(pid, settings):
            _write_pid_file(settings, pid)
            return pid
    _remove_pid_file(settings)
    return None


def _socks_listener_ready(settings: dict[str, Any]) -> bool:
    host = _string(settings.get("socks_host")) or DEFAULT_SOCKS_HOST
    port = _int(settings.get("socks_port"), DEFAULT_SOCKS_PORT)
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _ensure_socks_port_available(settings: dict[str, Any]) -> None:
    if not _socks_listener_ready(settings):
        return
    host = _string(settings.get("socks_host")) or DEFAULT_SOCKS_HOST
    port = _int(settings.get("socks_port"), DEFAULT_SOCKS_PORT)
    raise RuntimeError(
        f"Tor bridge SOCKS port {host}:{port} is already in use. "
        "Stop the existing Tor bridge process or choose another SOCKS port."
    )


def _read_log_tail(path: str, max_bytes: int = 65536) -> str:
    log_path = Path(path)
    if not log_path.exists():
        return ""
    try:
        with log_path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _parse_bootstrap_log(log_tail: str) -> dict[str, Any]:
    for line in reversed(log_tail.splitlines()):
        match = BOOTSTRAP_PATTERN.search(line)
        if not match:
            continue
        percent = min(100, max(0, int(match.group(1))))
        return {
            "bootstrap_status": "done" if percent == 100 else line.strip(),
            "bootstrap_percent": percent,
            "bootstrap_stage": match.group(2).strip(),
            "bootstrap_summary": match.group(3).strip(),
        }
    return {
        "bootstrap_status": "starting",
        "bootstrap_percent": 0,
        "bootstrap_stage": "starting",
        "bootstrap_summary": "Starting Tor",
    }


def _bootstrap_details(settings: dict[str, Any], process_running: bool) -> dict[str, Any]:
    if not process_running:
        return {
            "bootstrap_status": "not_running",
            "bootstrap_percent": 0,
            "bootstrap_stage": "not_running",
            "bootstrap_summary": "Tor is not running",
        }
    return _parse_bootstrap_log(_read_log_tail(_runtime_paths(settings)["log_path"]))


def _bootstrap_status(settings: dict[str, Any], process_running: bool) -> str:
    return str(_bootstrap_details(settings, process_running)["bootstrap_status"])


def _parse_exit_ip_payload(payload: Any) -> str:
    if not isinstance(payload, dict) or payload.get("IsTor") is not True:
        raise RuntimeError("exit IP check reports that the connection is not using Tor")
    raw_ip = _string(payload.get("IP"))
    try:
        return str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise RuntimeError("exit IP check returned an invalid IP address") from exc


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Tor SOCKS proxy closed the connection unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def _fetch_exit_ip_via_socks(settings: dict[str, Any]) -> str:
    socks_host = _string(settings.get("socks_host")) or DEFAULT_SOCKS_HOST
    socks_port = _int(settings.get("socks_port"), DEFAULT_SOCKS_PORT)
    check_host = _string(os.environ.get("DARKWEB_TOR_IP_CHECK_HOST")) or EXIT_IP_CHECK_HOST
    check_path = _string(os.environ.get("DARKWEB_TOR_IP_CHECK_PATH")) or EXIT_IP_CHECK_PATH
    timeout = max(2, _int(os.environ.get("DARKWEB_TOR_IP_CHECK_TIMEOUT_SECONDS"), 15))
    encoded_host = check_host.encode("idna")
    if len(encoded_host) > 255:
        raise RuntimeError("exit IP check host is too long for SOCKS5")

    with socket.create_connection((socks_host, socks_port), timeout=timeout) as proxy_socket:
        proxy_socket.settimeout(timeout)
        proxy_socket.sendall(b"\x05\x01\x00")
        if _recv_exact(proxy_socket, 2) != b"\x05\x00":
            raise RuntimeError("Tor SOCKS proxy rejected unauthenticated access")

        request = b"\x05\x01\x00\x03" + bytes([len(encoded_host)]) + encoded_host + (443).to_bytes(2, "big")
        proxy_socket.sendall(request)
        response = _recv_exact(proxy_socket, 4)
        if response[0] != 5 or response[1] != 0:
            raise RuntimeError(f"Tor SOCKS proxy could not reach the IP check service (code {response[1]})")
        address_type = response[3]
        if address_type == 1:
            _recv_exact(proxy_socket, 4)
        elif address_type == 3:
            _recv_exact(proxy_socket, _recv_exact(proxy_socket, 1)[0])
        elif address_type == 4:
            _recv_exact(proxy_socket, 16)
        else:
            raise RuntimeError("Tor SOCKS proxy returned an unknown address type")
        _recv_exact(proxy_socket, 2)

        context = ssl.create_default_context()
        with context.wrap_socket(proxy_socket, server_hostname=check_host) as tls_socket:
            tls_socket.sendall(
                (
                    f"GET {check_path} HTTP/1.1\r\n"
                    f"Host: {check_host}\r\n"
                    "Accept: application/json\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            response = http.client.HTTPResponse(tls_socket)
            response.begin()
            if response.status != 200:
                raise RuntimeError(f"exit IP check returned HTTP {response.status}")
            payload = json.loads(response.read(65536).decode("utf-8"))
    return _parse_exit_ip_payload(payload)


def _reset_exit_ip_state() -> None:
    global _exit_ip, _exit_ip_checked_at, _exit_ip_error, _exit_ip_checking
    global _exit_ip_last_attempt, _exit_ip_last_success, _runtime_generation
    with _exit_ip_lock:
        _runtime_generation += 1
        _exit_ip = ""
        _exit_ip_checked_at = ""
        _exit_ip_error = ""
        _exit_ip_checking = False
        _exit_ip_last_attempt = 0.0
        _exit_ip_last_success = 0.0


def _exit_ip_probe_worker(settings: dict[str, Any], generation: int) -> None:
    global _exit_ip, _exit_ip_checked_at, _exit_ip_error, _exit_ip_checking, _exit_ip_last_success
    try:
        exit_ip = _fetch_exit_ip_via_socks(settings)
        error = ""
    except Exception as exc:
        exit_ip = ""
        error = str(exc)
    with _exit_ip_lock:
        if generation != _runtime_generation:
            return
        _exit_ip = exit_ip
        _exit_ip_checked_at = _now_iso()
        _exit_ip_error = error
        _exit_ip_checking = False
        _exit_ip_last_success = time.monotonic() if exit_ip else 0.0


def _ensure_exit_ip_probe(settings: dict[str, Any], connected: bool) -> None:
    global _exit_ip_checking, _exit_ip_last_attempt
    if not connected:
        return
    now = time.monotonic()
    with _exit_ip_lock:
        if _exit_ip_checking:
            return
        if _exit_ip_last_attempt and now - _exit_ip_last_attempt < EXIT_IP_RETRY_SECONDS:
            return
        if _exit_ip_last_success and now - _exit_ip_last_success < EXIT_IP_RECHECK_SECONDS:
            return
        _exit_ip_checking = True
        _exit_ip_last_attempt = now
        generation = _runtime_generation
    Thread(target=_exit_ip_probe_worker, args=(dict(settings), generation), daemon=True).start()


def _exit_ip_status() -> dict[str, Any]:
    with _exit_ip_lock:
        exit_ip_fresh = bool(
            _exit_ip
            and not _exit_ip_error
            and _exit_ip_last_success
            and time.monotonic() - _exit_ip_last_success <= EXIT_IP_STALE_SECONDS
        )
        return {
            "exit_ip": _exit_ip,
            "exit_ip_checked_at": _exit_ip_checked_at,
            "exit_ip_error": _exit_ip_error,
            "exit_ip_checking": _exit_ip_checking,
            "exit_ip_fresh": exit_ip_fresh,
        }


def _terminate_process_locked(settings: dict[str, Any]) -> None:
    global _process
    if _process_running():
        assert _process is not None
        if os.name == "nt":
            _terminate_windows_process_tree(_process.pid)
        else:
            _process.terminate()
            try:
                _process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _process.kill()
                _process.wait(timeout=5)
        _process = None
        _remove_pid_file(settings)
        return
    _process = None
    pid = _find_external_tor_pid(settings)
    if pid is None:
        return
    if os.name == "nt":
        _terminate_windows_process_tree(pid)
        _remove_pid_file(settings)
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        _remove_pid_file(settings)
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and _pid_matches_runtime(pid, settings):
        time.sleep(0.1)
    if _pid_matches_runtime(pid, settings):
        try:
            os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))
        except OSError:
            pass
    _remove_pid_file(settings)


def _terminate_windows_process_tree(pid: int) -> None:
    try:
        parent = psutil.Process(pid)
        processes = parent.children(recursive=True) + [parent]
    except psutil.Error:
        return
    for process in reversed(processes):
        try:
            process.terminate()
        except psutil.Error:
            pass
    _, alive = psutil.wait_procs(processes, timeout=5)
    for process in alive:
        try:
            process.kill()
        except psutil.Error:
            pass


def _refresh_process_state(settings: dict[str, Any]) -> tuple[bool, int | None]:
    global _last_error, _process
    process = _process
    if process is None:
        external_pid = _find_external_tor_pid(settings)
        return external_pid is not None, external_pid
    return_code = process.poll()
    if return_code is None:
        return True, process.pid
    with _process_lock:
        if _process is process:
            _process = None
            if not _last_error:
                log_tail = _read_log_tail(_runtime_paths(settings)["log_path"], max_bytes=8192).strip()
                _last_error = f"tor exited with code {return_code}"
                if log_tail:
                    _last_error = f"{_last_error}: {log_tail[-1000:]}"
            _remove_pid_file(settings)
            _reset_exit_ip_state()
    return False, None


def _save_recovery_intent(requested: bool) -> None:
    # A disconnect must still work when the saved bridge configuration is invalid.
    payload = {**_load_raw_settings(), "recovery_requested": requested, "updated_at": _now_iso()}
    path = settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


@_serialized_operation
def start_tor_bridge() -> dict[str, Any]:
    global _last_error, _process
    settings = load_tor_bridge_settings()
    if not settings.get("enabled"):
        raise RuntimeError("Tor bridge is disabled")
    _validate_start_inputs(settings)
    if not settings.get("recovery_requested"):
        _save_recovery_intent(True)
    paths = _runtime_paths(settings)
    already_running = False
    with _process_lock:
        if _process_running() or _find_external_tor_pid(settings) is not None:
            already_running = True
        else:
            _ensure_socks_port_available(settings)
            torrc_path = write_torrc(settings)
            Path(paths["data_directory"]).mkdir(parents=True, exist_ok=True)
            Path(paths["log_path"]).write_text("", encoding="utf-8")
            Path(paths["snowflake_log_path"]).write_text("", encoding="utf-8")
            _last_error = ""
            _reset_exit_ip_state()
            log_handle = Path(paths["log_path"]).open("a", encoding="utf-8")
            try:
                try:
                    _process = subprocess.Popen(
                        [_string(settings["tor_executable"]), "-f", str(torrc_path)],
                        cwd=str(Path(_string(settings["tor_executable"])).expanduser().resolve().parent),
                        stdin=subprocess.DEVNULL,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        close_fds=True,
                    )
                    _write_pid_file(settings, _process.pid)
                except OSError as exc:
                    _process = None
                    _last_error = f"failed to start tor: {exc}"
                    raise RuntimeError(_last_error) from exc
            finally:
                log_handle.close()
    if already_running:
        return get_tor_bridge_status()
    time.sleep(0.15)
    process_running, _ = _refresh_process_state(settings)
    if not process_running:
        raise RuntimeError(_last_error or "tor exited before bootstrap started")
    save_tor_bridge_settings({"last_started_at": _now_iso()})
    return get_tor_bridge_status()


@_serialized_operation
def stop_tor_bridge() -> dict[str, Any]:
    global _last_error, _process
    settings = load_tor_bridge_settings()
    _save_recovery_intent(False)
    with _process_lock:
        _terminate_process_locked(settings)
        _last_error = ""
        _reset_exit_ip_state()
    return get_tor_bridge_status()


class _RecoveryMonitor:
    def __init__(self) -> None:
        self.unhealthy_since: float | None = None
        self.next_attempt = 0.0
        self.retry_delay = 60.0

    @_serialized_operation
    def tick(self) -> None:
        settings = load_tor_bridge_settings()
        if not settings.get("enabled") or not settings.get("recovery_requested"):
            self.__init__()
            return
        status = get_tor_bridge_status()
        now = time.monotonic()
        if status["connected"]:
            self.__init__()
            return
        if self.unhealthy_since is None:
            self.unhealthy_since = now
        # Let Tor repair circuits and finish bootstrap before replacing its process.
        grace = 300 if status["process_running"] else 60
        if now - self.unhealthy_since < grace or now < self.next_attempt:
            return
        self.next_attempt = now + self.retry_delay
        self.retry_delay = min(self.retry_delay * 2, 900)
        self.unhealthy_since = now
        if status.get("runtime_errors"):
            logger.warning("Tor recovery waiting for valid runtime configuration")
            return
        logger.warning("Tor connection unavailable; restarting managed Tor runtime")
        # Do not call the public stop action: it records a user's manual disconnect.
        with _process_lock:
            _terminate_process_locked(settings)
            _reset_exit_ip_state()
        start_tor_bridge()


def _run_recovery_monitor() -> None:
    monitor = _RecoveryMonitor()
    while not _recovery_stop.wait(15):
        try:
            monitor.tick()
        except Exception:
            # Runtime errors may contain bridge addresses; keep background logs bounded.
            logger.warning("Tor recovery check failed; will retry in the background")


@_serialized_operation
def start_tor_bridge_recovery() -> None:
    global _recovery_thread
    if _recovery_thread is not None and _recovery_thread.is_alive():
        return
    _recovery_stop.clear()
    _recovery_thread = Thread(target=_run_recovery_monitor, name="tor-recovery", daemon=True)
    _recovery_thread.start()


def stop_tor_bridge_recovery() -> None:
    _recovery_stop.set()
    thread = _recovery_thread
    if thread is not None:
        thread.join(timeout=15)


def get_tor_bridge_status() -> dict[str, Any]:
    settings = load_tor_bridge_settings()
    builtin_bridges = refresh_builtin_bridges(settings)
    paths = _runtime_paths(settings)
    process_running, pid = _refresh_process_state(settings)
    runtime_errors = _runtime_errors(settings)
    socks_port_open = _socks_listener_ready(settings) if process_running else False
    bootstrap = _bootstrap_details(settings, process_running)
    bootstrap_ready = bool(process_running and socks_port_open and bootstrap["bootstrap_percent"] == 100)
    _ensure_exit_ip_probe(settings, bootstrap_ready)
    exit_ip_status = _exit_ip_status()
    connected = bool(bootstrap_ready and exit_ip_status["exit_ip_fresh"])
    probe_failed = bool(bootstrap_ready and exit_ip_status["exit_ip_checked_at"] and exit_ip_status["exit_ip_error"])
    if not settings.get("enabled"):
        connection_state = "disabled"
    elif runtime_errors:
        connection_state = "error"
    elif connected:
        connection_state = "connected"
    elif probe_failed:
        connection_state = "error"
    elif process_running:
        connection_state = "connecting"
    elif _last_error:
        connection_state = "error"
    else:
        connection_state = "not_running"
    return {
        **settings,
        **paths,
        "settings_path": str(settings_path()),
        "bridge_count": len(_effective_bridge_lines(settings)),
        "builtin_bridge_auto_update": True,
        "builtin_bridge_source": builtin_bridges["source"],
        "builtin_bridge_source_path": builtin_bridges["source_path"],
        "builtin_bridge_updated_at": builtin_bridges["updated_at"],
        "builtin_bridge_recommended_mode": builtin_bridges["recommended_mode"],
        "builtin_bridge_modes": sorted(builtin_bridges["bridges"]),
        "builtin_bridge_update_error": builtin_bridges["source_error"],
        "process_running": process_running,
        "process_pid": pid,
        "runtime_ready": not runtime_errors,
        "runtime_errors": runtime_errors,
        "socks_port_open": socks_port_open,
        **bootstrap,
        "connection_state": connection_state,
        "connected": connected,
        **exit_ip_status,
        "collector_proxy": f"socks5h://{settings['socks_host']}:{settings['socks_port']}",
        "last_error": _last_error,
    }
