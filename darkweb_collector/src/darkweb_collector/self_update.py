from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, TextIO

import psutil

from darkweb_collector.version_check import (
    _is_newer_version,
    _open_update_request,
    _request_headers,
    _validate_update_url,
    current_version_payload,
    load_update_manifest,
)
from darkweb_collector.storage_paths import app_root, data_root, update_state_root


ACTIVE_STATUSES = {"queued", "running"}
UPDATER_VERSION = 1
MAX_ARCHIVE_MEMBERS = 50_000
MAX_UNPACKED_BYTES = 4 * 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 500
VERSION_DIR_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
REQUIRED_PACKAGE_FILES = (
    "version.json",
    "darkweb_collector/sites.yaml",
    "darkweb_collector/scripts/run_self_update.py",
    "darkweb_collector/scripts/start_all_services_windows.ps1",
    "threat-intelligence-dashboard/package.json",
)


class SelfUpdateError(RuntimeError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _state_dir() -> Path:
    try:
        return update_state_root()
    except ValueError as exc:
        raise SelfUpdateError(str(exc)) from exc


def _state_path() -> Path:
    return _state_dir() / "update-status.json"


def _log_path() -> Path:
    return _state_dir() / "update.log"


def _installation_path() -> Path:
    return _state_dir() / "installation.json"


def _releases_dir() -> Path:
    return app_root() / "releases"


def _downloads_dir() -> Path:
    return app_root() / "updates"


def _config_dir() -> Path:
    return data_root() / "config"


def _idle_status() -> dict[str, Any]:
    return {
        "status": "idle",
        "stage": "idle",
        "message": "尚未执行更新",
        "updated": False,
        "restart_required": False,
    }


def _read_update_status_raw() -> dict[str, Any]:
    path = _state_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _idle_status()
    return payload if isinstance(payload, dict) else _idle_status()


def _queued_within_start_grace(payload: dict[str, Any]) -> bool:
    if payload.get("status") != "queued":
        return False
    try:
        started = datetime.fromisoformat(str(payload.get("started_at") or "").replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - started.astimezone(timezone.utc)).total_seconds() < 15
    except (TypeError, ValueError):
        return False


def read_update_status() -> dict[str, Any]:
    payload = _read_update_status_raw()
    if payload.get("status") in ACTIVE_STATUSES and _process_running(payload.get("pid"), payload.get("pid_created_at")) is False:
        if _queued_within_start_grace(payload):
            return payload
        recorded = _read_update_status_raw()
        if recorded != payload:
            return recorded
        payload.update(
            status="failed",
            stage="failed",
            last_stage=payload.get("last_stage") or payload.get("stage"),
            message="更新进程已中止",
            error="更新进程意外退出",
            updated=False,
            finished_at=_now_iso(),
        )
        return _write_update_status(payload)
    return payload


def read_public_update_status() -> dict[str, Any]:
    payload = read_update_status().copy()
    payload.pop("log_path", None)
    return payload


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    temporary_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary_path, path)


def _write_update_status(payload: dict[str, Any]) -> dict[str, Any]:
    value = {**payload, "updated_at": _now_iso()}
    _atomic_json(_state_path(), value)
    return value


def _process_running(pid: object, created_at: object = None) -> bool | None:
    try:
        process_id = int(pid or 0)
    except (TypeError, ValueError):
        return False
    if process_id <= 0:
        return False
    try:
        process = psutil.Process(process_id)
        if created_at is not None and abs(process.create_time() - float(created_at)) >= 1:
            return False
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False
    except (psutil.Error, OSError, TypeError, ValueError):
        return None


@contextmanager
def _update_lock() -> Iterator[None]:
    path = _state_dir() / "update.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    stream = path.open("a+b")
    try:
        if path.stat().st_size == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SelfUpdateError("已有更新任务正在执行") from exc
        yield
    finally:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        stream.close()


def _ensure_update_enabled() -> None:
    if os.environ.get("DARKWEB_SELF_UPDATE_ENABLED", "1") == "0":
        raise SelfUpdateError("在线更新已被 DARKWEB_SELF_UPDATE_ENABLED 禁用")
    if os.name != "nt":
        raise SelfUpdateError("当前无 Git 更新器暂仅支持 Windows")


def _load_manifest_for_update(current: dict[str, Any]) -> dict[str, Any]:
    try:
        return load_update_manifest(str(current.get("manifest_url") or ""))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, UnicodeError, TimeoutError, ValueError) as exc:
        raise SelfUpdateError(f"无法读取更新清单：{exc}") from exc


def _read_installation() -> dict[str, Any]:
    try:
        payload = json.loads(_installation_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict) or payload.get("format") != 1:
        return {}
    return payload


def _launcher_command(project_root: Path, action: str) -> list[str]:
    if os.name == "nt":
        script = project_root / "darkweb_collector" / "scripts" / "start_all_services_windows.ps1"
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell or not script.exists():
            raise SelfUpdateError("找不到 Windows 服务启动脚本或 PowerShell")
        return [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), "-DataRoot", str(data_root()), action]
    raise SelfUpdateError("当前无 Git 更新器暂仅支持 Windows")


def _run_logged(command: list[str], project_root: Path, log: TextIO, timeout: int = 1800) -> None:
    log.write(f"\n[{_now_iso()}] $ {' '.join(command)}\n")
    log.flush()
    started = time.monotonic()
    try:
        environment = os.environ.copy()
        environment["DARKWEB_UPDATE_CONTROLLER_PID"] = str(os.getpid())
        environment["DARKWEB_UPDATE_CONTROLLER_CREATE_TIME"] = str(psutil.Process(os.getpid()).create_time())
        if os.name == "nt" and Path(command[0]).name.casefold() == "powershell.exe":
            for name in list(environment):
                if name.casefold() == "psmodulepath":
                    environment.pop(name, None)
        result = subprocess.run(
            command,
            cwd=project_root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, psutil.Error) as exc:
        log.write(f"\n[{_now_iso()}] Command failed: {type(exc).__name__}: {exc}\n")
        log.flush()
        raise SelfUpdateError(f"更新命令执行失败：{exc}") from exc
    native_code = f"0x{result.returncode & 0xffffffff:08X}"
    log.write(f"\n[{_now_iso()}] Command exited: exit_code={result.returncode} native_code={native_code} duration_ms={round((time.monotonic() - started) * 1000)}\n")
    log.flush()
    if result.returncode != 0:
        raise SelfUpdateError(f"更新命令退出码为 {result.returncode} ({native_code})，请查看自动更新日志")


def _signature_payload(manifest: dict[str, Any]) -> bytes:
    package = manifest["package"]
    payload = {
        "channel": manifest["channel"],
        "commit": manifest["commit"],
        "format": manifest["format"],
        "package": {
            "name": package["name"],
            "sha256": package["sha256"],
            "size": package["size"],
            "url": package["url"],
        },
        "published_at": manifest["published_at"],
        "minimum_updater_version": manifest["minimum_updater_version"],
        "data_schema": manifest["data_schema"],
        "rollback_compatible": manifest["rollback_compatible"],
        "release_url": manifest["release_url"],
        "version": manifest["version"],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _verify_manifest_signature(manifest: dict[str, Any]) -> str:
    signature = manifest.get("signature") if isinstance(manifest.get("signature"), dict) else {}
    required = os.environ.get("DARKWEB_UPDATE_REQUIRE_SIGNATURE", "") == "1"
    if not signature:
        if required:
            raise SelfUpdateError("更新清单缺少数字签名")
        return "not_configured"

    algorithm = str(signature.get("algorithm") or "").lower()
    encoded = str(signature.get("value") or "").strip()
    configured_key = os.environ.get("DARKWEB_UPDATE_PUBLIC_KEY_FILE", "").strip()
    key_path = Path(configured_key).expanduser().resolve() if configured_key else _project_root() / "update-signing-public.pem"
    if algorithm != "ed25519" or not encoded or not key_path.is_file():
        raise SelfUpdateError("更新清单数字签名配置无效")
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        public_key = load_pem_public_key(key_path.read_bytes())
        public_key.verify(base64.b64decode(encoded, validate=True), _signature_payload(manifest))
    except Exception as exc:
        raise SelfUpdateError("更新清单数字签名校验失败") from exc
    return "verified"


def _download_update_package(
    manifest: dict[str, Any],
    target: Path,
    state: dict[str, Any],
) -> Path:
    package = manifest["package"]
    expected_size = int(package["size"])
    expected_hash = str(package["sha256"])
    manifest_url = str(manifest["manifest_url"])
    package_url = _validate_update_url(str(package["url"]), "更新包地址", manifest_url)
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    partial.unlink(missing_ok=True)

    request = urllib.request.Request(package_url, headers=_request_headers("application/octet-stream"))
    timeout = int(os.environ.get("DARKWEB_UPDATE_DOWNLOAD_TIMEOUT_SECONDS") or 300)
    digest = hashlib.sha256()
    downloaded = 0
    last_percent = -1
    try:
        with _open_update_request(request, manifest_url, max(1, timeout)) as response, partial.open("wb") as output:
            _validate_update_url(response.geturl(), "更新包重定向地址", manifest_url)
            header_size = int(response.headers.get("Content-Length") or 0)
            if header_size and header_size != expected_size:
                raise SelfUpdateError("更新包响应大小与清单不一致")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > expected_size:
                    raise SelfUpdateError("更新包超过清单声明大小")
                digest.update(chunk)
                output.write(chunk)
                percent = int(downloaded * 100 / expected_size)
                if percent != last_percent and (percent == 100 or percent - last_percent >= 2):
                    last_percent = percent
                    state.update(stage="downloading", message=f"正在下载更新包 {percent}%", progress=percent)
                    _write_update_status(state)
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise SelfUpdateError(f"更新包下载失败：{exc}") from exc
    finally:
        if partial.exists() and downloaded != expected_size:
            partial.unlink(missing_ok=True)

    if downloaded != expected_size:
        raise SelfUpdateError("更新包下载不完整")
    if digest.hexdigest().lower() != expected_hash:
        partial.unlink(missing_ok=True)
        raise SelfUpdateError("更新包 SHA-256 校验失败")
    os.replace(partial, target)
    return target


def _safe_archive_name(name: str) -> PurePosixPath:
    normalized = str(name or "").replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or normalized.startswith("/")
        or normalized.startswith("//")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(":" in part for part in path.parts)
    ):
        raise SelfUpdateError(f"更新包包含非法路径：{name}")
    return path


def _extract_update_archive(archive_path: Path, destination: Path, expected_version: str) -> Path:
    maximum_unpacked = int(os.environ.get("DARKWEB_UPDATE_MAX_UNPACKED_BYTES") or MAX_UNPACKED_BYTES)
    seen: set[str] = set()
    total_size = 0
    destination.mkdir(parents=True, exist_ok=False)
    try:
        with zipfile.ZipFile(archive_path, "r", allowZip64=True) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                raise SelfUpdateError("更新包文件数量无效")
            for member in members:
                relative = _safe_archive_name(member.filename)
                identity = unicodedata.normalize("NFC", relative.as_posix()).casefold()
                if identity in seen:
                    raise SelfUpdateError(f"更新包包含重复路径：{member.filename}")
                seen.add(identity)

                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise SelfUpdateError(f"更新包包含符号链接：{member.filename}")
                total_size += member.file_size
                if total_size > maximum_unpacked:
                    raise SelfUpdateError("更新包展开大小超过限制")
                if member.compress_size > 0 and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO:
                    raise SelfUpdateError(f"更新包文件压缩比异常：{member.filename}")

                target = destination.joinpath(*relative.parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)

        for required in REQUIRED_PACKAGE_FILES:
            if not (destination / required).is_file():
                raise SelfUpdateError(f"更新包缺少必要文件：{required}")
        try:
            version_payload = json.loads((destination / "version.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SelfUpdateError("更新包 version.json 无效") from exc
        if str(version_payload.get("version") or "").strip() != expected_version:
            raise SelfUpdateError("更新包版本与更新清单不一致")
        return destination
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _raw_sites(payload: Any) -> list[dict[str, Any]]:
    value = payload.get("sites") if isinstance(payload, dict) else payload
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SelfUpdateError("站点配置格式无效")
    return value


def _merge_sites_config(current_path: Path, packaged_path: Path, destination: Path) -> Path:
    try:
        packaged_payload = json.loads(packaged_path.read_text(encoding="utf-8"))
        packaged_sites = _raw_sites(packaged_payload)
    except (OSError, json.JSONDecodeError) as exc:
        raise SelfUpdateError("新版站点配置无效") from exc

    enabled: dict[str, bool] = {}
    if current_path.is_file():
        try:
            for item in _raw_sites(json.loads(current_path.read_text(encoding="utf-8"))):
                name = str(item.get("site_name") or "").strip()
                if name:
                    enabled[name] = bool(item.get("enabled"))
        except (OSError, json.JSONDecodeError, SelfUpdateError):
            enabled = {}

    for item in packaged_sites:
        name = str(item.get("site_name") or "").strip()
        if name in enabled:
            item["enabled"] = enabled[name]
    destination.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(destination, packaged_payload if isinstance(packaged_payload, dict) else {"sites": packaged_sites})
    return destination


def _copy_shared_secrets(current_root: Path) -> None:
    source = current_root / "darkweb_collector" / "secrets"
    target = data_root() / "secrets"
    if not source.is_dir():
        return
    target.mkdir(parents=True, exist_ok=True)
    for item in source.rglob("*"):
        if not item.is_file():
            continue
        relative = item.relative_to(source)
        destination = target / relative
        if destination.exists():
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, destination)


def _user_data_dir() -> Path:
    return data_root()


def _uses_external_database() -> bool:
    if os.environ.get("DARKWEB_COLLECTOR_DATABASE_URL", "").strip():
        return True
    configured = os.environ.get("DARKWEB_ACTIVE_RELEASE_FILE", "").strip()
    path = Path(configured).expanduser().resolve() if configured else _user_data_dir() / "active-release.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(isinstance(payload, dict) and str(payload.get("database_url") or "").strip())


def _backup_sqlite_database(job_id: str) -> tuple[Path, Path] | None:
    if _uses_external_database():
        return None
    configured = os.environ.get("DARKWEB_COLLECTOR_DB_PATH", "").strip()
    source = Path(configured).expanduser().resolve() if configured else _user_data_dir() / "collector.db"
    if not source.is_file():
        return None
    backup = data_root() / "update-backups" / job_id / "collector.db"
    backup.parent.mkdir(parents=True, exist_ok=True)
    source_db = None
    target_db = None
    try:
        source_db = sqlite3.connect(source)
        target_db = sqlite3.connect(backup)
        source_db.backup(target_db)
        result = target_db.execute("PRAGMA integrity_check").fetchone()
        if not result or str(result[0]).lower() != "ok":
            raise SelfUpdateError("SQLite 更新前备份完整性检查失败")
    except (OSError, sqlite3.Error) as exc:
        raise SelfUpdateError(f"无法创建 SQLite 更新前备份：{exc}") from exc
    finally:
        if target_db is not None:
            target_db.close()
        if source_db is not None:
            source_db.close()
    return source, backup


def _restore_sqlite_database(database_backup: tuple[Path, Path] | None) -> None:
    if database_backup is None:
        return
    target, backup = database_backup
    if not backup.is_file():
        raise SelfUpdateError("SQLite 回滚备份不存在")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.{uuid.uuid4().hex}.rollback")
    shutil.copy2(backup, temporary)
    os.replace(temporary, target)
    Path(f"{target}-wal").unlink(missing_ok=True)
    Path(f"{target}-shm").unlink(missing_ok=True)


def _current_sites_path(current_root: Path, installation: dict[str, Any]) -> Path:
    configured = str(installation.get("sites_file") or os.environ.get("DARKWEB_COLLECTOR_SITES_FILE") or "").strip()
    path = Path(configured).expanduser() if configured else current_root / "darkweb_collector" / "sites.yaml"
    return path.resolve()


def _current_output_root(current_root: Path, installation: dict[str, Any]) -> Path:
    configured = str(installation.get("output_root") or os.environ.get("DARKWEB_COLLECTOR_OUTPUT_ROOT") or "").strip()
    path = Path(configured).expanduser() if configured else current_root / "darkweb_collector" / "output"
    return path.resolve()


def _release_directory(version: str, sha256: str) -> Path:
    safe_version = VERSION_DIR_PATTERN.sub("-", version).strip(".-") or "release"
    return _releases_dir() / f"{safe_version}-{sha256[:12]}"


def _prepare_release(archive: Path, manifest: dict[str, Any], job_id: str) -> Path:
    release_root = _release_directory(manifest["version"], manifest["package"]["sha256"])
    if release_root.is_dir():
        try:
            payload = json.loads((release_root / "version.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SelfUpdateError("已存在的版本目录无效") from exc
        if str(payload.get("version") or "") != manifest["version"]:
            raise SelfUpdateError("已存在的版本目录与清单不一致")
        return release_root

    staging = _releases_dir() / f".staging-{job_id}"
    _releases_dir().mkdir(parents=True, exist_ok=True)
    shutil.rmtree(staging, ignore_errors=True)
    _extract_update_archive(archive, staging, manifest["version"])
    try:
        os.replace(staging, release_root)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise SelfUpdateError(f"无法安装新版文件：{exc}") from exc
    return release_root


def _installation_payload(
    *,
    current_root: Path,
    current_version: str,
    sites_file: Path,
    output_root: Path,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "format": 1,
        "current_root": str(current_root.resolve()),
        "current_version": current_version,
        "sites_file": str(sites_file.resolve()),
        "output_root": str(output_root.resolve()),
        "control_root": str(_state_dir().resolve()),
        "app_root": str(app_root().resolve()),
        "data_root": str(data_root().resolve()),
        "previous": previous or {},
        "activated_at": _now_iso(),
    }


def _health_version(project_root: Path, expected_version: str) -> None:
    ports_path = project_root / "darkweb_collector" / ".runtime" / "windows" / "ports.json"
    try:
        ports = json.loads(ports_path.read_text(encoding="utf-8-sig"))
        api_base = str(ports.get("api_base_url") or "").rstrip("/")
        frontend_url = str(ports.get("frontend_url") or "")
        with urllib.request.urlopen(f"{api_base}/api/health", timeout=10) as response:
            health_status = json.loads(response.read().decode("utf-8"))
        if health_status.get("status") != "ok":
            raise SelfUpdateError("新版 API 健康检查失败")
        running_version = str(health_status.get("version") or "")
        if running_version != expected_version:
            raise SelfUpdateError(f"新版 API 版本校验失败：{running_version or 'unknown'}")
        with urllib.request.urlopen(frontend_url, timeout=10) as response:
            frontend = response.read(1024 * 1024).decode("utf-8", errors="replace")
        if '<meta name="darkweb-ui" content="xuanjian-new-ui"' not in frontend:
            raise SelfUpdateError("新版前端健康检查失败")
    except SelfUpdateError:
        raise
    except Exception as exc:
        raise SelfUpdateError(f"新版健康检查失败：{exc}") from exc


def _rollback(
    *,
    old_root: Path,
    old_version: str,
    old_installation: dict[str, Any],
    old_sites: Path,
    old_output: Path,
    new_root: Path | None,
    database_backup: tuple[Path, Path] | None,
    log: TextIO,
) -> str:
    try:
        stop_error: Exception | None = None
        if new_root is not None:
            try:
                _run_logged(_launcher_command(new_root, "stop"), new_root, log, timeout=300)
            except Exception as exc:
                stop_error = exc
        restore_payload = old_installation or _installation_payload(
            current_root=old_root,
            current_version=old_version,
            sites_file=old_sites,
            output_root=old_output,
            previous=None,
        )
        _atomic_json(_installation_path(), restore_payload)
        if stop_error is not None:
            raise SelfUpdateError(f"新版服务未能完全停止：{stop_error}")
        _restore_sqlite_database(database_backup)
        _run_logged(_launcher_command(old_root, "start"), old_root, log)
        _run_logged(_launcher_command(old_root, "health"), old_root, log, timeout=120)
        return "completed"
    except Exception as exc:
        log.write(f"\n[{_now_iso()}] Rollback failed: {exc}\n")
        return f"failed: {exc}"


def apply_release_update(job_id: str, state: dict[str, Any], log: TextIO) -> dict[str, Any]:
    _ensure_update_enabled()
    current = current_version_payload()
    manifest = _load_manifest_for_update(current)
    signature_status = _verify_manifest_signature(manifest)
    if manifest["minimum_updater_version"] > UPDATER_VERSION:
        raise SelfUpdateError("当前更新器版本过旧，无法安装该版本")
    if manifest["channel"] != current["channel"]:
        raise SelfUpdateError("更新清单通道与当前配置不一致")
    if not manifest["rollback_compatible"]:
        raise SelfUpdateError("该版本未声明可安全回滚，禁止自动更新")
    if int(manifest["data_schema"]) < int(current.get("data_schema") or 1):
        raise SelfUpdateError("更新包数据版本低于当前安装")
    if not _is_newer_version(manifest["version"], current["version"]):
        return {
            "updated": False,
            "before_version": current["version"],
            "after_version": current["version"],
        }

    state.update(
        target_version=manifest["version"],
        stage="verifying",
        message="正在校验更新清单",
        progress=0,
    )
    state["signature_status"] = signature_status
    _write_update_status(state)

    job_dir = _downloads_dir() / job_id
    archive = job_dir / "update.zip"
    old_root = _project_root().resolve()
    old_installation = _read_installation()
    old_sites = _current_sites_path(old_root, old_installation)
    old_output = _current_output_root(old_root, old_installation)
    new_root: Path | None = None
    database_backup: tuple[Path, Path] | None = None
    preserve_backup = False
    stop_attempted = False
    activated = False

    try:
        state.update(stage="downloading", message="正在下载更新包 0%", progress=0)
        _write_update_status(state)
        _download_update_package(manifest, archive, state)

        state.update(stage="extracting", message="正在安全解压更新包", progress=100)
        _write_update_status(state)
        new_root = _prepare_release(archive, manifest, job_id)
        new_sites = _config_dir() / f"sites-{new_root.name}.json"
        _merge_sites_config(old_sites, new_root / "darkweb_collector" / "sites.yaml", new_sites)
        _copy_shared_secrets(old_root)

        state.update(stage="installing", message="正在准备新版运行环境")
        _write_update_status(state)
        _run_logged(_launcher_command(new_root, "prepare-update"), new_root, log)

        previous = {
            "root": str(old_root),
            "version": str(current["version"]),
            "sites_file": str(old_sites),
            "output_root": str(old_output),
            "control_root": str(_state_dir()),
            "app_root": str(app_root()),
            "data_root": str(data_root()),
        }
        new_installation = _installation_payload(
            current_root=new_root,
            current_version=manifest["version"],
            sites_file=new_sites,
            output_root=old_output,
            previous=previous,
        )

        state.update(stage="stopping", message="更新包已就绪，正在停止旧版服务", restart_required=True)
        _write_update_status(state)
        stop_attempted = True
        _run_logged(_launcher_command(old_root, "stop"), old_root, log, timeout=300)
        _merge_sites_config(old_sites, new_root / "darkweb_collector" / "sites.yaml", new_sites)
        _copy_shared_secrets(old_root)
        state.update(stage="backing_up", message="正在创建更新前数据备份")
        _write_update_status(state)
        database_backup = _backup_sqlite_database(job_id)

        state.update(stage="switching", message="正在切换到新版本")
        _write_update_status(state)
        _atomic_json(_installation_path(), new_installation)
        activated = True

        state.update(stage="restarting", message="正在启动新版本")
        _write_update_status(state)
        _run_logged(_launcher_command(new_root, "start"), new_root, log)

        state.update(stage="health_check", message="正在检查新版服务")
        _write_update_status(state)
        _run_logged(_launcher_command(new_root, "health"), new_root, log, timeout=120)
        _health_version(new_root, manifest["version"])
        return {
            "updated": True,
            "before_version": current["version"],
            "after_version": manifest["version"],
            "before_commit": current["commit"],
            "after_commit": manifest["commit"],
            "release_root": str(new_root),
        }
    except Exception as exc:
        state["last_stage"] = state.get("stage")
        if stop_attempted:
            state.update(stage="rolling_back", message="更新失败，正在恢复旧版本")
            _write_update_status(state)
            rollback_status = _rollback(
                old_root=old_root,
                old_version=str(current["version"]),
                old_installation=old_installation if activated else {},
                old_sites=old_sites,
                old_output=old_output,
                new_root=new_root if activated else None,
                database_backup=database_backup,
                log=log,
            )
            state["rollback_status"] = rollback_status
            preserve_backup = rollback_status.startswith("failed:")
            if isinstance(exc, SelfUpdateError):
                exc.args = (f"{exc}; 回滚状态：{rollback_status}",)
            else:
                exc = SelfUpdateError(f"{exc}; 回滚状态：{rollback_status}")
        raise exc
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)
        if not preserve_backup:
            shutil.rmtree(data_root() / "update-backups" / job_id, ignore_errors=True)


def run_self_update(job_id: str, wait_seconds: float = 1.0) -> None:
    if wait_seconds > 0:
        time.sleep(wait_seconds)

    state = {**_read_update_status_raw(), "job_id": job_id}
    try:
        with _update_lock():
            recorded = _read_update_status_raw()
            if recorded.get("job_id") != job_id:
                return
            state.update(
                pid=os.getpid(),
                pid_created_at=psutil.Process(os.getpid()).create_time(),
                status="running",
                stage="checking",
                message="正在检查更新清单",
                updated=False,
                restart_required=False,
                log_path=str(_log_path()),
            )
            _write_update_status(state)
            _log_path().parent.mkdir(parents=True, exist_ok=True)
            with _log_path().open("a", encoding="utf-8") as log:
                result = apply_release_update(job_id, state, log)
        state.update(result)
        if result["updated"]:
            state.update(
                status="completed",
                stage="completed",
                message="更新完成，服务已重新启动",
                finished_at=_now_iso(),
            )
        else:
            state.update(
                status="completed",
                stage="completed",
                message="当前已经是最新版本",
                finished_at=_now_iso(),
            )
        _write_update_status(state)
    except Exception as exc:
        recorded = _read_update_status_raw()
        if recorded.get("job_id") == job_id:
            state.update(
                status="failed",
                stage="failed",
                last_stage=state.get("last_stage") or state.get("stage"),
                message="自动更新失败",
                error=str(exc),
                updated=False,
                finished_at=_now_iso(),
            )
            _write_update_status(state)


def start_self_update() -> dict[str, Any]:
    _ensure_update_enabled()
    with _update_lock():
        existing = read_update_status()
        if existing.get("status") in ACTIVE_STATUSES:
            raise SelfUpdateError("已有更新任务正在执行")

        current = current_version_payload()
        manifest = _load_manifest_for_update(current)
        _verify_manifest_signature(manifest)
        if manifest["minimum_updater_version"] > UPDATER_VERSION:
            raise SelfUpdateError("当前更新器版本过旧，无法安装该版本")

        job_id = uuid.uuid4().hex
        state = _write_update_status(
            {
                "job_id": job_id,
                "pid": 0,
                "status": "queued",
                "stage": "queued",
                "message": "更新任务已启动",
                "branch": str(current.get("branch") or ""),
                "remote": "",
                "target_version": manifest["version"],
                "updated": False,
                "restart_required": False,
                "started_at": _now_iso(),
                "log_path": str(_log_path()),
            }
        )

        helper = _project_root() / "darkweb_collector" / "scripts" / "run_self_update.py"
        command = [sys.executable, str(helper), "--job-id", job_id]
        kwargs: dict[str, Any] = {
            "cwd": str(_project_root()),
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "close_fds": True,
            "creationflags": (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "DETACHED_PROCESS", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            ),
        }

        try:
            process = subprocess.Popen(command, **kwargs)
        except OSError as exc:
            state.update(status="failed", stage="failed", message="无法启动更新进程", error=str(exc))
            _write_update_status(state)
            raise SelfUpdateError(str(exc)) from exc

        state["pid"] = process.pid
        return _write_update_status(state)
