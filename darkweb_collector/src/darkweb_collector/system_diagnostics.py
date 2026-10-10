from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import shutil
import sqlite3
import stat
import sys
from threading import BoundedSemaphore
import time
from typing import Literal

import psutil
from pydantic import BaseModel, ConfigDict, Field, model_validator

from darkweb_collector.diagnostic_commands import COMMAND_TIMEOUT_SECONDS, run_powershell
from darkweb_collector.runtime import configured_database_url, default_db_path, output_root, project_root, user_data_root
from darkweb_collector.storage_paths import update_state_root
from darkweb_collector.version_check import current_version_payload


logger = logging.getLogger(__name__)
MAX_BYTES = 262144
MAX_LINES = 500
_checks = {
    "runtime": "运行环境",
    "processes": "项目进程",
    "ports": "监听端口",
    "dependencies": "数据库与队列",
    "update": "在线更新状态与日志",
    "files": "项目文件",
    "logs": "日志查询",
    "command": "PowerShell 命令执行",
}
_command_examples = [
    {"label": "查看目录", "command": "dir"},
    {"label": "当前目录", "command": "Get-Location"},
    {"label": "CPU 排序", "command": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Id,ProcessName,CPU"},
    {"label": "监听端口", "command": "Get-NetTCPConnection -State Listen"},
    {"label": "查看服务", "command": "Get-Service"},
    {"label": "读取文件", "command": "Get-Content README.md -TotalCount 30"},
    {"label": "多行脚本", "command": "$here = Get-Location\nWrite-Output ('启动目录：' + $here.Path)\nGet-Date"},
    {"label": "Python 版本", "command": "python --version"},
]
_slots = BoundedSemaphore(2)
_blocked_parts = {
    "venv", ".venv", "node_modules", "dist", "data", "secrets", "config",
    "platform_sessions", "postgresql", "garnet-data", "playwright",
}
_source_suffixes = {".py", ".ps1", ".cmd", ".bat", ".js", ".vue", ".html", ".css", ".scss", ".md", ".toml"}
_secret_name = re.compile(r"password|passwd|pass2|pwd|credential|cookie|storage[_-]?state|secret|token|(?:private|api|access)[_-]?key", re.I)
_secret_key = r"password|passwd|pass2|pwd|secret|token|api[_-]?key|access[_-]?key|cookie|credential|authorization"
_assignment = re.compile(rf"(?i)(?<![\w-])([\"']?(?=[\w-]*(?:{_secret_key}))[\w-]+[\"']?\s*[:=]\s*)(\[REDACTED\]|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}}\]]+)")


class DiagnosticError(ValueError):
    pass


class DiagnosticBusyError(RuntimeError):
    pass


class DiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    check: Literal["runtime", "processes", "ports", "dependencies", "update", "files", "logs", "command"]
    root: Literal["project", "logs", "output", "data", "update"] = "project"
    path: str = Field(default="", max_length=512)
    keyword: str = Field(default="", max_length=120)
    limit: int = Field(default=200, ge=1, le=MAX_LINES)
    command: str = Field(default="", max_length=16384)

    @model_validator(mode="after")
    def validate_command(self):
        if self.command and self.check != "command":
            raise ValueError("命令文本只能用于命令执行")
        if self.check == "command" and not self.command.strip():
            raise ValueError("请输入 PowerShell 命令或脚本")
        if self.command:
            try:
                self.command.encode("utf-8")
            except UnicodeError as exc:
                raise ValueError("命令文本包含无效字符编码") from exc
        if self.check != "command" and self.root not in {"project", "logs", "output"}:
            raise ValueError("此目录仅用于命令执行的启动位置")
        if self.check == "update" and self.path:
            raise ValueError("更新诊断仅读取固定更新状态和日志，不接受文件路径")
        return self


def _roots() -> dict[str, Path]:
    return {
        "project": project_root().parent.resolve(),
        "logs": (project_root() / ".runtime" / "windows" / "logs").resolve(),
        "output": output_root().resolve(),
    }


def _command_roots() -> dict[str, Path]:
    return {
        "project": project_root().parent,
        "logs": project_root() / ".runtime" / "windows" / "logs",
        "output": output_root(),
        "data": user_data_root(),
        "update": update_state_root(),
    }


def redact_text(text: str) -> str:
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", "[REDACTED PRIVATE KEY]", text)
    text = re.sub(r"(?im)([\"']?(?:authorization|cookie|set-cookie)[\"']?\s*[:=]\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9+/=._-]+", r"\1 [REDACTED]", text)
    text = re.sub(r"(?i)(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*://)[^/\s]+@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?i)([?&](?:sig|signature|x-amz-signature|x-goog-signature)=)[^&#\s]+", r"\1[REDACTED]", text)
    text = _assignment.sub(r"\1[REDACTED]", text)
    for key, value in os.environ.items():
        if _secret_name.search(key) and len(value) >= 4:
            text = text.replace(value, "[REDACTED]")
    return text


def _redact(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


def catalog() -> dict:
    labels = {"project": "项目目录", "logs": "运行日志", "output": "采集输出", "data": "项目数据目录", "update": "更新状态目录"}
    return {
        "roots": [{"id": key, "label": labels[key], "path": str(path), "exists": path.is_dir()} for key, path in _roots().items()],
        "command_roots": [{"id": key, "label": labels[key], "path": str(path), "exists": path.is_dir()} for key, path in _command_roots().items()],
        "checks": [{"id": key, "label": label} for key, label in _checks.items()],
        "limits": {"max_lines": MAX_LINES, "max_bytes": MAX_BYTES},
        "read_only": False,
        "checks_read_only": True,
        "command_mode": "powershell",
        "command_scope": "working_directory",
        "command_max_length": 16384,
        "command_examples": _command_examples,
        "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
    }


def _allowed_part(part: str) -> bool:
    return (
        part == part.strip() and not part.endswith(".") and not part.startswith(".")
        and not any(char in part for char in '<>:"|?*')
        and not re.match(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part, re.I)
        and part.casefold() not in _blocked_parts and not _secret_name.search(part)
    )


def _resolve_path(root: Path, relative: str) -> Path:
    relative = relative.replace("\\", "/")
    if PureWindowsPath(relative).is_absolute() or relative.startswith("/") or any(char in relative for char in (":", "\x00")):
        raise DiagnosticError("请输入所选目录内的相对路径")
    parts = relative.split("/") if relative else []
    if any(not part or part in {".", ".."} or not _allowed_part(part) for part in parts):
        raise DiagnosticError("路径包含禁止访问的目录或文件")
    target = root
    for part in parts:
        target = target / part
        info = target.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise DiagnosticError("不支持通过符号链接或目录联接访问文件")
    resolved_parts = target.resolve().relative_to(root).parts
    if any(not _allowed_part(part) for part in resolved_parts):
        raise DiagnosticError("路径指向禁止访问的目录或文件")
    return target


def _readable_file(path: Path, root_id: str) -> bool:
    if not _allowed_part(path.name):
        return False
    if root_id != "project":
        return path.suffix.lower() in {".log", ".txt"}
    return path.suffix.lower() in _source_suffixes or path.name in {"version.json", "package.json", "requirements.txt"}


def _command_directory(root: Path, value: str) -> Path:
    value = value.replace("\\", "/")
    supplied = PureWindowsPath(value)
    if "\x00" in value or value.startswith("//") or supplied.anchor and not supplied.is_absolute():
        raise DiagnosticError("工作目录必须是所选范围内的本地目录")
    for part in supplied.parts[1:] if supplied.is_absolute() else supplied.parts:
        if part == ".." or part.endswith((".", " ")) or ":" in part:
            raise DiagnosticError("工作目录包含无效路径")
    root = Path(os.path.abspath(root))
    target = Path(os.path.abspath(value)) if supplied.is_absolute() else root.joinpath(*supplied.parts)
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise DiagnosticError("启动工作目录必须位于所选目录范围内") from exc
    for candidate in (target, *target.parents):
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise DiagnosticError("工作目录不支持符号链接或目录联接")
    if not target.is_dir():
        raise DiagnosticError("工作目录必须是现有目录")
    return target


def _command_query(request: DiagnosticRequest) -> tuple[dict, bool]:
    directory = _command_directory(_command_roots()[request.root], request.path)
    data, truncated = run_powershell(request.command, directory, MAX_BYTES)
    data["command"] = request.command
    data["command_mode"] = "powershell"
    data["command_scope"] = "working_directory"
    return data, truncated


def _file_query(request: DiagnosticRequest) -> tuple[dict, bool]:
    root = _roots()[request.root]
    target = _resolve_path(root, request.path)
    if not target.exists():
        raise DiagnosticError("目录或文件不存在")
    if target.is_dir():
        entries = []
        examined = 0
        for entry in target.iterdir():
            examined += 1
            if examined > 2000 or len(entries) > request.limit:
                break
            if not _allowed_part(entry.name) or (request.keyword and request.keyword.casefold() not in entry.name.casefold()):
                continue
            try:
                safe = _resolve_path(root, entry.relative_to(root).as_posix())
                info = safe.stat()
                is_dir = stat.S_ISDIR(info.st_mode)
                if not is_dir and (not stat.S_ISREG(info.st_mode) or not _readable_file(safe, request.root)):
                    continue
                entries.append({"name": entry.name, "path": entry.relative_to(root).as_posix(), "type": "directory" if is_dir else "file", "size": 0 if is_dir else info.st_size})
            except (OSError, ValueError):
                continue
        entries.sort(key=lambda entry: (entry["type"] != "directory", entry["name"].casefold()))
        return {"path": request.path, "entries": entries[:request.limit]}, len(entries) > request.limit or examined > 2000
    if not _readable_file(target, request.root):
        raise DiagnosticError("仅支持查询项目源码、运行日志及指定版本文件")
    with target.open("rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise DiagnosticError("不支持读取此文件类型")
        prefix = handle.read(3)
        encoding = "utf-16" if prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        offset = max(0, info.st_size - MAX_BYTES) if request.check == "logs" else 0
        if offset and encoding == "utf-16":
            encoding = "utf-16-le" if prefix.startswith(b"\xff\xfe") else "utf-16-be"
            offset += offset % 2
        handle.seek(offset)
        text = handle.read(MAX_BYTES).decode(encoding, errors="replace")
    lines = redact_text(text).splitlines()
    if offset and lines:
        lines = lines[1:]
    if request.keyword:
        lines = [line for line in lines if request.keyword.casefold() in line.casefold()]
    selected = lines[-request.limit:] if request.check == "logs" else lines[:request.limit]
    return {"path": request.path, "text": "\n".join(selected), "lines": len(selected), "scanned_bytes": min(info.st_size, MAX_BYTES)}, info.st_size > MAX_BYTES or len(lines) > request.limit


def _runtime() -> dict:
    root = project_root().parent
    total, used, free = shutil.disk_usage(root)
    version = current_version_payload()
    return {
        "version": version.get("version"), "commit": version.get("commit"),
        "platform": platform.platform(), "python": platform.python_version(),
        "python_executable": sys.executable, "pid": os.getpid(),
        "started_at": datetime.fromtimestamp(psutil.Process().create_time(), timezone.utc).isoformat(),
        "project_root": str(root), "data_root": str(user_data_root()),
        "database_path": str(default_db_path()), "output_root": str(output_root()),
        "disk": {"total_bytes": total, "used_bytes": used, "free_bytes": free},
    }


def _update_diagnostics(request: DiagnosticRequest) -> tuple[dict, bool]:
    try:
        expected_root = update_state_root()
    except ValueError as exc:
        raise DiagnosticError("更新状态目录无效") from exc
    configured = os.environ.get("DARKWEB_UPDATE_STATE_DIR", "").strip()
    local = os.environ.get("LOCALAPPDATA", "").strip()
    root = Path(configured).expanduser() if configured else (Path(local) / "DarkWebThreatIntel" if local else update_state_root())
    for directory in (root, *root.parents):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise DiagnosticError("不支持通过符号链接或目录联接读取更新日志")
    if root.resolve() != expected_root:
        raise DiagnosticError("更新状态目录无效")
    root = root.resolve()

    def read_fixed(name: str, maximum: int, tail: bool) -> tuple[str, int, bool]:
        try:
            path = _resolve_path(root, name)
        except FileNotFoundError:
            return "", 0, False
        before = path.lstat()
        with path.open("rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or (before.st_dev, before.st_ino) != (info.st_dev, info.st_ino):
                raise DiagnosticError("更新诊断文件类型或身份发生变化")
            if not tail and info.st_size > maximum:
                raise DiagnosticError("更新状态文件过大")
            prefix = handle.read(3)
            encoding = "utf-16" if prefix.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            offset = max(0, info.st_size - maximum) if tail else 0
            if offset and encoding == "utf-16":
                encoding = "utf-16-le" if prefix.startswith(b"\xff\xfe") else "utf-16-be"
                offset += offset % 2
            handle.seek(offset)
            text = handle.read(maximum).decode(encoding, errors="replace")
        if offset:
            text = text.split("\n", 1)[1] if "\n" in text else ""
            end = re.search(r"-----END [^-]*PRIVATE KEY-----", text)
            begin = re.search(r"-----BEGIN [^-]*PRIVATE KEY-----", text)
            if end and (begin is None or end.start() < begin.start()):
                text = "[REDACTED PRIVATE KEY]\n" + text[end.end():]
            elif begin is None:
                leading = re.match(r"(?:[A-Za-z0-9+/=]{40,}\r?\n)+", text)
                if leading:
                    text = "[REDACTED PRIVATE KEY FRAGMENT]\n" + text[leading.end():]
        return text, min(info.st_size, maximum), info.st_size > maximum

    status_text, _, _ = read_fixed("update-status.json", 16384, False)
    try:
        status = json.loads(status_text) if status_text else {"status": "idle"}
    except (ValueError, TypeError) as exc:
        raise DiagnosticError("更新状态文件无效") from exc
    if not isinstance(status, dict):
        raise DiagnosticError("更新状态文件无效")
    fields = {"status", "stage", "last_stage", "message", "error", "pid", "pid_created_at", "started_at", "updated_at", "finished_at", "job_id", "target_version", "before_version", "after_version", "rollback_status"}
    text, scanned, truncated = read_fixed("update.log", MAX_BYTES, True)
    lines = redact_text(text).splitlines()
    if request.keyword:
        lines = [line for line in lines if request.keyword.casefold() in line.casefold()]
    selected = lines[-request.limit:]
    return {"status": {key: value for key, value in status.items() if key in fields},
            "log": {"path": "update.log", "text": "\n".join(selected), "lines": len(selected), "scanned_bytes": scanned}}, truncated or len(lines) > request.limit


def _processes() -> list[dict]:
    related = []
    collector = str(project_root()).casefold().replace("\\", "/")
    dashboard = str(project_root().parent / "threat-intelligence-dashboard").casefold().replace("\\", "/")
    for process in psutil.process_iter(["pid", "name", "cmdline", "create_time", "status"]):
        try:
            info = process.info
            command = " ".join(info.get("cmdline") or []).casefold().replace("\\", "/")
            name = (info.get("name") or "").casefold().removesuffix(".exe")
            if process.pid != os.getpid() and collector not in command and dashboard not in command and "darkweb_collector." not in command and name not in {"postgres", "garnet", "redis-server", "tor"}:
                continue
            related.append({"pid": info["pid"], "name": info["name"], "status": info["status"], "started_at": datetime.fromtimestamp(info["create_time"], timezone.utc).isoformat() if info["create_time"] else None})
        except (psutil.Error, TypeError, ValueError):
            continue
    return sorted(related, key=lambda item: item["pid"])


def _ports() -> list[dict]:
    pids = {item["pid"] for item in _processes()}
    return [{"pid": connection.pid, "address": connection.laddr.ip, "port": connection.laddr.port}
            for connection in psutil.net_connections(kind="inet")
            if connection.status == psutil.CONN_LISTEN and connection.laddr and
            (connection.pid in pids or connection.laddr.port in {5432, 6379, 9050})]


def _dependencies() -> dict:
    from darkweb_collector.queueing import QUEUE_CONCURRENCY
    from darkweb_collector.worker_supervisor import queue_health_errors
    import redis

    result = {}
    database_url = configured_database_url()
    try:
        if database_url:
            import psycopg2
            connection = psycopg2.connect(database_url, connect_timeout=2, options="-c statement_timeout=2000 -c default_transaction_read_only=on")
        else:
            connection = sqlite3.connect(default_db_path().resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
            connection.execute("PRAGMA query_only=ON")
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            result["database"] = {"status": "ok" if cursor.fetchone()[0] == 1 else "error", "engine": "postgresql" if database_url else "sqlite"}
        finally:
            connection.close()
    except Exception as exc:
        result["database"] = {"status": "error", "error": str(exc)}
    client = None
    try:
        client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"), socket_connect_timeout=2, socket_timeout=2, retry_on_timeout=False)
        client.ping()
        keys = [(queue, queue if priority == 0 else f"{queue}\x06\x16{priority}") for queue in QUEUE_CONCURRENCY for priority in (0, 3, 6, 9)]
        pipeline = client.pipeline(transaction=False)
        for _, key in keys:
            pipeline.type(key)
        types = pipeline.execute()
        lengths = client.pipeline(transaction=False)
        list_keys = [item for item, kind in zip(keys, types) if kind in (b"list", "list")]
        for _, key in list_keys:
            lengths.llen(key)
        counts = lengths.execute() if list_keys else []
        queues = {queue: {"pending": 0, "status": "ok"} for queue in QUEUE_CONCURRENCY}
        for (queue, _), count in zip(list_keys, counts):
            queues[queue]["pending"] += count
        for (queue, _), kind in zip(keys, types):
            if kind not in (b"none", b"list", "none", "list"):
                queues[queue]["status"] = "wrong_type"
        result["redis"] = {"status": "ok", "queues": queues}
    except Exception as exc:
        result["redis"] = {"status": "error", "error": str(exc)}
    finally:
        if client is not None:
            client.close()
    result["worker_errors"] = queue_health_errors()
    result["worker_coverage"] = "守护进程已有的健康快照；无错误记录不代表所有 Worker 在线"
    return result


def run_check(request: DiagnosticRequest, username: str) -> dict:
    if not _slots.acquire(blocking=False):
        raise DiagnosticBusyError("已有诊断正在执行，请稍后重试")
    started = time.monotonic()
    outcome = "error"
    try:
        truncated = False
        if request.check == "command":
            data, truncated = _command_query(request)
        elif request.check in {"files", "logs"}:
            if request.check == "logs" and request.root == "project":
                raise DiagnosticError("日志查询请选择运行日志或采集输出目录")
            data, truncated = _file_query(request)
        elif request.check == "runtime":
            data = _runtime()
        elif request.check == "dependencies":
            data = _dependencies()
        elif request.check == "update":
            data, truncated = _update_diagnostics(request)
        else:
            rows = _processes() if request.check == "processes" else _ports()
            if request.keyword:
                rows = [row for row in rows if request.keyword.casefold() in str(row).casefold()]
            data = {"items": rows[:request.limit]}
            truncated = len(rows) > request.limit
        outcome = "ok"
        return {"check": request.check, "checked_at": datetime.now(timezone.utc).isoformat(), "duration_ms": round((time.monotonic() - started) * 1000), "data": _redact(data), "truncated": truncated}
    except (OSError, psutil.Error) as exc:
        raise DiagnosticError(redact_text(str(exc))) from exc
    finally:
        logger.info("system diagnostic user=%s check=%s root=%s outcome=%s duration_ms=%s", username.replace("\r", "").replace("\n", ""), request.check, request.root, outcome, round((time.monotonic() - started) * 1000))
        _slots.release()
