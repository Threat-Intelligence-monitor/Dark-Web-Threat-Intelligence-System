"""Owned Playwright scratch space; never reclaim a shared system temp directory."""
from __future__ import annotations

import atexit
from contextlib import contextmanager
import errno
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import stat
from threading import Lock, Thread
import time
from uuid import uuid4

import psutil

from darkweb_collector.storage_paths import data_root


logger = logging.getLogger(__name__)
_NAMES = ("TMP", "TEMP", "TMPDIR", "DARKWEB_BROWSER_TEMP_DIR")
_DIRECTORY = re.compile(r"p([1-9][0-9]*)-([1-9][0-9]*)-([a-f0-9]{32})\Z")
_LOCK = Lock()
_current: Path | None = None
_previous: dict[str, str | None] = {}
_cleanup_thread: Thread | None = None
_last_cleanup = 0.0
_last_warning = 0.0
MINIMUM_BROWSER_TEMP_FREE_BYTES = 2 * 1024 * 1024 * 1024


def _native(path: Path) -> Path:
    value = str(path)
    if os.name == "nt" and not value.startswith("\\\\?\\"):
        value = "\\\\?\\" + os.path.abspath(value)
    return Path(value)


def _normal(path: Path) -> Path:
    value = str(path)
    return Path(value[4:] if value.startswith("\\\\?\\") else value)


def _linked(path: Path) -> bool:
    return bool(_native(path).lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT) if os.name == "nt" else path.is_symlink()


def _plain_path(path: Path) -> None:
    path = _normal(path)
    for item in (path, *path.parents):
        if os.path.lexists(_native(item)):
            if _linked(item):
                raise ValueError("Browser temporary directory contains a linked path")


def _root() -> Path:
    root = data_root() / "runtime-temp" / "playwright"
    _plain_path(root)
    _native(root).mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


@contextmanager
def _root_lock(root: Path):
    path = root / ".cleanup.lock"
    _plain_path(path)
    with _native(path).open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            yield False
            return
        try:
            yield True
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _owner(path: Path) -> dict:
    match = _DIRECTORY.fullmatch(path.name)
    if match is None:
        raise ValueError("Unrecognized browser temporary directory")
    marker = path / "owner.json"
    _plain_path(marker)
    if _native(marker).stat().st_size > 1024:
        raise ValueError("Invalid browser temporary owner marker")
    payload = json.loads(_native(marker).read_text(encoding="utf-8"))
    if (not isinstance(payload, dict) or type(payload.get("format")) is not int or payload["format"] != 1
            or type(payload.get("pid")) is not int or payload["pid"] != int(match[1])
            or not isinstance(payload.get("started"), (float, int)) or isinstance(payload["started"], bool)
            or not math.isfinite(payload["started"]) or payload["started"] <= 0
            or round(payload["started"] * 1_000_000) != int(match[2])):
        raise ValueError("Invalid browser temporary process identity")
    return payload


def _alive(owner: dict) -> bool:
    try:
        process = psutil.Process(owner["pid"])
        return process.is_running() and abs(process.create_time() - owner["started"]) < 0.001
    except psutil.NoSuchProcess:
        return False


def _processes() -> list[dict]:
    if os.name == "nt":
        # psutil.ppid() takes a fresh system snapshot per PID on Windows.
        # One Toolhelp snapshot keeps normal shutdown independent of process count.
        import ctypes
        from ctypes import wintypes

        class Entry(ctypes.Structure):
            _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD), ("pid", wintypes.DWORD),
                        ("heap", ctypes.c_size_t), ("module", wintypes.DWORD), ("threads", wintypes.DWORD),
                        ("parent", wintypes.DWORD), ("priority", wintypes.LONG), ("flags", wintypes.DWORD),
                        ("name", wintypes.WCHAR * 260)]
        api = ctypes.WinDLL("kernel32", use_last_error=True)
        api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        api.Process32FirstW.argtypes = api.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        api.Process32FirstW.restype = api.Process32NextW.restype = wintypes.BOOL
        api.CloseHandle.argtypes = [wintypes.HANDLE]
        api.CloseHandle.restype = wintypes.BOOL
        handle = api.CreateToolhelp32Snapshot(2, 0)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        result = []
        try:
            entry = Entry()
            entry.size = ctypes.sizeof(entry)
            available = api.Process32FirstW(handle, ctypes.byref(entry))
            while available:
                result.append({"pid": entry.pid, "ppid": entry.parent, "name": entry.name})
                available = api.Process32NextW(handle, ctypes.byref(entry))
            if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            api.CloseHandle(handle)
        return result
    return [process.info for process in psutil.process_iter(["pid", "ppid", "name"])]


def _in_use(path: Path, owner: dict, processes: list[dict], *, owner_alive: bool = False) -> bool:
    # On Windows, the parent PID remains available even after its owner exits.
    # Keep descendants until the driver's own cleanup or the owning Job has ended.
    descendants = {owner["pid"]}
    while True:
        children = {item["pid"] for item in processes if item.get("ppid") in descendants
                    and item["pid"] not in descendants}
        if not children:
            break
        descendants.update(children)
    if len(descendants) > 1:
        return True
    if owner_alive:
        return False
    expected = os.path.normcase(str(path))
    for item in processes:
        if item["pid"] == 0:
            continue
        name = str(item.get("name") or "").casefold().removesuffix(".exe")
        if (item["pid"] != owner["pid"] and name not in {"python", "pythonw", "node", "nodejs", "firefox", "chrome", "chromium", "msedge",
                         "headless_shell", "chrome-headless-shell", "minibrowser", "webkitnetworkprocess",
                         "webkitwebprocess", "powershell", "pwsh", "cmd", "sh", "bash"}
                and re.fullmatch(r"python[0-9]+(?:\.[0-9]+)*", name) is None):
            continue
        try:
            if "temp_roots" not in item:
                environment = psutil.Process(item["pid"]).environ()
                item["temp_roots"] = {os.path.normcase(environment.get(key, "")) for key in _NAMES}
            if expected in item["temp_roots"]:
                return True
        except psutil.NoSuchProcess:
            continue
        except (psutil.AccessDenied, OSError):
            # An unknown browser/driver is not proof that an orphan is unused.
            return True
    return False


def _plain_tree(path: Path) -> None:
    pending = [path]
    while pending:
        current = pending.pop()
        _plain_path(current)
        with os.scandir(_native(current)) as entries:
            for entry in entries:
                value = Path(entry.path)
                if _linked(value):
                    raise ValueError("Linked browser temporary contents were preserved")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(value)


def _remove_owned(path: Path, owner: dict) -> None:
    # Retain the receipt through partial deletion, locks and process termination.
    for entry in _native(path).iterdir():
        if entry.name == "owner.json":
            continue
        if _linked(entry):
            raise ValueError("Linked browser temporary contents were preserved")
        if entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    marker = _native(path / "owner.json")
    marker.unlink()
    try:
        _native(path).rmdir()
    except OSError:
        if _native(path).is_dir():
            _plain_path(path)
            with marker.open("x", encoding="utf-8") as stream:
                json.dump(owner, stream)
                stream.flush()
                os.fsync(stream.fileno())
        raise


def cleanup_browser_temp(*, include_current: bool = False) -> dict[str, int]:
    """Reclaim dead owners, or this quiesced process when explicitly requested."""
    global _current, _previous
    result = {"removed": 0, "retained": 0, "errors": 0}
    if include_current and _current is None:
        return result
    try:
        root = _root()
        with _root_lock(root) as acquired:
            if not acquired:
                return result
            candidates = [_current] if include_current else [_normal(path) for path in _native(root).iterdir()]
            processes = None
            examined = 0
            for path in candidates:
                if not _native(path).is_dir() or not _DIRECTORY.fullmatch(path.name):
                    continue
                try:
                    _plain_path(path)
                    owner = _owner(path)
                    own = include_current and path == _current and owner["pid"] == os.getpid()
                    alive = _alive(owner)
                    if alive and not own:
                        result["retained"] += 1
                        continue
                    if processes is None:
                        processes = _processes()
                    if _in_use(path, owner, processes, owner_alive=alive):
                        result["retained"] += 1
                        continue
                    examined += 1
                    if not include_current and examined > 16:
                        break
                    _plain_tree(path)
                    # Recheck containment and ownership immediately before deletion.
                    _plain_path(path)
                    if _normal(_native(path).resolve()) != root / path.name or _owner(path) != owner or (_alive(owner) and not own):
                        raise ValueError("Browser temporary ownership changed")
                    _remove_owned(path, owner)
                    result["removed"] += 1
                    if own:
                        with _LOCK:
                            for name, previous in _previous.items():
                                if os.environ.get(name) == str(path):
                                    if previous is None:
                                        os.environ.pop(name, None)
                                    else:
                                        os.environ[name] = previous
                            _current, _previous = None, {}
                except (OSError, ValueError, psutil.Error):
                    result["errors"] += 1
    except (OSError, ValueError, psutil.Error):
        result["errors"] += 1
    return result


def request_browser_temp_cleanup() -> None:
    """Schedule bounded batches outside browser request deadlines."""
    global _cleanup_thread, _last_cleanup
    if not _LOCK.acquire(blocking=False):
        return
    try:
        now = time.monotonic()
        if (_cleanup_thread is not None and _cleanup_thread.is_alive()) or now - _last_cleanup < 30:
            return
        _last_cleanup = now
        def collect():
            global _last_warning
            result = cleanup_browser_temp()
            if result["removed"]:
                logger.info("Reclaimed %s inactive browser temporary directories", result["removed"])
            if result["errors"] and time.monotonic() - _last_warning >= 300:
                _last_warning = time.monotonic()
                logger.warning("Browser temporary cleanup could not verify or remove %s entries; preserved for retry", result["errors"])
        _cleanup_thread = Thread(target=collect, name="browser-temp-cleanup", daemon=True)
        try:
            _cleanup_thread.start()
        except (OSError, RuntimeError):
            _cleanup_thread = None
            logger.warning("Browser temporary cleanup could not start")
    finally:
        _LOCK.release()


def ensure_browser_temp() -> Path:
    """Select scratch space before starting a Playwright driver in this process."""
    global _current, _previous
    request_browser_temp_cleanup()
    with _LOCK:
        root = _root()
        free = shutil.disk_usage(_native(root)).free
        if free < MINIMUM_BROWSER_TEMP_FREE_BYTES:
            raise OSError(errno.ENOSPC, f"Browser temporary volume has {free} bytes free; at least "
                          f"{MINIMUM_BROWSER_TEMP_FREE_BYTES} bytes are required: {root}")
        if _current is not None:
            _plain_path(_current)
            if _owner(_current)["pid"] != os.getpid():
                raise RuntimeError("Browser temporary process ownership changed")
            return _current
        started = psutil.Process().create_time()
        path = root / f"p{os.getpid()}-{round(started * 1_000_000)}-{uuid4().hex}"
        _native(path).mkdir(mode=0o700)
        with _native(path / "owner.json").open("x", encoding="utf-8") as stream:
            os.chmod(_native(path / "owner.json"), 0o600)
            json.dump({"format": 1, "pid": os.getpid(), "started": started}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        _previous = {name: os.environ.get(name) for name in _NAMES}
        for name in _NAMES:
            os.environ[name] = str(path)
        _current = path
    return path


atexit.register(lambda: cleanup_browser_temp(include_current=True))
