from __future__ import annotations

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import time
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psutil


def _journal_url(value: str) -> str:
    parts = urlsplit(value)
    # Recovery reads the exact target from the owned DB job, so queries and userinfo are unnecessary.
    return urlunsplit((parts.scheme, parts.netloc.rsplit("@", 1)[-1], parts.path, "", ""))


def read_activity(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(payload, dict) or type(payload.get("schema_version")) is not int or payload["schema_version"] != 1:
        raise ValueError("unsupported worker activity journal")
    for name in ("task_id", "job_id", "site_name", "slot_owner"):
        if not isinstance(payload.get(name), str) or not payload[name] or len(payload[name]) > 512:
            raise ValueError("invalid worker activity identity")
    if type(payload.get("worker_pid")) is not int or payload["worker_pid"] <= 0:
        raise ValueError("invalid worker activity process")
    for name in ("worker_started", "started_at", "deadline_at", "started_monotonic",
                 "deadline_monotonic", "timeout_seconds"):
        value = payload.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError("invalid worker activity deadline")
    timeout = payload["timeout_seconds"]
    if timeout > 86400 or any(abs(payload[end] - payload[start] - timeout) > 0.01 for start, end in (
        ("started_at", "deadline_at"), ("started_monotonic", "deadline_monotonic"),
    )):
        raise ValueError("invalid worker activity duration")
    return payload


def clear_activity(path: Path, payload: dict) -> None:
    current = read_activity(path)
    if current is not None and current["task_id"] != payload["task_id"]:
        raise ValueError("worker activity ownership changed")
    path.unlink(missing_ok=True)


def activity_expired(payload: dict) -> bool:
    # Monotonic time is shared by processes on supported Windows/Python versions.
    # Wall time is a second bound with five minutes of permitted clock skew.
    return (time.monotonic() >= payload["deadline_monotonic"]
            or time.time() >= payload["deadline_at"] + 300)


@contextmanager
def track_task(job_id: str, site_name: str, target_url: str, slot_owner: str, timeout_seconds: float):
    path_value = os.environ.get("DARKWEB_WORKER_ACTIVITY_FILE")
    if not path_value:
        yield
        return
    path = Path(path_value)
    if path.exists():
        raise RuntimeError("previous worker task has not been recovered")
    job_id = str(job_id)
    if any(not isinstance(value, str) or not value or len(value) > 512 for value in (job_id, site_name, slot_owner)):
        raise ValueError("invalid task identity")
    timeout = float(timeout_seconds)
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 86400:
        raise ValueError("invalid task timeout")
    started_at, started_monotonic = time.time(), time.monotonic()
    payload = {
        "schema_version": 1, "task_id": uuid4().hex,
        "worker_pid": os.getpid(), "worker_started": psutil.Process().create_time(),
        "job_id": job_id, "site_name": site_name, "target_url": _journal_url(target_url),
        "slot_owner": slot_owner, "timeout_seconds": timeout,
        "started_at": started_at, "deadline_at": started_at + timeout,
        "started_monotonic": started_monotonic, "deadline_monotonic": started_monotonic + timeout,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".{os.getpid()}.{payload['task_id']}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(payload, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        # Windows rename fails if the destination exists; POSIX needs an exclusive link.
        if os.name == "nt":
            os.rename(temporary, path)
        else:
            os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    try:
        yield
    except BaseException:
        # Finalization failures must remain recoverable after the supervisor stops the worker.
        raise
    else:
        clear_activity(path, payload)
