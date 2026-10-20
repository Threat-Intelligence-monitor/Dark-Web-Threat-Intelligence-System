from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import uuid4

import psutil
import redis

from darkweb_collector.queueing import QUEUE_CONCURRENCY
from darkweb_collector.worker_activity import activity_expired, clear_activity, read_activity


logger = logging.getLogger(__name__)


class _JobLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
               ("read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedJobLimits(ctypes.Structure):
    _fields_ = [("basic", _JobLimits), ("io", _IoCounters)] + [
        (name, ctypes.c_size_t) for name in ("process_memory", "job_memory", "peak_process_memory", "peak_job_memory")
    ]


class _JobAccounting(ctypes.Structure):
    _fields_ = [(name, ctypes.c_longlong) for name in
               ("user_time", "kernel_time", "period_user_time", "period_kernel_time")] + [
        (name, wintypes.DWORD) for name in ("page_faults", "total_processes", "active_processes", "terminated_processes")
    ]


class _WorkerJob:
    """Keep all Windows browser descendants owned even after their Python parent exits."""

    def __init__(self, name: str, *, existing: bool = False):
        if not re.fullmatch(r"Local\\dwti-worker-[a-z0-9-]+-[0-9a-f]{32}", name):
            raise ValueError("invalid worker job ownership")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "OpenJobObjectW": ([wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "QueryInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p], wintypes.BOOL),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "IsProcessInJob": ([wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "OpenThread": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "ResumeThread": ([wintypes.HANDLE], wintypes.DWORD),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for method, (arguments, result) in signatures.items():
            function = getattr(self.api, method)
            function.argtypes, function.restype = arguments, result
        self.name = name
        self.handle = (self.api.OpenJobObjectW(0x0004 | 0x0008, False, name) if existing
                       else self.api.CreateJobObjectW(None, name))
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        if not existing:
            limits = _ExtendedJobLimits()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; children cannot break away.
            if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                error = ctypes.get_last_error()
                self.close()
                raise ctypes.WinError(error)

    def assign_and_resume(self, worker) -> None:
        if not self.api.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(worker._handle))):
            raise ctypes.WinError(ctypes.get_last_error())
        threads = psutil.Process(worker.pid).threads()
        if len(threads) != 1:
            raise OSError("suspended worker initial thread could not be identified")
        thread = self.api.OpenThread(0x0002, False, threads[0].id)
        if not thread:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if self.api.ResumeThread(thread) == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self.api.CloseHandle(thread)

    def contains(self, pid: int) -> bool:
        process = self.api.OpenProcess(0x1000, False, pid)
        if not process:
            error = ctypes.get_last_error()
            if error == 87:
                return False
            raise ctypes.WinError(error)
        try:
            contained = wintypes.BOOL()
            if not self.api.IsProcessInJob(process, self.handle, ctypes.byref(contained)):
                raise ctypes.WinError(ctypes.get_last_error())
            return bool(contained.value)
        finally:
            self.api.CloseHandle(process)

    def stop(self) -> bool:
        if not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())
        deadline = time.monotonic() + 15
        while True:
            accounting = _JobAccounting()
            if not self.api.QueryInformationJobObject(self.handle, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None):
                raise ctypes.WinError(ctypes.get_last_error())
            if not accounting.active_processes:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


def _warn_resource_error(message: str, exc: Exception) -> None:
    codes = [getattr(exc, name, None) for name in ("errno", "winerror")]
    errno, winerror = [value if isinstance(value, int) else None for value in codes]
    logger.warning("%s (%s; errno=%s; winerror=%s)", message, type(exc).__name__, errno, winerror)


def _health_directory() -> Path:
    return Path(__file__).resolve().parents[2] / ".runtime" / "windows" / "worker-health"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def mark_worker_ready(**kwargs) -> None:
    path = os.environ.get("DARKWEB_WORKER_READY_FILE")
    if path:
        _write_json(Path(path), {"pid": os.getpid(), "started": psutil.Process().create_time()})


def _process_alive(pid: int, started: float) -> bool:
    try:
        process = psutil.Process(pid)
        return process.create_time() == started and process.is_running()
    except (psutil.NoSuchProcess, ValueError, TypeError):
        return False


def queue_health_errors() -> dict[str, str]:
    """Read supervisor snapshots without broker commands or exposing connection settings."""
    healthy: set[str] = set()
    errors: dict[str, str] = {}
    for path in _health_directory().glob("*.json"):
        queues = []
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            queues = [queue for queue in state["queues"] if queue in QUEUE_CONCURRENCY]
            supervisor_alive = (
                time.time() - state["updated_at"] < 60
                and _process_alive(state["supervisor_pid"], state["supervisor_started"])
            )
            running = supervisor_alive and state["status"] == "running" and _process_alive(
                state["worker_pid"], state["worker_started"]
            )
            if running:
                healthy.update(queues)
            else:
                reason = state.get("error") if supervisor_alive else "采集守护进程离线，请检查运行环境"
                for queue in queues:
                    errors[queue] = reason or "采集进程未就绪，等待自动恢复"
        except (OSError, psutil.Error):
            for queue in queues:
                errors[queue] = "采集进程状态无法确认，请检查系统资源"
        except (ValueError, KeyError, TypeError):
            continue
    return {queue: message for queue, message in errors.items() if queue not in healthy}


def _queue_error(client, queues: list[str]) -> str:
    for queue in queues:
        for priority in (0, 3, 6, 9):
            key = queue if priority == 0 else f"{queue}\x06\x16{priority}"
            if client.type(key) not in (b"none", b"list"):
                return f"任务队列 {queue} 类型异常，已暂停恢复；请保留数据并检查消息服务"
    return ""


def _stop_worker(worker, state: dict, job: _WorkerJob | None = None) -> bool:
    try:
        if job is not None and not job.stop():
            return False
        processes = {}
        roots = []
        if worker is not None and worker.poll() is None:
            roots.append(worker.pid)
        # Windows venv redirectors can exit before their real Python child.
        if state.get("worker_pid"):
            try:
                tracked = psutil.Process(state["worker_pid"])
                if tracked.create_time() == state["worker_started"] and tracked.is_running():
                    roots.append(tracked.pid)
            except psutil.NoSuchProcess:
                pass
        for pid in set(roots):
            try:
                process = psutil.Process(pid)
                for child in process.children(recursive=True) + [process]:
                    processes[child.pid] = child
            except psutil.NoSuchProcess:
                pass
        for process in processes.values():
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                pass
        _, alive = psutil.wait_procs(list(processes.values()), timeout=10)
        for process in alive:
            try:
                process.kill()
            except psutil.NoSuchProcess:
                pass
        if alive:
            _, alive = psutil.wait_procs(alive, timeout=5)
        if worker is not None:
            worker.wait(timeout=5)
        return not alive
    except Exception as exc:
        _warn_resource_error("Worker stop was not confirmed; retaining ownership", exc)
        return False


def _ready_worker(path: Path, worker, job: _WorkerJob | None = None) -> psutil.Process | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        process = psutil.Process(payload["pid"])
        if "started" in payload and process.create_time() != payload["started"]:
            return None
        if ((job is not None and job.contains(process.pid)) or process.pid == worker.pid
                or any(parent.pid == worker.pid for parent in process.parents())):
            return process
    except (OSError, ValueError, KeyError, TypeError, psutil.Error):
        pass
    return None


def _activity_owned(payload: dict, state: dict, job: _WorkerJob | None) -> bool:
    if (payload["worker_pid"] == state["worker_pid"]
            and payload["worker_started"] == state["worker_started"]):
        return True
    return bool(job is not None and _process_alive(payload["worker_pid"], payload["worker_started"])
                and job.contains(payload["worker_pid"]))


def _recover_activity(path: Path, payload: dict | None, reason: str) -> bool:
    if payload is None:
        return True
    if _process_alive(payload["worker_pid"], payload["worker_started"]):
        raise RuntimeError("task worker is still alive; refusing ownership recovery")
    try:
        from darkweb_collector.task_recovery import recover_stopped_task

        if recover_stopped_task(payload, reason=reason) is False:
            return False
    except Exception as exc:
        _warn_resource_error("Stopped worker task recovery failed; retaining journal", exc)
        return False
    clear_activity(path, payload)
    return True


def supervise(name: str, queues: list[str], hostname: str, workdir: str | None = None) -> None:
    workdir = str(Path(workdir or Path(__file__).resolve().parents[2]).resolve())
    path = _health_directory() / f"{name}.json"
    ready_path = path.with_suffix(".ready")
    activity_path = path.with_suffix(".activity")
    previous = {}
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            previous_pid = int(previous["supervisor_pid"])
            previous_started = float(previous["supervisor_started"])
        except OSError as exc:
            raise RuntimeError("cannot read existing supervisor ownership; refusing duplicate") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError("cannot verify existing supervisor ownership; refusing duplicate") from exc
        else:
            try:
                previous_alive = _process_alive(previous_pid, previous_started)
            except (OSError, psutil.Error) as exc:
                raise RuntimeError("cannot confirm existing supervisor ownership; refusing duplicate") from exc
            if previous_alive:
                raise RuntimeError("worker supervisor already running")
    state = {
        "queues": queues, "supervisor_pid": os.getpid(),
        "supervisor_started": psutil.Process().create_time(),
        "worker_pid": previous.get("worker_pid", 0), "worker_started": previous.get("worker_started", 0),
        "worker_job": previous.get("worker_job", ""), "status": "starting", "error": "采集进程正在启动",
    }
    client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
                                 socket_connect_timeout=3, socket_timeout=3)
    worker = None
    job = None
    stop_pending = bool(state["worker_pid"] or state["worker_job"] or activity_path.exists())
    stop_reason = "worker_lost"
    pending_activity = None
    retry_delay = 15
    next_start = 0.0
    started_at = 0.0
    try:
        while True:
            now = time.monotonic()
            try:
                if job is None and state["worker_job"] and os.name == "nt":
                    try:
                        job = _WorkerJob(state["worker_job"], existing=True)
                    except OSError as exc:
                        if getattr(exc, "winerror", None) != 2:
                            raise
                        state["worker_job"] = ""
                activity = read_activity(activity_path)
                if activity is not None:
                    if not _activity_owned(activity, state, job):
                        # A stopped owner's journal is safe to recover; a different live owner is not.
                        if _process_alive(activity["worker_pid"], activity["worker_started"]):
                            raise RuntimeError("worker activity belongs to a different live process")
                        stop_pending = True
                        stop_reason = "worker_lost"
                    if pending_activity is None:
                        pending_activity = activity
                    elif pending_activity["task_id"] != activity["task_id"]:
                        if stop_pending:
                            raise RuntimeError("worker activity changed during recovery")
                        pending_activity = activity
                    if activity_expired(activity) and not stop_pending:
                        logger.warning("Worker task exceeded its total execution deadline")
                        stop_pending = True
                        stop_reason = "timeout"
                elif not stop_pending:
                    pending_activity = None
                worker_lost = worker is not None and (
                    (state["worker_pid"] == worker.pid and worker.poll() is not None)
                    or (state["worker_pid"] != worker.pid
                        and not _process_alive(state["worker_pid"], state["worker_started"]))
                )
                if stop_pending or worker_lost:
                    if not stop_pending:
                        logger.warning("Worker pid %s exited; retry in %ss", state["worker_pid"], retry_delay)
                        stop_reason = "worker_lost"
                    stop_pending = True
                    if _stop_worker(worker, state, job):
                        worker = None
                        # Read again after exit: a task may have started between the last poll and worker loss.
                        final_activity = read_activity(activity_path)
                        if final_activity is not None:
                            # The previous task can finish normally just before the stop signal,
                            # then accept another task. Its cleared journal proves finalization completed.
                            pending_activity = final_activity
                        if _recover_activity(activity_path, pending_activity, stop_reason):
                            if job is not None:
                                job.close()
                                job = None
                            stop_pending = False
                            pending_activity = None
                            state.update(worker_pid=0, worker_started=0, worker_job="", status="recovering",
                                         error="采集进程已退出，等待自动恢复")
                            next_start = now + retry_delay
                            retry_delay = min(retry_delay * 2, 300)
                        else:
                            state.update(status="error", error="采集任务恢复未完成，保留占位并等待重试")
                    else:
                        state.update(status="error", error="采集进程停止未确认，正在重试")
                if not stop_pending:
                    try:
                        error = _queue_error(client, queues)
                    except redis.RedisError:
                        error = "消息服务连接异常，正在重试"
                    if error:
                        state.update(status="error", error=error)
                        # Never rename/delete broker keys automatically. A type error needs evidence-preserving repair.
                    elif worker is None and now >= next_start:
                        ready_path.unlink(missing_ok=True)
                        env = {**os.environ, "DARKWEB_WORKER_READY_FILE": str(ready_path),
                               "DARKWEB_WORKER_ACTIVITY_FILE": str(activity_path)}
                        command = [sys.executable, "-m", "celery", "--workdir", workdir, "-A", "darkweb_collector.celery_app:app",
                                   "worker", "-Q", ",".join(queues), "--concurrency", "1", "--prefetch-multiplier", "1",
                                   "--pool", "solo", "--loglevel", "info", "--hostname", hostname]
                        try:
                            if os.name == "nt":
                                job = _WorkerJob(f"Local\\dwti-{name}-{uuid4().hex}")
                            flags = (subprocess.CREATE_NO_WINDOW | 0x00000004) if os.name == "nt" else 0  # CREATE_SUSPENDED
                            worker = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                                      creationflags=flags)
                            state.update(worker_pid=worker.pid, worker_started=psutil.Process(worker.pid).create_time(),
                                         worker_job=job.name if job is not None else "",
                                         status="starting", error="采集进程正在连接消息服务")
                            # Persist ownership before the child can create browsers or accept tasks.
                            state["updated_at"] = time.time()
                            _write_json(path, state)
                            if job is not None:
                                job.assign_and_resume(worker)
                            started_at = now
                        except (OSError, psutil.Error):
                            stop_pending = not _stop_worker(worker, state, job)
                            if not stop_pending:
                                worker = None
                                if job is not None:
                                    job.close()
                                    job = None
                                state.update(status="error", worker_pid=0, worker_started=0, worker_job="",
                                             error="采集进程启动失败，等待自动恢复")
                            else:
                                state.update(status="error", error="采集进程停止未确认，正在重试")
                            next_start = now + retry_delay
                            retry_delay = min(retry_delay * 2, 300)
                    elif worker is not None:
                        ready = _ready_worker(ready_path, worker, job)
                        state.update(status="running" if ready else "starting", error="" if ready else "采集进程尚未就绪")
                        if ready:
                            state.update(worker_pid=ready.pid, worker_started=ready.create_time())
                        if ready and now - started_at >= 300:
                            retry_delay = 15
                        elif not ready and now - started_at >= 300:
                            # Stop/recovery always goes through the same ownership-checked path.
                            stop_pending = True
                            stop_reason = "worker_lost"
                            state.update(status="error", error="采集进程启动超时，等待停止并恢复任务")
            except (OSError, psutil.Error, ValueError, KeyError, TypeError, RuntimeError) as exc:
                _warn_resource_error("Worker supervision resource/state query failed; retrying", exc)
                stop_pending = True
                # An unreadable journal cannot authorize task recovery or a replacement worker.
                # Stop only the already-owned process tree and retain its original journal.
                if _stop_worker(worker, state, job):
                    worker = None
                state.update(status="error", error="进程或任务恢复状态无法确认，保留占位并等待重试")
            state["updated_at"] = time.time()
            try:
                _write_json(path, state)
            except OSError as exc:
                _warn_resource_error("Worker health snapshot write failed; retrying", exc)
            time.sleep(15)
    finally:
        stopped = _stop_worker(worker, state, job)
        if stopped:
            try:
                stopped = _recover_activity(activity_path, read_activity(activity_path), "worker_lost")
            except Exception as exc:
                _warn_resource_error("Stopped worker task recovery failed; retaining journal", exc)
                stopped = False
        if job is not None:
            job.close()
        try:
            client.close()
        except (OSError, redis.RedisError) as exc:
            _warn_resource_error("Worker broker client close failed", exc)
        if stopped:
            state.update(status="stopped", worker_pid=0, worker_started=0, worker_job="",
                         error="采集守护进程已停止", updated_at=time.time())
        else:
            state.update(status="error", error="采集守护进程已停止，子进程停止未确认", updated_at=time.time())
        try:
            _write_json(path, state)
        except OSError as exc:
            _warn_resource_error("Final worker health snapshot write failed", exc)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--queues", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--workdir", default=str(Path(__file__).resolve().parents[2]))
    args = parser.parse_args()
    queues = args.queues.split(",")
    if not re.fullmatch(r"worker-[a-z0-9-]+", args.name) or any(q not in QUEUE_CONCURRENCY for q in queues):
        parser.error("invalid worker name or queues")
    logging.basicConfig(level=logging.INFO)
    supervise(args.name, queues, args.hostname, args.workdir)
