from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import psutil
import redis

from darkweb_collector.queueing import QUEUE_CONCURRENCY


logger = logging.getLogger(__name__)


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
        _write_json(Path(path), {"pid": os.getpid()})


def _process_alive(pid: int, started: float) -> bool:
    try:
        process = psutil.Process(pid)
        return abs(process.create_time() - started) < 1 and process.is_running()
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


def _stop_worker(worker, state: dict) -> bool:
    try:
        processes = {}
        roots = []
        if worker is not None and worker.poll() is None:
            roots.append(worker.pid)
        # Windows venv redirectors can exit before their real Python child.
        if state.get("worker_pid"):
            try:
                tracked = psutil.Process(state["worker_pid"])
                if abs(tracked.create_time() - state["worker_started"]) < 1 and tracked.is_running():
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


def _ready_worker(path: Path, worker) -> psutil.Process | None:
    try:
        process = psutil.Process(json.loads(path.read_text(encoding="utf-8"))["pid"])
        if process.pid == worker.pid or any(parent.pid == worker.pid for parent in process.parents()):
            return process
    except (OSError, ValueError, KeyError, psutil.Error):
        pass
    return None


def supervise(name: str, queues: list[str], hostname: str, workdir: str | None = None) -> None:
    workdir = str(Path(workdir or Path(__file__).resolve().parents[2]).resolve())
    path = _health_directory() / f"{name}.json"
    ready_path = path.with_suffix(".ready")
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            previous_pid = int(previous["supervisor_pid"])
            previous_started = float(previous["supervisor_started"])
        except OSError as exc:
            raise RuntimeError("cannot read existing supervisor ownership; refusing duplicate") from exc
        except (ValueError, KeyError, TypeError):
            logger.warning("Ignoring malformed worker supervisor snapshot")
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
        "worker_pid": 0, "worker_started": 0, "status": "starting", "error": "采集进程正在启动",
    }
    client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
                                 socket_connect_timeout=3, socket_timeout=3)
    worker = None
    stop_pending = False
    retry_delay = 15
    next_start = 0.0
    started_at = 0.0
    try:
        while True:
            now = time.monotonic()
            try:
                if stop_pending or (worker is not None and worker.poll() is not None):
                    if not stop_pending:
                        logger.warning("Worker pid %s exited with code %s; retry in %ss", worker.pid, worker.returncode, retry_delay)
                    if _stop_worker(worker, state):
                        worker = None
                        stop_pending = False
                        state.update(worker_pid=0, worker_started=0, status="recovering", error="采集进程已退出，等待自动恢复")
                        next_start = now + retry_delay
                        retry_delay = min(retry_delay * 2, 300)
                    else:
                        stop_pending = True
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
                        env = {**os.environ, "DARKWEB_WORKER_READY_FILE": str(ready_path)}
                        command = [sys.executable, "-m", "celery", "--workdir", workdir, "-A", "darkweb_collector.celery_app:app",
                                   "worker", "-Q", ",".join(queues), "--concurrency", "1", "--prefetch-multiplier", "1",
                                   "--pool", "solo", "--loglevel", "info", "--hostname", hostname]
                        try:
                            worker = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                                      creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                            state.update(worker_pid=worker.pid, worker_started=psutil.Process(worker.pid).create_time(),
                                         status="starting", error="采集进程正在连接消息服务")
                            started_at = now
                        except (OSError, psutil.Error):
                            stop_pending = not _stop_worker(worker, state)
                            if not stop_pending:
                                worker = None
                                state.update(status="error", worker_pid=0, error="采集进程启动失败，等待自动恢复")
                            else:
                                state.update(status="error", error="采集进程停止未确认，正在重试")
                            next_start = now + retry_delay
                            retry_delay = min(retry_delay * 2, 300)
                    elif worker is not None:
                        ready = _ready_worker(ready_path, worker)
                        state.update(status="running" if ready else "starting", error="" if ready else "采集进程尚未就绪")
                        if ready:
                            state.update(worker_pid=ready.pid, worker_started=ready.create_time())
                        if ready and now - started_at >= 300:
                            retry_delay = 15
                        elif not ready and now - started_at >= 300:
                            stop_pending = not _stop_worker(worker, state)
                            if not stop_pending:
                                worker = None
                                state.update(worker_pid=0, worker_started=0, status="recovering", error="采集进程已退出，等待自动恢复")
                                next_start = now + retry_delay
                                retry_delay = min(retry_delay * 2, 300)
                            else:
                                state.update(status="error", error="采集进程停止未确认，正在重试")
            except (OSError, psutil.Error) as exc:
                _warn_resource_error("Worker supervision resource/state query failed; retrying", exc)
                state.update(status="error", error="系统资源不足或进程状态读取失败，等待重试")
            state["updated_at"] = time.time()
            try:
                _write_json(path, state)
            except OSError as exc:
                _warn_resource_error("Worker health snapshot write failed; retrying", exc)
            time.sleep(15)
    finally:
        stopped = _stop_worker(worker, state)
        try:
            client.close()
        except (OSError, redis.RedisError) as exc:
            _warn_resource_error("Worker broker client close failed", exc)
        if stopped:
            state.update(status="stopped", worker_pid=0, error="采集守护进程已停止", updated_at=time.time())
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
