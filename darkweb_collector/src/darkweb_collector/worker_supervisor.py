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
    except (psutil.Error, ValueError, TypeError):
        return False


def queue_health_errors() -> dict[str, str]:
    """Read supervisor snapshots without broker commands or exposing connection settings."""
    healthy: set[str] = set()
    errors: dict[str, str] = {}
    for path in _health_directory().glob("*.json"):
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
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return {queue: message for queue, message in errors.items() if queue not in healthy}


def _queue_error(client, queues: list[str]) -> str:
    for queue in queues:
        for priority in (0, 3, 6, 9):
            key = queue if priority == 0 else f"{queue}\x06\x16{priority}"
            if client.type(key) not in (b"none", b"list"):
                return f"任务队列 {queue} 类型异常，已暂停恢复；请保留数据并检查消息服务"
    return ""


def _stop_worker(worker, state: dict) -> None:
    processes = {}
    roots = []
    if worker is not None and worker.poll() is None:
        roots.append(worker.pid)
    # Windows venv redirectors can exit before their real Python child.
    if state.get("worker_pid") and _process_alive(state["worker_pid"], state["worker_started"]):
        roots.append(state["worker_pid"])
    for pid in roots:
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
        process.kill()
    if worker is not None:
        worker.wait(timeout=5)


def _ready_worker(path: Path, worker) -> psutil.Process | None:
    try:
        process = psutil.Process(json.loads(path.read_text(encoding="utf-8"))["pid"])
        if process.pid == worker.pid or any(parent.pid == worker.pid for parent in process.parents()):
            return process
    except (OSError, ValueError, KeyError, psutil.Error):
        pass
    return None


def supervise(name: str, queues: list[str], hostname: str) -> None:
    path = _health_directory() / f"{name}.json"
    ready_path = path.with_suffix(".ready")
    if path.exists():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            if _process_alive(previous["supervisor_pid"], previous["supervisor_started"]):
                raise RuntimeError("worker supervisor already running")
        except (OSError, ValueError, KeyError):
            pass
    state = {
        "queues": queues, "supervisor_pid": os.getpid(),
        "supervisor_started": psutil.Process().create_time(),
        "worker_pid": 0, "worker_started": 0, "status": "starting", "error": "采集进程正在启动",
    }
    client = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
                                 socket_connect_timeout=3, socket_timeout=3)
    worker = None
    retry_delay = 15
    next_start = 0.0
    started_at = 0.0
    try:
        while True:
            now = time.monotonic()
            if worker is not None and worker.poll() is not None:
                logger.warning("Worker %s exited with code %s; retry in %ss", name, worker.returncode, retry_delay)
                _stop_worker(worker, state)
                worker = None
                state.update(worker_pid=0, worker_started=0, status="recovering", error="采集进程已退出，等待自动恢复")
                next_start = now + retry_delay
                retry_delay = min(retry_delay * 2, 300)
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
                command = [sys.executable, "-m", "celery", "-A", "darkweb_collector.celery_app:app",
                           "worker", "-Q", ",".join(queues), "--concurrency", "1", "--prefetch-multiplier", "1",
                           "--pool", "solo", "--loglevel", "info", "--hostname", hostname]
                try:
                    worker = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                    state.update(worker_pid=worker.pid, worker_started=psutil.Process(worker.pid).create_time(),
                                 status="starting", error="采集进程正在连接消息服务")
                    started_at = now
                except (OSError, psutil.Error):
                    _stop_worker(worker, state)
                    worker = None
                    state.update(status="error", worker_pid=0, error="采集进程启动失败，等待自动恢复")
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
                    _stop_worker(worker, state)
            state["updated_at"] = time.time()
            _write_json(path, state)
            time.sleep(15)
    finally:
        _stop_worker(worker, state)
        client.close()
        state.update(status="stopped", worker_pid=0, error="采集守护进程已停止", updated_at=time.time())
        _write_json(path, state)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--queues", required=True)
    parser.add_argument("--hostname", required=True)
    args = parser.parse_args()
    queues = args.queues.split(",")
    if not re.fullmatch(r"worker-[a-z0-9-]+", args.name) or any(q not in QUEUE_CONCURRENCY for q in queues):
        parser.error("invalid worker name or queues")
    logging.basicConfig(level=logging.INFO)
    supervise(args.name, queues, args.hostname)
