from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
from threading import Thread
import time


COMMAND_TIMEOUT_SECONDS = 15
_DRAIN_SECONDS = 0.5


class _BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
        ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("read_operations", "write_operations", "other_operations", "read_bytes", "write_bytes", "other_bytes")]


class _ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", _BasicLimits), ("io", _IoCounters)] + [
        (name, ctypes.c_size_t) for name in ("process_memory", "job_memory", "peak_process_memory", "peak_job_memory")
    ]


class _CommandJob:
    """Own a command's process lifetime; this does not restrict its permissions."""

    def __init__(self):
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE),
            "SetInformationJobObject": ([wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD], wintypes.BOOL),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "PeekNamedPipe": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                               ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            self.kill_on_close(True)
        except BaseException:
            self.close()
            raise

    def kill_on_close(self, enabled: bool) -> None:
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000 if enabled else 0
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process: subprocess.Popen) -> None:
        if not self.api.AssignProcessToJobObject(self.handle, wintypes.HANDLE(int(process._handle))):
            raise ctypes.WinError(ctypes.get_last_error())

    def terminate(self) -> None:
        if not self.api.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None

    def available(self, stream) -> int | None:
        import msvcrt

        count = wintypes.DWORD()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
        if self.api.PeekNamedPipe(handle, None, 0, None, ctypes.byref(count), None):
            return count.value
        error = ctypes.get_last_error()
        if error in (109, 232, 233):
            return None
        raise ctypes.WinError(error)


def run_powershell(script: str, directory: Path, max_bytes: int) -> tuple[dict, bool]:
    if os.name != "nt":
        raise OSError("命令执行目前仅支持 Windows PowerShell")
    payload = script.encode("utf-8")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    location = str(directory).replace("'", "''")
    # User text stays in stdin, preserving scripts and avoiding Windows' argv length limit.
    bootstrap = (
        "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "
        "$OutputEncoding = [Console]::OutputEncoding; $ProgressPreference = 'SilentlyContinue'; "
        "$ErrorActionPreference = 'Stop'; $source = [Console]::In.ReadToEnd(); "
        f"try {{ Set-Location -LiteralPath '{location}'; $LASTEXITCODE = $null; "
        "& ([scriptblock]::Create($source)); $succeeded = $?; "
        "if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE }; if (!$succeeded) { exit 1 } "
        "} catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }"
    )
    encoded = base64.b64encode(bootstrap.encode("utf-16-le")).decode("ascii")
    job = _CommandJob()
    process = None
    writer = None
    normal_exit = False
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = overflow = output_incomplete = False
    try:
        process = subprocess.Popen(
            [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
             "-OutputFormat", "Text", "-EncodedCommand", encoded],
            cwd=directory, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # Bootstrap cannot run the user's script before this association and stdin EOF.
        job.assign(process)

        def send_script() -> None:
            try:
                remaining = memoryview(payload)
                while remaining:
                    written = process.stdin.write(remaining)
                    if not written:
                        break
                    remaining = remaining[written:]
            except (BrokenPipeError, OSError):
                pass
            finally:
                process.stdin.close()

        writer = Thread(target=send_script, daemon=True, name="healthcheck-command-input")
        writer.start()
        started = time.monotonic()
        parent_exited = None
        streams = {"stdout": process.stdout, "stderr": process.stderr}
        closed = set()
        while True:
            for name, stream in streams.items():
                if name in closed:
                    continue
                available = job.available(stream)
                if available is None:
                    closed.add(name)
                elif available:
                    chunk = os.read(stream.fileno(), min(65536, available))
                    remaining = max_bytes - sum(len(value) for value in buffers.values())
                    buffers[name].extend(chunk[:remaining])
                    overflow = overflow or len(chunk) > remaining
            now = time.monotonic()
            timed_out = now - started >= COMMAND_TIMEOUT_SECONDS
            if overflow or timed_out:
                job.terminate()
                break
            if process.poll() is not None:
                parent_exited = now if parent_exited is None else parent_exited
                if len(closed) == len(streams) or now - parent_exited >= _DRAIN_SECONDS:
                    output_incomplete = len(closed) != len(streams)
                    normal_exit = True
                    break
            time.sleep(0.01)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise OSError("命令进程未能在终止后退出") from exc
    finally:
        try:
            if normal_exit:
                job.kill_on_close(False)
        finally:
            job.close()
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if writer is not None and writer.ident is not None:
                    writer.join(timeout=2)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                if process.stdin is not None and not process.stdin.closed and (writer is None or not writer.is_alive()):
                    process.stdin.close()
    return {
        "working_directory": str(directory), "stdout": buffers["stdout"].decode("utf-8", errors="replace"),
        "stderr": buffers["stderr"].decode("utf-8", errors="replace"), "exit_code": process.returncode,
        "timed_out": timed_out, "output_incomplete": output_incomplete,
    }, overflow
