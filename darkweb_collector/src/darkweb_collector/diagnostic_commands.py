from __future__ import annotations

import base64
import os
from pathlib import Path
import subprocess
from threading import Event, Lock, Thread
import time

import psutil


COMMAND_TIMEOUT_SECONDS = 15


def run_powershell(script: str, directory: Path, max_bytes: int) -> tuple[dict, bool]:
    if os.name != "nt":
        raise OSError("命令行查询目前仅支持 Windows PowerShell")
    executable = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    preamble = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); $OutputEncoding = [Console]::OutputEncoding; $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'; "
    body = preamble + "try { " + script + "; if ($null -ne $LASTEXITCODE) { exit $LASTEXITCODE } } catch { [Console]::Error.WriteLine($_.ToString()); exit 1 }"
    encoded = base64.b64encode(body.encode("utf-16-le")).decode("ascii")
    process = subprocess.Popen(
        [str(executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", encoded],
        cwd=directory, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    lock = Lock()
    overflow = Event()

    def read_stream(name: str, stream) -> None:
        try:
            while chunk := stream.read(4096):
                with lock:
                    remaining = max_bytes - sum(len(value) for value in buffers.values())
                    buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
        finally:
            stream.close()

    readers = [Thread(target=read_stream, args=(name, stream), daemon=True) for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))]
    for reader in readers:
        reader.start()
    started = time.monotonic()
    timed_out = False
    while process.poll() is None:
        timed_out = time.monotonic() - started >= COMMAND_TIMEOUT_SECONDS
        if timed_out or overflow.is_set():
            try:
                owner = psutil.Process(process.pid)
                for child in owner.children(recursive=True) + [owner]:
                    try:
                        child.kill()
                    except psutil.Error:
                        pass
            except psutil.Error:
                process.kill()
            process.wait(timeout=5)
            break
        overflow.wait(0.05)
    for reader in readers:
        reader.join(timeout=2)
    return {
        "working_directory": str(directory),
        "stdout": buffers["stdout"].decode("utf-8", errors="replace"),
        "stderr": buffers["stderr"].decode("utf-8", errors="replace"),
        "exit_code": process.returncode, "timed_out": timed_out,
    }, overflow.is_set()
