#!/usr/bin/env python3
"""Rebuild the pinned Garnet component from its verified upstream archive."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "patches" / "garnet"


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(*arguments: str, cwd: Path | None = None) -> str:
    result = subprocess.run(arguments, cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def build(source_archive: Path, sdk: str, output: Path) -> Path:
    spec = json.loads((COMPONENT / "build.json").read_text(encoding="utf-8"))
    if digest(source_archive) != spec["upstream_source_archive_sha256"]:
        raise RuntimeError("Upstream source archive SHA256 does not match the pinned source")
    patch = COMPONENT / spec["patch_filename"]
    if digest(patch) != spec["patch_sha256"]:
        raise RuntimeError("Garnet source patch SHA256 mismatch")
    if run(sdk, "--version") != spec["dotnet_sdk"]:
        raise RuntimeError(f"Build requires .NET SDK {spec['dotnet_sdk']}")
    output.mkdir(parents=True, exist_ok=False)
    source = output / "source"
    source.mkdir()
    with zipfile.ZipFile(source_archive) as archive:
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts or any(":" in p for p in path.parts):
                raise RuntimeError("Unsafe upstream archive path")
        archive.extractall(source)
    roots = list(source.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise RuntimeError("Unexpected upstream source archive layout")
    source = roots[0]
    run("git", "-c", "core.autocrlf=false", "apply", "--check", str(patch), cwd=source)
    run("git", "-c", "core.autocrlf=false", "apply", str(patch), cwd=source)
    for name, expected in spec["patched_source_files_sha256"].items():
        if digest(source / name) != expected:
            raise RuntimeError(f"Patched source SHA256 mismatch: {name}")
    runtime = output / "runtime"
    command = [sdk, "publish", str(source / "main/GarnetServer/GarnetServer.csproj"),
               "-c", "Release", "-f", spec["target_framework"], "-r", spec["runtime_identifier"],
               "--self-contained", "false", "-p:TargetFrameworks=net10.0",
               f"-p:VersionSuffix={spec['version_suffix']}", "-p:Deterministic=true",
               f"-p:PathMap={source}=/_/garnet",
               "-p:RestoreSources=https://api.nuget.org/v3/index.json", "-o", str(runtime)]
    subprocess.run(command, check=True)
    payload: dict[str, bytes] = {}
    for path in sorted(runtime.rglob("*")):
        if not path.is_file() or path.suffix.lower() in {".pfx", ".snk", ".pdb", ".xml"}:
            continue
        relative = path.relative_to(runtime)
        if relative.parts[0] == "runtimes" and relative.parts[1] != "win-x64":
            continue
        payload["net10.0/" + relative.as_posix()] = path.read_bytes()
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}
    if hashes != spec["file_sha256"]:
        raise RuntimeError("Rebuilt runtime differs from the validated component; refusing to package")
    embedded = dict(spec)
    embedded.pop("artifact", None)
    payload["garnet-build.json"] = (json.dumps(embedded, indent=2) + "\n").encode("utf-8")
    # Keep the ZIP identical regardless of Git checkout newline settings.
    payload["LICENSE.txt"] = (COMPONENT / "LICENSE.txt").read_text(encoding="utf-8").replace("\n", "\r\n").encode("utf-8")
    payload["README.txt"] = (COMPONENT / "runtime-readme.txt").read_text(encoding="utf-8").encode("utf-8")
    archive_path = output / spec["artifact"]["name"]
    with zipfile.ZipFile(archive_path, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(payload.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data, compresslevel=9)
    if digest(archive_path) != spec["artifact"]["sha256"]:
        raise RuntimeError("Rebuilt component archive differs from the validated component")
    shutil.copyfile(COMPONENT / "build.json", output / "build.json")
    return archive_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--sdk", default="dotnet")
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    print(build(arguments.source_archive.resolve(), arguments.sdk, arguments.output_dir.resolve()))


if __name__ == "__main__":
    main()
