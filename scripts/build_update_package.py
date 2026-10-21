#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PREFIXES = (".devcontainer/", ".github/")
VERSION_PATTERN = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?$")


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_bytes(*arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=True,
        capture_output=True,
    )
    return result.stdout


def tracked_files() -> list[str]:
    result = git_bytes("ls-tree", "-r", "-z", "HEAD")
    files = []
    for raw in result.split(b"\0"):
        if not raw:
            continue
        metadata, encoded_path = raw.split(b"\t", 1)
        mode, object_type, _ = metadata.decode("ascii").split(" ", 2)
        relative = encoded_path.decode("utf-8")
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or any(":" in part for part in path.parts):
            raise RuntimeError(f"unsafe tracked path: {relative}")
        if relative.startswith(EXCLUDED_PREFIXES):
            continue
        if mode == "120000":
            raise RuntimeError(f"release packages do not allow symlinks: {relative}")
        if object_type == "blob":
            files.append(relative)
    return sorted(files)


def tracked_file_bytes(relative: str) -> bytes:
    return git_bytes("show", f"HEAD:{relative}")


def canonical_signature_payload(manifest: dict[str, Any]) -> bytes:
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


def sign_manifest(manifest: dict[str, Any], key_path: Path, key_id: str) -> None:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    private_key = load_pem_private_key(key_path.read_bytes(), password=None)
    signature = private_key.sign(canonical_signature_payload(manifest))
    manifest["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
    }


def build_package(repository: str, version: str, output_dir: Path, signing_key: Path | None, key_id: str) -> dict[str, Path]:
    if not VERSION_PATTERN.fullmatch(version):
        raise RuntimeError(f"invalid release version: {version}")
    commit = git("rev-parse", "HEAD")
    commit_time = datetime.fromisoformat(git("show", "-s", "--format=%cI", "HEAD"))
    updated_at = commit_time.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    safe_version = version.replace("+", "-")
    package_name = f"DarkWebThreatIntel-{safe_version}-windows.zip"
    package_path = output_dir / package_name
    output_dir.mkdir(parents=True, exist_ok=True)

    version_payload = json.loads(tracked_file_bytes("version.json").decode("utf-8"))
    if str(version_payload.get("version") or "") != version:
        raise RuntimeError("release tag must match version.json")
    dashboard_payload = json.loads(tracked_file_bytes("threat-intelligence-dashboard/package.json").decode("utf-8"))
    release_core = version.removeprefix("v").split("-", 1)[0]
    expected_dashboard_version = release_core if "." in release_core else f"{release_core}.0.0"
    if str(dashboard_payload.get("version") or "") != expected_dashboard_version:
        raise RuntimeError("dashboard package version does not match release tag")
    version_payload.update({
        "version": version,
        "commit": commit,
        "branch": "stable",
        "channel": "stable",
        "repository": repository,
        "updated_at": updated_at,
        "data_schema": int(version_payload.get("data_schema") or 1),
    })

    with zipfile.ZipFile(package_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True) as archive:
        for relative in tracked_files():
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            data = (
                json.dumps(version_payload, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"
                if relative == "version.json"
                else tracked_file_bytes(relative)
            )
            archive.writestr(info, data)

    digest = hashlib.sha256()
    with package_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
    package_url = f"https://github.com/{repository}/releases/download/{version}/{package_name}"
    manifest: dict[str, Any] = {
        "format": 1,
        "channel": "stable",
        "version": version,
        "commit": commit,
        "published_at": updated_at,
        "release_url": f"https://github.com/{repository}/releases/tag/{version}",
        "minimum_updater_version": 2,
        "data_schema": int(version_payload.get("data_schema") or 1),
        "rollback_compatible": True,
        "package": {
            "name": package_name,
            "url": package_url,
            "size": package_path.stat().st_size,
            "sha256": sha256,
        },
    }
    if signing_key is not None:
        sign_manifest(manifest, signing_key, key_id)

    manifest_path = output_dir / "latest-stable.json"
    with manifest_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    return {"package": package_path, "manifest": manifest_path}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a Git-free self-update package")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", default=str(ROOT / "dist-update"))
    parser.add_argument("--signing-key", default="")
    parser.add_argument("--key-id", default="release-ed25519")
    args = parser.parse_args()

    signing_key = Path(args.signing_key).resolve() if args.signing_key else None
    outputs = build_package(
        args.repository.strip(),
        args.version.strip(),
        Path(args.output_dir).resolve(),
        signing_key,
        args.key_id.strip(),
    )
    print(json.dumps({name: str(path) for name, path in outputs.items()}))


if __name__ == "__main__":
    main()
