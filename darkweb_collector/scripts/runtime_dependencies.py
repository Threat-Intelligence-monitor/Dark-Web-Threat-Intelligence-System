"""Local dependency fingerprints and read-only Node installation validation."""
from __future__ import annotations

import argparse
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import sys
import sysconfig
from urllib.parse import urlsplit


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _text(path: Path) -> str:
    return path.read_bytes().decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")


def _object(path: Path) -> dict:
    value = json.loads(_text(path))
    if not isinstance(value, dict):
        raise ValueError("Invalid object")
    return value


def python_profile(requirements: Path) -> dict[str, str]:
    base = getattr(sys, "_base_executable", None) or sys.executable
    identity = _hash({
        "base": os.path.normcase(os.path.abspath(base)),
        "version": list(sys.version_info),
        "implementation": sys.implementation.name,
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "platform": sysconfig.get_platform(),
        "machine": platform.machine().casefold(),
        "bits": struct.calcsize("P") * 8,
        "gil_disabled": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
    })
    packages = []
    for distribution in metadata.distributions():
        name, version = distribution.metadata.get("Name"), distribution.version
        if not isinstance(name, str) or not name.strip() or not isinstance(version, str) or not version.strip():
            raise ValueError("Invalid distribution metadata")
        packages.append((re.sub(r"[-_.]+", "-", name).lower(), version))
    requirement_hash = hashlib.sha256(_text(requirements).encode("utf-8")).hexdigest()
    return {
        "identity": identity,
        "requirements": requirement_hash,
        "packages": _hash(sorted(packages)),
        "key": hashlib.sha256((identity + "\n" + requirement_hash).encode("utf-8")).hexdigest(),
    }


def _no_link(path: Path) -> os.stat_result:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Unsupported link")
    return info


def _dashboard(path: Path) -> Path:
    root = Path(os.path.abspath(path))
    for parent in (root, *root.parents):
        if not stat.S_ISDIR(_no_link(parent).st_mode):
            raise ValueError("Invalid directory")
    for name in ("package.json", "package-lock.json"):
        if not stat.S_ISREG(_no_link(root / name).st_mode):
            raise ValueError("Invalid manifest")
    return root


def node_profile(dashboard: Path) -> dict[str, str]:
    root = _dashboard(dashboard)
    package, lock = _object(root / "package.json"), _object(root / "package-lock.json")
    package.pop("version", None)
    lock.pop("version", None)
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise ValueError("Unsupported lock layout")
    packages[""].pop("version", None)
    return {"fingerprint": _hash({"package": package, "lock": lock})}


def _registry_spec(value: object) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("Unsupported dependency")
    if value.startswith("npm:"):
        name, separator, value = value[4:].rpartition("@")
        if not separator or not re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", name):
            raise ValueError("Unsupported dependency alias")
    if value in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9._*+^~<>=| -]+", value):
        raise ValueError("Unsupported dependency")


def _registry_entry(entry: dict, *, root: bool = False) -> None:
    if entry.get("link") or entry.get("workspaces"):
        raise ValueError("Unsupported dependency layout")
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = entry.get(field, {})
        if not isinstance(values, dict):
            raise ValueError("Invalid dependency mapping")
        for value in values.values():
            _registry_spec(value)
    if not root:
        version, resolved = entry.get("version"), entry.get("resolved")
        _registry_spec(version)
        if not isinstance(resolved, str):
            raise ValueError("Missing registry resolution")
        url = urlsplit(resolved)
        if url.scheme != "https" or not url.hostname or url.username or url.password or "/-/" not in url.path or not url.path.endswith(".tgz"):
            raise ValueError("Unsupported registry resolution")


def _module_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or "\\" in name:
        raise ValueError("Invalid module path")
    parts = name.split("/")
    if parts[0] != "node_modules" or len(parts) < 2 or any(
        part in {"", ".", ".."} or ":" in part or part.endswith((" ", ".")) for part in parts
    ):
        raise ValueError("Invalid module path")
    path = root.joinpath(*parts)
    path.relative_to(root / "node_modules")
    return path


def _tree_files(root: Path, excluded: frozenset[str] = frozenset()):
    if not stat.S_ISDIR(_no_link(root).st_mode):
        raise ValueError("Missing modules")
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                path.relative_to(root)
                info = _no_link(path)
                if stat.S_ISDIR(info.st_mode):
                    if entry.name not in excluded:
                        pending.append(path)
                elif not stat.S_ISREG(info.st_mode):
                    raise ValueError("Unsupported module file")
                else:
                    yield path


def _check_tree(root: Path) -> None:
    for _ in _tree_files(root):
        pass


def check_node_paths(dashboard: Path) -> None:
    modules = _dashboard(dashboard) / "node_modules"
    try:
        _no_link(modules)
    except FileNotFoundError:
        return
    _check_tree(modules)


def _file_inventory(root: Path, excluded: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    files = []
    for path in _tree_files(root, excluded):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        files.append((path.relative_to(root).as_posix(), digest.hexdigest()))
    return sorted(files)


def dashboard_profile(dashboard: Path, node_identity: str) -> dict[str, str | None]:
    root = _dashboard(dashboard)
    if not node_identity.strip():
        raise ValueError("Missing Node identity")
    excluded = frozenset({"node_modules", "dist", "dist-update", ".git", ".runtime", "output", "tests", "__pycache__", ".playwright-cli", ".vite", "coverage", "playwright-report", "test-results"})
    environment = {}
    for name, value in os.environ.items():
        name = name.upper() if os.name == "nt" else name
        if name.startswith("VITE_") or name == "NODE_ENV":
            environment[name] = value
    fingerprint = _hash({"files": _file_inventory(root, excluded), "node": node_identity, "environment": _hash(environment)})
    dist = root / "dist"
    try:
        _no_link(dist)
    except FileNotFoundError:
        return {"fingerprint": fingerprint, "dist": None}
    files = _file_inventory(dist)
    return {"fingerprint": fingerprint, "dist": _hash(files) if any(name == "index.html" for name, _ in files) else None}


def check_node(dashboard: Path) -> None:
    root = _dashboard(dashboard)
    package, lock = _object(root / "package.json"), _object(root / "package-lock.json")
    packages = lock.get("packages")
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise ValueError("Unsupported lock layout")
    _registry_entry(package, root=True)
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if package.get(field, {}) != packages[""].get(field, {}):
            raise ValueError("Dependency lock mismatch")
    _check_tree(root / "node_modules")
    for name, entry in packages.items():
        if not isinstance(entry, dict):
            raise ValueError("Invalid lock entry")
        _registry_entry(entry, root=name == "")
        if name == "":
            continue
        path = _module_path(root, name)
        if not path.exists() and entry.get("optional") is True:
            continue
        if _object(path / "package.json").get("version") != entry["version"]:
            raise ValueError("Installed version mismatch")
    if not (root / "node_modules/vite/bin/vite.js").is_file():
        raise ValueError("Missing Vite CLI")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("Invalid arguments")


def main() -> int:
    try:
        parser = _Parser(description=__doc__)
        commands = parser.add_subparsers(dest="command", required=True)
        commands.add_parser("python-profile").add_argument("--requirements", required=True, type=Path)
        for name in ("node-profile", "check-node", "check-node-paths"):
            commands.add_parser(name).add_argument("--dashboard", required=True, type=Path)
        dashboard = commands.add_parser("dashboard-profile")
        dashboard.add_argument("--dashboard", required=True, type=Path)
        dashboard.add_argument("--node-identity", required=True)
        args = parser.parse_args()
        if args.command == "python-profile":
            result = python_profile(args.requirements)
        elif args.command == "node-profile":
            result = node_profile(args.dashboard)
        elif args.command == "dashboard-profile":
            result = dashboard_profile(args.dashboard, args.node_identity)
        elif args.command == "check-node":
            check_node(args.dashboard)
            return 0
        else:
            check_node_paths(args.dashboard)
            return 0
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception:
        print("Runtime dependency validation failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
