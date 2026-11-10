"""Immutable evidence selected by the same transaction as its collected body."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import time
from uuid import uuid4
import zlib

import psutil


ARTIFACTS_KEY = "_collector_artifacts"
_legacy_view = ContextVar("legacy_artifact_view", default=False)


def legacy_artifact_view_active() -> bool:
    return bool(_legacy_view.get())


@contextmanager
def legacy_artifact_view():
    """Use verified aliases only during the caller's quiesced reprojection."""
    token = _legacy_view.set(True)
    try:
        yield
    finally:
        _legacy_view.reset(token)


def native_artifact_path(path: Path) -> Path:
    if os.name != "nt":
        return path
    value = str(path.absolute())
    if value.startswith("\\\\?\\"):
        return path
    return Path("\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value)


def display_artifact_path(path: Path) -> Path:
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        return Path("\\\\" + value[8:])
    return Path(value[4:]) if value.startswith("\\\\?\\") else path


def _complete_png(data: bytes) -> bool:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return False
    offset, header, pixels = 8, False, False
    while offset + 12 <= len(data):
        size = int.from_bytes(data[offset:offset + 4], "big")
        end = offset + size + 12
        if end > len(data):
            return False
        kind = data[offset + 4:offset + 8]
        chunk = memoryview(data)[offset + 8:end - 4]
        if zlib.crc32(chunk, zlib.crc32(kind)) != int.from_bytes(data[end - 4:end], "big"):
            return False
        if offset == 8:
            header = kind == b"IHDR" and size == 13 and int.from_bytes(chunk[:4], "big") > 0 and int.from_bytes(chunk[4:8], "big") > 0
            if not header:
                return False
        pixels = pixels or (kind == b"IDAT" and size > 0)
        if kind == b"IEND":
            return header and pixels and size == 0 and end == len(data)
        offset = end
    return False


def _payload(value) -> dict:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def forum_artifact_payload(row: dict) -> dict:
    payload = dict(_payload(row.get("raw_json")))
    for field in ("content_hash", "content", "attachments"):
        if field in row:
            payload[field] = row[field]
    return payload


def victim_artifact_payload(row: dict, raw_payload=None) -> dict:
    payload = dict(_payload(row.get("detail_raw_json") if raw_payload is None else raw_payload))
    for field in ("page_title", "text_excerpt", "outbound_link_count"):
        if field in row:
            payload[field] = row[field]
    return payload


def body_fingerprint(payload: dict, *, forum: bool = False) -> str:
    if forum:
        attachments = payload.get("attachments") or ""
        if isinstance(attachments, (list, tuple)):
            attachments = ", ".join(attachments)
        content = {"content_hash": payload.get("content_hash"), "content": payload.get("content"), "attachments": attachments}
    else:
        content = {key: payload.get(key) for key in ("page_title", "content", "text_excerpt", "outbound_link_count")}
    return sha256(json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _target_key(site_name: str, target_url: str) -> str:
    return sha256((site_name + "\0" + target_url).encode("utf-8")).hexdigest()


def _file_state(path: Path) -> tuple:
    stat = path.stat()
    return stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size, stat.st_ino


@lru_cache(maxsize=512)
def _legacy_json_matches(path: Path, state: tuple, expected_body: str, target_url: str, forum: bool) -> bool:
    try:
        captured = _payload(path.read_bytes())
        return (captured.get("source_url") in (None, target_url)
                and body_fingerprint(captured, forum=forum) == expected_body)
    except (OSError, ValueError):
        return False


@lru_cache(maxsize=512)
def _file_matches_hash(path: Path, state: tuple, expected_hash: str) -> bool:
    try:
        digest = sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        return digest.hexdigest() == expected_hash
    except OSError:
        return False


def _contained(root: Path, directory: Path, path: Path) -> bool:
    try:
        root, directory, path = map(display_artifact_path, (root, directory, path))
        relative_directory = directory.absolute().relative_to(root.absolute())
        relative_path = path.absolute().relative_to(directory.absolute())
        root_resolved, directory_resolved, path_resolved = map(
            display_artifact_path, (native_artifact_path(root).resolve(), native_artifact_path(directory).resolve(), native_artifact_path(path).resolve()))
        return (directory_resolved == root_resolved / relative_directory
                and path_resolved == directory_resolved / relative_path)
    except (OSError, RuntimeError, ValueError):
        return False


def detail_artifact_paths(root: Path, directory: Path, stem: str, raw_payload=None,
                          *, site_name: str, target_url: str, forum: bool = False) -> dict[str, Path]:
    """Never fall back to a fixed/fuzzy filename for a version-aware record."""
    payload = _payload(raw_payload)
    if not _contained(root, directory, directory):
        return {}
    if ARTIFACTS_KEY not in payload:
        stored_stem = payload.get("artifact_stem")
        if stored_stem not in (None, ""):
            if not isinstance(stored_stem, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", stored_stem) or stored_stem in {".", ".."}:
                return {}
            stem = stored_stem
        paths = {kind: path for kind in ("html", "json", "png")
                 if (path := native_artifact_path(directory / f"{stem}.{kind}")).is_file() and _contained(root, directory, path)}
        if not payload or "json" not in paths or not _legacy_json_matches(
            paths["json"], _file_state(paths["json"]), body_fingerprint(payload, forum=forum), target_url, forum
        ):
            return {}
        return paths
    manifest = payload[ARTIFACTS_KEY]
    target = _target_key(site_name, target_url)
    if (not isinstance(manifest, dict) or type(manifest.get("version")) is not int
        or manifest.get("version") != 1 or manifest.get("target") != target
        or manifest.get("body_hash") != body_fingerprint(payload, forum=forum)):
        return {}
    paths = {}
    for kind, suffix in (("html", "html"), ("json", "json"), ("png", "png"), ("previous_png", "png")):
        value = manifest.get(kind)
        if not value:
            continue
        if not isinstance(value, str) or not re.fullmatch(r"\.versions/" + target[:32] + r"/[0-9a-f]{64}\." + suffix, value):
            return {}
        path = directory.joinpath(*PurePosixPath(value).parts)
        if not _contained(root, directory, path):
            return {}
        path = native_artifact_path(path)
        if path.is_file() and path.stat().st_size:
            paths[kind] = path
    return paths


def referenced_artifact_resources(root: Path, directory: Path, stem: str, raw_payload,
                                  *, site_name: str, target_url: str, forum: bool, resource_entry, include_legacy=False):
    payload = _payload(raw_payload)
    if ARTIFACTS_KEY not in payload and not include_legacy:
        return None
    paths = detail_artifact_paths(root, directory, stem, raw_payload, site_name=site_name, target_url=target_url, forum=forum)
    if _legacy_view.get() and ARTIFACTS_KEY in payload:
        manifest = payload[ARTIFACTS_KEY]
        if (not isinstance(manifest, dict) or "json" not in paths
            or any(manifest.get(kind) and kind not in paths for kind in ("html", "png", "previous_png"))):
            raise ValueError("Committed evidence cannot be represented by a safe legacy view")
        legacy_stem = sha1(target_url.encode("utf-8")).hexdigest()[:10] if forum else manifest.get("legacy_stem")
        if not isinstance(legacy_stem, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", legacy_stem) or legacy_stem in {".", ".."}:
            raise ValueError("Committed evidence has no safe legacy filename")
        aliases = {}
        for kind in ("html", "json", "png"):
            if kind not in paths:
                continue
            alias = native_artifact_path(directory / f"{legacy_stem}.{kind}")
            if (not _contained(root, directory, alias) or not alias.is_file()
                or not _file_matches_hash(alias, _file_state(alias), paths[kind].stem)):
                raise ValueError("Legacy evidence view has not been materialized for this committed body")
            aliases[kind] = alias
        paths = aliases
    mirrors = [resource_entry(paths[key], label) for key, label in
               (("html", "本地HTML镜像"), ("json", "本地JSON镜像"), ("previous_png", "历史截图（非当前正文）")) if key in paths]
    screenshots = [resource_entry(paths["png"], "详情截图")] if "png" in paths else []
    return mirrors, screenshots


def _write_blob(root: Path, directory: Path, target: str, suffix: str, content: bytes) -> str:
    relative = f".versions/{target[:32]}/{sha256(content).hexdigest()}.{suffix}"
    destination = directory.joinpath(*PurePosixPath(relative).parts)
    if not _contained(root, directory, destination):
        raise ValueError("Evidence destination escapes the configured site output directory")
    destination = native_artifact_path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if destination.read_bytes() != content:
            raise ValueError("Existing immutable evidence does not match its content hash")
        return relative
    # A concurrent writer of this content has identical bytes. No published
    # filename ever changes to different evidence, including after a crash.
    _atomic_file(destination, content)
    if os.name != "nt":
        descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return relative


def _previous_payload(connection, config, result, section: str | None) -> dict:
    if section is not None:
        row = connection.execute("SELECT raw_json,content_hash,content,attachments FROM forum_details WHERE site_name=? AND section=? AND topic_url=?",
                                 (config.site_name, section, result.target_url)).fetchone()
    else:
        metadata = result.metadata
        row = connection.execute("""SELECT d.raw_json,d.page_title,d.text_excerpt,d.outbound_link_count FROM victims v JOIN victim_details d ON d.victim_id=v.id
            WHERE v.site_name=? AND v.source_url=? AND v.name=? AND ifnull(v.domain,'')=ifnull(?,'')
                AND v.status=? AND d.fetch_status='ok' ORDER BY d.id DESC LIMIT 1""",
            (config.site_name, str(metadata.get("source_url", "")), str(metadata.get("name", "")),
             metadata.get("domain"), str(metadata.get("status", "active")))).fetchone()
    if row is None:
        return {}
    return forum_artifact_payload(dict(row)) if section is not None else victim_artifact_payload(dict(row), row[0])


def _persist_new_artifacts(config, result, directory: Path, stem: str, section: str | None, previous: dict) -> dict:
    """Write durable blobs before SQL publishes references; never overwrite old files.

    Unreferenced blobs are harmless after rollback or an indeterminate commit.
    In particular, cleanup must never delete them by guessing whether SQL committed.
    """
    root = config.output_dir
    if not _contained(root, directory, directory):
        raise ValueError("Evidence directory escapes the configured site output directory")
    old_paths = detail_artifact_paths(root, directory, stem, previous,
                                      site_name=config.site_name, target_url=result.target_url, forum=section is not None)
    old_body = body_fingerprint(previous, forum=section is not None) if previous else ""
    previous_manifest = previous.get(ARTIFACTS_KEY)
    if previous_manifest is not None:
        if not isinstance(previous_manifest, dict) or previous_manifest.get("body_hash") != old_body:
            old_paths = {}
    # Legacy fixed files may already have been overwritten by a failed task.
    # Reuse an image only when its stored JSON agrees with committed SQL.
    try:
        captured_bytes = old_paths["json"].read_bytes()
        captured = _payload(captured_bytes)
        if (captured.get("source_url") not in (None, result.target_url)
            or body_fingerprint(captured, forum=section is not None) != old_body
            or (previous_manifest is not None and sha256(captured_bytes).hexdigest() != old_paths["json"].stem)):
            old_paths = {}
    except (KeyError, OSError, ValueError):
        old_paths = {}

    payload = dict(result.payload)
    # Source pages cannot supply their own filesystem references.
    payload.pop(ARTIFACTS_KEY, None)
    if section is None:
        payload["artifact_stem"] = stem
    current_body = body_fingerprint(payload, forum=section is not None)
    target = _target_key(config.site_name, result.target_url)
    manifest = {"version": 1, "target": target, "body_hash": current_body}
    image = result.screenshot_png
    if image and not _complete_png(image):
        result.metadata["artifact_error"] = "artifact: captured PNG is incomplete"
        payload["_collector_artifact_error"] = result.metadata["artifact_error"]
        image = None
    html = result.raw_html
    previous_image = None
    old_png = old_paths.get("png") or old_paths.get("previous_png")
    if old_png is not None and not image:
        try:
            data = old_png.read_bytes()
            if _complete_png(data) and (previous_manifest is None or sha256(data).hexdigest() == old_png.stem):
                previous_image = data
        except OSError:
            pass
    reused = False
    if current_body == old_body:
        if not image and "png" in old_paths and previous_image:
            image, reused = previous_image, True
        if not html and "html" in old_paths:
            html_bytes = old_paths["html"].read_bytes()
            if previous_manifest is None or sha256(html_bytes).hexdigest() == old_paths["html"].stem:
                html = html_bytes.decode("utf-8")
    if html:
        manifest["html"] = _write_blob(root, directory, target, "html", html.encode("utf-8", errors="replace"))
    if image:
        manifest["png"] = _write_blob(root, directory, target, "png", image)
    elif previous_image:
        manifest["previous_png"] = _write_blob(root, directory, target, "png", previous_image)
    manifest["complete"] = bool(html and image)
    payload["_collector_artifacts_complete"] = manifest["complete"]
    if reused:
        payload["_collector_artifact_reused"] = True
        warning = result.metadata.pop("artifact_error", "") or payload.pop("_collector_artifact_error", "")
        payload.pop("_collector_artifact_error", None)
        if warning:
            payload["_collector_artifact_warning"] = warning
    # JSON contains the body and completeness, not its own content-addressed URL.
    manifest["json"] = _write_blob(root, directory, target, "json",
                                   json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
    payload[ARTIFACTS_KEY] = manifest
    result.payload = payload
    result.raw_html, result.screenshot_png = html, image
    return manifest


@contextmanager
def _candidate_lock(path: Path):
    with native_artifact_path(path).open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
        deadline = time.monotonic() + 10
        while True:
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Evidence candidate is busy")
                time.sleep(0.05)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _atomic_file(path: Path, content: bytes) -> None:
    path = native_artifact_path(path)
    temporary = path.with_name(f".pending-{os.getpid()}-" + uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _cleanup_interrupted_writes(root: Path, directory: Path, folder: Path) -> None:
    # Only private temporary files whose producing process no longer exists.
    # Immutable blobs may already be committed and are never garbage-collected here.
    for index, path in enumerate(native_artifact_path(folder).glob(".pending-*")):
        if index >= 100:
            break
        match = re.fullmatch(r"\.pending-([0-9]+)-[0-9a-f]{32}", path.name)
        if match and _contained(root, directory, path) and not psutil.pid_exists(int(match.group(1))):
            path.unlink(missing_ok=True)


def persist_detail_artifacts(connection, config, result, directory: Path, stem: str,
                             *, section: str | None = None) -> dict:
    # Read SQL before acquiring a filesystem lock; release it before the adapter
    # writes SQL. This remains safe for multi-target caller-owned transactions.
    previous = _previous_payload(connection, config, result, section)
    body_hash = body_fingerprint(result.payload, forum=section is not None)
    target = _target_key(config.site_name, result.target_url)
    source_version = str(result.metadata.get("source_version") or "")
    candidate_key = sha256((body_hash + "\0" + source_version).encode("utf-8")).hexdigest()
    folder = directory / ".versions" / target[:32]
    if not re.fullmatch(r"[A-Za-z0-9._-]+", stem) or stem in {".", ".."}:
        raise ValueError("Invalid legacy evidence filename")
    if not _contained(config.output_dir, directory, folder):
        raise ValueError("Evidence candidate escapes the configured site output directory")
    folder = native_artifact_path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    _cleanup_interrupted_writes(config.output_dir, directory, folder)
    candidate = folder / (".candidate-" + candidate_key + ".json")
    lock = folder / (".artifact-lock-" + candidate_key)
    if not all(_contained(config.output_dir, directory, path) for path in (candidate, lock)):
        raise ValueError("Evidence candidate links outside its target directory")
    with _candidate_lock(lock):
        cached = _payload(candidate.read_text(encoding="utf-8")) if candidate.exists() else {}
        if cached:
            paths = detail_artifact_paths(config.output_dir, directory, stem, {**result.payload, ARTIFACTS_KEY: cached},
                site_name=config.site_name, target_url=result.target_url, forum=section is not None)
            if cached.get("source_version") != source_version or cached.get("body_hash") != body_hash or "json" not in paths:
                raise ValueError("Stored evidence candidate does not match this body")
            stored_files = {kind: path.read_bytes() for kind, path in paths.items()}
            captured = _payload(stored_files["json"])
            if body_fingerprint(captured, forum=section is not None) != body_hash:
                raise ValueError("Stored evidence JSON does not match this body")
            for kind, path in paths.items():
                if sha256(stored_files[kind]).hexdigest() != path.stem:
                    raise ValueError("Stored evidence candidate has changed")
            png = stored_files.get("png")
            if png and not _complete_png(png):
                raise ValueError("Stored evidence candidate has an incomplete PNG")
            committed = previous.get(ARTIFACTS_KEY)
            committed_candidate = isinstance(committed, dict) and all(
                committed.get(key) == cached.get(key) for key in ("target", "body_hash", "source_version", "html", "json", "png"))
            refresh = (bool(cached.get("complete")) and committed_candidate
                       and bool(result.raw_html and result.screenshot_png) and _complete_png(result.screenshot_png))
            can_upgrade = (("html" not in paths and bool(result.raw_html))
                           or (png is None and bool(result.screenshot_png) and _complete_png(result.screenshot_png)))
            if "html" in paths and not refresh:
                result.raw_html = stored_files["html"].decode("utf-8")
            if (cached.get("complete") and not refresh) or (not cached.get("complete") and not can_upgrade):
                if cached.get("complete") and not (result.raw_html and png):
                    raise ValueError("Stored complete evidence candidate is missing files")
                payload = dict(result.payload)
                cached = {**cached, "legacy_stem": stem}
                if section is None:
                    payload["artifact_stem"] = stem
                payload[ARTIFACTS_KEY] = cached
                payload["_collector_artifacts_complete"] = bool(cached.get("complete"))
                if cached.get("complete"):
                    warning = result.metadata.pop("artifact_error", "") or payload.pop("_collector_artifact_error", "")
                    payload.pop("_collector_artifact_error", None)
                    if warning:
                        payload["_collector_artifact_warning"] = warning
                    payload["_collector_artifact_reused"] = True
                result.payload, result.screenshot_png = payload, png
                if "html" not in paths:
                    result.raw_html = None
                return cached
            if not result.screenshot_png and png:
                result.screenshot_png = png
        manifest = _persist_new_artifacts(config, result, directory, stem, section, previous)
        manifest["legacy_stem"] = stem
        manifest["source_version"] = source_version
        _atomic_file(candidate, json.dumps(manifest, ensure_ascii=False, sort_keys=True).encode("utf-8"))
        return manifest


def _legacy_rows(connection):
    for forum in (True, False):
        after = 0
        while True:
            if forum:
                rows = connection.execute("""SELECT id,site_name,section,topic_url,raw_json,content_hash,content,attachments,fetched_at FROM forum_details
                    WHERE id>? ORDER BY id LIMIT 100""", (after,)).fetchall()
            else:
                rows = connection.execute("""SELECT v.id,v.site_name,v.detail_url,d.id AS detail_record_id,d.raw_json,
                    d.page_title,d.text_excerpt,d.outbound_link_count,d.fetched_at_utc FROM victims v
                    JOIN victim_details d ON d.id=(SELECT latest.id FROM victim_details latest
                        WHERE latest.victim_id=v.id ORDER BY latest.id DESC LIMIT 1)
                    WHERE v.id>? ORDER BY v.id LIMIT 100""", (after,)).fetchall()
            if not rows:
                break
            for row in rows:
                yield forum, dict(row)
            after = rows[-1]["id"]


def iter_committed_artifact_sources(connection):
    """Yield (normalizer source_type, source_id) without loading all bodies."""
    for forum, row in _legacy_rows(connection):
        if ARTIFACTS_KEY in _payload(row["raw_json"]):
            yield ("forum_details" if forum else "victims"), int(row["id"])


def materialize_legacy_views(connection, configs, *, quiesced: bool = False) -> dict:
    """Prepare a rollback view only while the caller has stopped all app writers.

    SQL is read-only. Any error must prevent the old application from starting;
    retrying this operation is safe after interruption and never removes blobs.
    """
    if not quiesced:
        raise ValueError("Legacy evidence materialization requires all application processes to be stopped")
    configs_by_name = {config.site_name: config for config in configs}
    report = {"complete": False, "records": 0, "aliases_written": 0, "aliases_removed": 0, "preserved_files": 0}
    signature = sha256()
    aliases = {}
    for forum, row in _legacy_rows(connection):
        payload = forum_artifact_payload(row) if forum else victim_artifact_payload(row, row["raw_json"])
        if ARTIFACTS_KEY not in payload:
            continue
        config = configs_by_name.get(row["site_name"])
        if config is None:
            raise ValueError("No output configuration for committed evidence: " + row["site_name"])
        signature.update(json.dumps({"source_type": "forum_details" if forum else "victims", "row": row,
            "output_dir": str(display_artifact_path(native_artifact_path(config.output_dir).resolve()))},
            sort_keys=True, ensure_ascii=False).encode("utf-8"))
        signature.update(b"\n")
        manifest = payload[ARTIFACTS_KEY]
        stem = manifest.get("legacy_stem") if isinstance(manifest, dict) else None
        if not isinstance(stem, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", stem) or stem in {".", ".."}:
            raise ValueError("Committed evidence has no safe legacy filename")
        directory = config.output_dir / row["section"] / "details" if forum else config.output_dir / "details"
        target_url = row["topic_url"] if forum else str(payload.get("source_url") or row.get("detail_url") or "")
        if forum:
            stem = sha1(target_url.encode("utf-8")).hexdigest()[:10]
        paths = detail_artifact_paths(config.output_dir, directory, stem, payload,
                                      site_name=config.site_name, target_url=target_url, forum=forum)
        if "json" not in paths or any(manifest.get(kind) and kind not in paths for kind in ("html", "png", "previous_png")):
            raise ValueError("Committed evidence is incomplete; legacy startup must not continue")
        contents = {kind: path.read_bytes() for kind, path in paths.items()}
        if any(sha256(contents[kind]).hexdigest() != path.stem for kind, path in paths.items()):
            raise ValueError("Committed evidence content hash does not match")
        if body_fingerprint(_payload(contents["json"]), forum=forum) != body_fingerprint(payload, forum=forum):
            raise ValueError("Committed evidence JSON does not match the database body")
        if "png" in contents and not _complete_png(contents["png"]):
            raise ValueError("Committed screenshot is incomplete")
        report["records"] += 1
        _cleanup_interrupted_writes(config.output_dir, directory, directory)
        for kind in ("html", "json", "png"):
            alias = native_artifact_path(directory / f"{stem}.{kind}")
            if not _contained(config.output_dir, directory, alias):
                raise ValueError("Legacy evidence alias escapes its site directory")
            content = contents.get(kind)
            identity = sha256(content).hexdigest() if content is not None else None
            if alias in aliases and aliases[alias] != identity:
                raise ValueError("Different committed bodies share one legacy evidence filename")
            aliases[alias] = identity
            old_content = alias.read_bytes() if alias.is_file() else None
            if old_content == content:
                continue
            if old_content is not None:
                _write_blob(config.output_dir, directory, manifest["target"], kind, old_content)
                report["preserved_files"] += 1
            if content is None:
                alias.unlink(missing_ok=True)
                report["aliases_removed"] += 1
            else:
                _atomic_file(alias, content)
                report["aliases_written"] += 1
    report["complete"] = True
    report["signature"] = signature.hexdigest()
    return report
