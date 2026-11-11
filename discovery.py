"""Read-only target discovery for Flatpak, folders, ELF/PE files and RPM.

Inputs are local paths and, on Linux, Flatpak/RPM metadata; outputs are bounded
target records and scan diagnostics. Discovery returns metadata and absolute
paths; it never launches a discovered file. POSIX uses descriptor-relative
walking; Windows uses a portable os.walk fallback. Keep both paths in sync
when adding target formats or platform-specific sources.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from analysis import has_elf_magic, has_pe_magic
from rpm_ingest import ingest_rpm

MAX_FILE_BYTES = 64 * 1024 * 1024

FLATPAK_COLUMNS = "application,name,version,branch,installation"
APP_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,254}$")
MAX_SCAN_FILES = 50_000
COMMAND_TIMEOUT = 20
EXCLUDED_DIRECTORIES = frozenset({"tools", "runs", "backups", "venv", "env", "__pycache__", "node_modules"})


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[..., object]


def _command(args: list[str], runner: CommandRunner) -> CommandResult:
    try:
        result = runner(
            args,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required local tool is unavailable: {args[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{args[0]} timed out while reading local package metadata.") from exc
    except OSError as exc:
        # e.g. PermissionError when a non-executable "flatpak" is on PATH:
        # report the tool as unavailable instead of failing the request.
        raise RuntimeError(f"Required local tool cannot be started: {args[0]} ({exc.strerror or exc})") from exc
    except subprocess.SubprocessError as exc:
        raise RuntimeError(f"{args[0]} could not be run: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(detail[:500] or f"{args[0]} returned exit code {result.returncode}.")
    return CommandResult(result.returncode, result.stdout or "", result.stderr or "")


def parse_flatpak_list(text: str) -> list[dict[str, str]]:
    apps: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        app_id, name, version, branch, installation = (field.strip() for field in fields)
        if not APP_ID_PATTERN.fullmatch(app_id) or app_id in seen:
            continue
        seen.add(app_id)
        apps.append({
            "app_id": app_id,
            "name": name or app_id,
            "version": version or "Unknown",
            "branch": branch or "Unknown",
            "installation": installation or "Unknown",
        })
    return sorted(apps, key=lambda app: (app["name"].casefold(), app["app_id"].casefold()))


def list_flatpak_apps(runner: CommandRunner = subprocess.run) -> list[dict[str, str]]:
    if os.name == "nt":
        raise ValueError("Flatpak discovery is unavailable on Windows.")
    result = _command(
        ["flatpak", "list", "--app", f"--columns={FLATPAK_COLUMNS}"],
        runner,
    )
    return parse_flatpak_list(result.stdout)


def find_elf_targets(root: str | Path, max_file_bytes: int = MAX_FILE_BYTES) -> list[dict[str, object]]:
    targets, scan = _scan_directory(root, max_file_bytes)
    if not scan["complete"]:
        raise ValueError(f"Incomplete directory scan: {scan['errors']}")
    return targets


def _is_link_like(path: Path) -> bool:
    """True for symlinks, NTFS junctions and other reparse points (CWE-59).

    ``Path.is_symlink`` is False for junctions, so a junction inside a chosen
    folder could otherwise lead the scan to another part of the disk.
    """
    try:
        if path.is_symlink():
            return True
        isjunction = getattr(os.path, "isjunction", None)
        if isjunction is not None and isjunction(path):
            return True
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    except OSError:
        return True


def _scan_directory_windows(root: str | Path, max_file_bytes: int = MAX_FILE_BYTES) -> tuple[list, dict]:
    """Portable directory walk for Windows (no dir_fd / O_DIRECTORY)."""
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("Selected application payload directory was not found.")
    targets: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    visited = 0
    excluded = 0
    for dirpath, dirnames, filenames in os.walk(base, topdown=True, followlinks=False):
        kept_names = []
        for name in dirnames:
            visited += 1
            if visited > MAX_SCAN_FILES:
                raise ValueError(f"Directory scan exceeded the {MAX_SCAN_FILES:,}-entry safety limit.")
            if name.startswith(".") or name in EXCLUDED_DIRECTORIES:
                excluded += 1
                continue
            candidate = Path(dirpath) / name
            if _is_link_like(candidate):
                excluded += 1
                continue
            if (candidate / "pyvenv.cfg").is_file():
                excluded += 1
                continue
            kept_names.append(name)
        dirnames[:] = kept_names
        for name in filenames:
            visited += 1
            if visited > MAX_SCAN_FILES:
                raise ValueError(f"Directory scan exceeded the {MAX_SCAN_FILES:,}-entry safety limit.")
            candidate = Path(dirpath) / name
            if name.startswith(".") or _is_link_like(candidate):
                excluded += 1
                continue
            try:
                if not stat.S_ISREG(candidate.stat(follow_symlinks=False).st_mode):
                    continue
                target = _file_target(candidate, candidate.relative_to(base).as_posix(), max_file_bytes)
                if target is not None:
                    targets.append(target)
            except OSError as exc:
                errors.append({"path": str(candidate), "error": str(exc)})
    return sorted(targets, key=lambda item: str(item["relative_path"]).casefold()), {
        "complete": not errors, "partial": bool(errors), "errors": errors,
        "visited_entries": visited, "excluded_entries": excluded,
    }


def _scan_directory(root: str | Path, max_file_bytes: int = MAX_FILE_BYTES) -> tuple[list, dict]:
    if os.name == "nt":
        return _scan_directory_windows(root, max_file_bytes)
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("Selected application payload directory was not found.")

    targets: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    visited = 0
    excluded = 0

    def walk(directory: Path, directory_fd: int) -> None:
        nonlocal visited, excluded
        try:
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    visited += 1
                    if visited > MAX_SCAN_FILES:
                        raise ValueError(f"Directory scan exceeded the {MAX_SCAN_FILES:,}-entry safety limit.")
                    candidate = directory / entry.name
                    try:
                        if entry.name.startswith(".") or entry.is_symlink():
                            excluded += 1
                            continue
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            if entry.name in EXCLUDED_DIRECTORIES:
                                excluded += 1
                                continue
                            child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                               dir_fd=directory_fd)
                            try:
                                try:
                                    os.stat("pyvenv.cfg", dir_fd=child_fd, follow_symlinks=False)
                                except FileNotFoundError:
                                    walk(candidate, child_fd)
                                else:
                                    excluded += 1
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(mode):
                            target = _file_target(candidate, candidate.relative_to(base).as_posix(),
                                                  max_file_bytes, dir_fd=directory_fd)
                            if target is not None:
                                targets.append(target)
                    except OSError as exc:
                        errors.append({"path": str(candidate), "error": str(exc)})
        except OSError as exc:
            errors.append({"path": str(directory), "error": str(exc)})

    fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(base, fd)
    finally:
        os.close(fd)
    return sorted(targets, key=lambda item: str(item["relative_path"]).casefold()), {
        "complete": not errors, "partial": bool(errors), "errors": errors,
        "visited_entries": visited, "excluded_entries": excluded,
    }


def _file_target(path: Path, relative: str, max_file_bytes: int = MAX_FILE_BYTES,
                 *, dir_fd: int | None = None) -> dict[str, object] | None:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    name = path.name if dir_fd is not None else path
    fd = os.open(name, flags, dir_fd=dir_fd) if dir_fd is not None else os.open(name, flags)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        header = stream.read(64)
        file_format = "ELF" if has_elf_magic(header) else "PE" if has_pe_magic(header) else None
        if not stat.S_ISREG(metadata.st_mode) or file_format is None:
            return None
    size = metadata.st_size
    return {
        "target_id": hashlib.sha256(relative.encode("utf-8", errors="surrogateescape")).hexdigest()[:20],
        "relative_path": relative, "absolute_path": str(path), "size_bytes": size, "format": file_format,
        "analyzable": size <= max_file_bytes,
        "reason": None if size <= max_file_bytes else f"Exceeds the {max_file_bytes // (1024 * 1024)} MiB analysis limit.",
    }


def discover_flatpak_targets(app_id: str, runner: CommandRunner = subprocess.run) -> dict[str, object]:
    if not APP_ID_PATTERN.fullmatch(app_id):
        raise ValueError("Invalid Flatpak application ID.")
    apps = list_flatpak_apps(runner=runner)
    app = next((item for item in apps if item["app_id"] == app_id), None)
    if app is None:
        raise ValueError("Selected Flatpak application is not installed.")
    runtime_ref = _command(["flatpak", "info", "--show-runtime", app_id], runner).stdout.strip()
    location = _command(["flatpak", "info", "--show-location", app_id], runner).stdout.strip()
    if not location:
        raise ValueError("Flatpak did not return an installed application location.")
    files_root = Path(location) / "files"
    targets, scan = _scan_directory(files_root)
    return {
        "app": app,
        "payload_root": str(files_root.resolve()),
        "targets": targets,
        "scan": scan,
        "runtime": {
            "listed": True,
            "dependencies": [runtime_ref] if runtime_ref else [],
            "scanned": False,
            "message": "Shared runtime dependencies are listed by Flatpak metadata only; they are not scanned automatically.",
        },
    }


def discover_path(path: str | Path, *, workspace: Path) -> dict[str, object]:
    """Inventory only an explicitly selected payload; never launch its files."""
    source = Path(path).expanduser().resolve(strict=True)
    scan = {"complete": True, "partial": False, "errors": [], "visited_entries": 1}
    dependencies: list[str] = []
    if source.is_dir():
        kind, root = "directory", source
        targets, scan = _scan_directory(source)
    elif source.is_file() and source.suffix.lower() == ".rpm":
        if os.name == "nt":
            raise ValueError("RPM ingestion is Linux-only in this build.")
        ingested = ingest_rpm(source, workspace=workspace)
        kind, root = "rpm", Path(ingested["payload_root"])
        dependencies = ingested["dependencies"]
        targets, scan = _scan_directory(root)
    elif source.is_file():
        target = _file_target(source, source.name)
        if target is None:
            raise ValueError("Selected file is not an ELF regular file.")
        kind, root, targets = "elf", source.parent, [target]
    else:
        raise ValueError("Select a directory, ELF regular file, or RPM package.")
    return {
        "app": {"name": source.name, "source_type": kind},
        "payload_root": str(root),
        "targets": targets,
        "scan": scan,
        "runtime": {"listed": kind == "rpm", "scanned": False, "dependencies": dependencies,
                    "message": ("RPM requirements are listed from package metadata only; never scanned."
                                if kind == "rpm" else "Dependencies are not inferred or scanned for local paths.")},
    }


def tool_inventory() -> dict[str, dict[str, object]]:
    tools = {name: shutil.which(name) for name in ("flatpak", "rpm", "rpm2cpio", "cpio", "ar", "7z")}
    return {name: {"available": bool(path), "path": path} for name, path in tools.items()}
