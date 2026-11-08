"""Bounded, data-only RPM ingestion.

rpm2cpio v6 is explicitly asked for uncompressed newc, not its default PAX
format. Preflight the entire archive before creating payload files. All limits
apply before payload writes; the private conversion spool is separately capped.

Inputs are RPM bytes and a caller-owned workspace; outputs are extracted
payload paths and dependency metadata. Nothing is installed, passed to a shell,
or executed. Extend supported payload members only with equivalent path,
size, count and link validation. This adapter is Linux-only.
"""
from __future__ import annotations

import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import BinaryIO

MAX_RPM_BYTES = 256 * 1024 * 1024
MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_PAYLOAD_BYTES + 64 * 1024 * 1024
MAX_MEMBERS = 50_000
COMMAND_TIMEOUT = 20


def _run_bounded(args: list[str], output: BinaryIO, *, limit: int,
                 timeout: float | None = None) -> None:
    """Drain both pipes, enforcing wall time and output caps, including stderr."""
    deadline = time.monotonic() + (COMMAND_TIMEOUT if timeout is None else timeout)
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env={**os.environ, "LC_ALL": "C"})
    except FileNotFoundError as exc:
        raise RuntimeError(f"Required local tool is unavailable: {args[0]}") from exc
    stderr = bytearray()
    count = 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            selector.register(process.stderr, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(f"{args[0]} timed out reading RPM data.")
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif key.fileobj is process.stdout:
                        count += len(chunk)
                        if count > limit:
                            raise ValueError("RPM command output exceeds the safety limit.")
                        output.write(chunk)
                    else:
                        stderr.extend(chunk)
                        if len(stderr) > 65536:
                            raise ValueError("RPM command stderr exceeds the safety limit.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(f"{args[0]} timed out reading RPM data.")
            try:
                status = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"{args[0]} timed out reading RPM data.") from exc
            if status:
                detail = stderr.decode("utf-8", errors="replace").strip()[:500]
                raise RuntimeError(detail or f"{args[0]} failed with exit code {status}.")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        process.stderr.close()
    output.seek(0)


def _plan_newc(archive: BinaryIO) -> list[tuple[str, bool, int, int]]:
    """Return validated (path, directory, data-offset, size) records; never write."""
    archive.seek(0, os.SEEK_END)
    archive_size = archive.tell()
    archive.seek(0)
    plan = []
    seen: dict[str, bool] = {}
    required_directories: set[str] = set()
    nodes: set[str] = set()
    total = 0
    while True:
        header = archive.read(110)
        if len(header) != 110 or header[:6] != b"070701":
            raise ValueError("Invalid or truncated RPM newc archive.")
        try:
            raw_fields = [header[index:index + 8] for index in range(6, 110, 8)]
            if any(not re.fullmatch(rb"[0-9A-Fa-f]{8}", field) for field in raw_fields):
                raise ValueError("non-hex")
            fields = [int(field, 16) for field in raw_fields]
        except (ValueError, TypeError) as exc:
            raise ValueError("Invalid RPM archive header.") from exc
        mode, links, size, name_size = fields[1], fields[4], fields[6], fields[11]
        if not 1 < name_size <= 4096:
            raise ValueError("Invalid RPM archive member name length.")
        raw_name = archive.read(name_size)
        if len(raw_name) != name_size or raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
            raise ValueError("Invalid RPM archive member name.")
        try:
            name = raw_name[:-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("RPM archive member names must be UTF-8.") from exc
        archive.seek((-archive.tell()) % 4, os.SEEK_CUR)
        offset = archive.tell()
        if name == "TRAILER!!!":
            if size:
                raise ValueError("Invalid RPM archive trailer.")
            while padding := archive.read(65536):
                if padding.strip(b"\0"):
                    raise ValueError("Unexpected data after RPM archive trailer.")
            return plan
        if len(plan) >= MAX_MEMBERS:
            raise ValueError("RPM archive exceeds the member-count safety limit.")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts:
            raise ValueError("Unsafe RPM archive member path.")
        name = path.as_posix()
        directory = stat.S_ISDIR(mode)
        if not (directory or stat.S_ISREG(mode)) or (not directory and links != 1):
            raise ValueError("RPM links and special nodes are not supported.")
        if directory and size:
            raise ValueError("RPM directory has unexpected data.")
        if name in seen:
            raise ValueError("Duplicate RPM archive member path.")
        if not directory and name in required_directories:
            raise ValueError("RPM archive file/directory path conflict.")
        for parent in path.parents:
            if parent.as_posix() in seen and not seen[parent.as_posix()]:
                raise ValueError("RPM archive file/directory path conflict.")
            required_directories.add(parent.as_posix())
            if parent.parts:
                nodes.add(parent.as_posix())
        nodes.add(name)
        if len(nodes) > MAX_MEMBERS:
            raise ValueError("RPM archive exceeds the member-count safety limit (including directories).")
        seen[name] = directory
        total += size
        if total > MAX_PAYLOAD_BYTES:
            raise ValueError("RPM payload exceeds the extracted-byte safety limit.")
        if offset + size > archive_size:
            raise ValueError("Truncated RPM archive member data.")
        plan.append((name, directory, offset, size))
        archive.seek(offset + size + (-size) % 4)


def _extract_newc(archive: BinaryIO, payload: Path) -> None:
    plan = _plan_newc(archive)
    payload.mkdir(mode=0o700)
    for name, directory, offset, size in plan:
        destination = payload / name
        if directory:
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            archive.seek(offset)
            remaining = size
            while remaining:
                chunk = archive.read(min(remaining, 65536))
                if not chunk:
                    raise ValueError("Truncated RPM archive member data.")
                output.write(chunk)
                remaining -= len(chunk)


def ingest_rpm(source: Path, *, workspace: Path) -> dict[str, object]:
    source_fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(source_fd, "rb") as original:
        metadata = os.fstat(original.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RPM_BYTES:
            raise ValueError("RPM input must be a regular file no larger than 256 MiB.")
        if original.read(4) != b"\xed\xab\xee\xdb":
            raise ValueError("Selected file does not have RPM magic.")
        original.seek(0)
        workspace = Path(workspace).resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix="rpm-", dir=workspace))
        try:
            snapshot = stage / "source.rpm"
            with snapshot.open("xb") as output:
                copied = 0
                while chunk := original.read(65536):
                    copied += len(chunk)
                    if copied > MAX_RPM_BYTES:
                        raise ValueError("RPM input exceeds the 256 MiB safety limit.")
                    output.write(chunk)
            with tempfile.TemporaryFile(dir=stage) as archive:
                _run_bounded(["rpm2cpio", "-n", "-f", "cpio", str(snapshot)], archive,
                             limit=MAX_ARCHIVE_BYTES)
                _extract_newc(archive, stage / "payload")
            with tempfile.TemporaryFile(dir=stage) as metadata_output:
                _run_bounded(["rpm", "-qp", "--requires", str(snapshot)], metadata_output,
                             limit=1024 * 1024)
                dependencies = sorted(set(metadata_output.read().decode("utf-8", errors="replace").splitlines()))
            snapshot.unlink()
            return {"payload_root": str(stage / "payload"), "dependencies": dependencies}
        except BaseException:
            shutil.rmtree(stage)
            raise
