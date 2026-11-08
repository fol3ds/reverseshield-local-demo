"""Binary-only metadata hygiene for a copy of any selected ELF or PE file.

Inputs are a validated ELF/PE source and run-local destination; outputs are a
metadata-reduced copy, hashes and command records. This is deliberately *not*
code obfuscation and not a binary rewriter. It removes non-essential metadata
from a copy:

* static symbol table and debug information (``strip --strip-all``);
* compiler/annobin comments and the GNU build-id note (``objcopy``);
* PE debug/PDB sections when present.

The source file is never modified. Nothing here executes the target. Extend
only with copy-based metadata edits and explicit format/tool capability checks.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from analysis import has_elf_magic, has_pe_magic, parse_pe_header

MAX_FILE_BYTES = 64 * 1024 * 1024
ROOT = Path(__file__).resolve().parent


def _tool(name: str) -> str:
    from platform_support import local_tool_dirs, which_tool
    path = which_tool(name, tuple(local_tool_dirs(ROOT)))
    if not path:
        raise RuntimeError(f"{name} is unavailable; binary hygiene cannot run.")
    return path


def _run(command: list[str], timeout: int = 60) -> dict:
    result = subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=timeout, check=False,
        shell=False, env={**os.environ, "LC_ALL": "C"},
    )
    return {
        "command": command,
        "return_code": result.returncode,
        "output": (result.stdout or "").strip()[:2000],
    }


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_binary_hygiene(source: str | Path, destination: str | Path) -> dict:
    """Create a stripped, metadata-reduced copy of one ELF.

    Returns a record suitable for the job report. Raises on invalid input or
    tool failure; the original file is never touched.
    """
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise ValueError("Select a regular ELF/PE file for binary hygiene.")
    if source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Binary hygiene is limited to ELF/PE files up to 64 MiB.")
    with source.open("rb") as stream:
        header = stream.read(64)
    file_format = "ELF" if has_elf_magic(header) else "PE" if has_pe_magic(header) else None
    if file_format is None:
        raise ValueError("Binary hygiene supports ELF and PE files only.")
    section_names = []
    if file_format == "PE":
        try:
            section_names = list(parse_pe_header(source).get("section_names", []))
        except ValueError:
            section_names = []

    strip = _tool("strip")
    objcopy = _tool("objcopy")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = destination / ("binary-hygiene.exe" if file_format == "PE" else "binary-hygiene.elf")
    if output.exists():
        output.unlink()

    before_sha = _sha256(source)
    before_size = source.stat().st_size
    shutil.copyfile(source, output)
    output.chmod(0o600)

    commands: list[dict] = []
    try:
        record = _run([strip, "--strip-all", str(output)])
        commands.append(record)
        if record["return_code"] != 0:
            raise RuntimeError("strip failed: " + (record["output"] or "no output"))

        removable = [".comment", ".annobin.notes", ".gnu.build.attributes",
                     ".note.gnu.build-id"]
        if file_format == "PE":
            removable += [name for name in section_names
                          if name.lower().startswith((".debug", ".pdb"))]
        objcopy_args = [objcopy]
        for section in dict.fromkeys(removable):
            objcopy_args.append(f"--remove-section={section}")
        objcopy_args.append(str(output))
        record = _run(objcopy_args)
        commands.append(record)
        if record["return_code"] != 0:
            raise RuntimeError("objcopy failed: " + (record["output"] or "no output"))
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        # Tools can create temporary siblings; keep only the final artifact.
        for sibling in destination.glob("binary-hygiene.elf.*"):
            if sibling.is_file():
                sibling.unlink(missing_ok=True)

    output.chmod(0o600)
    after_sha = _sha256(output)
    return {
        "path": str(output),
        "sha256": after_sha,
        "before_sha256": before_sha,
        "before_size": before_size,
        "after_size": output.stat().st_size,
        "format": file_format,
        "strip_version": _version(strip),
        "objcopy_version": _version(objcopy),
        "commands": commands,
        "method": "strip --strip-all + objcopy non-alloc metadata removal",
        "strength": "metadata_only",
        "obfuscation": False,
        "behavior_verified": False,
        "removed_sections": list(dict.fromkeys(removable)),
    }


def _version(tool: str) -> str:
    try:
        result = subprocess.run([tool, "--version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=5, check=False, env={**os.environ, "LC_ALL": "C"})
        return (result.stdout or "").splitlines()[0][:200]
    except (OSError, subprocess.TimeoutExpired):
        return "Version unavailable"
