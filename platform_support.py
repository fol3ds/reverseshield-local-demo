"""Cross-platform process and permission helpers for the workbench.

The workbench is developed on Fedora but is expected to run natively on
Windows for the team hand-off. Inputs are tool names, paths and analysis-tool
processes; outputs are platform-appropriate argv, process flags, tool paths and
permission behavior. These helpers launch analysis tools only, never selected
targets. Add OS differences here instead of scattering checks through analysis
code.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

IS_WINDOWS = os.name == "nt"


def which_tool(name: str, extra_dirs: tuple[Path, ...] = ()) -> str | None:
    """Find a tool on PATH or in a project-local tool directory."""
    candidates = [name]
    if IS_WINDOWS:
        candidates = [name + ".exe", name + ".bat", name + ".cmd", name]
    for directory in extra_dirs:
        for candidate in candidates:
            path = Path(directory) / candidate
            if path.is_file():
                return str(path)
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    return None


# cmd.exe re-parses its command line, so quoting by subprocess does not stop
# these characters from being interpreted (CVE-2024-3566 "BatBadBut" class).
CMD_METACHARACTERS = frozenset('&|<>^%!"\r\n')


def system_executable(name: str) -> str:
    """Absolute System32 path for a Windows system tool.

    A bare ``cmd.exe`` or ``taskkill`` is resolved by CreateProcess, which
    searches the current directory before System32 (CWE-427). Use the real
    system copy instead.
    """
    if not IS_WINDOWS:
        return name
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    candidate = Path(root) / "System32" / name
    return str(candidate) if candidate.is_file() else name


def command_for(path: str, *arguments: str) -> list[str]:
    """Build an argv list; batch files must go through cmd.exe on Windows.

    Arguments passed through cmd.exe are refused if they contain characters
    cmd.exe would interpret (for example a project folder named ``R&D``).
    """
    if IS_WINDOWS and path.lower().endswith((".bat", ".cmd")):
        unsafe = [value for value in (path, *map(str, arguments)) if CMD_METACHARACTERS & set(value)]
        if unsafe:
            raise ValueError("A path passed to a Windows batch launcher contains a character that cmd.exe would "
                             "interpret (& | < > ^ % ! or a quote). Move the project to a folder without these characters.")
        return [system_executable("cmd.exe"), "/d", "/c", path, *map(str, arguments)]
    return [path, *map(str, arguments)]


def popen_kwargs() -> dict:
    """Process-group flags that exist on the current platform."""
    if IS_WINDOWS:
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


def terminate_tree(process: subprocess.Popen, *, grace: float = 0.3) -> None:
    """Stop a tool and its children without requiring POSIX process groups."""
    if process.poll() is not None:
        return
    if IS_WINDOWS:
        try:
            subprocess.run(
                [system_executable("taskkill.exe"), "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            process.kill()
        except OSError:
            pass
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        process.terminate()
        return
    time.sleep(grace)
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass


def private_chmod(path: Path, mode: int = 0o600) -> None:
    """Apply POSIX private permissions; Windows ACLs are unchanged."""
    if IS_WINDOWS:
        return
    try:
        Path(path).chmod(mode)
    except OSError:
        pass


def open_flags(*, nonblock: bool = False) -> int:
    """Read-only flags without POSIX-only constants on Windows."""
    flags = os.O_RDONLY
    if nonblock:
        flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def file_identity(info: os.stat_result) -> tuple:
    """Stable-enough identity for snapshot race checks on both platforms."""
    inode = getattr(info, "st_ino", 0) or 0
    return (getattr(info, "st_dev", 0), inode, info.st_size, info.st_mtime_ns)


def local_tool_dirs(root: Path) -> list[Path]:
    """Project-local tool directories, in preference order."""
    dirs: list[Path] = []
    if IS_WINDOWS:
        dirs.extend([
            root / "tools" / "windows" / "w64devkit" / "bin",
            root / "tools" / "windows" / "mingw64" / "bin",
            root / "tools" / "windows" / "binutils" / "bin",
            root / "tools" / "jdk25" / "bin",
        ])
    else:
        dirs.extend([root / "tools" / "jdk25" / "bin"])
    return [path for path in dirs if path.is_dir()]
