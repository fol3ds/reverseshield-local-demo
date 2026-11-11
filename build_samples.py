"""Compile bundled self-authored C sources into native ELF or PE fixtures.

Compilation is a build step; the resulting samples are not executed. The
source profiles transform copies of these sources and rebuild them. Inputs are
the sources under ``samples/src`` and a compiler; outputs are ``samples/bin``
artifacts. Compilation is allowed, but targets are never launched. Extend the
source list here and keep the compile-only boundary.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
from platform_support import local_tool_dirs, which_tool

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "samples" / "src"
OUT = ROOT / "samples" / "bin"
# Keep useful project-relative DWARF and __FILE__ metadata, not builder paths.
# Compile from ROOT so DW_AT_comp_dir is mapped to the same stable ".".
PREFIX_MAP_FLAGS = [f"-ffile-prefix-map={ROOT}=.", f"-fdebug-prefix-map={ROOT}=."]
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-g"]

SPECS = [
    ("level-1", "single-function arithmetic", ["-O0"], [SRC / "level-1" / "main.c"]),
    ("level-2", "helpers, branches, switch and constants", ["-O1"], [SRC / "level-2" / "main.c"]),
    ("level-3", "lookup table and loop-based transform", ["-O2"], [SRC / "level-3" / "main.c"]),
    ("level-4", "record parsing and checksum logic", ["-O0", "-fno-inline"], [SRC / "level-4" / "main.c"]),
    ("level-5", "multi-file policy engine", ["-O1"], [SRC / "level-5" / "main.c", SRC / "level-5" / "rules.c"]),
]


HARDENED_FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-O2", "-g0",
                  "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-fPIE", "-pie",
                  "-Wl,-z,relro,-z,now"]


def build_hardened_sample(output_dir: Path = OUT) -> Path:
    """Compile the Linux-only Level 5 mitigation comparison, never execute it."""
    if os.name == "nt":
        raise RuntimeError("The hardened Level 5 build needs Linux ELF linker flags; use the bundled ELF fixture for static analysis.")
    from hardening import analyze_hardening

    compiler = which_tool("gcc", tuple(local_tool_dirs(ROOT))) or which_tool("clang", tuple(local_tool_dirs(ROOT)))
    if not compiler:
        raise RuntimeError("A C compiler is required to build the hardened sample.")
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / "level-5-hardened.elf"
    command = [compiler, *HARDENED_FLAGS, *PREFIX_MAP_FLAGS, "-I", str(SRC / "level-5"),
               str(SRC / "level-5-hardened/main.c"), str(SRC / "level-5/rules.c"), "-o", str(output.resolve())]
    subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True, timeout=30)
    output.chmod(0o600)
    observed = analyze_hardening(output)
    unexpected = {
        name: observed.get("checks", {}).get(name, {}).get("state", "unknown")
        for name in ("nx", "pie", "relro", "canary", "fortify")
        if observed.get("checks", {}).get(name, {}).get("state") != "present"
    }
    if unexpected or observed.get("errors") or observed.get("input_truncated") or observed.get("format") != "ELF":
        raise RuntimeError(f"Hardened Level 5 static validation failed: {unexpected}; errors={observed.get('errors', [])}")
    return output


def main() -> int:
    compiler = which_tool("gcc", tuple(local_tool_dirs(ROOT))) or which_tool("clang", tuple(local_tool_dirs(ROOT)))
    if not compiler:
        print("Build requires gcc or clang; no compiler was found.", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    for slug, description, optimization, source_files in SPECS:
        suffix = ".exe" if os.name == "nt" else ".elf"
        output = OUT / f"{slug}{suffix}"
        command = [compiler, *FLAGS, *optimization, *PREFIX_MAP_FLAGS,
                   "-I", str(SRC / "level-5"), *map(str, source_files), "-o", str(output)]
        print(f"Building {slug}: {description}")
        try:
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True, timeout=30)
        except subprocess.CalledProcessError as exc:
            if exc.stderr:
                print(exc.stderr, file=sys.stderr)
            return exc.returncode or 1
        if os.name != "nt":
            output.chmod(0o600)
        print(f"  created {output.relative_to(ROOT)} ({output.stat().st_size} bytes); binary was not executed")
    if os.name != "nt":
        try:
            hardened = build_hardened_sample()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as exc:
            print(f"Hardened Level 5 build failed: {exc}", file=sys.stderr)
            return 1
        print(f"  created {hardened.relative_to(ROOT)} ({hardened.stat().st_size} bytes); binary was not executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
