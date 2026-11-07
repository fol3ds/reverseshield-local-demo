"""Compile the bundled sample sources into ELF files.

Compilation is a build step; the resulting samples are not executed. The
source profiles transform copies of these sources and rebuild them.
"""
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "samples" / "src"
OUT = ROOT / "samples" / "bin"
FLAGS = ["-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-g"]

SPECS = [
    ("level-1", "single-function arithmetic", ["-O0"], [SRC / "level-1" / "main.c"]),
    ("level-2", "helpers, branches, switch and constants", ["-O1"], [SRC / "level-2" / "main.c"]),
    ("level-3", "lookup table and loop-based transform", ["-O2"], [SRC / "level-3" / "main.c"]),
    ("level-4", "record parsing and checksum logic", ["-O0", "-fno-inline"], [SRC / "level-4" / "main.c"]),
    ("level-5", "multi-file policy engine", ["-O1"], [SRC / "level-5" / "main.c", SRC / "level-5" / "rules.c"]),
]


def main() -> int:
    compiler = shutil.which("gcc") or shutil.which("clang")
    if not compiler:
        print("Build requires gcc or clang; no compiler was found.", file=sys.stderr)
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    for slug, description, optimization, source_files in SPECS:
        output = OUT / f"{slug}.elf"
        command = [compiler, *FLAGS, *optimization, "-I", str(SRC / "level-5"), *map(str, source_files), "-o", str(output)]
        print(f"Building {slug}: {description}")
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
        except subprocess.CalledProcessError as exc:
            if exc.stderr:
                print(exc.stderr, file=sys.stderr)
            return exc.returncode or 1
        print(f"  created {output.relative_to(ROOT)} ({output.stat().st_size} bytes); binary was not executed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
