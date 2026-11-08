"""Create the reproducible, tools-free Windows Day 1 source archive.

Inputs are the current repository tree and the fixed output filename; output is
``ReverseShield_Lite_Windows_Day1.zip`` plus a detached ``.sha256`` file in the
repository root, with a stable ``reverseshield-local-demo`` top-level directory
regardless of checkout name. Build tools, run evidence, backups, VCS metadata
and Python caches are excluded. The script
only reads source files and writes the archive; it never opens or executes a
selected analysis target. Add exclusion rules here when new local-only data
directories are introduced.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "ReverseShield_Lite_Windows_Day1.zip"
CHECKSUM_OUTPUT = ROOT / "ReverseShield_Lite_Windows_Day1.zip.sha256"
ARCHIVE_ROOT_NAME = "reverseshield-local-demo"
EXCLUDED_DIRECTORIES = {"tools", "runs", "backups", ".git", "__pycache__"}
EXCLUDED_FILES = {
    "docs/handoff/day1.md",
    "docs/reverseshield_3-day_execution_plan.docx",
    "docs/reverseshield_3-day_execution_plan.pdf",
    "docs/reverseshield_project_report_and_plan.docx",
    "docs/reverseshield_project_report_and_plan.pdf",
}


def source_files():
    """Yield regular repository files while pruning local-only directories."""
    for directory, names, filenames in os.walk(ROOT, topdown=True, followlinks=False):
        names[:] = [name for name in names
                    if name.casefold() not in EXCLUDED_DIRECTORIES
                    and not (Path(directory) / name).is_symlink()]
        for filename in filenames:
            path = Path(directory) / filename
            relative = path.relative_to(ROOT).as_posix().casefold()
            if (
                path.resolve() in {OUTPUT.resolve(), CHECKSUM_OUTPUT.resolve()}
                or path.is_symlink()
                or relative in EXCLUDED_FILES
            ):
                continue
            yield path


def sha256(path: Path) -> str:
    """Return a streaming SHA-256 digest for the completed archive."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    """Write the archive and print its reproducibility metrics."""
    with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as archive:
        for path in sorted(source_files()):
            relative = path.relative_to(ROOT)
            info = zipfile.ZipInfo(
                (Path(ARCHIVE_ROOT_NAME) / relative).as_posix(),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=6,
            )
    print(f"Output: {OUTPUT.name}")
    print(f"Size: {OUTPUT.stat().st_size} bytes")
    checksum = sha256(OUTPUT)
    CHECKSUM_OUTPUT.write_text(f"{checksum}  {OUTPUT.name}\n", encoding="ascii")
    print(f"SHA-256: {checksum}")
    print(f"Checksum file: {CHECKSUM_OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
