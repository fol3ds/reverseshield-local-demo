"""Create a reviewed local Windows Lite candidate from the Git index.

Only indexed source files enter the archive; generated video, raw scanner
outputs, tools, runs and private workspace data are excluded. This script
never launches a selected analysis target or publishes the resulting ZIP.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "dist" / "ReverseShield_Lite_Windows_v0.5.0-team.zip"
CHECKSUM_OUTPUT = ROOT / "dist" / "SHA256SUMS.txt"
ARCHIVE_ROOT_NAME = "reverseshield-local-demo"
EXCLUDED_DIRECTORIES = {"tools", "runs", "backups", ".git", "__pycache__", ".scratch-ollvm"}
EXCLUDED_PREFIXES = {("docs", "security"), ("docs", "assets"),
                     ("docs", "handoff"), ("docs", "event"),
                     ("docs", "document-review"), ("docs", "demo", "frames")}
EXCLUDED_FILES = {
    "docs/handoff/day1.md",
    "docs/reverseshield_3-day_execution_plan.docx",
    "docs/reverseshield_3-day_execution_plan.pdf",
    "docs/reverseshield_project_report_and_plan.docx",
    "docs/reverseshield_project_report_and_plan.pdf",
}
# The source ZIP is not a dump of project-internal notes, scanner output,
# historical screenshots, or the local video draft.
ALLOWED_DOCS = {
    "docs/ai_context.md", "docs/build_plan.py", "docs/build_report.py",
    "docs/build_day4_documents.py", "docs/docx_helpers.py", "docs/finalize_tocs.py",
    "docs/release_checklist.md",
    "docs/roadmap.md", "docs/evidence/hardening-level5.json",
    "docs/evidence/ollvm-five-qemu.json", "docs/evidence/verification.json",
    "docs/evidence/security-day4.json", "docs/evidence/security_review_day4.md",
    "docs/evidence/acceptance_matrix_day4.md",
    "docs/evidence/claim_evidence_day4.md",
}


def source_files(root: Path = ROOT):
    """Yield reviewed index files only; a dirty workspace is not an archive."""
    root = Path(root).resolve()
    indexed = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "-z"],
                             check=True, capture_output=True, timeout=30).stdout
    for raw in indexed.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = root / relative
        parts = {part.casefold() for part in relative.parts[:-1]}
        lowered = tuple(part.casefold() for part in relative.parts)
        if (parts & EXCLUDED_DIRECTORIES
                or any(lowered[:len(prefix)] == prefix for prefix in EXCLUDED_PREFIXES)
                or relative.as_posix().casefold() in EXCLUDED_FILES
                or (lowered[0] == "docs" and
                    relative.as_posix().casefold() not in ALLOWED_DOCS)
                or relative.suffix.casefold() in {".zip", ".sha256", ".pdf", ".docx", ".log", ".mp4"}
                or path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(root)):
            continue
        yield path


def sha256(path: Path) -> str:
    """Return a streaming SHA-256 digest for the completed archive."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(*, root: Path = ROOT, output: Path = OUTPUT,
         checksum_output: Path = CHECKSUM_OUTPUT) -> int:
    """Write a deterministic, local-only ZIP and detached SHA-256 line."""
    root, output, checksum_output = Path(root).resolve(), Path(output), Path(checksum_output)
    selected = sorted(source_files(root))
    unstaged = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", "-z", "--"],
        check=True, capture_output=True, timeout=30,
    ).stdout
    dirty = {os.fsdecode(item) for item in unstaged.split(b"\0") if item}
    if dirty & {path.relative_to(root).as_posix() for path in selected}:
        raise RuntimeError("unstaged changes to indexed archive source; review and stage first")
    output.parent.mkdir(parents=True, exist_ok=True)
    checksum_output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=6) as archive:
        for path in selected:
            relative = path.relative_to(root)
            info = zipfile.ZipInfo(
                (Path(ARCHIVE_ROOT_NAME) / relative).as_posix(),
                date_time=(1980, 1, 1, 0, 0, 0),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            mode = 0o755 if relative.suffix == '.sh' else (
                0o600 if relative.suffix.casefold() in {'.elf', '.exe'} else 0o644)
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(
                info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=6,
            )
    print(f"Output: {output.name}")
    print(f"Size: {output.stat().st_size} bytes")
    checksum = sha256(output)
    checksum_output.write_text(f"{checksum}  {output.name}\n", encoding="ascii")
    print(f"SHA-256: {checksum}")
    print(f"Checksum file: {checksum_output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
