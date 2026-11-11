"""Definitions and public metadata for six self-authored samples.

The first five support source-level protection profiles. The sixth is a
Linux-hardened build of the Level 5 policy engine, selectable for read-only
static analysis and binary hygiene but not recompilable via source profiles.
binaries are built from ``samples/src`` by ``build_samples.py``. Inputs are
sample IDs and definitions; outputs are static metadata and paths for analysis.
The binaries are never executed by the workbench or its tests. Add exercises
as source-only fixtures and update the public metadata here.
"""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE_ROOT = ROOT / "samples"
def sample_binary(slug: str) -> Path:
    """Return the native build when present, otherwise the bundled fixture."""
    windows_build = SAMPLE_ROOT / "bin" / f"{slug}.exe"
    if os.name == "nt" and windows_build.is_file():
        return windows_build
    return SAMPLE_ROOT / "bin" / f"{slug}.elf"


SAMPLES = [
    {
        "id": "level-1",
        "name": "Level 1 · Badge Math",
        "complexity": "Starter",
        "description": "One C file with a small arithmetic routine and a constant.",
        "topics": ["single function", "constant", "ELF header"],
        "sources": ["samples/src/level-1/main.c"],
        "binary": "samples/bin/level-1.exe" if os.name == "nt" and (SAMPLE_ROOT / "bin/level-1.exe").is_file() else "samples/bin/level-1.elf",
    },
    {
        "id": "level-2",
        "name": "Level 2 · Tiered Score",
        "complexity": "Basic",
        "description": "Helper functions, branches, a switch statement, and named constants.",
        "topics": ["functions", "branches", "switch", "strings"],
        "sources": ["samples/src/level-2/main.c"],
        "binary": "samples/bin/level-2.exe" if os.name == "nt" and (SAMPLE_ROOT / "bin/level-2.exe").is_file() else "samples/bin/level-2.elf",
    },
    {
        "id": "level-3",
        "name": "Level 3 · Lookup Transform",
        "complexity": "Intermediate",
        "description": "A local lookup table and loop-based byte transformation.",
        "topics": ["lookup table", "loop", "optimized build"],
        "sources": ["samples/src/level-3/main.c"],
        "binary": "samples/bin/level-3.exe" if os.name == "nt" and (SAMPLE_ROOT / "bin/level-3.exe").is_file() else "samples/bin/level-3.elf",
    },
    {
        "id": "level-4",
        "name": "Level 4 · Record Decoder",
        "complexity": "Advanced",
        "description": "A parser for a tiny in-memory record format and a checksum routine; no file or network I/O.",
        "topics": ["structs", "bounds checks", "parser", "checksum"],
        "sources": ["samples/src/level-4/main.c"],
        "binary": "samples/bin/level-4.exe" if os.name == "nt" and (SAMPLE_ROOT / "bin/level-4.exe").is_file() else "samples/bin/level-4.elf",
    },
    {
        "id": "level-5",
        "name": "Level 5 · Policy Engine",
        "complexity": "Multi-file",
        "description": "A small local policy example spread across multiple C translation units.",
        "topics": ["multiple files", "enums", "structs", "interprocedural symbols"],
        "sources": ["samples/src/level-5/main.c", "samples/src/level-5/rules.c", "samples/src/level-5/policy.h"],
        "binary": "samples/bin/level-5.exe" if os.name == "nt" and (SAMPLE_ROOT / "bin/level-5.exe").is_file() else "samples/bin/level-5.elf",
    },
    {
        "id": "level-5-hardened",
        "name": "Level 5 Hardened · Policy Engine",
        "complexity": "Mitigation comparison",
        "description": "Linux ELF build of the self-authored Level 5 policy, with PIE, full RELRO, stack canary, FORTIFY and non-executable stack. Analyze only; no source obfuscation on this fixture.",
        "topics": ["NX", "PIE", "RELRO", "canary", "FORTIFY"],
        "sources": ["samples/src/level-5-hardened/main.c", "samples/src/level-5/rules.c", "samples/src/level-5/policy.h"],
        "binary": "samples/bin/level-5-hardened.elf",
        "source_transform_supported": False,
    },
]


def public_sample(sample: dict) -> dict:
    binary = ROOT / sample["binary"]
    from analysis import detect_format
    detected_format = detect_format(binary.read_bytes()[:64]) if binary.is_file() else None
    return {
        **sample,
        "available": binary.is_file(),
        "size_bytes": binary.stat().st_size if binary.is_file() else None,
        "format": detected_format,
    }


def get_sample(sample_id: str) -> dict | None:
    return next((sample for sample in SAMPLES if sample["id"] == sample_id), None)
