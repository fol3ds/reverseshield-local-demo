"""Definitions for the five bundled, self-authored analysis samples.

These are the only targets for the source-level protection profiles. The
binaries are built from ``samples/src`` by ``build_samples.py`` and are never
executed by the workbench or its tests.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLE_ROOT = ROOT / "samples"
SAMPLES = [
    {
        "id": "level-1",
        "name": "Level 1 · Badge Math",
        "complexity": "Starter",
        "description": "One C file with a small arithmetic routine and a constant.",
        "topics": ["single function", "constant", "ELF header"],
        "sources": ["samples/src/level-1/main.c"],
        "binary": "samples/bin/level-1.elf",
    },
    {
        "id": "level-2",
        "name": "Level 2 · Tiered Score",
        "complexity": "Basic",
        "description": "Helper functions, branches, a switch statement, and named constants.",
        "topics": ["functions", "branches", "switch", "strings"],
        "sources": ["samples/src/level-2/main.c"],
        "binary": "samples/bin/level-2.elf",
    },
    {
        "id": "level-3",
        "name": "Level 3 · Lookup Transform",
        "complexity": "Intermediate",
        "description": "A local lookup table and loop-based byte transformation.",
        "topics": ["lookup table", "loop", "optimized build"],
        "sources": ["samples/src/level-3/main.c"],
        "binary": "samples/bin/level-3.elf",
    },
    {
        "id": "level-4",
        "name": "Level 4 · Record Decoder",
        "complexity": "Advanced",
        "description": "A parser for a tiny in-memory record format and a checksum routine; no file or network I/O.",
        "topics": ["structs", "bounds checks", "parser", "checksum"],
        "sources": ["samples/src/level-4/main.c"],
        "binary": "samples/bin/level-4.elf",
    },
    {
        "id": "level-5",
        "name": "Level 5 · Policy Engine",
        "complexity": "Multi-file",
        "description": "A small local policy example spread across multiple C translation units.",
        "topics": ["multiple files", "enums", "structs", "interprocedural symbols"],
        "sources": ["samples/src/level-5/main.c", "samples/src/level-5/rules.c", "samples/src/level-5/policy.h"],
        "binary": "samples/bin/level-5.elf",
    },
]


def public_sample(sample: dict) -> dict:
    binary = ROOT / sample["binary"]
    return {
        **sample,
        "available": binary.is_file(),
        "size_bytes": binary.stat().st_size if binary.is_file() else None,
    }


def get_sample(sample_id: str) -> dict | None:
    return next((sample for sample in SAMPLES if sample["id"] == sample_id), None)
