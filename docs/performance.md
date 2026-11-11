# Day 3 performance and limits

Measured 11 November 2026 on Windows 11 AMD64, 16 logical CPUs, Python 3.12.14,
Ghidra 12.2 and the installed MinGW static tools. Single observations, not
statistical benchmarks; setup/download time excluded. The target never runs.

| Input | Ghidra | Wall seconds | Raw report bytes | Truncation |
|---|---|---:|---:|---|
| Level 5 ELF | No | 0.417 | 41,927 | None |
| Level 5 ELF | Yes | 22.017 | 76,515 | None |
| PE fixture | No | 0.503 | 7,941 | None |
| PE fixture | Yes | 24.490 | 24,801 | None |

Lightweight tools available: readelf, objdump, strings, nm. `file` was unavailable.
readelf is explicitly skipped for PE. All other selected tools succeeded.
Machine-readable per-tool timing/status/output sizes: `performance-day3.json`.
Raw report size includes local evidence; it is not the size of the shareable export.

Large real Linux target / EasyEffects: not available here. Faisal must run the
same matrix on Fedora with and without Ghidra, recording target hash/size,
elapsed time, report bytes and every truncation flag. No substituted or invented
large-application timing is claimed. The synthetic >8 MiB guard test passes.

## Verified bounds

64 MiB per ELF/PE target; 256 MiB package upload; 1 MiB captured tool output;
16 targets per job; 32 jobs/session; 4 queued/running jobs; 64 selections;
50,000 discovery entries. Ghidra warning above 8 MiB, default 240 s timeout,
60–1800 s configurable range and default 2 CPUs. UI offers lightweight-only
analysis. Timeout/cancellation probes verify process-tree cleanup on Windows.
Ghidra export caps include 1,000 functions, 40 decompiled functions and a
bounded decompilation budget. Missing/truncated coverage remains visible.

These limits do not constitute a cumulative disk quota. Old run directories
persist across restarts; Ghidra temporary database growth is not governed by an
OS quota. Monitor disk space and remove unwanted evidence with the server stopped.
Do not claim that disk exhaustion is impossible. Stronger storage quotas and
parser process isolation remain hardening work.

The local MinGW distribution failed compilation from a path containing spaces.
Testing used a copy in a path without spaces; this agrees with the existing
setup recommendation. Keep the release/demo folder path free of spaces until
that third-party toolchain limitation is resolved.
