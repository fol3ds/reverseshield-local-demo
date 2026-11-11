# ReverseShield — Roadmap

Items here are **not fully built yet**. Do not demo or claim unbuilt parts as
features. R1 now has a partial implementation (`hardening.py`); the advanced
checks below remain planned. Status as of 11 November 2026 (Day 4).

## Next (after the event submission)

### R1 — Hardening checks (exploit-mitigation flags) — partially implemented

Implemented: ELF NX/DEP, PIE/ASLR, RELRO, canary and FORTIFY; PE ASLR/DEP,
Control Flow Guard and bounded security-cookie evidence. The report shows
Present / Absent / Partial / Unknown / Not applicable, never a score.

Still planned: CET/IBT, Authenticode, RPATH/RUNPATH, and before/after rows in
the Compare view.

Static checks, from the file bytes only, for whether standard exploit
protections were enabled at build time. Each result names the weakness class
the protection reduces and the build flag that turns it on.

| Check | ELF (Linux) | PE (Windows) | Reduces exploitation of | Fix |
|---|---|---|---|---|
| Address randomisation | PIE: `ET_DYN` + `DF_1_PIE` | ASLR: `DYNAMICBASE`, `HIGH_ENTROPY_VA` | CWE-119 memory-safety bugs | `-fPIE -pie` · `/DYNAMICBASE` or `-Wl,--dynamicbase,--high-entropy-va` |
| Non-executable data | NX: `PT_GNU_STACK` not `X` | DEP: `NX_COMPAT` | CWE-119 / code injection | default in modern toolchains · `/NXCOMPAT` or `-Wl,--nxcompat` |
| Read-only relocations | RELRO: `PT_GNU_RELRO` + `BIND_NOW` (full) | — | GOT overwrite after CWE-787 | `-Wl,-z,relro,-z,now` |
| Stack canary | imports `__stack_chk_fail` | imports `__security_check_cookie` / `/GS` | CWE-121 stack buffer overflow | `-fstack-protector-strong` · `/GS` |
| Fortified libc calls | `*_chk` imports | — | CWE-120 / CWE-787 | `-O2 -D_FORTIFY_SOURCE=3` |
| Control-flow guard | CET/IBT notes (`.note.gnu.property`) | `GUARD_CF` | CWE-119 control-flow hijack | `-fcf-protection` · `/guard:cf` |
| Signed binary | — | Authenticode security directory present | tampering (CWE-494) | sign releases |
| Library search path | `RPATH`/`RUNPATH` with `.` or relative paths | — | CWE-427 | remove relative RPATH |

Rules:

- Report **"protection absent"**, never "vulnerable". A missing flag is not a
  vulnerability by itself.
- Show `N/A` when a check does not apply to the format.
- Add before/after rows to the comparison, and unit tests with built samples
  (with and without each flag).

Estimate: 1–2 days. It reuses the `metrics.py` ELF/PE readers.

### R2 — Known-vulnerable component lookup (CVE matching)

Find embedded third-party libraries and versions, then look them up in an
**offline** vulnerability database snapshot. Examples are version strings
such as `OpenSSL 1.0.2k`, `zlib 1.2.11`, `libpng`, `curl` and `SQLite`.

- Candidate adapters (do not reinvent): Intel `cve-bin-tool`, or Anchore
  `syft` (component list / SBOM) plus `grype` (CVE matching). They would run
  as static adapters like the existing ones.
- Show each match as **"possible match — verify"** with the evidence string
  and the database date. Never call it a confirmed vulnerability.
- Risks: false positives from version strings, database size and updates,
  and the licence of the data feed. All of these must be shown in the
  limitations list.

Estimate: 2–4 days, plus an update process for the database.

## Later

- CI integration: run on every build and fail on chosen exposure thresholds.
- More formats: Mach-O, APK, DEB.
- Sanitized evidence packs: Day 4 has a local allowlist-based builder and
  draft summaries; actual PDF review, archive verification and publication
  remain separate gates. Do not bundle raw `runs/` data.
- Sandboxed adapters: separate user or container, memory limits (RS-06).
- Token on every API read; token passed in the URL fragment (RS-05).
- A stronger protection profile with broader behaviour verification. The current
  OLLVM workflow records `driver_vectors_matched` only for separate QEMU driver
  builds; `behavior_verified` stays false for the downloadable protected ELF.
  External targets remain analysis-only for source transformations.
