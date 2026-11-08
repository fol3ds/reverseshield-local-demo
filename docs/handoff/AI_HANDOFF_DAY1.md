# Day 1 — AI Handoff for the Next Teammate

This file gives a teammate and their AI agent the verified Day 1 project context,
what changed, how to reproduce the checks, and what to do next. Read it together
with `docs/AI_CONTEXT.md` and `docs/TEAM_TASKS_DAY1-4.md`.

## Repository state

- Repository: `fol3ds/reverseshield-local-demo`
- Day 1 branch: `Day-1---Nasser`
- Day 1 base commit: `6ceb1f2`
- Day 1 implementation tip before this AI handoff: `4214ca7` (`Complete Day 1 handoff and sanitize report PDFs`)
- Day 1 branch is pushed. It has not been merged into `main`; start Day 2 only
  from the owner-approved base. The Day 1 work did not open a pull request.
- No selected target, sample, or transformed executable was launched.

## Project purpose and safety invariants

ReverseShield is a local, static-only inspection workbench for ELF and PE files.
It discovers targets, reads file bytes, invokes bounded static tools, and writes
reports under `runs/`. Dynamic analysis is disabled. The application and its
tests must never execute a selected binary, bundled sample, or transformed
artifact. Do not describe the demonstration transformations as protection or
behavior-preserving obfuscation.

Tests should use inert fixtures, fake processes, or static analyzers. Keep
subprocess calls argument-based and bounded. Do not commit `tools/`, `runs/`,
`backups/`, `.env`, credentials, private identity data, or user-specific paths.

## Day 1 work completed

### Windows setup and first run

- Updated `setup.bat` / `scripts/setup_windows.ps1` to select an accessible
  Python 3.11+ interpreter and report missing optional dependencies.
- Updated `run.bat` to fall back to a manual loopback URL if browser launch fails.
- Ran setup without Administrator rights and started the workbench.
- Completed the bundled Level 5 static analysis through Ghidra: 13 functions,
  10 pseudocode bodies, and 6 call edges.

### PE support and Windows discovery

- PE identification uses file signatures. The API upload path accepts the PE
  fixture and labels it `PE`.
- Windows directory scanning accepts `.exe` and `.dll`, parses PE headers, and
  respects scan limits.
- Tested a copied Windows Notepad executable as data only. It was detected as
  PE32+ x86-64 with 8 sections and an entry point; `objdump` inspection and the
  report hash matched the input.
- `readelf` is skipped for PE/COFF. No PE upload `WinError`, `FileNotFoundError`,
  or “not ELF” rejection was observed. Reports state that targets were never
  executed.

### Tests and documentation

- Added PE upload/report, Windows walker, malformed-header, and missing-tool
  coverage. Linux-only API, Flatpak, POSIX permission, and related assumptions
  are skipped with reasons when unavailable on Windows.
- Added Windows/Fedora GitHub Actions workflow configuration.
- Added Python module docstrings, C sample headers, a JavaScript structural
  section map, and the `never use innerHTML` rule.
- Updated `docs/AI_CONTEXT.md`, `README.md`, and the Windows startup guidance.

### Handoff, event draft, and packages

- `docs/handoff/DAY1.md` contains task status, counts, limitations, safe
  fallbacks, ZIP metrics, and Zayed’s first three actions.
- `docs/handoff/EVENT_DRAFT_DAY1.md` contains placeholder answers and supporting
  file references; it contains no sensitive identity or contact information.
  The actual discovery source and final team participation details remain for
  the owner to fill in privately.
- `scripts/package_lite_windows.py` creates the reproducible Lite source ZIP and
  checksum. Its current size, digest, entry count and exclusions are recorded
  in `docs/handoff/DAY1.md`; two builds had identical hashes. It excludes
  `tools/`, `runs/`, `backups/`, `.git/`, Python caches, and generated reports.
- A complete committed-tree snapshot was prepared under ignored
  `runs/full-project-share/`. Regenerate it after adding this handoff if it will
  be shared; it contains no Git history or local tool/run data.

## Test evidence

On the Day 1 Windows tool-equipped environment:

```bat
python -m unittest discover -s tests -v
```

Result: **65 tests, 48 passed, 17 skipped, 0 failed**. Skips were 8 legacy
ELF/Flatpak API cases, 5 Flatpak-only cases, 2 POSIX symlink/permission cases,
1 opt-in Ghidra test, and 1 RPM integration test requiring Linux package tools.

The Ghidra opt-in run:

```bat
set RUN_GHIDRA_TESTS=1
python -m unittest tests.test_engine -v
```

Result: **7 passed, 0 skipped, 0 failed**. PowerShell equivalent:

```powershell
$env:RUN_GHIDRA_TESTS = "1"
python -m unittest tests.test_engine -v
```

Additional checks passed:

```text
python -m py_compile app.py analysis.py workflow.py engine.py discovery.py rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py samples.py build_samples.py scripts/package_lite_windows.py
node --check static/workbench.js
```

## Known limits and safe fallbacks

- Native Windows may not have `file` or `readelf`. The built-in parser handles
  PE metadata; use available GNU `objdump`, Ghidra, or other PE-capable tools.
  Missing adapters should be shown as unavailable/skipped, not as a target
  analysis failure.
- Flatpak and RPM ingestion are Linux-only. The legacy `/api/analyze` routes are
  ELF-only; use the token-protected upgraded API for PE uploads.
- In the fresh Lite extraction, `run.bat` started and `/api/status` returned
  `static_only`; the UI returned HTTP 200. The browser opener could not launch,
  so visit the printed loopback URL manually.
- The fresh extracted copy’s `setup.bat` attempted the Ghidra download but could
  not resolve `github.com` in the handoff environment. It reported the error.
  On a network-connected Windows host, rerun `setup.bat` to install the
  project-local Ghidra/JDK/MinGW tools. Until then, static-only fallback
  behavior remains available.
- Current report PDFs have no workstation username in extracted text. The
  affected pages were replaced with reviewed image pages, so those specific
  pages are not text-searchable; other pages retain selectable text. The DOCX
  text was checked for the username, but its layout was not visually checked.
- Earlier Git history predates PDF cleanup and may still contain the original
  PDF bytes. History was not rewritten. The branch tip contains sanitized PDFs.
- Event details were checked on the official IS CyberNext site on 8 November
  2026; verify current dates and Terms & Conditions again before submission.

## Day 2 starting point for Zayed

1. Confirm the owner has merged Day 1 into `main`; create `day2-zayed` from the
   approved current base. If it is not merged, ask the owner which base to use.
2. Repeat the Windows setup, Level 5 Ghidra smoke, and PE fixture upload. Check
   the fresh-install network dependency described above.
3. Follow D2-01 through D2-06 in `docs/TEAM_TASKS_DAY1-4.md`:
   - Add bounded ELF/PE section, entropy, imports/exports, string-category,
     debug/symbol-presence, and tool-coverage metrics. Keep Ghidra counts
     separate; add deterministic tests.
   - Add Ghidra timeout/resource limits, large-target warning and lightweight
     option, cancellation cleanup, and timing evidence.
   - Add a one-click Level 5 demo, clear format/tool badges, accessible controls,
     and actionable empty/error states. Do not auto-scan on page load.
   - Improve before/after comparison matching and missing-data `N/A` behavior.
   - Validate on Windows and capture sanitized screenshots.
   - Draft the pitch deck and timed demo script; complete `DAY2.md`, push the
     branch, and open the PR required by the team plan.

Day 2 acceptance requires existing and new tests to pass, reports to show
separate ELF/PE/Ghidra evidence, comparisons to preserve baseline state on
failure, and no target execution claims.
