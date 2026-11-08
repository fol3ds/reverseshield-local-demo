# Day 1 Hand-Off — Naser

## Branch and PR

- Branch: `Day-1---Nasser`
- Base commit: `6ceb1f2` (the GitHub branch tip fetched before the Day 1 changes).
- PR: not opened. The Day 1 commit is pushed to `origin/Day-1---Nasser`.
- Date (Riyadh): 8 November 2026

## What changed

- Windows setup now falls back from an unusable `py.exe` to a working Python
  3.11+ `python.exe`; the batch file prints the selected interpreter.
- `run.bat` reports a manual browser URL if automatic browser launch is blocked.
- Ghidra selection now prefers `analyzeHeadless.bat` on Windows and uses a
  writable per-run profile. The job work directory is normalized before use.
- PE sample labeling is derived from file signatures. Windows sample rebuilds
  emit `.exe` files; the upgraded API, workflow and artifact lookup accept the
  resulting PE reports.
- Windows directory walking counts files and directories, skips virtual
  environments and preserves scan limits. Tests now skip Linux-only API,
  Flatpak, POSIX descriptor and chmod assumptions with explicit reasons.
- Added PE upload/report, Windows directory walker, and bounded malformed-header
  tests. Added Windows/Fedora GitHub Actions jobs.
- Added module docstrings, C sample source headers, the workbench.js section map
  and the “never use innerHTML” rule. Updated the Windows quick start and
  AI context guide.
- Added the event application draft, a Lite package manifest, and a reproducible
  ZIP builder that writes a detached SHA-256 sidecar.

## What works

- [x] `setup.bat` completed from a non-elevated terminal; local Ghidra, JDK and
  MinGW were already present.
- [x] `run.bat` started the loopback workbench. In this restricted session its
  browser opener was denied; opening `http://127.0.0.1:8765/` manually is the
  fallback.
- [x] Level 5 static analysis completed through Ghidra headless: 13 functions
  exported, 10 pseudocode bodies and 6 call edges. No sample was executed.
- [x] PE upload was accepted by the upgraded API and generated a static report;
  the test verifies the PE label, SHA-256 and non-execution limitation.
- [x] A copied Windows `notepad.exe` was discovered as PE32+ x86-64 with 8
  sections and an entry point. The file was read as data and never launched.
- [x] GNU `objdump` completed static inspection of that copied Notepad target;
  the report hash matched the input file and explicitly made no execution claim.
- [x] PE `objdump` analysis succeeded; `readelf` was recorded as `skipped` for
  PE/COFF. No `WinError`, `FileNotFoundError` or “not ELF” rejection occurred in
  the PE upload flow.
- [x] The Lite ZIP extracted into a fresh directory and the app process started
  from that extracted tree. This environment denied loopback HTTP requests, so
  the fresh-copy status/UI endpoint check could not be completed here.

## Tests run

```text
python -m unittest discover -s tests -v
Ran 65 tests: 48 passed, 0 failed, 17 skipped.
Skip reasons: 8 legacy ELF/Flatpak API cases; 5 Flatpak-only cases; 2 POSIX
symlink-race/permission cases; 1 opt-in Ghidra test; 1 missing RPM fixture-tool
set. Windows PE upload and directory-walker tests passed.

RUN_GHIDRA_TESTS=1 python -m unittest tests.test_engine -v
Ran 7 tests: 7 passed, 0 failed, 0 skipped.

python -m py_compile app.py analysis.py workflow.py engine.py discovery.py rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py samples.py build_samples.py
Passed.
```

On Windows, set the Ghidra opt-in with `set RUN_GHIDRA_TESTS=1` in Command
Prompt, or `$env:RUN_GHIDRA_TESTS = "1"` in PowerShell before running the
second command. The suite used a writable temporary directory under ignored
`runs/` data. `PATH`, `GHIDRA_HOME` and `JAVA_HOME` pointed to tools already
installed in the original source workspace; they are not included in this
branch or Lite ZIP. No selected target was executed.

## Lite ZIP

- File: `ReverseShield_Lite_Windows_Day1.zip` (created by
  `scripts/package_lite_windows.py`)
- Size: **753,787 bytes**
- SHA-256: **`e0526bfa1eefe741cbaf4166fa2cbf1ed95f70455076ea0d6d0baaedc91430d2`**
- The builder was run twice with identical size and digest. A detached
  `ReverseShield_Lite_Windows_Day1.zip.sha256` file is written beside the ZIP.
- Contents: 78 entries under a stable `reverseshield-local-demo/` directory;
  no `tools/`, `runs/`, `backups/`, `.git/` or
  `__pycache__/` entries. The generated workspace-specific DOCX/PDF reports
  are excluded. This
  hand-off file is omitted from the ZIP to avoid a self-referential archive
  hash. The ZIP itself is ignored and is not part of the commit.

## Known issues and safe fallbacks

- Native Windows has no `file` identification utility in this setup. The
  adapter reports unavailable; the built-in PE header parser and GNU `objdump`
  still produce PE metadata and static disassembly.
- `readelf` is ELF-only. For PE, the report marks it skipped and continues with
  PE-aware `objdump`, strings, Ghidra or built-in metadata.
- Flatpak and RPM ingestion are Linux-only. On Windows, use a selected local
  folder or upload an ELF/PE file. The legacy `/api/analyze` endpoints remain
  ELF-only; Windows PE flows use the token-protected upgraded API.
- `py.exe` was present but inaccessible in this session; setup now tries
  `python.exe` and succeeded with Python 3.15.2.
- The app server started, but automatic browser launch was blocked by the
  execution environment. The safe fallback is to open the loopback URL manually.
- The fresh Lite extraction omits local tool bundles by design. Its app process
  started, but `setup.bat` was not rerun from that tree because it could trigger
  large tool downloads; loopback HTTP requests from this environment were denied.
- The opt-in RPM package integration test was skipped because `rpmbuild`,
  `rpm2cpio` and a native Linux build toolchain are unavailable on Windows.
- The two DOCX files were regenerated from sanitized builders, and text-level
  extraction found no home-directory path. Their visual layout could not be
  checked because LibreOffice is unavailable and Word UI automation failed.
  The two tracked PDFs remain unchanged and still contain an absolute home
  directory in extracted evidence text. All four generated reports are excluded
  from the Lite ZIP. Do not share the PDFs; re-export sanitized copies, then
  visually inspect them before event submission.
- No PR was opened. Open one from `Day-1---Nasser` if these changes should be
  merged into `main`.

## Next person's first three actions (Zayed, Day 2)

1. Start from the owner-merged `main`, create `day2-zayed`, and repeat the
   Windows setup, Level 5 Ghidra smoke and PE fixture flow.
2. Implement D2-01 content/structure metrics for ELF and PE, keeping Ghidra
   counts separate and adding bounded parser tests.
3. Complete D2-02/03 Ghidra large-target handling and the one-click demo; verify
   skipped-tool reasons, cancellation cleanup and the visible no-execution
   claim before recording screenshots.

## Safety and claims check

- [x] No selected target, bundled sample or transformed artifact was executed.
- [x] No tools, runs, backups, secrets, keys or absolute personal paths are
  staged in this hand-off.
- [x] Demo source transformation remains demonstration-only; behavior is not
  verified.
- [x] Reports describe static observations and state explicitly that targets
  were not executed or emulated.
