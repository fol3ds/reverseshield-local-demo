# ReverseShield — AI Context and Extension Guide

This file is the first thing an AI coding agent should read before changing the
project. It explains what the project is, where the boundaries are, and how to
extend it without breaking the safety model.

## 1. What this project is

ReverseShield is a **local, static-only application-security workbench** for
Linux ELF and Windows PE files. It:

1. discovers an installed application, a local folder/ELF/PE/RPM, an upload,
   or a bundled self-authored sample;
2. copies selected files into a run-local snapshot;
3. runs bounded read-only static tools (`file`, `readelf`, `objdump`,
   `strings`, `nm`, Ghidra headless);
4. streams real tool events to a browser UI;
5. stores evidence under `runs/<job_id>/`;
6. compares a copy before/after one of four transformations:
   - GNU symbol removal (bundled samples only);
   - demo constant blinding + opaque guard (bundled samples only);
   - OLLVM source obfuscation + QEMU behaviour check (bundled samples only);
   - binary metadata hygiene (any selected ELF/PE copy).

It is **not**:

- a malware sandbox;
- a production protector or a security proof;
- a reverse-engineering-resistance score;
- a tool that executes installed or third-party targets on the host.

## 2. Non-negotiable safety invariants

Any change must preserve these:

- **Never execute the selected target on the host.** No host `subprocess` call may
  launch the target, its libraries, or a transformed copy. Tools read the file as
  data. The only exception is the optional OLLVM profile, which boots a QEMU
  micro-VM with no disk/network and runs deterministic drivers built from the
  bundled sample sources. It must never be pointed at an external target.
- **No host-side emulation or dynamic tracing** in the current mode.
- **Loopback only.** The HTTP server binds `127.0.0.1`; remote access is out of
  scope.
- **Session token + same-origin check** protect state-changing API calls.
- **Snapshots, not originals.** Analysis works on a copy under `runs/`; the
  original application/file is never modified.
- **Source-level protection is sample-only.** Do not apply the C transformer to
  third-party applications.
- **Binary metadata hygiene is metadata-only.** It is not code rewriting.
- **No security score.** Report observed artifact changes and limitations; do
  not claim resistance or certification.
- **Bounded resources.** Keep target size, output size, tool timeouts, job
  counts and scan counts bounded.
- **Do not commit `tools/`, `runs/`, or `backups/`.** They are large or
  sensitive. Use a release asset or a setup script.

## 3. Architecture map

| File | Role |
|---|---|
| `app.py` | HTTP server, legacy metadata endpoints, static assets, main entry point |
| `http_upgrade.py` | Upgraded JSON API: status, discovery, ingest, jobs, report/artifact |
| `discovery.py` | Flatpak listing, local folder/ELF/PE scan, RPM ingestion path |
| `rpm_ingest.py` | Bounded RPM header/payload extraction (Linux only) |
| `engine.py` | Tool adapters, cross-platform process runner, parsers, Ghidra export |
| `analysis.py` | ELF/PE header parsing and legacy metadata helpers |
| `metrics.py` | Bounded content metrics from file bytes (sections, entropy, imports/exports, strings, debug flags) |
| `workflow.py` | Selections, async jobs, events, comparison, protections |
| `demo_protection.py` | Sample-only C source transformer and protected build |
| `binary_protection.py` | Binary-only metadata hygiene on a copy |
| `hardening.py` | Static ELF/PE mitigation-property checks; never a safety score |
| `ollvm_protection.py` / `behavior_qemu.py` | Linux-only, five-original-sample source transforms and bounded guest-driver comparison |
| `platform_support.py` | Windows/POSIX process, tool discovery and permission helpers |
| `samples.py` / `build_samples.py` | Bundled sample definitions and builds |
| `static/` | Browser UI (Operate, Compare, Monitor, Read Me) |
| `ghidra_scripts/ReverseShieldExport.java` | Ghidra post-script JSON exporter |
| `tests/` | Unit, API, UI-contract and PE-support tests |
| `docs/` | Plans, report, evidence, handoff and event requirements |

## 4. Data flow

```text
source (Flatpak / folder / RPM / upload / sample)
  -> discovery (metadata only; no execution)
  -> selection (target IDs + absolute paths + identity)
  -> job start (authorization required)
  -> snapshot copy under runs/<job_id>/original-N.<ext>
  -> engine.analyze(snapshot, options) with selected tools
     (+ metrics.content_metrics(snapshot) and a coverage summary)
  -> events.jsonl + report.json + Ghidra export/logs
  -> optional transform on the snapshot copy
  -> reanalyze the transformed copy
  -> compare_reports(before, after)
  -> UI / sanitized export
```

## 5. Important data structures

### Selection

```json
{
  "selection_id": "hex",
  "app": {"name": "..."},
  "targets": [
    {"target_id": "hex", "relative_path": "bin/app", "absolute_path": "...",
     "size_bytes": 123, "format": "ELF|PE", "analyzable": true, "reason": null}
  ],
  "runtime": {"dependencies": [], "scanned": false}
}
```

`absolute_path` and `_identity` are removed from the public API response.

### Job

In memory: `status`, `operation`, `profile`, `events`, `next_seq`, `result`,
`_directory`, `_cancel`, `_future`. Final record (without private keys) is
written to `runs/<job_id>/report.json`.

Terminal states: `completed`, `partial`, `failed`, `cancelled`.

### Protection states

| State | Operation | Meaning |
|---|---|---|
| `symbol_removal_applied` | `strip_compare` | Sample-only `strip --strip-unneeded` |
| `demo_obfuscation_applied` | `protect_compare` | Sample-only source transform + rebuild |
| `binary_metadata_hygiene_applied` | `binary_compare` | Any selected ELF/PE copy; metadata only |
| `ollvm_obfuscation_applied` | `ollvm_compare` | Bundled sample source only; xollvm rebuild, then QEMU behaviour check |

`hardening.py` adds static exploit-mitigation properties to every analysis:
NX/DEP, PIE/ASLR, RELRO, canary, FORTIFY, and PE ASLR/DEP/CFG. These are
observed properties, never a security score. Add checks in that module rather
than mixing them into `metrics.py`. `level-5-hardened` is the sixth bundled
selection and is analysis-only for source transforms; only the original five
self-authored sample sources may enter the OLLVM/QEMU driver workflow.

Metadata-only transformations include `behavior_verified: false`. OLLVM also
keeps that field **false**: QEMU tests separately rebuilt driver executables,
not the downloadable protected ELF. `driver_vectors_matched` records only
whether those separate deterministic drivers matched; `behavior_scope` is
`separate_deterministic_drivers`. A failed driver check makes the job `partial`.
Neither result is full behavioral equivalence.

## 6. Adding a new analysis tool

1. Add a label and adapter name in `engine.LABELS`.
2. Add a command spec in `engine.analyze` (argv list, no shell).
3. Add a parser (structured JSON preferred; otherwise bounded text parsing).
4. Add a handler in the per-tool branch that merges artifacts with limits.
5. Add an inventory/version path in `engine.inventory`.
6. Update `http_upgrade` status if the UI needs capability metadata.
7. Add tests with a real fixture; never execute a target.
8. Update `docs/AI_CONTEXT.md` and the UI labels if needed.

## 7. Adding a new transformation profile

1. Decide the scope: bundled samples only, or any selected copy.
2. Implement a pure function/class with explicit input/output and hashes.
3. Never modify the original; write under the job directory with `0600`.
4. Add a workflow branch that records a state, hashes, commands and limits.
5. Add `artifact_path` support.
6. Add UI profile option, payload validation, labels and artifact download.
7. Add tests for hash preservation, original immutability, artifact mode and
   failure handling.
8. State clearly what the profile is **not**.

## 8. Windows-specific notes

Native Windows support is implemented in the code, and earlier merged-baseline
CI jobs ran on Windows; **this unmerged Day 4 candidate has not had a clean
native-Windows manual acceptance run**. The OLLVM/QEMU workflow is Linux-only.
The Windows scripts probe compatible Python versions 3.15→3.11 explicitly;
project-local Ghidra 12.2, JDK 25 and MinGW-w64 are optional downloaded tools.

- `platform_support.py` handles `.exe`/`.bat` lookup, process groups,
  termination and permissions.
- `engine._run` uses a reader thread because Windows pipes are not selectable.
- Ghidra is invoked through `analyzeHeadless.bat` and a Windows JDK.
- PE files are accepted by discovery, upload, snapshot and analysis.
- `readelf` is skipped for PE; `objdump`, `strings`, `nm` and Ghidra are used.
- Flatpak and RPM are Linux-only; the UI/backend should return a clear error.
- `tools/` is not committed. `setup.bat` downloads Ghidra/JDK and MinGW-w64;
  it validates Python 3.11+ by trying the `py` launcher and then `python`, so
  an inaccessible stale launcher does not block a usable Python installation.
- Missing `readelf` is expected on native Windows. PE reports record it as
  `skipped`/not applicable; absent Ghidra or binutils adapters are reported as
  unavailable and do not prevent built-in PE header parsing. Do not turn these
  capability gaps into silent success or target-analysis failures.
- Windows folder discovery uses `_scan_directory_windows`, accepts `.exe` and
  `.dll` by PE signatures and extracts the PE32/PE32+, machine, section and
  entry-point fields. Extension alone never establishes an executable format.
- Sample files built with MinGW on Windows use `.exe` extensions and are
  labeled from their parsed file signatures. Bundled Linux ELF fixtures are
  intended for static Ghidra analysis when Ghidra is installed; confirm this
  on a clean native-Windows account before claiming acceptance.
- `tests/test_app_api.py` covers the legacy ELF/Flatpak API and is skipped on
  Windows; Windows acceptance uses the upgraded token-protected API and PE
  tests. Flatpak, RPM, and POSIX descriptor/permission behavior are Linux-only.
- File modes (`0600`/`0700`) are POSIX-only; Windows uses the project folder
  location and user account as the boundary.

## 9. Tests and checks

```bat
python -m unittest discover -s tests -v
set RUN_GHIDRA_TESTS=1
python -m unittest tests.test_engine -v
```

In PowerShell use `$env:RUN_GHIDRA_TESTS = "1"` before the second test
command. Current Windows test evidence and known environment-specific failures
are recorded in `docs/handoff/DAY1.md`.

```bash
python3 -m unittest discover -s tests -v
RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
python3 -m py_compile app.py analysis.py workflow.py engine.py discovery.py metrics.py \
  rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py
node --check static/workbench.js
```

Do not add any test that executes an installed application or selected
external target. The only permitted behavior probe runs deterministic drivers
from the five original self-authored samples inside a no-disk/no-network QEMU
guest; never run those sample executables on the host. The sixth hardened ELF
is analysis-only.

## 10. Common pitfalls

- `runs/` reports contain absolute paths, commands and (for the demo profile)
  the demo key. Use the sanitized export before sharing.
- `tools/` is ~1.2 GB; never put it in Git or email it.
- Ghidra needs a writable project directory; the workflow deletes the temporary
  project and keeps only the JSON export/logs.
- `readelf` is ELF-only; do not call it on PE.
- "Parsed symbol entries" is the merged list (ELF symbols + Ghidra labels).
  Use `content_metrics.symbols` (`elf_symbols`, `readelf_symbols`,
  `nm_symbols`, `ghidra_symbols`) when a source-specific count is needed. None
  of these is a resistance score.
- Missing metrics are `null` in JSON and `N/A` in the UI; never coerce to 0.
- Never launch a `.bat`/`.cmd` with arguments containing `& | < > ^ % !` or
  quotes; `platform_support.command_for` refuses them (BatBadBut class).
- A failed reanalysis must preserve the baseline report and transformation
  state.
- Sequential ZIP editing causes merge conflicts; use the Git workflow in
  `docs/GITHUB_WORKFLOW.md`.

## 11. Where the team tasks live

- `docs/TEAM_TASKS_DAY1-4.md` — Naser → Zayed → Nomai → Faisal, day by day.
- `docs/IS_CYBERNEXT_REQUIREMENTS.md` — event requirements and gap analysis.
- `docs/GITHUB_WORKFLOW.md` — beginner Git/GitHub Desktop handoff.
- `START_HERE.md` — Windows/Linux setup and run instructions.


## Day 3 privacy and sharing

All API reads and writes require the per-session token. Open the workbench
page to bootstrap it; `/api/status` does not disclose it. The browser sends
the token in a header, including downloads. Host, Origin, Referer and browser
fetch-site checks protect against foreign websites. This is local browser
request protection, not user accounts, enterprise IAM or protection from a
malicious process running as the same OS user.

Analysis reads target bytes locally and never runs the target. The application
has no telemetry or cloud analysis upload. Setup downloads third-party tools;
developer security scanners may download rules. Inputs, reports and temporary
analysis workspaces live in `runs/` until manually removed. Stop the server
before deleting unwanted runs; the job index resets on restart. There is no
encrypted evidence store or cumulative disk quota: monitor available space.

Use **Download sanitized report** for sharing. It creates a separate JSON
summary, retaining hashes, numerical measurements, coverage and tool status.
Raw output, recovered code, artifacts, event text, commands and environment
values are omitted; identifiable paths and known secret patterns are redacted.
The original local report is unchanged. This is not a universal secret detector;
review the exported summary before publishing. The authenticated `/report`
endpoint remains an internal raw-evidence route. `/report-sanitized` is the
shareable route. Changed binaries are not sanitized reports and may retain
embedded strings; do not publish them as proof of privacy.

Offline export (refuses to overwrite the source or an existing destination):

```sh
python sanitize_report.py runs/JOB_ID/report.json sanitized-report.json
```

Day 3 verification and unresolved release gates are recorded in
`docs/handoff/DAY3.md`. Older PDF/DOCX reports and Day 2 screenshots describe
earlier builds; use the Day 3 evidence for current security claims.
