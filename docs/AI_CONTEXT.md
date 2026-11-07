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
6. compares a copy before/after one of three transformations:
   - GNU symbol removal (bundled samples only);
   - demo constant blinding + opaque guard (bundled samples only);
   - binary metadata hygiene (any selected ELF/PE copy).

It is **not**:

- a malware sandbox;
- a production obfuscator;
- a reverse-engineering-resistance score;
- a tool that executes or emulates the selected target.

## 2. Non-negotiable safety invariants

Any change must preserve these:

- **Never execute the selected target.** No `subprocess` call may launch the
  target, its libraries, or a transformed copy. Tools read the file as data.
- **No emulation or dynamic tracing** in the current mode.
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
| `workflow.py` | Selections, async jobs, events, comparison, protections |
| `demo_protection.py` | Sample-only C source transformer and protected build |
| `binary_protection.py` | Binary-only metadata hygiene on a copy |
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
  -> engine.analyze(snapshot) with selected tools
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

Always include `behavior_verified: false` and a limitations list.

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

Windows support is native, not WSL:

- `platform_support.py` handles `.exe`/`.bat` lookup, process groups,
  termination and permissions.
- `engine._run` uses a reader thread because Windows pipes are not selectable.
- Ghidra is invoked through `analyzeHeadless.bat` and a Windows JDK.
- PE files are accepted by discovery, upload, snapshot and analysis.
- `readelf` is skipped for PE; `objdump`, `strings`, `nm` and Ghidra are used.
- Flatpak and RPM are Linux-only; the UI/backend should return a clear error.
- `tools/` is not committed. `setup.bat` downloads Ghidra/JDK; optional
  `w64devkit` supplies `gcc`/binutils for source protection and binary hygiene.
- File modes (`0600`/`0700`) are POSIX-only; Windows uses the project folder
  location and user account as the boundary.

## 9. Tests and checks

```bash
python3 -m unittest discover -s tests -v
RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
python3 -m py_compile app.py analysis.py workflow.py engine.py discovery.py \
  rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py
node --check static/workbench.js
```

Never add a test that executes a bundled sample or a selected target.

## 10. Common pitfalls

- `runs/` reports contain absolute paths, commands and (for the demo profile)
  the demo key. Use the sanitized export before sharing.
- `tools/` is ~1.2 GB; never put it in Git or email it.
- Ghidra needs a writable project directory; the workflow deletes the temporary
  project and keeps only the JSON export/logs.
- `readelf` is ELF-only; do not call it on PE.
- The comparison counts mix ELF symbols and Ghidra labels; do not present them
  as a resistance score.
- A failed reanalysis must preserve the baseline report and transformation
  state.
- Sequential ZIP editing causes merge conflicts; use the Git workflow in
  `docs/GITHUB_WORKFLOW.md`.

## 11. Where the team tasks live

- `docs/TEAM_TASKS_DAY1-4.md` — Naser → Zayed → Nomai → Faisal, day by day.
- `docs/IS_CYBERNEXT_REQUIREMENTS.md` — event requirements and gap analysis.
- `docs/GITHUB_WORKFLOW.md` — beginner Git/GitHub Desktop handoff.
- `START_HERE.md` — Windows/Linux setup and run instructions.
