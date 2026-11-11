# Changelog

## Day 3 (Nomai) — 11 November 2026

- Authenticate API reads and legacy writes; bootstrap token in the local page.
- Add conservative sanitized report exports, CLI and authenticated browser downloads.
- Harden CSP, error responses, linked storage and malformed PE inputs.
- Bound legacy analyzer output; add cross-platform process-tree regression probes.
- Record SAST/DAST results, performance, English storyboard and current event gaps.
- Keep Fedora/large Linux benchmark and authenticated PR as explicit hand-off gates.


## Day 2 (Zayed) — analysis accuracy, one-click demo, comparison, security review

- Added `metrics.py`: bounded content metrics from file bytes for ELF and PE
  (section counts, executable/writable sections, per-section and file
  entropy, imports/exports, string categories, debug/symbol flags). ELF/PE
  symbol tables, readelf/nm counts and Ghidra symbols are reported separately.
- Added a coverage block: tools ran / skipped (with reason) / failed /
  unavailable / not selected, and truncated outputs.
- Ghidra: per-run time limit and CPU limit, large-target guard (> 8 MiB needs
  confirmation or "Lightweight tools only"), timing in the report, process-tree
  stop and project cleanup on cancel/timeout (tested with a fake launcher).
- UI: "Run demo · Level 5" one-click flow, ELF/PE badges, Ghidra options,
  actionable empty/error/offline states, Windows drive paths accepted.
- Comparison: functions matched by address then name with unmatched/renamed
  lists; content metrics before/after; N/A never shown as zero; "what changed /
  did not change" summary; limitations box; neutral "transformed copy" labels.
- Security: review in `docs/security/DAY2_SECURITY_REVIEW.md`; fixed
  System32 paths for cmd.exe/taskkill, cmd.exe metacharacter refusal for batch
  launch (BatBadBut class), UNC path refusal, junction skipping.
- Readable redesign (10 Nov): calm light theme with a matching dark mode
  (header toggle), system font at 15 px, plain-English labels everywhere, a
  "What someone could learn from this file" summary at the top of each report,
  explained metric tables, Yes/No instead of true/false, thousands separators,
  folded-away disclaimers, readable activity log (local times, shortened
  paths), English file picker and Latin digits in number fields. The old
  dark-cyan colour tokens in `tests/test_ui_contract.py` were replaced with
  the new theme tokens.
- Docs: pitch deck draft + 3-minute demo script, Day 2 hand-off, screenshots,
  `docs/ROADMAP.md` (hardening checks and CVE lookup planned, not built).

## 0.3.0-team — four-person Windows/Fedora hand-off edition

- Added Windows PE/COFF header support to discovery, upload ingestion, snapshot
  validation and the static engine.
- Added a portable Windows target-scan path and project-local tool lookup.
- Added a Windows Ghidra/JDK setup path, `setup.bat`, `run.bat` and `run.sh`.
- Added AI-oriented architecture, safety and extension notes.
- Added a synthetic minimal PE32+ fixture and PE-support tests.
- Added team hand-off: Day 1–4 tasks, GitHub Desktop workflow, event gap
  analysis and start-here instructions.
- Kept source-level protection sample-only and dynamic analysis disabled.

## 0.2.0 — workbench upgrade

- Asynchronous jobs, live events, target discovery and Ghidra headless.
- Comparison reports for symbol removal, demo constant blinding and binary
  metadata hygiene.
- Dark-cyan browser UI and report/plan documents.

## 0.1.0 — initial local demo

- Loopback Python server, ELF metadata parsing, five self-authored samples.
- Read-only tool adapters and a browser UI.
