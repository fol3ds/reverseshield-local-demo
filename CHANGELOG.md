# Changelog

## Unreleased — source cleanup

- Removed 45 straightforward internal/team/event files, obsolete generated
  documents/screenshots and raw historical scanner outputs. A private local
  archive was verified before removal; Git history was not rewritten.
- Preserved privacy warnings and open acceptance gates in
  `docs/RELEASE_CHECKLIST.md`; removed links to retired files from onboarding.
- Kept conditional AI/security documentation, optional screenshots, document and
  video tooling, evidence fixtures and functional/security regression tests.
- Updated Lite selection so retired team/event guides are excluded and the
  release/privacy checklist is included. No release or visibility change.

Earlier entries below describe historical work, not fresh verification of this
cleanup. Refer to the exact candidate commit and test output before release.

## 0.5.0-team — local Day 4 candidate (unmerged, unpublished)

- Six selectable ELF samples: five original source-transformable samples and
  one `level-5-hardened` analysis-only fixture. Measured static NX/PIE/RELRO,
  canary and FORTIFY evidence is in `docs/evidence/hardening-level5.json`;
  observed mitigation properties do not prove security or equivalence.
- All five original sample-driver pairs produced matching deterministic
  transcripts in a no-disk/no-network QEMU guest; this is bounded test-vector
  evidence, not general behavioral equivalence. See
  `docs/evidence/ollvm-five-qemu.json`.
- Compare labels now identify tool-derived counts and say `N/A` means
  unmeasured, not zero. The UI and backend identify native-Windows OLLVM/QEMU
  as unavailable; the Windows static workbench still needs a clean manual run.
- Fixed the backend operation/profile mismatch so an analysis-labelled job
  cannot dispatch a source transformation. Added HTTP and worker-queue regression checks.
- Scoped QEMU results to separate deterministic driver builds:
  `driver_vectors_matched` is separate from `behavior_verified: false` on the
  downloadable artifact; it was not the executable tested in the guest.
- The Windows Lite ZIP is a **local candidate only**. Package selection uses
  indexed files and excludes raw scanner output, old screenshots and video.
  The sanitized evidence map and acceptance matrix are in `docs/evidence/`.
- The `v0.4.0-team` GitHub draft release has older assets and does not contain
  this local work. No event sign-in, upload or submission has been performed.

### Earlier 0.5.0-team prototype work — OLLVM source obfuscation

- Added an optional xollvm/LLVM 22 profile for the bundled self-authored
  samples: control-flow flattening, bogus control flow, instruction substitution
  and string encryption.
- Added a QEMU micro-VM behaviour check with no disk and no network. It compares
  deterministic original/protected drivers and is required for a clean status.
- Source-only restriction is explicit: arbitrary ELF/PE targets remain
  analysis-only, and OLLVM cannot be applied without source.
- Added comparison/UI evidence, a project-local setup script, third-party
  attribution, and tests. An earlier prototype run recorded 105 tests with
  1 skip; see the current verification file for the Day 4 candidate.
- Added static exploit-mitigation checks for ELF and PE: NX/DEP, PIE/ASLR,
  RELRO, stack canary, FORTIFY and PE Control Flow Guard. These are observed
  properties, not a security score.
- The OLLVM profile is a real transformation, but not a security proof; Ghidra
  can still recover code and the QEMU check covers only deterministic drivers.

## Day 4 (Faisal) — 11 November 2026

- Integrated the reviewed Day 2 and Day 3 branches into `main`; the Day 3 tree is
  now the current source baseline.
- Fixed the Windows CI path assertion so the Day 2 branch passes on GitHub
  Actions as well as Fedora.
- Normalized line endings (LF for source/docs, CRLF for `.bat`/`.ps1`) and
  restored the executable bit on `run.sh`.
- Updated release metadata to `0.4.0-team` and synchronized the test count to
  **98 tests** in the README and event requirements.
- Fedora verification: 98 tests, 1 skip with Ghidra enabled. GitHub Actions:
  Windows and Fedora jobs pass on the merged `main` commit.
- Remaining Day 4 gates: final documents, demo video, Lite release asset with
  SHA-256, Git tag, and event submission.

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
