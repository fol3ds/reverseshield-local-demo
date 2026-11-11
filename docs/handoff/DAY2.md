# Day 2 Hand-Off — Zayed

## Branch and PR

- Branch: `day2-zayed` *(create it from `main` after Naser's Day 1 PR is merged,
  copy these changes in, commit, push and open the PR)*
- Base: the `reverseshield-local-demo-main` ZIP that already contains Naser's
  Day 1 work (`0.3.0-team` + `docs/handoff/DAY1.md`)
- PR link: `<add after opening>`
- Date (Riyadh): 9 November 2026

## Day 2 task checklist

- [x] **D2-01 — Content and structure metrics.** New `metrics.py` computes,
  from file bytes only: section count, executable/writable sections, entropy
  per section and for the whole file, imports/exports (ELF `.dynsym` +
  `DT_NEEDED`; PE import/export directories), strings by category (paths,
  URLs, compiler notes, messages, other), and debug/symbol flags. ELF/PE
  symbol tables, readelf, nm and Ghidra counts are kept separate
  (`content_metrics.symbols`). A coverage block lists ran / skipped (with
  reason) / failed / unavailable / not selected tools and truncated outputs.
  All parsers are bounded and deterministic. Malformed input records an error
  and does not raise.
- [x] **D2-02 — Ghidra quality and large targets.** Per-run options
  `ghidra_timeout_seconds` (60–1800) and `ghidra_max_cpu` (1–CPU count) are
  validated by the backend. Targets over 8 MiB need "Run Ghidra anyway" or
  "Skip Ghidra (lightweight tools only)"; the backend enforces this too. Cancel and timeout
  stop the whole process tree and delete the temporary project. This is
  tested with a fake launcher that spawns a child. Ghidra time, CPU limit,
  functions, decompiled count and call edges are recorded in
  `content_metrics.ghidra`.
- [x] **D2-03 — One-click demo and usability.** "Run demo · Level 5" selects
  the sample and all its targets, runs every available tool and returns to the
  report. It never runs on page load (contract test). The UI also has ELF/PE
  badges, Ghidra options, a "may take several minutes" warning, run hints that
  name the blocking step, and readable messages for server offline, expired
  token, cancelled job and failed job. Windows `C:\…` paths are accepted in
  *Local path* (they were rejected before). All rendering still uses
  `textContent`.
- [x] **D2-04 — Comparison accuracy.** Functions are matched by address, then
  by name. Unmatched and renamed functions are listed. Content metrics are
  shown before/after. Missing values are `N/A`, never zero. There is a "what
  changed / did not change / not collected" summary and a limitations box. A
  failed reanalysis keeps the baseline and the transform state (existing test
  still passes, and the UI shows the reason). Labels are neutral ("After ·
  symbols-removed copy", "Download demo-transformed copy"); nothing says
  "protected".
- [x] **D2-05 — Windows validation.** Done on Zayed's Windows 11 PC
  (10 Nov): setup, one-click demo, PE fixture, notepad.exe as data, full test
  suite and the real Ghidra test all passed. See the results table below. Done on Linux: full suite, real Ghidra 12.2 +
  JDK 25 runs, a browser run of the one-click demo, a compare run, the
  large-target warning, the offline state, and a MinGW-built **PE** Level 5
  uploaded and analysed (34 imports / 2 DLLs / 19 sections / debug sections
  detected).
- [x] **D2-06 — Pitch deck draft and hand-off.** See
  `docs/event/PITCH_DECK_DRAFT.md` (slides 1–6 with measured numbers, a
  3-minute click-by-click script) and this file.
- [x] **Extra — security review.** See
  `docs/security/DAY2_SECURITY_REVIEW.md`: 12 findings with CWE, CVE where
  one exists, and mitigation. 4 are fixed with tests (System32 paths for
  `cmd.exe`/`taskkill`, `cmd.exe` metacharacter refusal, UNC path refusal,
  junction skipping); 8 are open for Day 3/4.

## What changed (files)

- `metrics.py` *(new)*: bounded ELF/PE content metrics.
- `engine.py`: metrics + coverage in every report; Ghidra options,
  validation, timing, cleanup; refused launch becomes a tool error.
- `workflow.py`: `options` on jobs, large-target guard,
  `match_functions()`, upgraded `compare_reports()` (summary, functions, N/A).
- `http_upgrade.py`: passes `options`; `/api/status` reports Ghidra limits and
  the demo sample; UNC paths refused.
- `analysis.py`: PE long section names (`/4` → `.debug_info`) resolved from
  the COFF string table.
- `app.py`: missing Flatpak returns an empty list with a reason (no more
  HTTP 503 console error on Windows).
- `platform_support.py`: `system_executable()`, safe `command_for()`.
- `discovery.py`: Windows walker skips junctions/reparse points; a `flatpak`
  that exists but cannot be started is reported as unavailable (was HTTP 400).
- `static/index.html`, `workbench.js`, `workbench.css`: demo panel, Ghidra
  options, metrics/coverage view, comparison summary/functions/limitations,
  friendly errors.
- Tests: `tests/test_metrics.py`, `tests/test_ui_day2.py`,
  `tests/test_security_day2.py` *(new)*. `tests/test_discovery.py` now skips
  the chmod test when run as root.
- Docs: `docs/ROADMAP.md` (hardening checks + CVE lookup, planned only),
  README, START_HERE (demo + troubleshooting rows), CHANGELOG,
  AI_CONTEXT, security README, pitch deck draft, this hand-off, 7 screenshots
  in `docs/assets/day2-*.png`.

## Tests run

```text
# Windows 11, PowerShell, Python 3.11.9, Node.js 26.13.0 (10 Nov)
python -m unittest discover -s tests -v
Ran 86 tests: 67 passed, 0 failed, 19 skipped
$env:RUN_GHIDRA_TESTS = "1"; python -m unittest tests.test_engine -v
Ran 7 tests: 7 passed, 0 skipped (real Ghidra smoke test)

# Linux, normal user, without project tools/ (Ghidra unavailable)
python3 -m unittest discover -s tests
Ran 86 tests: 83 passed, 0 failed, 3 skipped
  skips: Ghidra opt-in; Windows-only PE walker; RPM fixture tools missing

# Linux, with project-local Ghidra 12.2 + Temurin JDK 25
RUN_GHIDRA_TESTS=1 python3 -m unittest discover -s tests
Ran 86 tests: 83 passed, 0 failed, 3 skipped (Ghidra smoke test PASSED)
  skips: Windows-only PE walker; RPM fixture tools; chmod test as root

python3 -m py_compile <all modules> && node --check static/workbench.js  → OK
bandit -r . -x ./tools,./runs,./tests → 27 low, 0 medium, 0 high
```

Day 1 baseline was 65 tests. Day 2 adds 21: 13 metrics/Ghidra/comparison,
3 UI, 5 security.

## Evidence (measured, Level 5, all six tools)

| | Original | Symbol removal | Binary hygiene | Demo blinding |
|---|---|---|---|---|
| Size (bytes) | 16,088 | 10,784 | 9,960 | 20,120 |
| ELF symtab entries | 35 | 0 | 0 | 40 |
| File/folder names | 14 | 1 | 1 | 13 |
| Paths inside a user home folder | 4 | 0 | 0 | 1 |
| Ghidra functions decompiled | 10 | 8 | 8 | 9 |
| Ghidra time | ~9 s | — | — | — |

One-click demo end-to-end: about 10 s in the browser (Linux, 2 CPUs).

Screenshots (sanitized; command paths shortened, no user folders):
`docs/assets/day2-demo-button.png`, `day2-demo-report-metrics.png`,
`day2-compare-symbol-removal.png`, `day2-pe-metrics.png`,
`day2-large-target-warning.png`, `day2-lightweight-selected.png`,
`day2-offline-message.png`.

## Readable redesign (10 November, Zayed's request)

The dark-cyan terminal look was hard on the eyes and the report was hard to
read, so the UI was redesigned. No backend behaviour changed.

- Light theme by default, plus a soft dark mode (**Dark mode** button, remembered
  per browser). The system font is used at 15 px; monospace is only for code,
  hashes and logs.
- Every report starts with **What someone could learn from this file**: names
  left in the file, debug info, file paths, build details, recovered code and
  imports, each with one line on why it matters.
- The **Overview** tab groups the numbers (file structure, links to other
  software, readable text, names and debug info, Ghidra) with a "What it
  means" column. Raw header fields, sections and limits are folded away.
- Standard disclaimers are folded into **About this report**. Only real
  problems stay highlighted.
- Plain labels throughout: "Analyze selected files", "Make copy & compare",
  "Skip Ghidra", "Recovered code", "Activity log". Statuses read "Done",
  "Skipped", "Not installed".
- The activity log shows local times and hides folder paths (the full text is
  in the tooltip). Tool install paths moved to tooltips (privacy, RS-09).
- The file picker is always in English, and the Ghidra fields always show 0–9
  digits.
- **Owner note:** `tests/test_ui_contract.py` used to require the dark-cyan
  colour values. It now checks the new theme tokens and the dark-mode block.
  Screenshots in `docs/assets/day2-*.png` were re-taken in the new design.

## D2-05 Windows results so far (10 November)

| Step | Result |
|---|---|
| Setup | Python 3.11.9 (Microsoft Store; no `py` launcher, `run.bat` uses `python`). `setup.bat` OK: Ghidra 12.2 and JDK 25 checksums OK, MinGW installed (binutils 2.47). `file` missing as expected. |
| One-click demo | **Passed.** "Step 3/3 · done". readelf, objdump, strings, nm, Ghidra ran OK. Level 5 metrics identical to Linux: 36 sections, 3 exec, 7 writable, entropy 2.9802, 2 imports / 1 library. |
| PE fixture upload | **Passed.** PE badge; `readelf skipped: readelf does not parse PE/COFF files.`; 1 section (exec), 0 writable, 0 imports; Ghidra ran OK on PE. |
| notepad.exe (uploaded copy) | **Passed.** PE, 352 KB, 8 sections (2 code, 2 writable), entropy 6.48, 315 imports from 50 libraries, 0 exports, no symbol table, no debug sections but a PDB reference. Ghidra finished in 162 s: 519 functions, 40 decompiled (the per-run decompile limit), 1,865 call edges. objdump output capped at 1 MB of 1.74 MB (reported). Not executed. |
| Windows test suite (first run) | 86 run: 5 FAIL, 5 ERROR, 19 skipped. **5 FAIL:** Node.js is not installed (UI contract tests need `node`). **4 ERROR:** the tests read `index.html`/`workbench.js` with the Windows default code page (cp1252) and the new UTF-8 punctuation broke it. Fixed: tests now read UTF-8. **1 ERROR:** creating a symlink needs Developer Mode or admin rights (WinError 1314). Fixed: the test skips only the symlink part. |
| **Windows test suite (final)** | **86 run: 67 passed, 19 skipped, 0 failed** (Windows 11, Python 3.11.9 Microsoft Store, Node.js 26.13.0, MinGW binutils 2.47). Skips: 8 legacy ELF/Flatpak API, 5 Flatpak-only, 2 POSIX fake-Ghidra probes, 1 POSIX symlink race, 1 chmod, 1 RPM fixture tools, 1 Ghidra opt-in (run separately). |
| **Ghidra opt-in test (final)** | **7 run: 7 passed, 0 skipped** (`$env:RUN_GHIDRA_TESTS = "1"`, real Ghidra 12.2 + JDK 25, 14.9 s). |
| Ghidra opt-in test (first run) | Not actually run: in PowerShell `set RUN_GHIDRA_TESTS=1` does not set an environment variable, so the test was skipped. Use `$env:RUN_GHIDRA_TESTS = "1"` in PowerShell (or `set` in Command Prompt). |

Fixed after the Windows run: a PE report showed the readelf skip twice (now
once), and printing the page showed "Skip to workbench" on every page.

## D2-05 Windows steps (reference)

1. Copy the changed files into your clone on branch `day2-zayed`.
2. Run `setup.bat` (skip if tools already exist), then `run.bat`.
3. Press **Run demo · Level 5**. Confirm it reaches "Step 3/3 · done" and the
   report shows the findings cards and the Overview tab.
4. *Upload file* → `tests\fixtures\minimal-pe64.exe` → Analyze. Expect a PE
   badge, `readelf skipped: readelf does not parse PE/COFF files.`, 1 section.
5. *Local path* → `C:\Windows\System32` → select `notepad.exe` only → Analyze
   with Ghidra. Note imports/exports and Ghidra time. Do **not** launch it.
6. Run `py -3 -m unittest discover -s tests -v` and
   `set RUN_GHIDRA_TESTS=1` + `py -3 -m unittest tests.test_engine -v`.
   Record the counts here.
7. Re-take screenshots on Windows if the deck needs Windows visuals. Crop out
   the *Analysis tools* sidebar: it shows tool paths that include your user
   name.

## Known issues and safe fallbacks

- Windows behaviour of the new code (System32 lookup, junction skip,
  `cmd.exe /d`) is unit-tested with mocks only. Step 5 above is the real check.
- Content metrics read up to 64 MiB, but entropy is capped at 4 MiB per section
  and 32 MiB in total. The cap is flagged as `entropy_truncated`.
- The string categories are simple heuristics: a word with a dot can count
  as a "path" (for example `main.c`). The counts are labelled as a byte scan,
  not a tool result.
- Demo constant blinding rebuilds the sample, so addresses change: functions
  match by name (13), not address (0). That is expected and shown.
- The *Analysis tools* sidebar still shows full tool paths. Crop it out of any
  shared screenshot (privacy; see RS-09).

- **The bundled sample binaries contain the owner's Linux home folder**
  (`/home/<owner>/…/reverseshield-local-demo/…`, 4 strings in `level-5.elf`).
  This is exactly what the tool is meant to find, and it makes a good demo
  point. If the owner does not want that user name in the video, rebuild the
  samples with `-ffile-prefix-map=<project folder>=.` added to `FLAGS` in
  `build_samples.py`. The numbers in the deck would then change.
- String categories are heuristics. Library names such as `libc.so.6` or
  `KERNEL32.dll` are **not** counted as paths (they are imports). Source and
  header names such as `main.c` are counted as file names.

- **GitHub checks were red on `main` before Day 2** (0/2 passing, 10 Nov).
  Likely causes, now addressed in this PR: the Fedora job runs as root in a
  container, so the chmod test failed (it now skips as root), and the Fedora
  image has no Node.js for the UI tests (`nodejs` added to the install step).
  The Windows job added `C:\msys64\mingw64\bin` to PATH, but `setup-msys2`
  installs elsewhere; it now uses the action's `msys2-location` output. The
  CI logs were not visible from here, so confirm on the PR's **Checks** tab.

## Next person's first three actions (Nomai, Day 3)

1. Pull `main` after this PR merges. Run the suite and the one-click demo.
2. Start from the **open** items in `docs/security/DAY2_SECURITY_REVIEW.md`:
   RS-05 (token on all API reads), RS-09 (sanitized export), then the
   SAST/DAST runs in `docs/security/README.md`.
3. Fill slides 7–10 in `docs/event/PITCH_DECK_DRAFT.md` with the Day 3
   validation evidence.

## Safety and claims check

- [x] No target, sample or transformed copy was executed. The cancel/timeout
  probes use a fake shell script, never a target.
- [x] No `tools/`, `runs/`, keys or personal paths are in the change set.
  Screenshots were checked.
- [x] Demo transform is described as demonstration-only; no "protected" claim.
- [x] Every number in the deck draft comes from a recorded run.
