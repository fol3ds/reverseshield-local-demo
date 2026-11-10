# ReverseShield — Pitch Deck Draft (Day 2)

Owner: Zayed (slides 1–6) → Nomai (slides 7–10, Day 3) → Faisal (final deck
and video, Day 4).
Outline source: `docs/IS_CYBERNEXT_REQUIREMENTS.md` §7.
Rule: every number on a slide must come from a recorded run. The numbers
below come from Day 2 runs of the bundled Level 5 sample (Linux, binutils
2.42, Ghidra 12.2) on 9 November 2026. Re-check them on the Windows demo
machine before recording; tool versions can shift counts slightly.

---

## Slide 1 — Title

- **ReverseShield — Reverse-Engineering Exposure Workbench**
- One line: *See what a reverse engineer can recover from your build, before
  you ship it.*
- Team: Owner (lead, Fedora) · Naser · Zayed · Nomai · Faisal *(confirm the
  final 4 registered names; the event allows at most 4)*
- IS CyberNext 2026 · Cybersecurity track

**Visual:** the Operate page with the "Run demo · Level 5" panel
(`docs/assets/day2-demo-button.png`).

## Slide 2 — Problem: what binaries leak

- A compiled program is not a black box. Our 16 KB Level 5 sample, a normal
  debug build, contains:
  - **35** symbol-table entries (function and variable names);
  - **14** file and folder names, **4** of them inside a developer's home
    folder (`/home/<user>/…`), so a real user name is visible;
  - **7** compiler/build notes;
  - full debug sections and a build-ID note.
- From that one file, Ghidra recovers **13 functions**, **10** of them as
  readable pseudocode, and **6 call edges**, in about **9 seconds** on a
  laptop.
- Who cares: small software teams, students and vendors who ship binaries
  without ever seeing the attacker's view.

**Visual:** metrics table from `docs/assets/day2-demo-report-metrics.png`
(crop the "What someone could learn from this file" cards).

## Slide 3 — Current practice and why it is hard

- Full reverse-engineering suites (Ghidra, IDA, Binary Ninja) are powerful,
  but they take expert time and give no before/after view of a release.
- Release checklists say "strip symbols" but rarely measure what changed.
- Cloud scanners mean uploading proprietary builds to a third party.
- **Gap:** no lightweight, local, evidence-first check that a developer can
  run in minutes on Windows or Linux.

## Slide 4 — Solution: a local evidence workbench

- Pick a source: bundled sample, local folder, ELF/PE file, RPM or upload.
- Run six static tools: `file`, `readelf`, `objdump`, `strings`, `nm` and
  Ghidra headless. Every event is shown live.
- Read the evidence: functions, symbols, strings, pseudocode, call graphs and
  CFGs, plus **content metrics** computed from the file bytes (sections,
  entropy, imports/exports, string categories, debug flags).
- Compare a release-hygiene change on a **copy**: before/after table,
  "what changed / what did not", and functions matched by address, then name.
- **Never executes the target.** Loopback only. No cloud upload. No
  "security score".

## Slide 5 — Architecture

```text
source → discovery (metadata only) → selection → authorized job
       → run-local snapshot copy (hash-checked, never executable)
       → static adapters (+ Ghidra with time & CPU limits)
       → content metrics from bytes + coverage (ran / skipped / unavailable)
       → optional transform of the copy → re-analysis → comparison
       → browser UI + JSON report
```

- Python standard library + Ghidra headless + vanilla HTML/JS (no frameworks).
- Windows 10/11 and Fedora. Setup downloads tools into the project folder;
  no admin rights.

**Visual:** `docs/assets/architecture.png` and `docs/assets/pipeline.png`.

## Slide 6 — Demo evidence: Level 5 before/after

Measured on the same Level 5 sample (all six tools, Ghidra included):

| Metric | Original | Symbol removal | Binary hygiene | Demo constant blinding |
|---|---|---|---|---|
| File size (bytes) | 16,088 | 10,784 | 9,960 | 20,120 |
| ELF symbol-table entries | 35 | 0 | 0 | 40 |
| Strings (byte scan) | 135 | 60 | 35 | 128 |
| · file/folder names | 14 | 1 | 1 | 13 |
| · paths inside a user home folder | 4 | 0 | 0 | 1 (rebuilt on the demo PC) |
| · compiler notes | 7 | 5 | 1 | 8 |
| Debug sections | present | absent | absent | present |
| Build-ID note / compiler comment | present | present | absent | present |
| Ghidra symbols | 101 | 68 | 60 | 110 |
| Ghidra functions decompiled | 10 | 8 | 8 | 9 |
| Functions matched by address / name | — | 11 / 0 (9 renamed) | 11 / 0 (9 renamed) | 0 / 13 |

What it shows:

- **Metadata hygiene works for what it targets.** Symbols, debug info,
  paths and compiler notes drop sharply.
- **It does not hide the logic.** Ghidra still decompiles 8 functions after
  stripping. The demo constant-blinding build still decompiles 9.
- The tool says this plainly. No transform is labelled "protected"; every
  report carries `behavior_verified: false`.

**Visual:** `docs/assets/day2-compare-symbol-removal.png`.

---

## Slides 7–10 — for Nomai (Day 3)

7. **Safety and responsible use:** no execution, loopback, authorization
   checkbox, sample-only source transforms. Cite
   `docs/security/DAY2_SECURITY_REVIEW.md` (4 issues fixed on Day 2; open
   items with mitigations).
8. **Validation:** test counts (Windows + Fedora), SAST/DAST results, Ghidra
   opt-in test.
9. **Impact and roadmap** (from `docs/ROADMAP.md`; say "next", not "done"):
   - **Hardening checks:** is PIE/NX/RELRO/stack canary (Linux) or
     ASLR/DEP/CFG (Windows) turned on? Each missing flag shows the CWE it
     helps prevent and the compiler flag that fixes it.
   - **Known-vulnerable components:** find embedded library versions
     (OpenSSL, zlib, curl…) and match them offline to CVEs as "possible
     match — verify".
   - CI integration, Mach-O/APK/DEB, sanitized evidence packs, sandboxed
     adapters (RS-06).
10. **Team, ask, contact.**

---

## 3-minute demo script (exact clicks)

Before recording: run `run.bat`, open `http://127.0.0.1:8765/`, press
**Refresh** in *Analysis tools* and confirm all six tools say AVAILABLE. Close
other windows and notifications. Use a folder path with no user name visible.

| Time | Screen / click | Say |
|---|---|---|
| 0:00–0:15 | Title slide | "A build can reveal more than its source code. ReverseShield shows that exposure before release." |
| 0:15–0:25 | Browser: **Operate** tab, point at *Execution boundary* panel | "Everything is local. The file is read as data; it is never run." |
| 0:25–0:35 | Click **Run demo · Level 5** | "One click picks our Level 5 sample, a small policy engine, and starts six static tools." |
| 0:35–0:55 | Monitor page shows live events (auto) | "Each tool's output streams live: readelf, objdump, strings, nm, then Ghidra's decompiler." |
| 0:55–1:20 | Demo returns to **Operate → Report**; point at the *What someone could learn from this file* cards | "From one 16 KB file: 35 names, debug info, 14 file and folder names — four of them show a developer's home folder — and readable code for 10 of 13 functions." |
| 1:20–1:35 | Click the **Recovered code** tab, choose `policy_allows` | "This is what an analyst reads: near-source pseudocode." |
| 1:35–1:45 | **Change to apply to the copy** → *Remove symbol names* · tick the permission box · click **Make copy & compare** | "Now a common release step: strip symbols, on a copy only." |
| 1:45–2:15 | **Compare** tab: *What changed* box, then the metrics table | "Names 35 to 0, file and folder names 14 to 1, no home-folder paths left, debug info gone, file a third smaller." |
| 2:15–2:35 | Scroll to *Function matching* and *Limitations* | "But Ghidra still decompiles 8 functions. Stripping hides names, not logic. We say that plainly; there is no fake security score." |
| 2:35–2:50 | Click **Download full report (JSON)** | "Every run keeps a hash-checked report: evidence, tool versions and limitations." |
| 2:50–3:00 | Closing slide | "Windows and Linux, local-first, built by our team. Next: CI integration and sandboxed adapters." |

Fallback: if Ghidra is slow on the demo PC, set **Which tools to run → Let
me choose** and untick Ghidra, or press **Skip Ghidra**. The metrics, strings
and symbols parts of the story still work.
