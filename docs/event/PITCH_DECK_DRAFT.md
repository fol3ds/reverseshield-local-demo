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
- Team: Faisal (owner, Fedora) · Naser · Zayed · Nomai *(confirm the
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

## Slide 7 — Safety and shareable evidence

- Target binaries are read, never executed; operations work on copies.
- Token-authenticated API reads/writes plus same-origin loopback checks.
- Bounded input, tool output and Ghidra execution; visible missing coverage.
- Sanitized export omits raw text/code and retains hashes and measurements.
- Local-only is not a sandbox: hostile parsers and same-user malware remain risks.

Speaker: “Our safety claim is specific: we never launch the selected program.
We keep original evidence locally and share a reduced, sanitized summary.”

## Slide 8 — Validation with traceable evidence

Use exact current counts from `docs/handoff/DAY3.md`, with pass and skip counts
separate. Show `docs/security/README.md` and `docs/performance.md` rather than
reusing earlier test counts. Windows results are measured here; Fedora remains
Faisal's required verification. The API negative tests exercise missing tokens,
foreign origins, traversal, malformed uploads, cancellation and export integrity.
SAST checks our implementation; it does not prove every analyzed binary safe.

## Slide 9 — Users, impact and next steps

For analysts: inspect authorized ELF/PE files and compare measurable exposure.
For developers: identify debug metadata and path leakage before sharing builds.
For both: export reproducible evidence without raw workstation data.

Next, not implemented: platform hardening checks (PIE/NX/RELRO, ASLR/DEP/CFG),
offline component/CVE hints requiring analyst verification, CI integration and
process isolation. Validate usefulness with analyst/developer pilot sessions;
do not claim commercial adoption or measured customer benefit yet.

## Slide 10 — Team and ask

Faisal: owner, Fedora validation and release. Naser: Windows/PE baseline.
Zayed: metrics and demo usability. Nomai: API security, privacy and validation.
Four members total. Principal presenter to be confirmed by the team.

Ask: feedback from application-security teams and developer pilot users.
Repository: https://github.com/fol3ds/reverseshield-local-demo
Confirm judge access before submitting a private repository link.

### What we do not claim

No automatic vulnerability/exploitability verdict; no malware sandbox;
no production obfuscation or reverse-engineering resistance score; no enterprise
IAM, universal DLP, incident response or cyber recovery. “Demo constant blinding”
is educational; binary hygiene removes metadata, not program logic.

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
| 2:35–2:50 | Click **Download sanitized report** | "The shareable summary keeps hashes, metrics and coverage while omitting raw output, commands and recovered code. The original evidence stays local." |
| 2:50–3:00 | Closing slide | "Windows and Linux, local-first, built by our team. Next: CI integration and sandboxed adapters." |

Fallback: if Ghidra is slow on the demo PC, set **Which tools to run → Let
me choose** and untick Ghidra, or press **Skip Ghidra**. The metrics, strings
and symbols parts of the story still work.


Day 3 recording note: the numerical comparison above is historical Day 2
evidence, not a new benchmark. Precompute the comparison for a reliable
three-minute recording and identify it as a completed run. Never imply that a
long Ghidra job completed instantly; show a labelled cut or lightweight fallback.
Avoid showing raw logs, local paths or recovered strings in the public recording.
Use the sanitized export and measurement table for the public evidence segment.
