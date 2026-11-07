# ReverseShield — Day 1–4 Team Execution Plan

Version: `0.3.0-team` · Prepared: 7 November 2026
Project: **ReverseShield — Reverse-Engineering Exposure Workbench**
Event: **IS CyberNext 2026**, Cybersecurity track · registration closes
**12 November 2026** · final stage published for 1–3 December 2026 at Black Hat,
Riyadh (Black Hat 2026 is postponed; organisers will announce new dates).

This is the complete hand-off plan. Each day builds on the previous day's merged
work. The Fedora owner (project lead) reviews every pull request, runs the
Fedora checks, and merges before the next person starts.

## Team and order

| Order | Person | OS | Day | Branch | Hands to |
|---|---|---|---|---|---|
| 0 | Owner (you) | Fedora | setup/review | `main` | Naser |
| 1 | **Naser** | Windows | Day 1 | `day1-naser` | Zayed |
| 2 | **Zayed** | Windows | Day 2 | `day2-zayed` | Nomai |
| 3 | **Nomai** | Windows | Day 3 | `day3-nomai` | Faisal |
| 4 | **Faisal** | Windows | Day 4 | `day4-faisal` | Owner / event |

**Hard rules**

1. One branch per day; one pull request per day; no direct pushes to `main`.
2. The next person starts only after the owner merges the previous PR.
3. Never commit `tools/`, `runs/`, `backups/`, `.env`, keys or personal data.
4. Never execute the selected target, bundled sample or protected copy.
5. Do not describe the demo protection as real protection.
6. If a task cannot be completed, write the blocker in the hand-off file and
   propose the smallest safe fallback; do not silently skip it.

## Global definition of done

The four-day project is done when all of these are true:

- [ ] A clean Windows 10/11 machine can extract the Lite ZIP, run `setup.bat`
      and `run.bat`, and open <http://127.0.0.1:8765/>.
- [ ] A bundled sample completes analysis and a comparison report.
- [ ] `tests/fixtures/minimal-pe64.exe` is accepted as PE; a real Windows
      binary is discovered and analysed without being launched.
- [ ] A Fedora machine can pull `main`, run the same flow, and open the reports.
- [ ] The current automated suite passes; record the exact counts in the PR.
- [ ] SAST has no unresolved high/medium findings; DAST has no high findings.
- [ ] Reports shared outside the team are sanitized (no local paths, usernames,
      keys or command lines).
- [ ] The pitch deck, 2–3 minute video, report, plan and team details are ready.
- [ ] The IS CyberNext registration is submitted before 12 November 2026 and the
      confirmation is saved.
- [ ] Every claim in the submission matches observed evidence and limitations.

## Day 0 — Owner preparation (before Naser)

Do this before handing the project to the team.

| ID | Task | Acceptance |
|---|---|---|
| D0-01 | Freeze the baseline: run the full tests, record counts, tag/backup `main`. | Tests pass; backup outside Git. |
| D0-02 | Create the private GitHub repo, push `main`, invite Naser/Zayed/Nomai/Faisal, protect `main`. | All four can clone; PR required. |
| D0-03 | Remove `tools/`, `runs/`, `backups/` from the repo; confirm `.gitignore`. | Repo is small; no secrets/paths. |
| D0-04 | Create the event account and add the team; collect legal names, emails, LinkedIn, IDs only in the official form (never in Git). | Account ready; team added or invited. |
| D0-05 | Decide the release shape: Lite ZIP (source + docs, setup downloads tools) and optional Offline ZIP (tools included, shared by release asset). | Decision written in `docs/handoff/DAY0.md`. |
| D0-06 | Prepare a clean Windows test folder/account or ask a teammate to confirm one. | A clean-machine check is possible. |
| D0-07 | Read `docs/IS_CYBERNEXT_REQUIREMENTS.md`; confirm the claims and the 12 November deadline. | Owner signs off the claim list. |

**Owner gate before Day 1:** `main` is reproducible; a teammate can clone it;
the event deadline is in everyone's calendar.

---

# Day 1 — Naser: Windows baseline, PE validation, reproducibility

**Goal:** prove the project runs normally on Windows, accept PE files safely, and
leave a clean, reproducible baseline for Zayed.

**Branch:** `day1-naser` · **Time:** 8–10 hours · **Hand-off:** `docs/handoff/DAY1.md`

### D1-01 — Windows setup and first run (90 min)

**Why:** three of four teammates use Windows; the project must not depend on WSL.

**Steps**

1. Clone the repo with GitHub Desktop; choose a path without spaces.
2. Read `START_HERE.md`.
3. Double-click `setup.bat`; wait for Ghidra/JDK/MinGW downloads. Do not use
   Administrator rights.
4. Double-click `run.bat`; open <http://127.0.0.1:8765/>.
5. Run **Bundled sample → Level 5 → Analyze**.
6. Record every error, missing tool and confusing label in
   `docs/handoff/DAY1.md`.

**Acceptance**

- [ ] `setup.bat` completes or has a documented, reproducible workaround.
- [ ] `run.bat` opens the UI and the status panel loads.
- [ ] Level 5 completes with at least Ghidra; tools unavailable on Windows are
      clearly listed, not silently missing.
- [ ] No terminal window closes before the user can read an error.

**Files:** `setup.bat`, `run.bat`, `scripts/setup_windows.ps1`,
`START_HERE.md`, `platform_support.py`.

### D1-02 — PE acceptance and real Windows target (120 min)

**Why:** the team edits on Windows; analysis must accept PE without executing it.

**Steps**

1. In **Operate → Upload file**, upload `tests/fixtures/minimal-pe64.exe`.
   Confirm the target is labelled **PE** and analysis reaches the report.
2. In **Operate → Local path**, select the folder `C:\Windows\System32` or a
   smaller safe folder. Select **one** binary such as `notepad.exe`,
   `where.exe` or `curl.exe`. Do not launch it.
3. Confirm:
   - discovery accepts `.exe`/`.dll`;
   - PE header fields (class, machine, sections, entry point) appear;
   - `readelf` is skipped, not treated as a failure;
   - Ghidra and/or `objdump` run;
   - the report hash matches the file.
4. Add or update a Windows-only test if a real gap is found. Never add a test
   that launches the binary.

**Acceptance**

- [ ] PE fixture and one real Windows binary are analysed as data.
- [ ] No `WinError`, `FileNotFoundError`, or “not ELF” rejection for PE.
- [ ] The UI labels ELF vs PE clearly.
- [ ] The report contains no claim that the binary was executed.

**Files:** `analysis.py`, `discovery.py`, `engine.py`, `workflow.py`,
`http_upgrade.py`, `static/index.html`, `static/workbench.js`,
`tests/test_pe_support.py`.

### D1-03 — Make the test suite honest on Windows (90 min)

**Steps**

1. Run:
   ```bat
   py -3 -m unittest discover -s tests -v
   ```
2. Fix tests that assume Linux (`/bin/true`, `readelf`, `chmod`, POSIX paths,
   `os.name`) by skipping only when the dependency is genuinely unavailable.
3. Add a test for the Windows directory walker (`_scan_directory_windows`) using
   a temporary folder and the PE fixture.
4. Run the Ghidra opt-in test on Windows if Ghidra is installed:
   ```bat
   set RUN_GHIDRA_TESTS=1
   py -3 -m unittest tests.test_engine -v
   ```
5. Record exact pass/fail/skip counts in the PR.

**Acceptance**

- [ ] Full suite passes on Windows (skips are explained).
- [ ] Full suite passes on Fedora after the owner pulls the branch.
- [ ] No test executes a sample or target.
- [ ] The test count is recorded, not guessed.

### D1-04 — AI-readable comments and hand-off notes (90 min)

**Why:** the next teammate's AI agent must continue safely.

**Steps**

1. Read `docs/AI_CONTEXT.md`; fix anything that is inaccurate after your Windows
   changes.
2. Ensure every Python module has a top docstring: purpose, inputs/outputs,
   safety boundary, extension points.
3. Ensure every C sample starts with: purpose, input, output, safety note.
4. Ensure `static/workbench.js` has a section map and a “never use innerHTML”
   rule.
5. Add comments only where they explain **why**, not obvious syntax.
6. Update `README.md` with the Windows quick start and the exact test command.
7. Create `docs/handoff/DAY1.md` from the template.

**Acceptance**

- [ ] A new AI agent can answer: what runs, what never runs, where reports go,
      how to add a tool, how to run tests.
- [ ] Comments do not contradict the code.
- [ ] No personal paths or secrets in committed docs.

### D1-05 — Lite ZIP and Windows reproducibility (60 min)

**Steps**

1. Create `ReverseShield_Lite_Windows_Day1.zip` excluding `tools/`, `runs/`,
   `backups/`, `.git/`, `__pycache__/`.
2. Extract to a new folder on Windows; run `setup.bat` and `run.bat`.
3. Confirm the ZIP contains `START_HERE.md`, `setup.bat`, `run.bat`,
   `samples/bin/`, `tests/fixtures/`, docs and source.
4. Record the ZIP size and SHA-256 in the hand-off (do not commit the ZIP).

**Acceptance**

- [ ] A fresh extraction runs; no dependency on your user profile.
- [ ] The ZIP is under the event upload limit; if not, use a release link.
- [ ] No `tools/` or `runs/` in the ZIP.

### D1-06 — Event registration draft (60 min)

Do **not** submit yet; the owner reviews on Day 4.

1. Collect team legal names, emails, LinkedIn, participant categories and
   availability in a private file outside Git.
2. Draft answers for: problem, solution, technology, stage, participation,
   discovery, objective.
3. List supporting files: report PDF, plan PDF, demo video placeholder, repo or
   release link.
4. Check the event's current FAQ/Terms for language, in-person attendance, IP
   and eligibility. Write down uncertainties for the owner.
5. Save the draft as `docs/handoff/EVENT_DRAFT_DAY1.md` **without** IDs,
   passport numbers or private contact details.

**Acceptance**

- [ ] Draft is complete enough for the owner to finish.
- [ ] No sensitive identity data in Git.
- [ ] Deadline and missing answers are explicit.

### D1-07 — Hand-off to Zayed (30 min)

1. Push `day1-naser`; open the PR.
2. Fill `docs/handoff/DAY1.md`: branch, PR, tests, screenshots, known issues,
   Zayed's first three actions.
3. Tell Zayed to pull `main` after the owner merges.
4. Do not start Day 2 work on Day 1's branch.

**Day 1 owner gate**

```bash
python3 -m unittest discover -s tests -v
RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
node --check static/workbench.js
```

Open the UI; run Level 5 and the PE fixture; confirm no target execution; merge
the PR; tell Zayed.

---

# Day 2 — Zayed: analysis accuracy, evidence quality, usable demo

**Goal:** make the analysis more accurate and the UI usable for a timed demo.
Zayed starts from merged `main` (Naser's work).

**Branch:** `day2-zayed` · **Time:** 8–10 hours · **Hand-off:** `docs/handoff/DAY2.md`

### D2-01 — Content and structure metrics (150 min)

**Why:** file size and symbol counts are weak evidence; reviewers need content
signals.

**Steps**

1. Add **content metrics** to the analysis report for ELF and PE:
   - section count, executable/writable section count;
   - section entropy (bounded, computed from bytes; no execution);
   - import/export counts where available (PE import directory, ELF dynamic
     symbols);
   - string count by category (paths, URLs, messages, compiler notes);
   - debug/symbol presence as separate booleans;
   - Ghidra function/decompiled/call-edge counts as a separate source.
2. Do not merge ELF `.symtab` counts and Ghidra synthetic labels into one
   “symbols” number. Show `elf_symbols` and `ghidra_symbols` separately.
3. Add a `coverage` block: which tools ran, which were skipped and why, which
   outputs were truncated.
4. Keep all parsers bounded and deterministic; sort lists.
5. Add unit tests with the five samples and the PE fixture.

**Acceptance**

- [ ] Report shows separate ELF/PE and Ghidra counts.
- [ ] Entropy/import/export metrics are computed from file bytes only.
- [ ] A skipped tool is visible with a reason.
- [ ] Existing tests pass; new tests cover the metrics.

**Files:** `engine.py`, `analysis.py`, `workflow.py`, `static/workbench.js`,
`static/index.html`, tests.

### D2-02 — Ghidra quality and large-target handling (90 min)

**Steps**

1. Add/verify a per-run Ghidra option for analysis timeout and CPU limit.
2. For large targets (for example EasyEffects), make the UI warn before running
   Ghidra and offer a “lightweight tools only” choice.
3. Validate the Ghidra export: functions, decompiled functions, call edges,
   strings, truncation flags.
4. On cancellation, ensure the Ghidra process is terminated and the temp project
   is cleaned up.
5. Add a test with a timeout/cancel probe; do not run Ghidra on every test.

**Acceptance**

- [ ] Large-target warning and opt-out exist.
- [ ] Cancellation leaves no orphan Java/Ghidra process.
- [ ] Ghidra test passes with `RUN_GHIDRA_TESTS=1`.
- [ ] Ghidra timing is recorded in the report, not hidden.

### D2-03 — One-click demo and UI usability (150 min)

**Why:** the event demo must work in 2–3 minutes without hunting through forms.

**Steps**

1. Add a **Run demo** action that:
   - selects `Level 5 · Policy Engine`;
   - selects all bundled targets;
   - runs analysis with the relevant tools;
   - opens the report when complete.
   Do not auto-run anything on page load.
2. Add clear target format badges (`ELF`, `PE`), tool availability and a
   “Ghidra may take several minutes” warning.
3. Improve empty/error states: no source selected, no targets, failed job,
   cancelled job, port/server offline.
4. Keep keyboard focus visible; use buttons, labels and ARIA where needed.
5. Do not use `innerHTML` for backend strings; keep `textContent`.
6. Test in a fresh browser profile; no console errors.

**Acceptance**

- [ ] One click reaches a completed Level 5 report.
- [ ] A first-time user can explain what happened from the screen.
- [ ] Errors are actionable, not raw tracebacks.
- [ ] No target execution and no automatic scan on load.

### D2-04 — Comparison accuracy and reporting (90 min)

**Steps**

1. Normalize function matching by address first, then name; report unmatched
   functions instead of silently dropping them.
2. Show content metrics before/after (size, sections, entropy, imports/exports,
   strings by category).
3. Keep `N/A` for metrics that were not collected; never render missing data as
   zero.
4. Add a “what changed / what did not change” summary and a limitations box.
5. Fix any comparison labels that imply a security score.
6. Add tests for normalization, N/A and failure preservation.

**Acceptance**

- [ ] Before/after table is accurate and readable.
- [ ] Missing metrics are `N/A`.
- [ ] A failed reanalysis preserves the baseline and the transform state.
- [ ] No “protected” claim; use `symbol_removal_applied`,
      `demo_obfuscation_applied`, `binary_metadata_hygiene_applied`.

### D2-05 — Windows validation of Day 2 (60 min)

1. Pull `main` after Day 1 merge.
2. Run the new metrics on Level 5 and the PE fixture.
3. Run the one-click demo on Windows; capture screenshots.
4. Confirm no Windows-specific regression; update `START_HERE.md` if needed.
5. Record screenshots under `docs/assets/` (sanitized; no user paths).

### D2-06 — Pitch deck draft and hand-off (60 min)

1. Create `docs/event/PITCH_DECK_DRAFT.md` with the ten-slide outline from
   `docs/IS_CYBERNEXT_REQUIREMENTS.md`.
2. Fill slides 1–6 with real evidence and screenshots; leave 7–10 for Day 3.
3. Write the 3-minute demo script with exact clicks and timings.
4. Create `docs/handoff/DAY2.md`; push and open the PR.

**Day 2 owner gate:** tests, one-click demo, metrics on ELF/PE, screenshots, no
regressions; merge; tell Nomai.

---

# Day 3 — Nomai: security evidence, data-leak controls, performance

**Goal:** make the project defensible as a security project: SAST/DAST, report
sanitization, API hardening, and performance limits. This is also the day the
event narrative and video storyboard are finalized.

**Branch:** `day3-nomai` · **Time:** 8–10 hours · **Hand-off:** `docs/handoff/DAY3.md`

### D3-01 — SAST baseline and fixes (90 min)

1. Run and save:
   ```bash
   bandit -r . -x ./tools,./runs,./tests -f json -o docs/security/bandit-day3.json
   semgrep --config p/security-audit --config p/secrets --config p/python \
     --config p/javascript --json -o docs/security/semgrep-day3.json
   detect-secrets scan --all-files --exclude-files 'tools/.*' \
     > docs/security/detect-secrets-day3.json
   ```
2. Triage every medium/high finding; fix or document why it is a false positive.
3. Do not suppress a real issue to make the report green.
4. Add a short `docs/security/README.md` with commands, results and residual
   risks.

**Acceptance**

- [ ] No unresolved high/medium SAST findings.
- [ ] Findings are traceable to a fix or a written justification.
- [ ] Reports are committed without secrets/paths.

### D3-02 — DAST against the loopback server (90 min)

**Why:** the workbench is a web app; test it as one, locally and authorized.

1. Start the server on `127.0.0.1` only.
2. Run an OWASP ZAP baseline scan against `http://127.0.0.1:8765/` (or the
   installed ZAP equivalent). Keep it local; do not scan third-party sites.
3. Check manually:
   - state-changing calls without the session token are rejected;
   - cross-origin POSTs are rejected;
   - path traversal in report/artifact IDs is rejected;
   - malformed/oversized uploads fail closed;
   - error responses do not leak stack traces or absolute paths.
4. Save the ZAP report under `docs/security/zap-day3.html` (sanitized) and a
   summary in `docs/security/README.md`.
5. If ZAP cannot be installed, document the manual checks and the exact reason;
   do not claim a scan that did not run.

**Acceptance**

- [ ] No high findings; medium findings fixed or justified.
- [ ] Token/origin/traversal/upload tests pass.
- [ ] DAST scope is written down and local-only.

### D3-03 — Report sanitizer (120 min)

**Why:** current reports contain local paths, commands and the demo key.

1. Add `sanitize_report(report)` or a `scripts/export_clean_report.py` that
   removes/rewrites:
   - home directories (`/home/<user>`, `C:\Users\<user>`);
   - absolute run paths and usernames;
   - the demo key and `rs_key` value;
   - command lines that reveal local paths;
   - environment variables and temp paths.
2. Keep hashes, sizes, counts, tool names and evidence intact.
3. Add an API endpoint or CLI to download the sanitized report; never overwrite
   the original evidence.
4. Add tests: no `/home/`, no `C:\Users\`, no `0x9E3779B9`, no username, hashes
   unchanged.
5. Update the UI label: “Download sanitized report”.

**Acceptance**

- [ ] A sanitized report can be shared without leaking the workstation.
- [ ] Original `runs/<job>/report.json` remains unchanged.
- [ ] Tests cover Linux and Windows path patterns.

### D3-04 — Data-leak and secret controls (75 min)

1. Confirm `.gitignore` covers `tools/`, `runs/`, `backups/`, `.env`, keys,
   archives and caches.
2. Run `detect-secrets` and a manual search for tokens, emails, private keys and
   absolute paths in tracked files.
3. Ensure sample sources contain no real credentials, customer data or internal
   hostnames.
4. Ensure upload errors do not echo file contents or paths.
5. Document the data-flow: target bytes stay local; no cloud calls; no telemetry.
6. Add a “privacy” section to `README.md` and `START_HERE.md`.

**Acceptance**

- [ ] No secrets in tracked files.
- [ ] No telemetry/network upload from the app.
- [ ] Reports can be sanitized before sharing.
- [ ] Privacy claims match the code.

### D3-05 — API security tests (90 min)

Add tests for:

- missing/invalid token on POST/PUT/DELETE;
- wrong `Origin`/`Referer`;
- path traversal in artifact/report names;
- symlinked target and symlinked run directory;
- oversized `Content-Length` and short body;
- malformed ELF/PE headers;
- malformed JSON and unknown methods;
- job cancellation and repeated polling.

**Acceptance**

- [ ] Every case returns a safe error and does not create files outside `runs/`.
- [ ] Tests run on Linux and Windows (skip POSIX-only cases with a reason).
- [ ] No stack traces in HTTP responses.

### D3-06 — Performance and limits (75 min)

1. Measure Level 5, the PE fixture and a large Linux target (EasyEffects if
   available) with and without Ghidra.
2. Record wall time, output size and truncation flags.
3. Confirm limits: 64 MiB target, bounded tool output, Ghidra timeout, max jobs,
   scan-entry cap.
4. Add a UI warning for large files and a “lightweight tools only” path.
5. Document results in `docs/performance.md`; do not claim speed that was not
   measured.

**Acceptance**

- [ ] Large targets do not freeze the server or fill the disk.
- [ ] Truncation is visible in the report.
- [ ] Measured numbers are recorded with the machine/OS.

### D3-07 — Event narrative, video storyboard, hand-off (60 min)

1. Complete slides 7–10 of the pitch deck: safety, validation, impact, roadmap,
   team.
2. Finalize the 3-minute video storyboard with exact screens and narration.
3. Prepare a “what we do not claim” slide/section.
4. Create `docs/handoff/DAY3.md`; push and open the PR.

**Day 3 owner gate:** SAST/DAST results, sanitizer tests, API tests, performance
numbers, storyboard; merge; tell Faisal.

---

# Day 4 — Faisal: final integration, release, event submission

**Goal:** turn the merged work into a reproducible release and submit the event
package before the deadline. Faisal is the last hand-off; the owner co-signs.

**Branch:** `day4-faisal` · **Time:** 8–10 hours · **Hand-off:** final release

### D4-01 — Cross-platform acceptance matrix (90 min)

Run and record:

| Check | Windows 10/11 | Fedora |
|---|---|---|
| Clean extract + `setup.bat` | | |
| `run.bat` / `python3 app.py` | | |
| Status panel loads | | |
| Level 5 analysis | | |
| PE fixture analysis | | |
| Real Windows binary analysis (no launch) | | |
| Symbol-removal comparison | | |
| Demo-blinding comparison | | |
| Binary hygiene comparison | | |
| Sanitized report download | | |
| Full test suite | | |
| No console/browser errors | | |

Fix only release blockers; move nice-to-haves to the roadmap.

### D4-02 — Demo polish and video (120 min)

1. Rehearse the 3-minute script three times; cut anything that does not fit.
2. Record at 1080p with a clean desktop, no notifications and no personal data.
3. Use a Windows machine for the setup/PE segment and Fedora for the
   comparison/report segment if possible.
4. Show the limitations explicitly; do not overclaim.
5. Upload as an unlisted/public link; test it in a private browser window.
6. Capture 5–8 sanitized screenshots for the deck/report.

**Acceptance**

- [ ] Video is 2–3 minutes, audible, readable, and shows a complete workflow.
- [ ] No secrets, paths, usernames or unrelated windows.
- [ ] The link works without team login.

### D4-03 — Release package and checksums (90 min)

1. Update `VERSION` and `CHANGELOG.md`.
2. Build:
   - `ReverseShield_Lite_Windows.zip` — source, docs, samples, setup/run, no
     `tools/`;
   - optional `ReverseShield_Offline_Windows.zip` — includes tools; share as a
     release asset, not Git.
3. Generate `SHA256SUMS.txt`.
4. Test the Lite ZIP on a clean Windows folder/account.
5. Confirm no `runs/`, `backups/`, `.git/`, keys or personal paths.
6. Create Git tag `v0.3.0-team` and a GitHub Release with the assets and
   release notes.

**Acceptance**

- [ ] A new user can reproduce the demo from the release instructions.
- [ ] Checksums match the uploaded assets.
- [ ] The release does not contain analysis evidence or secrets.

### D4-04 — Event submission (120 min)

1. Open the live registration form; re-check the deadline and FAQ.
2. Fill:
   - primary applicant and three team members;
   - project title and one-line pitch;
   - problem, solution, technology, stage;
   - participation/discovery/objective answers;
   - supporting PDFs, video link, repository/release link or ZIP.
3. Upload `ReverseShield_Project_Report_and_Plan.pdf` and the plan PDF.
4. Review declarations, IP/third-party rights and the accuracy of every claim.
5. Submit **before 12 November 2026**; save the confirmation page/email.
6. Send the confirmation and any organiser reply to the owner; do not post
   private links publicly.

**Acceptance**

- [ ] Submission confirmation saved.
- [ ] Team members receive a copy of what was submitted.
- [ ] No sensitive identity data in Git or the public release.

### D4-05 — Final documentation sync (60 min)

1. Update `README.md`, `START_HERE.md`, `docs/AI_CONTEXT.md` and the event docs
   with final test counts, features and limitations.
2. Add a “known limitations” section:
   - static only; dynamic disabled;
   - source protection sample-only; demonstration-grade;
   - binary hygiene metadata-only;
   - Flatpak/RPM Linux-only;
   - in-memory job list resets on restart;
   - large apps may need Ghidra opt-out.
3. Add a short “how to verify this release” section with commands and expected
   outcomes.
4. Ensure all links resolve and no placeholder text remains.

### D4-06 — Final hand-off and retro (45 min)

1. Create `docs/handoff/DAY4.md`: release link, checksums, test counts, event
   confirmation, known issues, next steps.
2. The owner runs the final Fedora gate and merges.
3. Tag the final merge if not already tagged.
4. 15-minute retro: what worked, what to improve, who owns the next milestone.

**Day 4 owner gate:** release reproducible, event submitted, tests pass, claims
clean. Then archive the evidence and stop changing `main` until the event.

---

# A–Z roadmap (how the days fit together)

| Letter | Workstream | Where | Outcome |
|---|---|---|---|
| A | Agree scope and claims | Day 0 | No “real protection” claims |
| B | Baseline and repo | Day 0 | Reproducible `main` |
| C | Discovery | already + Day 1 | Flatpak/folder/ELF/PE/RPM inputs |
| D | ELF/PE parsing | Day 1–2 | Format-aware metadata |
| E | Static tools | existing | `file`, `readelf`, `objdump`, `strings`, `nm` |
| F | Ghidra | existing + Day 2 | Functions, pseudocode, call edges |
| G | Live jobs | existing | Events, progress, cancellation |
| H | Evidence storage | existing | Snapshots, logs, reports, hashes |
| I | Comparison | existing + Day 2 | Before/after with N/A and coverage |
| J | Demo protections | existing | Sample-only transform or binary hygiene |
| K | Accuracy metrics | Day 2 | Entropy, imports/exports, separate counts |
| L | UI usability | Day 2 | One-click demo, badges, errors |
| M | Windows | Day 1 | Native setup/run/PE |
| N | Tests | every day | Current suite + PE/Windows tests |
| O | SAST | Day 3 | Bandit/Semgrep/detect-secrets |
| P | DAST | Day 3 | Local ZAP/manual API checks |
| Q | Data-leak controls | Day 3 | Sanitizer, privacy, secrets |
| R | Performance | Day 3 | Limits and measured timings |
| S | Documentation | Day 1–4 | AI context, hand-offs, README |
| T | Packaging | Day 4 | Lite/Offline ZIP, checksums |
| U | Video | Day 4 | 2–3 minute demo |
| V | Event registration | Day 1 + 4 | Submitted before deadline |
| W | Release | Day 4 | Tag and GitHub Release |
| X | Rehearsal | Day 4 | Three timed runs |
| Y | Submission | Day 4 | Confirmation saved |
| Z | Retro/roadmap | Day 4 | Next milestones |

## Event-gap mapping

| Gap | Task(s) |
|---|---|
| Windows native validation | D1-01, D1-02, D1-03, D4-01 |
| Analysis accuracy | D2-01, D2-02, D2-04 |
| One-click demo/UI | D2-03, D4-02 |
| SAST/DAST | D3-01, D3-02 |
| Report/data leakage | D3-03, D3-04 |
| API hardening | D3-05 |
| Performance/large targets | D3-06 |
| Pitch/video/team narrative | D2-06, D3-07, D4-02, D4-04 |
| Packaging/reproducibility | D1-05, D4-03 |
| Registration/deadline | D1-06, D4-04 |
| Claim discipline | Day 0, every hand-off |

## Suggested daily schedule (Riyadh time)

| Time | Block |
|---|---|
| 09:00–10:30 | Deep work: the day's main code task |
| 10:30–10:45 | Break |
| 10:45–12:30 | Second code task / tests |
| 12:30–13:30 | Break |
| 13:30–15:30 | UI/docs/event work |
| 15:30–16:30 | Test, screenshots, hand-off file |
| 16:30–17:00 | Push PR; notify owner |

If a teammate has less than 8 hours, do the acceptance-critical tasks first:
D1-01/02/03/07, D2-01/03/06, D3-01/03/07, D4-01/03/04.

## Risks and fallbacks

| Risk | Fallback |
|---|---|
| `setup.bat` download blocked | Use the offline release asset or manual links in `scripts/setup_windows.ps1`; do not disable antivirus globally. |
| No MinGW/GCC on Windows | Analysis still works via Ghidra; disable source protection and binary hygiene in the UI; document it. |
| Ghidra too slow on a large app | Select one target; choose lightweight tools only; record the trade-off. |
| Windows tests fail on POSIX assumptions | Skip only with an explicit reason; add a Windows-specific test. |
| Teammate cannot use Git | ZIP fallback in `docs/GITHUB_WORKFLOW.md` §7; owner reviews the diff. |
| Event deadline slips | Submit the best available package by 12 November; keep improvements for the final stage. |
| Video cannot be recorded | Use screenshots + a live demo; upload a slide-based walkthrough; tell the owner. |
| Last-minute merge conflict | Owner resolves; no force-push; re-run the full gate. |

## Final acceptance summary

- [ ] Naser: Windows + PE + tests + hand-off.
- [ ] Zayed: accuracy + one-click UI + comparison + deck draft.
- [ ] Nomai: SAST/DAST + sanitizer + API tests + performance + storyboard.
- [ ] Faisal: matrix + video + release + event submission.
- [ ] Owner: Fedora gate + merge + final claim review.

**Do not submit a claim you cannot demonstrate in the video or report.**
