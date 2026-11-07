# GitHub Desktop Workflow — ReverseShield Four-Person Hand-Off

Goal: Naser finishes Day 1 and hands a working project to Zayed; Zayed hands to
Nomai; Nomai hands to Faisal. The Fedora owner reviews and merges every hand-off.
Use **GitHub Desktop** only; no command line is required for the team.

## 1. One-time owner setup (Fedora, before Day 1)

1. Create a **private** GitHub repository named `reverseshield-local-demo`.
2. Do **not** upload `tools/`, `runs/` or `backups/`; `.gitignore` already
   excludes them.
3. Push `main` as the baseline. Confirm `VERSION` says `0.3.0-team`.
4. Invite the three teammates: **Settings → Collaborators → Add people**.
5. Protect `main`: **Settings → Branches → Add branch protection rule** →
   require a pull request before merging; do not allow force pushes.
6. Create the first release later (Day 4), not now. Keep the repository small.
7. Give each teammate the repository URL and the Windows setup instructions in
   `START_HERE.md`.

### Why not send ZIPs by email/WhatsApp?

- `tools/` is roughly 1.2 GB and cannot go through email or WhatsApp.
- `.exe`/`.elf`/ZIP attachments are often blocked or quarantined.
- Sequential ZIP editing causes merge conflicts and silently loses work.
- Git keeps history, authorship and review; it is the hand-off evidence.

If a teammate cannot use GitHub, use the ZIP fallback in §7.

## 2. Every teammate: first-time setup

1. Install **GitHub Desktop** from <https://desktop.github.com/>.
2. Sign in with the GitHub account the owner invited.
3. **File → Clone repository → GitHub.com → reverseshield-local-demo**.
4. Choose a short local path **without spaces**, for example
   `C:\Projects\reverseshield-local-demo`.
5. Click **Fetch origin**, then **Pull origin** if available.
6. Read `START_HERE.md` and run `setup.bat` once.
7. Confirm `run.bat` opens <http://127.0.0.1:8765/> and a bundled sample runs.

## 3. Daily hand-off pattern

Each day uses one branch and one pull request:

| Day | Owner | Branch | PR into |
|---|---|---|---|
| 1 | Naser | `day1-naser` | `main` |
| 2 | Zayed | `day2-zayed` | `main` |
| 3 | Nomai | `day3-nomai` | `main` |
| 4 | Faisal | `day4-faisal` | `main` |

Nothing is merged directly into `main` by a teammate. The owner reviews, runs
the tests in Fedora, and merges. The next teammate starts only after the merge.

### Start a day

1. Open GitHub Desktop.
2. **Fetch origin**, then **Pull origin** on `main`.
3. **Branch → New branch**; use the exact branch name above.
4. Do the tasks in `docs/TEAM_TASKS_DAY1-4.md`.
5. Test before committing.

### Commit and publish

1. Review the **Changes** list. Never commit `tools/`, `runs/`, `backups/`,
   `.env`, keys, private screenshots or personal data.
2. Write a summary such as `Day 1: Windows PE setup and analysis accuracy`.
3. Click **Commit to day1-naser**.
4. Click **Publish branch** (first push) or **Push origin**.
5. On GitHub, click **Compare & pull request**.
6. Fill the PR template:
   - what changed;
   - how it was tested (commands and screenshots);
   - known issues;
   - hand-off notes for the next person.
7. Request the owner as reviewer; do not merge your own PR.

### Owner review gate

- Pull the branch locally or use **GitHub Desktop → Current branch**.
- Run:
  ```bash
  python3 -m unittest discover -s tests -v
  RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
  python3 -m py_compile app.py analysis.py workflow.py engine.py discovery.py \
    rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py
  node --check static/workbench.js
  ```
- Open the UI, run one bundled sample and one PE sample, check the report.
- Merge the PR, then tell the next teammate to pull `main`.
- If tests fail, request changes; do not “fix forward” on `main`.

## 4. What each teammate must leave for the next

Create `docs/handoff/DAY<N>.md` from `docs/handoff/TEMPLATE.md` and include:

- branch name and PR link;
- what works and what does not;
- exact commands used;
- screenshots/GIF paths;
- test output (pass/fail counts);
- known bugs and workarounds;
- next person's first three actions;
- any event/deadline notes.

The next person must be able to start without asking “what did you do?”.

## 5. Avoiding conflicts

- Pull `main` before creating your branch.
- One person edits one area at a time; announce shared files
  (`workflow.py`, `static/workbench.js`, `README.md`) in the team chat.
- Do not reformat whole files; make small patches.
- Never force-push or delete `main`.
- If GitHub Desktop shows a conflict, stop and ask the owner; do not delete
  files blindly.
- Keep generated reports in `runs/` (ignored) and share only sanitized copies.

## 6. Windows-specific checks

Before opening a PR, a Windows teammate must confirm:

- `setup.bat` completes without Administrator rights;
- `run.bat` opens the UI;
- a bundled sample completes analysis;
- `tests/fixtures/minimal-pe64.exe` is accepted as **PE**;
- a real Windows binary (for example `C:\Windows\System32\notepad.exe`) is
  discovered and analysed **without launching it**;
- source protection is either working with MinGW or clearly disabled with a
  message;
- no absolute Windows paths, usernames or keys appear in a shared screenshot.

## 7. ZIP fallback (only if Git is impossible)

If a teammate cannot use GitHub:

1. Pull the latest `main` first.
2. Create a ZIP that excludes `tools/`, `runs/`, `backups/`, `.git/` and
   `__pycache__/`.
3. Name it `ReverseShield_Day<N>_<Name>.zip`.
4. Include `HANDOFF.md` with the base commit, changed files, tests and known
   issues.
5. Send by a shared drive the owner controls; never post a public link.
6. The owner unzips into a separate folder, reviews the diff, and copies only
   reviewed files into `main`; never overwrite the whole project blindly.
7. Record the source commit in the merge commit message.

ZIPs are a last resort because they lose history and make conflicts likely.

## 8. Release discipline

- Version: `0.3.0-team` for the hand-off edition.
- Tag after Day 4: `v0.3.0-team`.
- Release assets:
  - `ReverseShield_Lite_Windows.zip` — source, docs, samples, setup scripts, no
    `tools/`;
  - `ReverseShield_Offline_Windows.zip` — optional, includes tools; large;
  - `ReverseShield_Project_Report.pdf` and `ReverseShield_Plan.pdf`;
  - `SHA256SUMS.txt`.
- Never attach `runs/` or a report containing personal paths/keys.
- Test the release ZIP on a clean Windows account before sharing.
