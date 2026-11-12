# Day 0 Hand-Off — Owner Baseline

## Baseline

- Version: `0.3.0-team`
- Branch: `main`
- Date: 7 November 2026
- Tests: 58 tests, 1 opt-in Ghidra skip; run the command below and record the
  actual current count.
- Platforms checked: Fedora (author), Windows (acceptance pending Day 1).

## Commands

```bash
python3 -m unittest discover -s tests -v
RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
python3 -m py_compile app.py analysis.py workflow.py engine.py discovery.py \
  rpm_ingest.py demo_protection.py binary_protection.py platform_support.py http_upgrade.py
node --check static/workbench.js
```

## Owner gate

- [ ] Private repo created; `main` protected; four collaborators invited.
- [ ] `tools/`, `runs/`, `backups/` not tracked.
- [ ] Lite release shape decided.
- [ ] Event account created; team invitations sent.
- [ ] Claims reviewed: no real-protection claim; dynamic analysis disabled.
- [ ] Deadline 12 November 2026 in the team calendar.

## Known baseline limitations

- Dynamic analysis disabled.
- Source protection is sample-only and demonstration-grade.
- Binary metadata hygiene is metadata-only (ELF/PE).
- Flatpak and RPM are Linux-only.
- Jobs are in memory; `runs/<job_id>/report.json` survives a restart.
- Reports can contain local paths; sanitizer is a Day 3 task.

## First action for Naser.

Pull `main`, run `setup.bat` and `run.bat` on Windows, then start D1-01.
