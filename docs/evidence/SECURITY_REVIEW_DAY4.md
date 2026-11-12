# Day 4 security validation — current local tree

**Date:** 11 November 2026. **Scope:** Python source, tests and scripts on this branch; `tools/`, `runs/`, `backups/`, `.git/` and bundled binary fixtures excluded. Machine-readable summary: `security-day4.json`. Raw outputs stay under `runs/day4-qa/` and are not for sharing.

## What actually ran

| Check | Tool / version | Result |
|---|---|---|
| Python SAST | Bandit **1.9.4** (project-local venv `tools/day4-qa`) | 8,859 LOC scanned; **116 findings: 0 high, 3 medium, 113 low** |
| Secret scan | detect-secrets **1.5.0** | Findings only in evidence hashes, setup-script checksums and deliberate sanitizer fixtures |
| ZAP DAST | Not run in this pass | Day 3 ZAP results describe an older tree; raw output was archived privately during source cleanup |
| Semgrep | Not installed | Not run; do not describe as current |

## Disposition of the five notable findings

- **B404 ×26, B603 ×58, B607 ×24 (low)** — expected in a tool orchestrator: `subprocess` with argv lists, `shell=False`, fixed/validated tool paths and timeouts. Verified in `engine.py`, `workflow.py`, `behavior_qemu.py`, packaging and setup helpers.
- **B314 ×2 (medium, tests)** — `tests/test_day4_documents.py` parses the project's *own generated* DOCX to assert content. Not untrusted uploader XML.
- **B108 ×1 (medium, tests)** — a literal `/tmp/private/a` string used as sanitizer test data; no file is created or opened.
- **B105 ×2, B101 ×2, B405 ×1 (low)** — test fixtures and `assert` usage in tests.
- **detect-secrets** — SHA-256 digests in `hardening-level5.json` / `ollvm-five-qemu.json`, archive checksums in `setup_ollvm.sh` / `setup_windows.ps1`, the historical Day 3 report, and the intentional `ghp_…`/private-key markers in `test_security_day3.py`. **No live credential found.**

## Boundaries

This is SAST of the project's own code. It does not prove the application is secure, does not analyze the binaries the workbench inspects, and does not replace the Day 3 scoped ZAP baseline. Parser isolation for hostile ELF/PE input remains future work (RS-06). Re-run these scans after any further code change; the reviewed content is this working tree, not a tagged release.
