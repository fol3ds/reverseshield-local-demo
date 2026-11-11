# Day 4 claim → evidence map (local candidate)

Use these scoped statements in the demo and draft submission. Evidence is generated locally; **do not substitute the historical Day 2/3 report for the current branch**. A test or status label is not a security certification.

| Claim permitted | Evidence in this branch | What it does **not** establish |
|---|---|---|
| The workbench analyzes authorized ELF/PE bytes statically. | `engine.py`, `workflow.py`, `tests/test_engine.py`, `tests/test_app_api.py`; Fedora browser job for `level-5-hardened`. | Parser isolation from hostile files or proof every external target is benign. |
| Host-selected targets are not intentionally launched. | Snapshot/tool argv implementation in `workflow.py` and `engine.py`; static-analysis tests; browser labels. | Absence of all parser vulnerabilities or sandbox-grade isolation. |
| Six bundled sample choices are shown. | `samples.py`; `tests/test_app_api.py`; live Fedora sample selector showed six options. | Six source-transformable samples: **only the original five** are eligible for OLLVM/source transforms. |
| The hardened Level 5 fixture has five observed ELF mitigation properties. | `docs/evidence/hardening-level5.json` with sample SHA-256, bytes, NX/PIE/RELRO/canary/FORTIFY states and underlying header/import indications; `tests/test_hardening.py`. | A security score, coverage of every function, exploitation resistance, or behavioral equivalence with Level 5. |
| The original Level 5 already had NX, but lacked some other observed properties. | Original entry in `docs/evidence/hardening-level5.json`: NX present; PIE absent, RELRO partial, canary and FORTIFY absent. | An exploitable vulnerability; this is a compiler/linker property comparison. |
| Copy-only binary hygiene reduces metadata. | `binary_protection.py`, `tests/test_binary_protection.py`; compare tests. | Rewriting code, fixing a CWE, or preventing decompilation. |
| Compare metrics identify tool-derived counts and missing values. | `workflow.py` metric labels, `static/workbench.js` caveat, `tests/test_metrics.py`, `tests/test_workflow.py`; live Fedora Level 5 symbol-removal Compare job reached Done. | A scalar protection score; increases or decreases alone do not measure resistance. |
| OLLVM produced transformed copies of **five self-authored samples**, and **separate deterministic driver builds** matched in QEMU. | `docs/evidence/ollvm-five-qemu.json` (five sample IDs, `scope: separate_deterministic_drivers`, exit codes, transcript and driver hashes); `tests/test_ollvm_protection.py`; `behavior_qemu.py`. | Full equivalence, behavior of the downloadable `protected.elf`, third-party-target execution, native Windows support or an unbreakable binary. |
| The six bundled ELF fixtures contain no developer home/build path in DWARF. | `tests/test_sample_build_privacy.py`, rebuilt `samples/bin/*.elf`, `build_samples.py` prefix maps. | That binaries are otherwise free of identifying metadata or secrets. |
| The current tree passed a fresh Bandit/detect-secrets scan. | `docs/evidence/security-day4.json` and `SECURITY_REVIEW_DAY4.md`: Bandit 1.9.4, 8,859 LOC, 0 high / 3 medium / 113 low; detect-secrets 1.5.0 findings only checksums and test fixtures. | Security of the application, security of analyzed binaries, Semgrep, or a fresh ZAP scan. |
| Native Windows OLLVM is unavailable. | `ollvm_protection.available()` platform guard, `tests/test_ollvm_protection.py`, `static/index.html`, `static/workbench.js`. | A complete native-Windows manual test of other workbench features. |
| Authenticated local browser requests and sanitized report route are implemented. | `http_upgrade.py`, `sanitize_report.py`, API security tests and prior Day 3 review. | Multi-user IAM, protection from same-OS-user malware, or a universally safe report; inspect exports before sharing. |
| Fedora automated tests pass. | `docs/evidence/verification.json`: **167 tests, 1 skipped, passed**, Ghidra enabled, plus the log SHA-256. | Clean Windows installation or external-user usability. |
| A local Windows Lite ZIP can be built from reviewed indexed files. | `scripts/package_lite_windows.py`, `tests/test_package_selection.py`, later `dist/SHA256SUMS.txt` and archive inventory. | A published release or a successful clean native-Windows setup; both remain gated. |

## Claims to avoid

- “Secure”, “unhackable”, “vulnerabilities fixed”, “behavior-equivalent”, or a single resistance/security score.
- “Tested on native Windows” until a teammate supplies a clean-machine transcript.
- “Released”, “submitted”, “event accepted”, or “video published” before the owner completes those actions.
- “Six OLLVM samples”: the sixth hardened fixture is for static analysis only.

The owner should verify each final submission sentence against this map and the exact packaged candidate before approving any publication.
