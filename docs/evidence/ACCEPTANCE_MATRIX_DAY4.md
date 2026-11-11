# Day 4 cross-platform acceptance matrix — local candidate

**Status:** not signed off. Branch `feature/ollvm-protection`, version `0.5.0-team`. Results below describe this local branch on Fedora 43 unless explicitly labelled historical. The Windows CI result from merged `main` does **not** verify this unmerged branch or a clean Windows installation. No arbitrary target or bundled sample was executed on the host.

| Check | Fedora 43 local evidence | Native Windows 10/11 | Release gate |
|---|---|---|---|
| Clean extract + setup | Existing working-tree installation, not a clean extract | **Not manually tested** | Test Lite ZIP in an empty folder on a Windows account |
| `run.bat` / `python3 app.py` | Loopback server ran at `127.0.0.1:8765`; browser connected | **Not manually tested** | Run `setup.bat`, `run.bat`, check port and UI |
| Status and six-sample catalog | Fresh browser check on 11 November: loopback page loaded with Operate/Compare/Monitor/Read Me navigation and six `level-*` sample options | **Not manually tested** | Confirm catalog, formats and installed-tool status |
| Original Level 5 static analysis | Real Fedora analysis/Compare job reached Done | **Not manually tested** | Analyze sample without executing it |
| Hardened Level 5 static analysis | Real browser job completed; hardening rows observed, analyze enabled, source transform disabled | **Not manually tested** | Confirm ELF fixture is selectable/readable but source transforms unavailable |
| PE fixture static analysis | Unit/API fixture coverage exists; no fresh Day 4 browser PE run recorded | **Not manually tested** | Analyze PE fixture through UI on native Windows |
| Real Windows PE static analysis | Not run on Fedora for Day 4 | **Not manually tested** | Authorized benign PE, never launch it |
| Symbol-removal comparison | Level 5 UI job reached Done, four qualified Compare labels observed | **Not manually tested** | Repeat on clean Windows account |
| Demo constant-blinding comparison | Tests exist; no fresh Day 4 browser run recorded | **Not manually tested** | Run on a copy and inspect report |
| Binary-hygiene comparison | Tests exist; no fresh Day 4 browser run recorded | **Not manually tested** | Run on one selected ELF/PE copy, verify original hash |
| Sanitized report download | Route and tests exist; no fresh Day 4 download inspection recorded | **Not manually tested** | Open downloaded JSON, check redaction and retained hashes |
| OLLVM + QEMU | Five separate deterministic driver builds matched in a no-disk/no-network guest; `docs/evidence/ollvm-five-qemu.json` | **Unavailable on native Windows** by design | Linux optional feature; do not claim Windows support |
| Full test suite | **Final run after all edits: 167 tests, 1 skipped, OK** with `RUN_GHIDRA_TESTS=1`, Fedora 43, Python 3.14.7; log hash recorded in `docs/evidence/verification.json`. | **Not run on clean Windows for this branch** | Re-run after any further change and record the exact output |
| Bundled-sample privacy | All six ELF fixtures rebuilt; DWARF `DW_AT_comp_dir` is `.` and paths are `./samples/src/...`; new privacy suite passes | **Not manually tested** | Rebuild samples only through `build_samples.py` |
| Current-tree SAST | Bandit 1.9.4: 8,859 LOC, 0 high / 3 medium / 113 low, mediums confined to tests; detect-secrets: only checksums/test fixtures. See `docs/evidence/SECURITY_REVIEW_DAY4.md` | — | Re-run after code changes; Semgrep/ZAP not fresh |
| QEMU harness scope | Separate deterministic driver builds; `artifact_behavior_verified: false`; hash-only evidence regenerated | **Unavailable on native Windows** by design | Never present as downloadable-artifact behavior proof |
| Browser console/errors | Catalog and jobs rendered; JS asset returned 200; no comprehensive console capture after final edits | **Not manually tested** | Clean-profile asset/console check |
| Package extraction/checksum | Built from the staged Git index: **101 entries**, six ELF fixtures mode `0600`, `run.sh` executable; extracted copy ran the suite: **167 tests, OK (7 skipped** without optional Ghidra/xollvm/QEMU). SHA-256 in `dist/SHA256SUMS.txt`. | **Not manually tested on Windows** | Fresh Windows extraction and `setup.bat`/`run.bat` remain owner/teammate gates |

**Windows limitation (D4-12):** Linux-only xollvm/LLVM 22 and QEMU micro-VM drivers are not bundled or supported on native Windows. The API reports OLLVM unavailable there, and the UI explains why. Windows may still analyze ELF/PE statically and use supported copy-only profiles when prerequisites exist; a clean-machine manual acceptance run remains necessary. GitHub Actions is a separate CI signal, not a substitute for manual Windows evidence.

**Security boundary:** Mitigation presence is not proof of safety. Matching deterministic QEMU transcripts do not establish general equivalence. Raw `runs/` reports and changed binaries must not be uploaded as shareable evidence.
