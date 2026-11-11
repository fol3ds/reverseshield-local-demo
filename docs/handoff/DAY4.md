# ReverseShield Day 4 handoff — Faisal → owner review

**Local candidate:** `0.5.0-team` on `feature/ollvm-protection`, 11 November 2026. **Not merged, tagged, publicly released, or submitted.** The existing `v0.4.0-team` GitHub draft uses older assets. Do not confuse it with this candidate. This handoff is an internal review record, not an approval or acceptance certificate.

## What is real

- Six bundled choices are available for static analysis. The sixth, `level-5-hardened`, is analysis-only for source transformations; five original sample sources are eligible for the demonstration transforms.
- Fedora browser jobs statically analyzed the hardened fixture and completed a Level 5 symbol-removal Compare job. Mitigation properties and the original/hardened ELF hashes are in `docs/evidence/hardening-level5.json`; no bundled sample ELF was executed on the host.
- Five original self-authored **separate driver builds** produced matching transcripts and zero exit codes inside a no-disk/no-network QEMU guest; the downloadable protected ELF was not executed. See `docs/evidence/ollvm-five-qemu.json`. This is narrow test-vector evidence, not general equivalence or resistance.
- The backend/UI identify OLLVM/QEMU as Linux-only; static ELF/PE functionality is separate. The Compare labels name their source; `N/A` is not zero.
- Consult `docs/evidence/CLAIM_EVIDENCE_DAY4.md` for every externally stated claim and `ACCEPTANCE_MATRIX_DAY4.md` for what has and has not been exercised. The exact suite result is recorded in `docs/evidence/verification.json`.

## Hard release gates (not represented as passed)

1. **Clean Windows acceptance, owner/Windows teammate:** use the exact local Lite ZIP and SHA-256 line in `dist/` after the owner approves sharing it with a teammate. Extract in a new non-admin Windows 10/11 account/folder; record OS build and `py -0p`; run `setup.bat` then `run.bat`; open the loopback page; select six samples; statically analyze the original and hardened Level 5 ELFs and a benign authorized PE; complete a supported Compare job; download and inspect a sanitized JSON report. Record failures and tool versions. Do not run selected targets. Confirm OLLVM unavailable in the UI. **Do not mark Windows passed based on old CI.**
2. **Owner review of local artifacts:** inspect the source diff, source ZIP entries/checksum, evidence-pack manifest, report/plan PDF pages and the silent demo draft/script. Strip all personal paths, tokens, raw `runs/` evidence, credentials and demonstration keys before anything leaves the machine. Check both binary filenames and message wording against the claim map.
3. **Resolve any acceptance failures and rerun automated tests.** Recorded for this tree: `RUN_GHIDRA_TESTS=1` → **167 tests, 1 skipped, OK** in `docs/evidence/verification.json`; re-run if anything changes.
4. **Only after approval:** decide whether to merge/push a branch, update the GitHub draft release, host a video/link, or submit event materials. No such operation is authorized by this handoff. The owner must independently read and accept event terms and verify the exact deadline/time zone.

## Local review checklist

- [ ] `docs/evidence/verification.json` shows **167 tests, 1 skipped, passed**; JS syntax check and `git diff --check` are clean.
- [ ] Six sample binary hashes match the reviewed index/ZIP; sixth hardening evidence hash matches the ELF.
- [ ] No raw run reports, downloaded tools, backup folders, secret files, old screenshots, internal handoffs or draft MP4 inside the Lite ZIP.
- [ ] Evidence ZIP contains only manifest-listed sanitized summaries and rendered final PDFs; PDF text visually checked.
- [ ] `docs/demo/` video draft is clearly labelled as draft; narration is owner-provided or separately scripted, never represented as the owner's recorded voice.
- [ ] Windows teammate returns reproducible results or a truthful blocker report.
- [ ] Owner signs off final wording, legal identity/team roster, third-party/IP rights and event declarations **tomorrow, not today**.

## Retro inputs

**Worked:** bounded static scope, self-authored fixtures, observable tool-origin Compare data, local evidence hashes, TDD fixes to sample eligibility and package selection. **Needs improvement:** clean Windows proof, end-user documentation/export review, and the limited meaning of QEMU test vectors. **Avoid next:** feature creep into dynamic third-party analysis, equating flag presence with safety, or publishing a package that was not verified after extraction.

**Owners:** Faisal owns final local integration and source diff; Naser/Zayed/Nomai can execute or witness a clean Windows check; the project owner decides any GitHub publication or event action. Fill the actual operator/date/result in the matrix rather than inventing them here.
