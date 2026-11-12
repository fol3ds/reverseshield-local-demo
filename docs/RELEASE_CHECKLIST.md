# Release and privacy checklist

This checklist preserves unresolved warnings from the retired team handoffs.
Deleting internal documentation is not release approval or privacy clearance.
The source cleanup started from `f08ddedda21cfd5fd31e378bf99e00f1bfe07e6f`.
Historical evidence files describe their recorded tree and date, not fresh
verification of a later commit.

## Before changing repository visibility or publishing artifacts

- [ ] Review the full Git history for sensitive material. The earlier handoff
  explicitly recorded that original report PDF bytes could remain in history
  and that history had not been rewritten. Removing files at the branch tip
  does not remove them from older commits. No history clearance is claimed.
- [ ] Review PDFs, Office documents, screenshots, binaries and archive contents,
  not only extracted text. Earlier PDF pages were rasterized during cleanup;
  text search alone cannot clear the images or embedded document metadata.
- [ ] Exclude raw `runs/`, downloaded `tools/`, backups, credentials, tokens,
  personal paths and demonstration keys from shared artifacts. Sanitized report
  exports still require human review; changed binaries are not sanitized reports.
- [x] Select the project license: MIT, with the owner's confirmation that all four
  contributors agree. Copyright holders are listed in the root `LICENSE` file.
- [ ] Review third-party attribution and redistribution terms separately. Keep
  `THIRD_PARTY_NOTICES.md` with the source; upstream licenses remain unchanged.
- [ ] Confirm the intended commit, version and release assets. The historical
  `v0.4.0-team` draft is not approval of newer source or evidence. Do not publish,
  rewrite history, submit event materials or change visibility without the owner's
  explicit approval.

## Verification of the exact candidate

- [ ] Run the automated suite and JavaScript syntax check on the final candidate.
  Record actual output, skips, interpreter and tested commit; do not reuse old
  totals as proof of a changed tree. Ghidra integration is an explicit opt-in.
- [ ] Build the Lite ZIP from reviewed indexed files, inspect every entry and its
  checksum, extract it into an empty folder and verify the extracted copy.
  Required evidence fixtures must match the bundled sample bytes.
- [ ] Complete clean native-Windows manual acceptance: non-admin extraction,
  compatible Python, `setup.bat`, `run.bat`, loopback UI, six sample choices,
  original/hardened ELF and authorized benign PE static analysis, a supported
  Compare operation, and an inspected sanitized JSON download. Record tool
  versions and failures. CI success is not a replacement for this manual test.
- [ ] Verify Fedora/browser download behavior and measure any claimed large Linux
  target with and without Ghidra. Historical sample/PE timings do not establish
  performance for a large installed application.
- [ ] Resolve any acceptance failures and repeat relevant checks after changes.
  See `evidence/ACCEPTANCE_MATRIX_DAY4.md` and `evidence/CLAIM_EVIDENCE_DAY4.md`;
  their historical results and pending checks must remain clearly scoped.

## Boundaries that must remain visible

- Selected targets, bundled sample executables and transformed artifacts are
  never launched on the host. The optional Linux-only OLLVM workflow tests
  separate deterministic drivers inside a no-disk/no-network QEMU guest, not
  the downloadable protected ELF. Matching vectors are not full equivalence.
- Native-Windows OLLVM/QEMU support is unavailable. The sixth hardened fixture
  is for static analysis, not a sixth source-transformable sample.
- Mitigation flags and metadata reduction are observations, not a security
  score, certification, vulnerability verdict or proof of protection.
- Parser isolation, same-OS-user threats and third-party tool/PATH/installer
  trust remain residual risks. Loopback/token controls are not a malware sandbox
  or multi-user IAM. Tool download provenance still requires review.
- There is no cumulative disk quota, encrypted evidence store or automatic run
  retention. Monitor storage and clean unwanted runs with the server stopped.

## Cleanup scope

The straightforward team/event notes, obsolete reports/screenshots and raw
historical scanner outputs were removed from the source tree. A private local
archive was made before removal; it is not a release asset. AI architecture
notes, historical review material requiring consolidation, optional screenshots,
document/video builders and their tests were retained for a separate decision.
Historical raw scanner filenames in retained evidence are provenance, not
promises that those outputs are still shipped. No release was published and
no Git history was rewritten by this cleanup.
