# Day 3 — Nomai hand-off

Date: 11 November 2026. Input: supplied ReverseShield Day 2 archive.
Working deliverable: Day 3 source package; original archive unchanged.
Intended branch: `day3-nomai`. No commit/push/PR was made: the supplied repository
returned HTTP 404 anonymously and an authenticated GitHub connection is pending.
Faisal is the owner; team = Faisal, Naser, Zayed, Nomai (four total).

## Task status

| Task | Result |
|---|---|
| D3-01 SAST | Complete locally: Bandit 28 low; Semgrep one justified developer-CLI false positive; secret scan four false positives. No unresolved medium/high scanner finding. See security README. |
| D3-02 DAST | Complete locally: scoped ZAP spider/passive scan and 21 HTTP checks; 0 high/medium/low alerts, 4 informational. Additional regression tests exercise negative cases. |
| D3-03 Sanitizer | Implemented and tested: separate summary export, CLI, authenticated download, no original mutation. |
| D3-04 Privacy | Secret exclusions, error redaction, data-flow/retention documentation and source review complete. This is not a full Git-history audit. |
| D3-05 API security | Implemented/tested: all API tokens, Origin/Referer/Host/fetch-site checks, safe methods/errors, malformed upload/JSON/body tests, traversal, cancellation/polling, linked storage controls. Windows symlink-creation test is explicitly skipped for missing privilege. |
| D3-06 Performance | Level 5 + PE with/without Ghidra measured; bounds and warnings verified. Real large Linux target and Fedora execution remain for Faisal. No cumulative disk quota is claimed. |
| D3-07 Narrative/handoff | English slides 7–10, exact three-minute storyboard, claim boundaries and event review complete. GitHub PR pending authenticated access. |

## Validation

Final Windows suite with Ghidra enabled: **98 total, 81 passed, 17 skipped,
0 failures, 0 errors**, 28.257 s. Seven engine checks including the real Ghidra
export passed. Windows process-tree timeout/cancel probes now pass rather than
being skipped. Skips: 8 legacy Linux HTTP cases, 5 Flatpak cases, 2 POSIX
filesystem cases, 1 RPM dependency case, 1 symlink privilege case.

ZAP's initial two medium CSP findings and version-disclosure low findings were
fixed and a clean session rerun verified the fixes. Semgrep's earlier rule
timeout was resolved with a 30 s limit; final scan errors/timeouts = 0.
Evidence: `docs/security/` and `docs/performance-day3.json`.

## Faisal's next actions

1. Compare the patch/package against the actual merged Day 2 branch, then open
   `day3-nomai` for review. Do not overwrite unrelated repository changes.
2. On Fedora: run the full suite with Ghidra enabled, verify the browser download,
   run a real large Linux target with/without Ghidra, and record exact results.
3. Complete Day 4 clean-machine/release checks, render the final deck/report and
   record/rehearse the English video. Historical PDFs are not current Day 3 proof.
4. Confirm the principal presenter, judge access to supporting links and private
   applicant details; submit through the official form by 12 November. No event
   registration or legal declaration has been submitted by this task.

## Known boundaries

Static-only; no selected binary execution. Demo transforms do not prove real
protection. No CVE verdict, enterprise IAM, general DLP, response automation or
cyber recovery claim. Raw reports stay private; sanitized exports omit free-form
evidence but still require human review. Same-user malware, parser isolation,
storage quota and third-party toolchain trust remain documented residual risks.
