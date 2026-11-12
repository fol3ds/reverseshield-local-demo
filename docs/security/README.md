# Day 3 security evidence — 11 November 2026

Historical record of the delivered Day 3 source tree, not a fresh audit of the
cleaned repository. Raw scanner/test exports were archived privately and are
no longer shipped; the historical counts below were not regenerated during
source cleanup. The original review did not cover Git history. See
`../RELEASE_CHECKLIST.md` for preserved privacy and acceptance gates.

| Check | Observed result | Disposition |
|---|---|---|
| Windows full suite, Ghidra enabled | 98 total: 81 passed, 17 skipped, 0 failed/errors | Pass for executed cases; platform skips remain visible |
| Bandit 1.9.4 | 28 low, 0 medium/high | Accepted subprocess/tooling review below |
| Semgrep 1.185.0 | 387 rules, 78 targets, 1 finding, 0 errors/timeouts | One false positive justified below; no suppression |
| detect-secrets 1.5.0 | 4 candidates, 0 real credentials identified | Two published checksums and two synthetic test fixtures |
| ZAP 2.17.0 | 21 explicit HTTP checks passed; 0 high/medium/low, 4 informational alerts | Local scoped spider/passive scan; not a full active scan |

The earlier ZAP pass found missing CSP form-action, unnecessary inline-style
permission and server version disclosure. The final pass verifies their fixes.
Informational findings: Modern Web Application (one) and Suspicious Comments
(three). Public source comments describe behavior; no secret values are needed
in those comments. These alerts were retained in the historical exported report, now archived.

## Reproduction

From the project root, install scanners in a separate environment. Keep scanner
environments, tool distributions and raw sessions outside the deliverable.

```sh
python -m unittest discover -s tests -v
RUN_GHIDRA_TESTS=1 python -m unittest discover -s tests -v
node --check static/workbench.js
bandit -r . -x ./tools,./runs,./tests -f json -o bandit-local.json
semgrep scan --config p/security-audit --config p/secrets --config p/python --config p/javascript --timeout 30 --timeout-threshold 0 --metrics=off --disable-version-check --no-git-ignore --exclude tests --exclude runs --exclude '*.json' --json -o semgrep-local.json .
detect-secrets scan --all-files --exclude-files '(^|[\/])(tools|runs|.git|__pycache__)[\/]|baseline\.json$|day3\.json$' > secrets-local.json
python scripts/zap_local.py --zap-home /path/to/ZAP --java /path/to/java --work /private/zap-work --output /private/zap-results
```

On PowerShell use `$env:RUN_GHIDRA_TESTS='1'` before the unittest command.
The optional ZAP helper requires `requests`; the application still uses the
Python standard library. It creates and shuts down a temporary loopback server,
never scans a supplied remote URL, and exports sanitized alert summaries.
Official ZAP download: https://www.zaproxy.org/download/
Verified portable ZIP SHA-256:
`94c8f767b1c2e94f0db66b3ae56514d5e3f5a728ee1b6c798e0c8fe2d61fbff0`.

Semgrep's final run includes document builders and the optional scanner helper.
It excludes tests, run evidence and JSON evidence, and skips two files larger
than its 1 MiB limit. A previous default-timeout run timed out on one JS rule;
the final 30-second-per-rule run completed without errors. Do not reuse the
earlier zero-finding scan as the final result.

## Finding-by-finding triage policy

Detailed Bandit findings and file/line references were preserved in the private
archive rather than shipped in the product source.
B404 (11) flags subprocess imports; B603 (14) flags argv tool launches;
B607 (3) flags document-builder tool names resolved through PATH. These call
trusted compilers/static analyzers, document tools or the operator-selected
Java executable, not the selected binary. No shell=True is used. Document
generation is a developer action, not an HTTP route. Tool-installation/PATH
trust remains an explicit residual risk. No findings were silenced.

Semgrep rule `python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args` at `scripts\zap_local.py` line 83:
the CLI operator selects a Java installation to launch ZAP. This is not an
HTTP-controlled input or a shell command. The helper resolves and validates
the Java executable name, uses a separate argument list with `shell=False`,
and accepts no remote scan target. An operator already able to choose an
executable has the authority to run it. Classified as a false positive for
command injection in this developer-only helper; retained in raw findings.

detect-secrets candidates are all retained: `scripts/setup_windows.ps1:42`
and `:56` are public SHA-256 integrity pins; `tests/test_security_day3.py:29`
is a dummy fixture value, and `:49` is a deliberately invalid private-key
marker used to test redaction. None is a working credential. A manual text
review found no new workstation username or private key material in delivered
source/docs. Synthetic fixture names and public contact details are intentional.

## Controls and residual risks

- RS-05: token required for API reads/writes; status no longer discloses it;
  document bootstrap has same-origin checks, no-store and no-referrer.
- RS-09: authenticated sanitized summary endpoint/CLI and browser downloads;
  raw evidence is unchanged. Labels/raw text/code/artifacts are omitted, known
  paths and secret patterns redacted. Human review is still required.
- RS-12: legacy writes require the same token; legacy tool output now uses
  the bounded streaming runner rather than unbounded capture.
- Linked run paths/download files and linked discovery inputs are rejected.
  This is not a hardened boundary against a hostile process with the same OS
  account, including filesystem replacement races.
- Static parsers/Ghidra are not isolated in a sandbox (RS-06). Analyze only
  authorized benign inputs. Trusted tool installations remain necessary
  (RS-07); installer provenance work remains part of the release review (RS-08).
- No cumulative disk quota/automatic retention (RS-10); monitor and clean
  stopped runs. Windows executable filenames are not an OS execution barrier
  (RS-11). The application never launches those files.
- API tokens are local browser request protection, not multi-user IAM.
- Fedora, real large Linux target performance, clean-machine setup and final
  browser/video rehearsal remain release gates. There was no external pentest.
