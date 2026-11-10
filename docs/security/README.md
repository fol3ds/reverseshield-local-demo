# Security Checks and Evidence

This folder records the project's own security checks. They are supporting
evidence, not a certification.

## Current baseline (7 November 2026)

| Check | Result | File |
|---|---|---|
| Bandit | 15 low, 0 medium, 0 high (initial baseline) | `bandit-baseline.json` |
| Semgrep (`p/security-audit`, `p/secrets`, `p/python`, `p/javascript`) | 0 findings | `semgrep-baseline.json` |
| detect-secrets | 0 findings | `detect-secrets-baseline.json` |
| ZAP/DAST | Not executed yet; Day 3 task D3-02 | — |
| Day 2 manual review + Bandit re-run (9 Nov) | 12 findings: 4 fixed, 8 open with mitigations; Bandit 27 low / 0 medium / 0 high | `DAY2_SECURITY_REVIEW.md` |

The interface is loopback-only, state-changing calls require a per-session
token and a same-origin check, and the selected target is never executed.

## Day 3 commands

```bash
bandit -r . -x ./tools,./runs,./tests -f json -o docs/security/bandit-day3.json
semgrep --config p/security-audit --config p/secrets --config p/python \
  --config p/javascript --json -o docs/security/semgrep-day3.json
detect-secrets scan --all-files --exclude-files 'tools/.*' \
  > docs/security/detect-secrets-day3.json
```

Run DAST only against the local server:

```bash
python3 app.py
# in another terminal, with an installed ZAP:
zap-baseline.py -t http://127.0.0.1:8765/ -r docs/security/zap-day3.html
```

Do not scan third-party sites. Do not treat a green report as proof that the
application is secure.

## Residual risks to re-check

- The local API has no multi-user authentication; do not bind it to a network.
- Ghidra and binutils parse untrusted bytes; isolate genuinely hostile inputs.
- `runs/` reports can contain local paths and command lines; sanitize before
  sharing.
- The demo protection profile is not a real obfuscator and must not be sold or
  described as one.
