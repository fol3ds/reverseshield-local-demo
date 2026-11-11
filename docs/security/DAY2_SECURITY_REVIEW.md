> Day 3 follow-up: see `README.md` in this directory for current fixes and evidence.

# ReverseShield — Day 2 Security Code Review

Reviewer: Zayed (Day 2, with AI assistance) · Date: 9 November 2026 (Riyadh)
Scope: every Python module, `static/workbench.js`, `ghidra_scripts/`,
`setup.bat`, `run.bat`, `run.sh` and `scripts/setup_windows.ps1` at
`0.3.0-team` plus the Day 2 changes.
Method: manual code reading, Bandit (27 low, 0 medium, 0 high), targeted
tests, and checking third-party tools against public CVE records.

This is a review, not a certification. Nomai's Day 3 tasks (SAST/DAST,
sanitized export) should start from the open items below.

## How to read this

- **CWE**: the general weakness type (a catalogue of bug classes).
- **CVE**: a specific, published vulnerability in a named product. Most
  findings in our own code have **no CVE**, because CVEs are only assigned to
  released products. When a CVE is listed, it is either in a third-party tool
  we run, or a public CVE that shows the same weakness class elsewhere. The
  table says which.
- **Severity** is for *this* tool: a local, loopback-only workbench run by
  the person analysing the file. High = could run attacker code without
  unusual user action. Medium = needs a plausible setup (shared PC, hostile
  input). Low = needs local write access or an unusual user action.

## Summary

| ID | Finding | CWE | CVE | Severity | Status |
|---|---|---|---|---|---|
| RS-01 | `cmd.exe` / `taskkill` started by bare name (search-path hijack) | CWE-427 | Same class as CVE-2019-17664 (Ghidra) | Low | **Fixed Day 2** |
| RS-02 | Command injection through `cmd.exe` when launching `analyzeHeadless.bat` | CWE-78, CWE-88 | CVE-2024-3566 ("BatBadBut") | Medium | **Fixed Day 2** |
| RS-03 | UNC network path in *Local path* makes Windows contact another host (NTLM leak) | CWE-918 | Same class as CVE-2023-23397 | Low | **Fixed Day 2** |
| RS-04 | Windows folder scan follows NTFS junctions | CWE-59 | — | Low | **Fixed Day 2** |
| RS-05 | Local API reads need no token; `/api/status` gives the token to any local process | CWE-306 | — | Medium (shared PC) / Low | Open → Day 3 |
| RS-06 | Hostile ELF/PE/RPM bytes parsed by binutils, Ghidra and rpm | CWE-787, CWE-125 | CVE-2025-0840, CVE-2014-8485, CVE-2021-20266 | Medium | Open (mitigated in part) |
| RS-07 | An older Ghidra found on `PATH` is preferred over the pinned project copy | CWE-1104 | CVE-2023-22671, CVE-2019-17664 (older Ghidra) | Low | Open |
| RS-08 | MinGW download checked against a hash fetched from the same place; skipped if empty | CWE-494 | — | Medium | Open → Day 4 packaging |
| RS-09 | Local paths and user names in reports, logs and error messages | CWE-200, CWE-209 | — | Low | Partly fixed (UI); open → Day 3 |
| RS-10 | Uploads and run folders are never cleaned (disk exhaustion) | CWE-770 | — | Low | Open |
| RS-11 | Windows artifacts stored and downloaded with a runnable `.exe` name | — (hardening) | — | Low | Open |
| RS-12 | Legacy `/api/analyze/*` routes: no token, no `--` before the file path | CWE-352, CWE-88 | — | Low / info | Open |

## Fixed in Day 2

### RS-01 — Uncontrolled search path for `cmd.exe` and `taskkill`

- **Where:** `platform_support.command_for()` built `["cmd.exe", "/c", …]` and
  `terminate_tree()` ran `["taskkill", …]`.
- **Problem:** Windows `CreateProcess` looks in the *current folder* before
  `System32` when given a bare program name. `run.bat` starts Python from the
  project folder, so a `cmd.exe` or `taskkill.exe` placed in that folder (a
  tampered ZIP, a shared drive) would run instead of the real one. Ghidra had
  the same bug class: **CVE-2019-17664** (Ghidra ≤ 9.0.4 ran `cmd.exe` from its
  working directory).
- **Fix:** `system_executable()` resolves `%SystemRoot%\System32\cmd.exe` and
  `taskkill.exe` to absolute paths. `cmd.exe` also gets `/d`, which turns off
  registry AutoRun commands.
- **Test:** `tests/test_security_day2.py::WindowsLauncherTests`.

### RS-02 — Command injection through `cmd.exe` argument parsing (BatBadBut)

- **Where:** Ghidra is launched on Windows as
  `cmd.exe /c analyzeHeadless.bat <project> … <target> …`. All of these paths
  sit under the project folder.
- **Problem:** `cmd.exe` re-reads its command line. Python's quoting does not
  protect `&`, `|`, `<`, `>`, `^`, `%` or `!`. If the project is extracted to a
  folder such as `C:\Users\<name>\Downloads\R&D\reverseshield`, the `&` splits
  the command: Ghidra breaks, and a crafted folder name runs a second command.
  This is the "BatBadBut" class (**CVE-2024-3566**; the Rust fix was
  CVE-2024-24576). Python documents the behaviour but has no CVE or fix, so the
  application must defend itself.
- **Fix:** `command_for()` refuses any argument containing a `cmd.exe`
  metacharacter and returns a clear message ("move the project to a folder
  without these characters"). `engine._analyze_ghidra()` records this as a
  Ghidra `tool_error`, so the other tools' evidence is kept.
- **Tests:** `WindowsLauncherTests` and `RefusedGhidraLaunchTests`.

### RS-03 — UNC paths cause outbound SMB authentication

- **Where:** *Local path* discovery (`http_upgrade._discover`). The Day 2 UI
  also now accepts Windows drive paths such as `C:\…`.
- **Problem:** A path like `\\attacker.example\share\app` makes Windows open
  an SMB connection and offer the user's NTLM credentials. Someone who
  persuades a user to paste such a path can capture or relay that hash. The
  well-known example of this class is **CVE-2023-23397** (Outlook). There is
  no CVE for our code.
- **Fix:** The server and the browser client both refuse `\\…` and `//…`
  paths: "Copy the files to a local folder first."
- **Test:** `tests/test_security_day2.py::UncPathTests`.

### RS-04 — NTFS junctions followed during folder scans

- **Where:** `discovery._scan_directory_windows()` skipped symlinks only.
- **Problem:** `Path.is_symlink()` is `False` for NTFS junctions. A junction
  inside the chosen folder could lead the scan to another part of the disk
  (CWE-59, link following).
- **Fix:** `_is_link_like()` also rejects junctions (`os.path.isjunction`,
  Python 3.12+) and any reparse point (`FILE_ATTRIBUTE_REPARSE_POINT`).
- **Test:** `tests/test_security_day2.py::JunctionTests`.

## Open findings and recommended mitigations

### RS-05 — Missing authentication on local API reads (CWE-306)

`GET /api/status` returns the per-session token to any caller on the machine.
`GET /api/jobs`, `/api/jobs/<id>/report` and `/artifact` need no token. On a
shared PC (lab machine, event laptop) another local user or process can list
jobs, download reports (strings, pseudocode, local paths) and use the token to
discover any file readable by the person running the server. DNS-rebinding,
cross-site and framing attacks are **already blocked**: the `Host`, `Origin`
and `Sec-Fetch-Site` checks, CSP `frame-ancestors 'none'` and
`X-Frame-Options: DENY`.

**Mitigation:**

1. Generate the token at start-up, print it, and open the browser at
   `http://127.0.0.1:8765/#token=…`. The page reads it from the fragment,
   which is never sent to the server.
2. Require `X-ReverseShield-Token` on *all* `/api/*` routes, including GET,
   and stop returning the token from `/api/status`.
3. Document "single-user machine only" in START_HERE until this is done.

### RS-06 — Third-party parsers process hostile bytes (CWE-787, CWE-125)

The workbench never runs targets, but `objdump`, `readelf`, `nm`, `strings`,
`strip`, `objcopy`, Ghidra and `rpm`/`rpm2cpio` all parse attacker-controlled
bytes. Memory-safety bugs in those parsers are common:

- **CVE-2025-0840**: stack buffer overflow in `objdump` (`disassemble_bytes`,
  GNU binutils ≤ 2.43).
- **CVE-2014-8485**: `strings` used libbfd and could be driven to memory
  corruption by a crafted file. ReverseShield already calls `strings -a`,
  which scans the raw file and avoids the BFD path.
- **CVE-2021-20266**: missing bounds check when `rpm` reads a corrupted
  package header (out-of-bounds read).

**Already in place:** argv-only execution (no shell), timeouts, output caps,
process-tree kill, a run-local copy, no network flags.

**Mitigation:**

- Keep binutils ≥ 2.44 (Fedora/Windows MinGW builds) and Ghidra 12.x current.
  Record tool versions in each report; this already happens.
- Run the adapters as a separate low-privilege user, or inside a
  container/bubblewrap (Linux) or Windows Sandbox/AppContainer.
- Add memory limits: `RLIMIT_AS` on POSIX, a Job Object on Windows.
- Keep the README statement that hostile inputs need isolation.

### RS-07 — Ghidra version and source not enforced (CWE-1104)

`engine.inventory()` tries `analyzeHeadless` on `PATH` before the project's
pinned `tools/ghidra/ghidra_12.2_PUBLIC`. An old system Ghidra would be used
silently. Older Ghidra releases have published bugs: **CVE-2023-22671**
(`launch.sh` passed input to `eval`, command injection, Ghidra ≤ 10.2.2) and
**CVE-2019-17664** (see RS-01). Ghidra 12.2 is not affected.

**Mitigation:** prefer the project-local copy, refuse versions below a
minimum (for example 11.0), and show a warning badge in the tool list.

### RS-08 — Download integrity for setup (CWE-494)

`scripts/setup_windows.ps1` pins SHA-256 hashes for Ghidra and the JDK. The
Ghidra hash was re-checked on Day 2 and matches. MinGW is checked against a
`.sha256` file downloaded from the same release, so a tampered release passes.
The check is also skipped when that file is empty. `setup.bat` uses
`-ExecutionPolicy Bypass`, which is normal for a local script but means
nothing else vets it.

**Mitigation:** hard-code the MinGW SHA-256 like the other two downloads and
fail closed when a hash is missing or does not match.

### RS-09 — Sensitive data in reports and errors (CWE-200, CWE-209)

`report.json` contains absolute paths (`command`, `work_directory`, snapshot
paths). These can include Windows user names. Raw tool output and error
strings such as `[Errno 2] … 'C:\Users\<name>\…'` are shown as-is.

- **Day 2 change:** the Compare view shows commands with folder names
  removed.
- **Day 3 (D3 sanitized export):** export a copy with
  `<PROJECT>`/`<RUN>` placeholders, drop `work_directory` and log paths, and
  map OS errors to messages without paths.

### RS-10 — Unbounded storage (CWE-770)

Each upload can be up to 256 MiB, and RPM payloads up to 512 MiB. They are
kept under `runs/inputs/` until deleted by hand.

**Mitigation:** delete inputs when their selection expires, cap the total
size of `runs/` (for example 2 GiB), and add a "Clear old runs" action.

### RS-11 — Runnable artifacts on Windows (hardening)

Uploaded PE files are stored as `input.exe`. Hygiene and demo copies are
named `.exe` and downloaded with that name. `chmod 600` does nothing on
Windows, so a double-click would run them. That breaks the "never executed"
promise through user error.

**Mitigation:** store as `.bin`, download as `<name>.exe.bin`, and say why in
the UI.

### RS-12 — Legacy routes (CWE-352, CWE-88)

`POST /api/analyze/sample/*` and `/api/analyze/upload` do not require the
token. Cross-site use is still blocked by the `Origin`/`Sec-Fetch-Site`
checks. `analysis.analyze_elf()` passes file paths without a `--` separator.
This is not exploitable today because the paths are absolute.

**Mitigation:** remove the legacy routes, or require the token and add `--`.

## Things that are already done well

- Loopback-only bind, plus `Host`/`Origin`/`Sec-Fetch-Site` checks, which stop
  DNS rebinding and cross-site requests.
- A per-session token for writes, compared with `secrets.compare_digest`.
- Strict CSP, `X-Frame-Options`, `nosniff`, `no-referrer`, `no-store`.
- The UI renders with `textContent` and DOM builders: no `innerHTML` and no
  `eval`. A contract test checks this.
- Snapshot copies use `O_NOFOLLOW` plus device/inode/size/mtime identity
  checks against TOCTOU swaps. Copies get permission 0600 with no execute bit.
- RPM extraction rejects absolute paths, `..`, links, special files and
  duplicates, and enforces size and member limits before writing anything.
- Subprocesses are argv lists (`shell=False`) with timeouts, output caps and
  process-tree termination.
- The Day 2 metrics parser (`metrics.py`) bounds-checks every offset and
  records parse errors instead of raising. Tests cover malformed input.

## Sources

- [NVD — CVE-2019-17664 (Ghidra untrusted search path)](https://nvd.nist.gov/vuln/detail/CVE-2019-17664)
- [NVD — CVE-2023-22671 (Ghidra launch.sh command injection)](https://nvd.nist.gov/vuln/detail/CVE-2023-22671)
- [NVD — CVE-2024-3566 (BatBadBut, CreateProcess batch argument injection)](https://nvd.nist.gov/vuln/detail/cve-2024-3566)
- [discuss.python.org — Is Python affected by CVE-2024-24576?](https://discuss.python.org/t/is-python-affected-by-cve-2024-24576/50740)
- [NVD — CVE-2023-23397 (Outlook UNC path NTLM leak, same class as RS-03)](https://nvd.nist.gov/vuln/detail/CVE-2023-23397)
- [NVD — CVE-2025-0840 (binutils objdump stack overflow)](https://nvd.nist.gov/vuln/detail/CVE-2025-0840)
- [NVD — CVE-2014-8485 (strings / libbfd)](https://nvd.nist.gov/vuln/detail/CVE-2014-8485)
- [Red Hat — CVE-2021-20266 (rpm out-of-bounds read)](https://access.redhat.com/security/cve/CVE-2021-20266)
- [CWE list (MITRE)](https://cwe.mitre.org/)
