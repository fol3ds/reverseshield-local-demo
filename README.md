# ReverseShield Local Workbench

A local, static-only application-security workbench for Linux **ELF** and
Windows **PE** files. It discovers a real installed application, a local folder,
an ELF/PE file, an RPM package, an upload or a bundled sample; runs bounded
static-analysis tools with a live event stream; and compares a copy
before/after one of three transformations.

It is **not** a production protection product, a malware sandbox, or a
reverse-engineering-resistance benchmark. It includes an optional, sample-only
OLLVM transformation and a QEMU behaviour check for that demonstration.

## Quick start

### Windows 10/11

1. Extract the project to a normal folder (not inside the ZIP).
2. Install Python 3.11+ and enable **Add python.exe to PATH**.
3. Run **`setup.bat`** once. It downloads Ghidra, a Windows JDK 25 and
   MinGW-w64 into this project's `tools\` folder; no Administrator rights.
4. Run **`run.bat`**. Open <http://127.0.0.1:8765/> if the browser does not.

The setup and run scripts use the current Windows account and project-local
folders; neither needs Administrator rights. If Ghidra or its JDK cannot be
downloaded, static PE header parsing and any installed `objdump` remain usable;
Ghidra is reported as unavailable and skipped. `readelf` is ELF-only and is
explicitly marked not applicable for PE reports. Missing optional adapters are
shown as unavailable instead of being treated as a failed target analysis.

See `START_HERE.md` for troubleshooting and what works without MinGW.
The source-only Lite archive and its exclusions are described in
`LITE_PACKAGE.md`.

### Fedora / Linux

```bash
python3 app.py
# open http://127.0.0.1:8765/
```

Or `./run.sh`. Open the printed loopback address. The server binds only to
loopback, requires a per-session token for state-changing calls and rejects
foreign origins. Stop it with `Ctrl+C`.

The **six** sample ELF binaries are included under `samples/bin/`: five
original source-transformable samples and a separate `level-5-hardened` ELF for
static mitigation-property comparison. To rebuild them from self-authored C
sources without executing them, run:

```bash
python3 build_samples.py
```

The build emits ELF fixtures on Linux and `.exe` PE fixtures on Windows; the
sample catalog detects the actual format from file headers.

## Windows test commands

Run the project tests from a Command Prompt in the extracted project folder:

```bat
python -m unittest discover -s tests -v
set RUN_GHIDRA_TESTS=1
python -m unittest tests.test_engine -v
```

The first command includes the Windows PE upload and directory-walker checks.
The second enables the real headless Ghidra smoke test. In PowerShell, set the
opt-in for the current shell with `$env:RUN_GHIDRA_TESTS = "1"` before running
`python -m unittest tests.test_engine -v`.

GitHub Actions also runs the regular suite on Windows and Fedora; the Ghidra
smoke remains opt-in because it requires a separate local tool installation.

## What the workbench does

1. **Select a source** — installed Flatpak application, local app folder /
   ELF / PE / RPM package (absolute path), uploaded ELF/PE/RPM, or a bundled
   sample.
2. **Preview discovered targets** — every ELF/PE is listed with size, format and
   analyzability; you choose one or more. Flatpak dependencies are listed but
   not scanned automatically.
3. **Analyze with live events** — available adapters run by default, or choose
   them manually: `file`, `readelf`, `objdump`, `strings`, `nm`, and Ghidra
   headless (decompiler, call edges, CFG). `readelf` is ELF-only; PE is parsed
   by the built-in PE/COFF reader and the available PE-aware tools.
4. **Read the report** — it opens with plain-language findings (names, debug
   info, file paths, recovered code), then metadata, functions, symbols, strings, pseudocode,
   graphs and raw bounded output, plus **content metrics** computed from the
   file bytes (sections, executable/writable counts, entropy, imports/exports,
   string categories, debug/symbol flags), **exploit-mitigation properties**
   (NX/DEP, PIE/ASLR, RELRO, stack canary, FORTIFY; PE ASLR/DEP/CFG and security
   cookie) and a tool-coverage table. ELF/PE symbol tables and Ghidra symbols are
   counted separately. Unavailable or truncated data is labelled **N/A**, never
   treated as zero or a security result.
   Ghidra runs with a per-run time and CPU limit; targets over 8 MiB need an
   explicit confirmation or the lightweight-tools option.
5. **Transformation comparison** — profiles act on a run-local copy; the
   original is untouched:
   - **GNU symbol removal** (`strip --strip-unneeded`, bundled samples only);
   - **Demo constant blinding** — sample sources are transformed so integer
     constants become volatile-key XOR expressions and an opaque guard is added,
     then rebuilt (bundled samples only; demonstration-grade);
   - **OLLVM source obfuscation** — the project-local xollvm toolchain rebuilds a
     bundled sample with control-flow flattening, bogus control flow,
     instruction substitution and string encryption, then compares the original
     and protected copy. Deterministic sample drivers are run only inside a
     QEMU micro-VM with no disk and no network; the host never executes the
     sample. These are **separate driver builds**, not the downloadable
     protected ELF. `driver_vectors_matched` records that narrow result;
     `behavior_verified` stays false for the downloadable artifact. This is
     not a guarantee of security;
   - **Binary metadata hygiene** — `strip --strip-all` plus `objcopy` removal of
     `.comment`, `.annobin.notes`, `.gnu.build.attributes` and
     `.note.gnu.build-id` on a copy of any selected ELF/PE. This is metadata
     reduction, not code obfuscation.

   Before/after reports and a downloadable JSON record are produced.

The project-local Ghidra 12.2 and Temurin JDK 25 live under `tools/` in the full
development copy. They are **not committed**; `setup.bat` downloads them, or the
owner provides an offline release asset.

The optional OLLVM profile needs the xollvm/LLVM 22 toolchain. On Fedora/Linux:

```bash
bash scripts/setup_ollvm.sh
```

It downloads about 101 MiB into `tools/xollvm/` and verifies the archive
checksum. The project-local xollvm toolchain is Linux-only. On native Windows, **OLLVM
source transforms and QEMU driver verification are unsupported**; the profile
reports unavailable. Static ELF/PE analysis and supported copy-only operations
remain separate features and still need a clean Windows manual test. The Lite
ZIP does not include xollvm or QEMU. The five original sample sources are the
only OLLVM-eligible inputs; the sixth hardened fixture is selectable for static
analysis, not a source transform. OLLVM cannot transform an arbitrary ELF/PE.

### One-click demo

Press **Run demo · Level 5** on the Operate page. It selects the bundled Level 5
sample, runs every available tool and opens the report. It never runs on page
load. The 3-minute event script is in `docs/event/PITCH_DECK_DRAFT.md`.

## Scope and safety

- **Host execution is disabled for analysed targets**, including uploaded files,
  bundled samples, Windows PE files and installed applications such as Easy
  Effects. The optional OLLVM profile builds a copy of a bundled sample and
  exercises **only deterministic test drivers inside a QEMU micro-VM with no
  disk and no network**. It does not execute installed or third-party targets.
- **Dynamic analysis is disabled.** DEB and APK inputs are not supported. RPM
  payloads are unpacked as data, never installed or script-executed; RPM
  ingestion is Linux-only.
- **Source-level protection is restricted to bundled samples.** Installed or
  third-party applications are analysed read-only and never modified. OLLVM
  cannot transform a binary-only ELF/PE; arbitrary files remain analysis-only.
- **Binary metadata hygiene** runs on a copy of any selected ELF/PE; it removes
  metadata only, not code. It is not obfuscation or a protection guarantee.
- GNU symbol removal is a **baseline transformation, not obfuscation**. The demo
  transformer is also **demonstration-grade only**. OLLVM is a real source
  transformation, but it is not a security proof: Ghidra can still recover
  logic, and the QEMU check covers only deterministic drivers. None of the
  profiles establishes full behavioural equivalence or resistance.
- Loopback plus temporary snapshots are not a malware sandbox. Use only files
  you own or are authorised to assess.
- Local tools (especially decompilers) parse untrusted bytes and may themselves
  have vulnerabilities; isolate genuinely hostile inputs.
- Inputs, snapshots, event logs and reports are retained under `runs/` until you
  delete them. Reports can contain local paths; use the sanitized export before
  sharing (Day 3 task).
- The local API has no authentication beyond a per-session token; do not expose
  it to a network.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

On Windows use the explicit compatible launcher (for example `py -3.14`),
not `py -3` blindly. The final verified suite result for this local candidate
belongs in `docs/evidence/verification.json`. The GitHub Actions run on merged
`main` is not a test of the unmerged Day 4 branch; native-Windows manual setup
and UI checks remain outstanding.
GitHub Actions runs the suite on both Windows and Fedora; platform-specific skips
are reported in the job output. Tests cover ELF/PE parsing, discovery, RPM
ingestion, job orchestration, comparison, API and UI contracts. They do not
execute the sample programs. The real Ghidra test is opt-in:

```bash
RUN_GHIDRA_TESTS=1 python3 -m unittest tests.test_engine -v
```

## Documentation

| File | Purpose |
|---|---|
| `START_HERE.md` | Windows/Linux setup and first run |
| `docs/AI_CONTEXT.md` | Architecture, invariants, extension guide for AI agents |
| `docs/TEAM_TASKS_DAY1-4.md` | Naser → Zayed → Nomai → Faisal task plan |
| `docs/GITHUB_WORKFLOW.md` | Beginner GitHub Desktop hand-off |
| `docs/IS_CYBERNEXT_REQUIREMENTS.md` | Event requirements, positioning, gap analysis |
| `docs/event/PITCH_DECK_DRAFT.md` | Day 2 pitch deck draft and 3-minute demo script |
| `docs/security/DAY2_SECURITY_REVIEW.md` | Day 2 security review: findings, CWE/CVE, mitigations |
| `docs/handoff/DAY2.md` | Day 2 hand-off (Zayed → Nomai) |
| `docs/ROADMAP.md` | Planned features (hardening checks, CVE lookup) — not built yet |
| `docs/ReverseShield_Project_Report_and_Plan.pdf` | Project report and plan |
| `docs/ReverseShield_3-Day_Execution_Plan.pdf` | Earlier three-day plan |

## Version

`0.5.0-team` — see `CHANGELOG.md`.


## Day 3 privacy and sharing

All API reads and writes require the per-session token. Open the workbench
page to bootstrap it; `/api/status` does not disclose it. The browser sends
the token in a header, including downloads. Host, Origin, Referer and browser
fetch-site checks protect against foreign websites. This is local browser
request protection, not user accounts, enterprise IAM or protection from a
malicious process running as the same OS user.

Analysis reads target bytes locally and never runs the target on the host. The optional
OLLVM check runs only deterministic sample drivers inside QEMU. The application
has no telemetry or cloud analysis upload. Setup downloads third-party tools;
developer security scanners may download rules. Inputs, reports and temporary
analysis workspaces live in `runs/` until manually removed. Stop the server
before deleting unwanted runs; the job index resets on restart. There is no
encrypted evidence store or cumulative disk quota: monitor available space.

Use **Download sanitized report** for sharing. It creates a separate JSON
summary, retaining hashes, numerical measurements, coverage and tool status.
Raw output, recovered code, artifacts, event text, commands and environment
values are omitted; identifiable paths and known secret patterns are redacted.
The original local report is unchanged. This is not a universal secret detector;
review the exported summary before publishing. The authenticated `/report`
endpoint remains an internal raw-evidence route. `/report-sanitized` is the
shareable route. Changed binaries are not sanitized reports and may retain
embedded strings; do not publish them as proof of privacy.

Offline export (refuses to overwrite the source or an existing destination):

```sh
python sanitize_report.py runs/JOB_ID/report.json sanitized-report.json
```

Day 3 verification and unresolved release gates are recorded in
`docs/handoff/DAY3.md`. Older PDF/DOCX reports and Day 2 screenshots describe
earlier builds; use the Day 3 evidence for current security claims.
