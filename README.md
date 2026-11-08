# ReverseShield Local Workbench

A local, static-only application-security workbench for Linux **ELF** and
Windows **PE** files. It discovers a real installed application, a local folder,
an ELF/PE file, an RPM package, an upload or a bundled sample; runs bounded
static-analysis tools with a live event stream; and compares a copy
before/after one of three transformations.

It is **not** a protection product, an obfuscator, a malware sandbox, or a
reverse-engineering-resistance benchmark.

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

### Fedora / Linux

```bash
python3 app.py
# open http://127.0.0.1:8765/
```

Or `./run.sh`. Open the printed loopback address. The server binds only to
loopback, requires a per-session token for state-changing calls and rejects
foreign origins. Stop it with `Ctrl+C`.

The five sample binaries are included under `samples/bin/`. To rebuild them from
the self-authored C sources without executing them, run:

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
4. **Inspect evidence** — metadata, functions, symbols, strings, pseudocode,
   graphs and raw bounded output. Unavailable or truncated data is labelled,
   never treated as a security result.
5. **Transformation comparison** — profiles act on a run-local copy; the
   original is untouched:
   - **GNU symbol removal** (`strip --strip-unneeded`, bundled samples only);
   - **Demo constant blinding** — sample sources are transformed so integer
     constants become volatile-key XOR expressions and an opaque guard is added,
     then rebuilt (bundled samples only; demonstration-grade);
   - **Binary metadata hygiene** — `strip --strip-all` plus `objcopy` removal of
     `.comment`, `.annobin.notes`, `.gnu.build.attributes` and
     `.note.gnu.build-id` on a copy of any selected ELF/PE. This is metadata
     reduction, not code obfuscation.

   Before/after reports and a downloadable JSON record are produced.

The project-local Ghidra 12.2 and Temurin JDK 25 live under `tools/` in the full
development copy. They are **not committed**; `setup.bat` downloads them, or the
owner provides an offline release asset.

## Scope and safety

- **Static analysis only. Targets are never executed or emulated**, including
  uploaded files, bundled samples, Windows PE files and installed applications
  such as Easy Effects.
- **Dynamic analysis is disabled.** DEB and APK inputs are not supported. RPM
  payloads are unpacked as data, never installed or script-executed; RPM
  ingestion is Linux-only.
- **Source-level protection is restricted to bundled samples.** Installed or
  third-party applications are analysed read-only and never modified.
- **Binary metadata hygiene** runs on a copy of any selected ELF/PE; it removes
  metadata only, not code. It is not obfuscation or a protection guarantee.
- GNU symbol removal is a **baseline transformation, not obfuscation**. The demo
  transformer is also **demonstration-grade only**; none of the profiles
  establishes behavioural equivalence or resistance.
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

On Windows use `py -3` instead of `python3`. The current suite has **58 tests, 1
opt-in Ghidra skip**. Tests cover ELF/PE parsing, discovery, RPM ingestion, job
orchestration, comparison, API and UI contracts. They do not execute the sample
programs. The real Ghidra test is opt-in:

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
| `docs/ReverseShield_Project_Report_and_Plan.pdf` | Project report and plan |
| `docs/ReverseShield_3-Day_Execution_Plan.pdf` | Earlier three-day plan |

## Version

`0.3.0-team` — see `CHANGELOG.md`.
