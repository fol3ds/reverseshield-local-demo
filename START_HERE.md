# Start Here — ReverseShield Local Demo

ReverseShield is a **local static-analysis workbench**. You give it an installed
Flatpak application, a local folder, a Linux ELF, a Windows PE, an RPM package,
or a bundled sample. It copies the selected file into a run folder, runs
read-only static tools, and shows evidence in your browser.

It **does not execute** the selected application or sample. There is no
emulation, no dynamic tracing, and no network exposure: the server listens on
loopback only.

## Windows 10/11 (the team's default)

### One-time setup

1. Extract the project ZIP to a normal folder, for example
   `C:\ReverseShield\reverseshield-local-demo`.
   Do **not** run it from inside the ZIP.
2. Install **Python 3.11 or newer** from
   <https://www.python.org/downloads/windows/>. During installation, tick
   **Add python.exe to PATH**.
3. Double-click **`setup.bat`**.
   It downloads Ghidra, a Windows JDK 25 and MinGW-w64 **into this project's
   `tools\` folder**; it does not install system-wide and does not need
   Administrator rights. Allow a few minutes and about 1–2 GB of disk.
4. Double-click **`run.bat`**.
   Your browser should open <http://127.0.0.1:8765/>. If it does not, open that
   address manually. Keep the console window open while using the app.

### If setup is blocked

- Antivirus/SmartScreen may scan a large download or `setup.bat`. Allow the
  project folder in your antivirus, or ask your organiser before changing
  security settings.
- If `setup.bat` cannot download, open `START_HERE.md` on another machine, copy
  the links from `scripts/setup_windows.ps1`, download the three archives, and
  ask the project owner for the offline release ZIP.
- If Python is installed as `py`, `run.bat` uses `py -3`; otherwise it uses
  `python`.

### What works on Windows

| Feature | Windows status |
|---|---|
| ELF analysis | Works (Ghidra; PE/ELF copied as data) |
| PE analysis | Works (header metadata + Ghidra; `objdump` when MinGW is present) |
| Flatpak discovery | Linux only |
| RPM ingestion | Linux only |
| Sample analysis | Works |
| Source demo protection | Works only when MinGW `gcc` is present |
| Binary metadata hygiene | Works when `strip`/`objcopy` are present |
| Dynamic analysis | Disabled |

## Fedora / Linux (project owner)

```bash
cd reverseshield-local-demo
python3 app.py
# open http://127.0.0.1:8765/
```

Or use `./run.sh`. Linux already has the system tools used by the adapters;
Ghidra and JDK are under `tools/` in the full project.

## First five minutes in the UI

1. **Operate** → choose **Bundled sample** → `Level 5 · Policy Engine`.
2. Leave the targets selected and run **Analyze selected targets**.
3. Watch the live tool log; open the report when the job completes.
4. Open **Compare** → choose a profile:
   - `symbol_removal` or `constant_blinding` for a bundled sample;
   - `binary_hygiene` for any one selected ELF/PE copy.
5. Read the limitations. The demo profiles are evidence for the project, not a
   claim of real protection.

## Where things live

| Path | What it is |
|---|---|
| `app.py` | server entry point |
| `static/` | browser UI |
| `samples/` | self-authored C sources and built samples |
| `runs/` | per-job snapshots, logs, reports (do not commit) |
| `tools/` | project-local Ghidra/JDK/etc. (do not commit) |
| `docs/TEAM_TASKS_DAY1-4.md` | Naser → Zayed → Nomai → Faisal hand-off |
| `docs/GITHUB_WORKFLOW.md` | beginner Git/GitHub Desktop workflow |
| `docs/IS_CYBERNEXT_REQUIREMENTS.md` | event requirements and gap analysis |
| `docs/AI_CONTEXT.md` | architecture and safety rules for AI agents |

## Troubleshooting

| Symptom | Check |
|---|---|
| “Python was not found” after installing a new version | Open a new Command Prompt; run `py -0p` to list installed versions. `run.bat` now tries 3.15→3.11 explicitly. If your version is listed, run `py -3.14 app.py` (use your version). Also disable Windows **App execution aliases** for `python.exe` if they point at the Store. |
| Browser shows connection refused | Keep `run.bat` open; wait 2 seconds; check the console for the actual port. |
| Ghidra unavailable | Run `setup.bat` again; check `tools\windows\jdk25\bin\java.exe`; check `Java` in the app's status panel. |
| Ghidra is slow on a large app | Select a single target, disable Ghidra for that run, or use a smaller sample. |
| Antivirus quarantines a download | Allow the project folder or use the offline release; do not disable antivirus globally. |
| Reports contain local paths | Use the sanitized export before sharing; see `docs/AI_CONTEXT.md` §10. |

## Safety reminder

Only analyse applications you own or are authorised to inspect. The bundled
samples are self-authored. Do not upload malware, customer data, credentials or
third-party binaries without permission.
