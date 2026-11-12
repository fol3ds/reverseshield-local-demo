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
- `setup.bat` and `run.bat` probe compatible Python 3.15→3.11
  explicitly; they do not assume `py -3` resolves to a compatible interpreter.
  A clean Windows account must still verify this release candidate manually.

### What works on Windows

| Feature | Native Windows status for this candidate |
|---|---|
| ELF analysis | Implemented (Ghidra); clean-machine manual verification pending |
| PE analysis | Implemented (header metadata + Ghidra, `objdump` with MinGW); manual verification pending |
| Flatpak discovery / RPM ingestion | Linux only |
| Six bundled sample choices | Implemented; manual Windows UI check pending |
| Source demo protection on the five original samples | Requires MinGW `gcc`; manual verification pending |
| Binary metadata hygiene | Requires `strip`/`objcopy`; manual verification pending |
| OLLVM source transforms / QEMU behavior drivers | **Unavailable on native Windows; Linux-only optional workflow** |
| Dynamic target analysis | Disabled |

## Fedora / Linux (project owner)

```bash
cd reverseshield-local-demo
python3 app.py
# open http://127.0.0.1:8765/
```

Or use `./run.sh`. Linux already has the system tools used by the adapters;
Ghidra and JDK are under `tools/` in the full project.

## First five minutes in the UI

Fastest path: press **Run demo · Level 5** at the top of **Operate**. It does
steps 1–3 below for you and opens the report.

1. **Operate** → **Bundled sample** → `Level 5 · Policy Engine` → **Use sample**.
2. Leave the file selected, tick the permission checkbox and press **Analyze selected files**.
3. Watch the live tool log; open the report when the job completes. The
   report opens with **What someone could learn from this file**, then the
   **Overview** tab explains every number. Use the **Dark mode** button if you
   prefer a dark page.
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
| `docs/RELEASE_CHECKLIST.md` | privacy review, platform acceptance and publication gates |
| `docs/AI_CONTEXT.md` | architecture and safety rules for AI agents |

## Troubleshooting

| Symptom | Check |
|---|---|
| “Python was not found” after installing a new version | Open a new Command Prompt; run `py -0p` to list installed versions. `run.bat` now tries 3.15→3.11 explicitly. If your version is listed, run `py -3.14 app.py` (use your version). Also disable Windows **App execution aliases** for `python.exe` if they point at the Store. |
| Browser shows connection refused | Keep `run.bat` open; wait 2 seconds; check the console for the actual port. |
| Ghidra unavailable | Run `setup.bat` again; check `tools\windows\jdk25\bin\java.exe`; check `Java` in the app's status panel. |
| Ghidra is slow on a large app | Select a single target, disable Ghidra for that run, or use a smaller sample. |
| Antivirus quarantines a download | Allow the project folder or use the offline release; do not disable antivirus globally. |
| "contains a character that cmd.exe would interpret" | Ghidra is refused when the project folder path contains `& | < > ^ % !` or a quote. Move the project to a plain folder such as `C:\ReverseShield\reverseshield-local-demo`. |
| "Network (UNC) paths are not supported" | Copy the files from the network share to a local folder, then use that local path. |
| "Large target … Ghidra may take several minutes" | Press **Skip Ghidra (lightweight tools only)**, or tick **Run Ghidra anyway** and raise the Ghidra time limit. |
| Reports contain local paths | Use the sanitized export before sharing; see `docs/AI_CONTEXT.md` §10. |

## Safety reminder

Only analyse applications you own or are authorised to inspect. The bundled
samples are self-authored. Do not upload malware, customer data, credentials or
third-party binaries without permission.


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

Unresolved acceptance and publication gates are preserved in
`docs/RELEASE_CHECKLIST.md`. Historical results are not a fresh test of a later
cleaned tree, and source cleanup does not clear older Git history for sharing.
