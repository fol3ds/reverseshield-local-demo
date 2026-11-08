# ReverseShield Lite Windows package

This is a source-only Windows package for the local static-analysis workbench.
It does not contain analysis tool bundles or run evidence, and it never runs a
selected target.

## Start on Windows

1. Extract the ZIP.
2. Open a non-administrator Command Prompt in the extracted folder.
3. Run `setup.bat`, then `run.bat`.
4. Open <http://127.0.0.1:8765/> if the browser does not open automatically.

Setup installs optional analysis tools under `tools/`. If Ghidra or another
optional tool is unavailable, the workbench reports that limit and continues
with available PE parsing and static-analysis tools. Targets are read as data;
they are not executed.

## Test commands

```bat
python -m unittest discover -s tests -v
set RUN_GHIDRA_TESTS=1
python -m unittest tests.test_engine -v
```

For PowerShell, set the Ghidra opt-in with
`$env:RUN_GHIDRA_TESTS = "1"` before the second test command.

## Package contents and exclusions

The ZIP includes source, tests, project documentation, and the event draft. It
omits `tools/`, `runs/`, `backups/`, `.git/`, Python caches, generated report
DOCX/PDF files, and the full `docs/handoff/DAY1.md` handoff. The handoff and its
ZIP metrics are maintained on the project branch. `scripts/package_lite_windows.py`
creates a detached `ReverseShield_Lite_Windows_Day1.zip.sha256` checksum file
beside the archive.
