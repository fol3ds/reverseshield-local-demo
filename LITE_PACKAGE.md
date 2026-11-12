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

`python3 scripts/package_lite_windows.py` creates a **local, unreviewed release
candidate** in `dist/ReverseShield_Lite_Windows_v0.5.0-team.zip`, together with
`dist/SHA256SUMS.txt`. It uses only reviewed Git-index files; untracked working
files are not included until explicitly staged. The ZIP includes source, tests,
setup scripts, the six bundled ELF fixtures (the sixth is analysis-only), and
selected project documentation/sanitized summaries. It excludes `tools/`,
`runs/`, `backups/`, `.git/`, Python caches, raw `docs/security/` outputs,
old `docs/assets/` screenshots, internal `docs/handoff/` and `docs/event/`
notes, generated PDFs/DOCX and draft MP4s. **Inspect the exact staged index
and ZIP before sharing.** Retired team/event guides are excluded; the preserved
privacy and acceptance gates are included as `docs/RELEASE_CHECKLIST.md`.
Neither the ZIP nor its checksum was published by this preparation work.

On native Windows the optional OLLVM/QEMU workflow is unavailable. After
extracting the candidate into a clean directory, a Windows teammate must run
`setup.bat`, `run.bat`, static sample and PE analysis and a report download.
Record the OS, interpreter, tool versions, screenshots/logs without private
paths, and any failures in the Day 4 acceptance matrix. CI on the older merged
branch is not a replacement for this manual test.
