#!/usr/bin/env bash
# ReverseShield local launcher for Fedora/Linux.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$PWD/tools/windows/mingw64/bin:$PWD/tools/jdk25/bin:$PWD/tools/ghidra/ghidra_12.2_PUBLIC/support:$PATH"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required (Python 3.11+)." >&2
  exit 1
fi
exec python3 app.py
