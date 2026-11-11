#!/usr/bin/env bash
# Download the project-local xollvm toolchain used by the optional OLLVM profile.
# The archive is data until extracted; no sample or target is executed here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/tools/xollvm"
ARCHIVE="$DEST/xollvm-linux-llvm22-Release.tar.zst"
URL="https://github.com/und3ath/xollvm/releases/download/v0.12.0/xollvm-linux-llvm22-Release.tar.zst"
EXPECTED="5139e2f70643d838a5fe3da17d591a9e065bd21af46eca947ed6948a51d88ce7"

for tool in curl tar zstd sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done

mkdir -p "$DEST"
if [ ! -f "$ARCHIVE" ]; then
  echo "Downloading xollvm (about 101 MiB)..."
  curl -L --fail --retry 3 --output "$ARCHIVE" "$URL"
fi

ACTUAL="$(sha256sum "$ARCHIVE" | awk '{print $1}')"
if [ "$ACTUAL" != "$EXPECTED" ]; then
  echo "Checksum mismatch for $ARCHIVE" >&2
  echo "expected: $EXPECTED" >&2
  echo "actual:   $ACTUAL" >&2
  exit 1
fi

if [ ! -x "$DEST/linux-llvm22/bin/clang" ] || [ ! -x "$DEST/linux-llvm22/bin/opt" ]; then
  echo "Extracting xollvm..."
  mkdir -p "$DEST/linux-llvm22"
  tar --zstd -xf "$ARCHIVE" -C "$DEST/linux-llvm22"
fi

"$DEST/linux-llvm22/bin/clang" --version | head -1
"$DEST/linux-llvm22/bin/opt" --version | head -1
echo "xollvm is ready under $DEST/linux-llvm22"
