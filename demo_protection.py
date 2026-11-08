"""Demo-grade, sample-only source transformation.

This is deliberately NOT a production obfuscator. It makes a compiled sample
harder to read casually:

* volatile constant blinding: integer literals become XOR expressions that the
  compiler cannot fold away, so immediates disappear from the disassembly;
* an opaque guard that is always false at runtime but survives compilation.

Inputs are a bundled sample ID and destination directory; outputs are
transformed C sources, a compiled inert artifact and hashes. The transformation
is applied to copies of the bundled self-authored samples. Compilation is
allowed, but the generated target is never launched. Extend only for the
self-authored sample corpus and keep limitations in reports.
"""
from __future__ import annotations

import hashlib
import os
import os
import re
import shutil
import subprocess
from pathlib import Path

from build_samples import FLAGS, ROOT, SPECS
from platform_support import local_tool_dirs, which_tool

KEY = 0x9E3779B9
LITERAL = re.compile(r"(?<![\w.])(0x[0-9A-Fa-f]+|\d+)u\b")
GUARDED = re.compile(r"^([ \t]*(?:static\s+)?(?:uint32_t|int)\s+\w+\s*\([^;{}]*\)\s*\{)", re.MULTILINE)


def _encoded(value: int, key: int) -> str:
    return f"(0x{value ^ key:08X}u ^ rs_key)"


def blind_constants(text: str, key: int = KEY) -> str:
    lines = text.splitlines(keepends=True)
    output: list[str] = []
    in_initializer = False
    for line in lines:
        stripped = line.lstrip()
        if in_initializer:
            output.append(line)
            if "};" in line:
                in_initializer = False
            continue
        if re.search(r"static\s+const\b.*\{", line) and "};" not in line:
            in_initializer = True
            output.append(line)
            continue
        if stripped.startswith("#") or re.search(r"\bstatic\s+const\b|\benum\b", line):
            output.append(line)
            continue
        case = re.search(r"\bcase\s+[^:]+:", line)
        if case:
            # The label must stay a constant expression; its body may be blinded.
            def replace_body(match):
                value = int(match.group(1), 0)
                return match.group(0) if value < 2 else _encoded(value, key)
            output.append(line[:case.end()] + LITERAL.sub(replace_body, line[case.end():]))
            continue
        def replace(match):
            value = int(match.group(1), 0)
            return match.group(0) if value < 2 else _encoded(value, key)
        output.append(LITERAL.sub(replace, line))
    transformed = "".join(output)
    declaration = f"static volatile uint32_t rs_key = 0x{key:08X}u;\n"
    includes = list(re.finditer(r"^[ \t]*#include[^\n]*\n", transformed, re.MULTILINE))
    position = includes[-1].end() if includes else 0
    return transformed[:position] + declaration + transformed[position:]


def add_guards(text: str) -> str:
    guard = "\n    if ((rs_key ^ rs_key) != 0u) { return 0; }"
    return GUARDED.sub(lambda match: match.group(1) + guard, text)


def build_protected(sample_id: str, destination: Path, key: int = KEY) -> dict:
    spec = next((item for item in SPECS if item[0] == sample_id), None)
    if spec is None:
        raise ValueError("Protection is restricted to the bundled self-authored samples.")
    extra = tuple(local_tool_dirs(ROOT))
    compiler = which_tool("gcc", extra) or which_tool("clang", extra)
    if not compiler:
        raise RuntimeError("A C compiler (gcc/clang) is required to build the protected sample.")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = destination / "transformed-src"
    work.mkdir(mode=0o700, exist_ok=True)
    sources = []
    headers = set()
    for source in spec[3]:
        source = Path(source)
        transformed = add_guards(blind_constants(source.read_text(encoding="utf-8"), key))
        target = work / source.name
        target.write_text(transformed, encoding="utf-8")
        sources.append(target)
        for header in source.parent.glob("*.h"):
            headers.add(header)
    for header in headers:
        shutil.copyfile(header, work / header.name)
    output_suffix = ".exe" if os.name == "nt" else ".elf"
    output = destination / f"{sample_id}-protected{output_suffix}"
    command = [compiler, *FLAGS, *spec[2], "-I", str(work), *map(str, sources), "-o", str(output)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False,
                            env={**os.environ, "LC_ALL": "C"})
    if result.returncode != 0:
        raise RuntimeError("Protected build failed: " + (result.stderr or result.stdout)[:1500])
    output.chmod(0o600)  # Analysis artifact only; never executable.
    return {"path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "key": f"0x{key:08X}", "method": "volatile constant blinding + opaque guard",
            "sources": [str(item.relative_to(ROOT)) for item in spec[3]]}
