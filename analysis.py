"""ELF and PE header parsing helpers.

Inputs are bounded ELF/PE byte streams and static-tool output; outputs are
validated metadata dictionaries and tool records. Only metadata is parsed
here. No function executes or maps the selected file. Add new container
formats as separate bounded parsers rather than weakening ELF/PE validation.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
MAX_FILE_BYTES = 16 * 1024 * 1024
OUTPUT_LIMIT = 48_000
TOOL_TIMEOUT = 12


def has_elf_magic(data: bytes) -> bool:
    """Check only the ELF signature; this helper never launches the input."""
    return isinstance(data, (bytes, bytearray)) and len(data) >= len(ELF_MAGIC) and bytes(data[:4]) == ELF_MAGIC


def has_pe_magic(data: bytes) -> bool:
    """Check only the DOS signature; the PE header is validated later."""
    return isinstance(data, (bytes, bytearray)) and len(data) >= 64 and bytes(data[:2]) == PE_MAGIC


def detect_format(data: bytes) -> str | None:
    """Return ``ELF`` or ``PE`` for supported executable formats."""
    if has_elf_magic(data):
        return "ELF"
    if has_pe_magic(data):
        return "PE"
    return None


def parse_pe_header(path: str | Path) -> dict[str, Any]:
    """Parse PE/COFF headers without executing or loading the image.

    This is intentionally a metadata parser, not a full PE loader. It reads
    the DOS stub, COFF header, optional header and section table with bounds
    checks so malformed uploads fail closed.
    """
    target = Path(path)
    with target.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) < 64 or dos[:2] != PE_MAGIC:
            raise ValueError("Not a PE file.")
        pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
        stream.seek(pe_offset)
        signature = stream.read(4)
        if signature != b"PE\x00\x00":
            raise ValueError("Invalid PE signature.")
        coff = stream.read(20)
        if len(coff) < 20:
            raise ValueError("Truncated PE COFF header.")
        machine, section_count, timestamp, symbol_ptr, symbol_count, optional_size, characteristics = struct.unpack(
            "<HHIIIHH", coff
        )
        if not 1 <= section_count <= 96:
            raise ValueError("Invalid PE section count.")
        optional = stream.read(optional_size)
        if len(optional) < optional_size:
            raise ValueError("Truncated PE optional header.")
        magic = struct.unpack_from("<H", optional, 0)[0] if len(optional) >= 2 else 0
        if magic == 0x10B:
            width, entry_offset, base_offset = "PE32", 16, 28
        elif magic == 0x20B:
            width, entry_offset, base_offset = "PE32+", 16, 24
        else:
            raise ValueError("Unknown PE optional-header magic.")
        if len(optional) < (96 if magic == 0x10B else 112):
            raise ValueError("Truncated PE optional header.")
        entry = struct.unpack_from("<I", optional, entry_offset)[0] if len(optional) >= entry_offset + 4 else 0
        image_base = struct.unpack_from("<I" if width == "PE32" else "<Q", optional, base_offset)[0] if len(optional) >= base_offset + (4 if width == "PE32" else 8) else 0

        machine_name = {0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64"}.get(machine, f"0x{machine:04x}")
        kind = "DLL" if characteristics & 0x2000 else "Executable"
        sections: list[dict[str, str]] = []
        section_offset = pe_offset + 4 + 20 + optional_size
        for index in range(min(section_count, 96)):
            stream.seek(section_offset + index * 40)
            raw = stream.read(40)
            if len(raw) < 40:
                raise ValueError("Truncated PE section table.")
            name = raw[:8].split(b"\x00", 1)[0].decode("ascii", "replace") or f"section{index + 1}"
            if name.startswith("/") and name[1:].isdigit() and symbol_ptr:
                # MinGW keeps long names such as .debug_info in the COFF string table.
                name = _coff_long_name(stream, symbol_ptr + symbol_count * 18 + int(name[1:])) or name
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", raw, 8)
            if raw_size and raw_pointer + raw_size > target.stat().st_size:
                raise ValueError("PE section data exceeds the file.")
            section_characteristics = struct.unpack_from("<I", raw, 36)[0]
            if section_characteristics & 0x20000000:
                section_kind = "CODE"
            elif section_characteristics & 0x80000000:
                section_kind = "DATA"
            else:
                section_kind = "DATA"
            sections.append({
                "index": str(index + 1),
                "name": name,
                "type": section_kind,
                "address": f"0x{virtual_address:08x}",
                "offset": f"0x{raw_pointer:08x}",
                "size": f"0x{max(virtual_size, raw_size):08x}",
            })
    section_names = [section["name"] for section in sections]
    return {
        "class": width,
        "endianness": "Little endian",
        "type": f"{width} {kind.lower()}",
        "machine": machine_name,
        "entry_point": f"0x{image_base + entry:016x}",
        "os_abi": "Windows",
        "image_base": f"0x{image_base:016x}",
        "timestamp": timestamp,
        "sections": sections,
        "sections_count": len(sections),
        "section_names": section_names,
        "symbol_entries": symbol_count,
        "debug_info_present": any(name.lower().startswith((".debug", ".pdb")) for name in section_names),
        "symbol_table_present": bool(symbol_ptr),
        "format": "PE",
    }


def _coff_long_name(stream, offset: int) -> str:
    """Read one bounded NUL-terminated COFF string-table entry."""
    position = stream.tell()
    try:
        stream.seek(offset)
        raw = stream.read(256).split(b"\x00", 1)[0]
        return raw.decode("ascii", "replace") if raw.isascii() else ""
    finally:
        stream.seek(position)


def _field(text: str, label: str) -> str:
    found = re.search(rf"^\s*{re.escape(label)}:\s*(.*?)\s*$", text, re.MULTILINE)
    return found.group(1) if found else "Unknown"


def parse_elf_header(text: str) -> dict[str, str]:
    raw_data = _field(text, "Data")
    if "little endian" in raw_data.lower():
        endian = "Little endian"
    elif "big endian" in raw_data.lower():
        endian = "Big endian"
    else:
        endian = raw_data
    return {
        "class": _field(text, "Class"),
        "endianness": endian or "Unknown",
        "type": _field(text, "Type"),
        "machine": _field(text, "Machine"),
        "entry_point": _field(text, "Entry point address"),
        "os_abi": _field(text, "OS/ABI"),
    }


def parse_sections(text: str) -> list[dict[str, str]]:
    row_pattern = re.compile(
        r"^\s*\[\s*(\d+)\]\s+(\S+)\s+(\S+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    parsed: list[dict[str, str]] = []
    for line in text.splitlines():
        row = row_pattern.match(line)
        if row is None:
            continue
        index, name, kind, address, offset, size = row.groups()
        if index == "0" or name == "NULL":
            continue
        parsed.append({
            "index": index,
            "name": name,
            "type": kind,
            "address": "0x" + address,
            "offset": "0x" + offset,
            "size": "0x" + size,
        })
    return parsed


def tool_inventory() -> dict[str, dict[str, Any]]:
    found = {name: shutil.which(name) for name in ("file", "readelf", "objdump")}
    ghidra = shutil.which("analyzeHeadless")
    ghidra_home = os.environ.get("GHIDRA_HOME")
    if not ghidra and ghidra_home:
        candidate = Path(ghidra_home) / "support" / "analyzeHeadless"
        if candidate.is_file():
            ghidra = str(candidate)
    found["ghidra_headless"] = ghidra
    return {name: {"available": bool(path), "path": path} for name, path in found.items()}


def _invoke(label: str, arguments: list[str]) -> dict[str, Any]:
    display = shlex.join([*arguments[:-1], "<selected ELF>"])
    executable = shutil.which(arguments[0])
    if executable is None:
        return {"label": label, "command": display, "status": "unavailable", "return_code": None, "output": f"{arguments[0]} is not installed."}
    from engine import _run
    result = _run(label, [executable, *arguments[1:]], label=label,
                  timeout=TOOL_TIMEOUT, output_limit=OUTPUT_LIMIT)
    result['command'] = display
    return result


def analyze_elf(path: str | Path, filename: str | None = None, detail: str = "summary") -> dict[str, Any]:
    """Inspect an ELF file with metadata utilities; never invoke the selected binary."""
    target = Path(path)
    if not target.is_file():
        raise ValueError("Selected file was not found.")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("Selected file exceeds the 16 MiB demo limit.")
    with target.open("rb") as stream:
        if not has_elf_magic(stream.read(4)):
            raise ValueError("Unsupported input: choose a Linux ELF executable. RPM, DEB and APK require separate adapters.")

    command_specs = [
        ("file description", ["file", "-b", str(target)]),
        ("ELF header", ["readelf", "-hW", str(target)]),
        ("sections", ["readelf", "-SW", str(target)]),
        ("symbol table", ["readelf", "-sW", str(target)]),
        ("object summary", ["objdump", "-f", "-h", str(target)]),
    ]
    if detail == "full":
        command_specs += [
            ("program headers", ["readelf", "-lW", str(target)]),
            ("ELF notes", ["readelf", "-nW", str(target)]),
            ("objdump symbols", ["objdump", "-t", str(target)]),
        ]
    outputs = [_invoke(label, args) for label, args in command_specs]
    by_name = {item["label"]: item for item in outputs}
    header = parse_elf_header(by_name.get("ELF header", {}).get("output", ""))
    sections = parse_sections(by_name.get("sections", {}).get("output", ""))
    section_names = [section["name"] for section in sections]
    symbol_output = by_name.get("symbol table", {}).get("output", "")
    symbols = sum(bool(re.match(r"^\s*\d+:\s", line)) for line in symbol_output.splitlines())
    return {
        "filename": filename or target.name,
        "size_bytes": size,
        "analysis_mode": "static_only",
        "metadata": {
            "file_type": by_name.get("file description", {}).get("output", "Unknown"),
            **header,
            "sections_count": len(sections),
            "section_names": section_names,
            "symbol_entries": symbols,
            "debug_info_present": any(name.startswith((".debug_", ".zdebug_")) for name in section_names),
            "symbol_table_present": ".symtab" in section_names,
        },
        "sections": sections,
        "tools": outputs,
        "limitations": [
            "This result describes static file metadata; the selected application was not executed.",
            "Metadata and tool failures do not establish reverse-engineering resistance.",
            "Ghidra headless is optional and is not invoked by this demo.",
        ],
    }
