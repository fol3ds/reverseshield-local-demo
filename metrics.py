"""Bounded content and structure metrics computed from ELF/PE file bytes.

Inputs are a validated ELF or PE snapshot path; outputs are deterministic
metric dictionaries (sections, per-section entropy, imports/exports, string
categories and debug/symbol flags). Everything here reads bytes as data. No
function loads, maps, executes or emulates the target. Every loop is capped
and every offset is bounds-checked so malformed inputs produce a recorded
parse error instead of an exception or an unbounded scan.

Extend by adding new bounded readers and keeping missing values as ``None``
(rendered as N/A), never as zero.
"""
from __future__ import annotations

import math
import re
import struct
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 512
ENTROPY_SECTION_BYTES = 4 * 1024 * 1024
ENTROPY_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SYMBOLS = 200_000
MAX_DYNAMIC_ENTRIES = 10_000
MAX_IMPORT_DESCRIPTORS = 4096
MAX_IMPORT_FUNCTIONS = 65_536
MAX_DEBUG_ENTRIES = 64
STRING_MIN_LENGTH = 4
STRING_LIMIT = 10_000
STRING_SCAN_BYTES = 32 * 1024 * 1024

# Categories are checked in this order; the first match wins.
STRING_CATEGORIES = ("urls", "paths", "compiler_notes", "messages", "other")
_URL = re.compile(r"\b(?:https?|ftp|file|wss?)://", re.I)
_WIN_PATH = re.compile(r"(?:^|[\s\"'=])(?:[A-Za-z]:[\\/]|\\\\[\w.$-]+\\)")
_UNIX_PATH = re.compile(r"(?:^|[\s\"'=])(?:/[\w.+-]+){2,}/?")
_SOURCE_FILE = re.compile(r"^[\w.+-]+\.(?:c|cc|cpp|cxx|h|hpp|rs|go|s|asm|pdb|o|obj)$", re.I)
_ABSOLUTE_PATH = re.compile(r"(?:^|[\s\"'=])(?:[A-Za-z]:[\\/]|\\\\[\w.$-]+\\|/(?:[\w.+-]+/)+)")
# A home folder in a path exposes a user name: /home/<name>/, /Users/<name>/, C:\Users\<name>\.
_USER_HOME = re.compile(r"(?:/home/|/Users/|[A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/])(?!Public\b|Default\b|All Users\b)[^\\/\s]+", re.I)
_COMPILER = re.compile(r"\b(?:GCC|GNU C\d*|clang version|LLVM|MinGW|mingw-w64|Ubuntu|Red Hat|Fedora|"
                       r"Microsoft \(R\)|MSVC|rustc|go\d\.\d+|annobin|GLIBC_\d|GLIBCXX_\d|CXXABI_\d)\b")
# A message has at least two words separated by a space ("libc.so" is not a message).
_MESSAGE = re.compile(r"[A-Za-z]{2,}[,.:;!?'-]?\s+[A-Za-z]{2,}")


def shannon_entropy(data: bytes | bytearray | memoryview) -> float | None:
    """Return bits per byte (0.0–8.0); ``None`` for empty input."""
    view = bytes(data)
    total = len(view)
    if not total:
        return None
    entropy = 0.0
    for value in range(256):
        count = view.count(value.to_bytes(1, "little"))
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def categorize_string(text: str) -> str:
    """Deterministically assign a printable string to one category."""
    if _URL.search(text):
        return "urls"
    if _WIN_PATH.search(text) or _UNIX_PATH.search(text) or _SOURCE_FILE.match(text):
        return "paths"
    if _COMPILER.search(text):
        return "compiler_notes"
    if _MESSAGE.search(text):
        return "messages"
    return "other"


def scan_strings(data: bytes, *, min_length: int = STRING_MIN_LENGTH, limit: int = STRING_LIMIT) -> dict[str, Any]:
    """Count printable ASCII runs by category using a bounded byte scan."""
    window = data[:STRING_SCAN_BYTES]
    counts = {name: 0 for name in STRING_CATEGORIES}
    absolute = user_home = 0
    total = 0
    truncated = len(data) > len(window)
    pattern = re.compile(rb"[\x20-\x7e\t]{%d,}" % min_length)
    for match in pattern.finditer(window):
        if total >= limit:
            truncated = True
            break
        text = match.group().decode("ascii", "replace").strip()
        if len(text) < min_length:
            continue
        category = categorize_string(text)
        counts[category] += 1
        if category == "paths":
            absolute += bool(_ABSOLUTE_PATH.search(text))
            user_home += bool(_USER_HOME.search(text))
        total += 1
    return {"total": total, "categories": counts, "min_length": min_length, "limit": limit,
            "paths_absolute": absolute, "paths_in_user_home": user_home,
            "scanned_bytes": len(window), "truncated": truncated, "source": "built_in_byte_scan"}


class _Reader:
    """Bounds-checked struct reader over an in-memory byte buffer."""

    def __init__(self, data: bytes, endian: str = "<"):
        self.data = data
        self.endian = endian

    def unpack(self, fmt: str, offset: int) -> tuple:
        full = self.endian + fmt
        size = struct.calcsize(full)
        if offset < 0 or offset + size > len(self.data):
            raise ValueError(f"Read outside file bounds at 0x{max(offset, 0):x}.")
        return struct.unpack_from(full, self.data, offset)

    def cstring(self, offset: int, limit: int = 1024) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\0", offset, min(len(self.data), offset + limit))
        raw = self.data[offset:end if end != -1 else min(len(self.data), offset + limit)]
        return raw.decode("utf-8", "replace")


class _EntropyBudget:
    def __init__(self):
        self.remaining = ENTROPY_TOTAL_BYTES
        self.truncated = False

    def measure(self, data: bytes, offset: int, size: int) -> float | None:
        if size <= 0 or offset < 0 or offset >= len(data):
            return None
        size = min(size, len(data) - offset)
        take = min(size, ENTROPY_SECTION_BYTES, self.remaining)
        if take < size:
            self.truncated = True
        if take <= 0:
            return None
        self.remaining -= take
        return shannon_entropy(memoryview(data)[offset:offset + take])


def _empty_metrics(file_format: str | None) -> dict[str, Any]:
    return {
        "source": "built_in_byte_parser",
        "format": file_format,
        "file_entropy": None,
        "sections": {"count": None, "executable": None, "writable": None, "items": [],
                     "entropy_truncated": False},
        "imports": {"count": None, "libraries": None, "source": None, "truncated": False},
        "exports": {"count": None, "named": None, "source": None, "truncated": False},
        "strings": None,
        "debug": {},
        "symbols": {},
        "errors": [],
    }


# --------------------------------------------------------------------- ELF

SHT_SYMTAB, SHT_DYNSYM, SHT_DYNAMIC, SHT_NOBITS = 2, 11, 6, 8
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
DT_NEEDED = 1


def _elf_metrics(data: bytes, metrics: dict[str, Any], budget: _EntropyBudget) -> None:
    if len(data) < 52:
        raise ValueError("Truncated ELF header.")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        raise ValueError("Unknown ELF class or byte order.")
    is64 = elf_class == 2
    reader = _Reader(data, "<" if elf_data == 1 else ">")
    if is64:
        shoff, = reader.unpack("Q", 0x28)
        shentsize, shnum, shstrndx = reader.unpack("HHH", 0x3A)
    else:
        shoff, = reader.unpack("I", 0x20)
        shentsize, shnum, shstrndx = reader.unpack("HHH", 0x2E)
    expected_entsize = 64 if is64 else 40
    if shoff == 0:
        shnum = 0
    elif shentsize != expected_entsize:
        raise ValueError("Unexpected ELF section header size.")
    if shoff and shnum == 0:
        # Extended numbering: the real count lives in section 0's sh_size.
        shnum = reader.unpack("Q" if is64 else "I", shoff + (32 if is64 else 20))[0]
    truncated_sections = shnum > MAX_SECTIONS
    headers = []
    for index in range(min(shnum, MAX_SECTIONS)):
        base = shoff + index * expected_entsize
        if is64:
            name, kind, flags, _addr, offset, size, link, _info, _align, entsize = reader.unpack("IIQQQQIIQQ", base)
        else:
            name, kind, flags, _addr, offset, size, link, _info, _align, entsize = reader.unpack("IIIIIIIIII", base)
        headers.append({"name_offset": name, "type": kind, "flags": flags, "offset": offset,
                        "size": size, "link": link, "entsize": entsize})
    names_base = headers[shstrndx]["offset"] if headers and shstrndx < len(headers) else None
    items = []
    for index, header in enumerate(headers):
        if index == 0 and header["type"] == 0:
            continue
        name = reader.cstring(names_base + header["name_offset"], 256) if names_base is not None else ""
        header["name"] = name or f"section{index}"
        in_file = header["type"] != SHT_NOBITS
        items.append({
            "index": index, "name": header["name"], "size": header["size"],
            "executable": bool(header["flags"] & SHF_EXECINSTR),
            "writable": bool(header["flags"] & SHF_WRITE),
            "entropy": budget.measure(data, header["offset"], header["size"]) if in_file else None,
        })
    names = [item["name"] for item in items]
    metrics["sections"].update({
        "count": len(items), "executable": sum(i["executable"] for i in items),
        "writable": sum(i["writable"] for i in items), "items": items,
        "header_count_truncated": truncated_sections,
    })

    def symbol_table(kind: int) -> tuple[int | None, list[tuple[str, int, int]]]:
        table = next((h for h in headers if h["type"] == kind), None)
        if table is None:
            return None, []
        entsize = 24 if is64 else 16
        count = min(table["size"] // entsize, MAX_SYMBOLS)
        strtab = headers[table["link"]]["offset"] if table["link"] < len(headers) else None
        entries = []
        for i in range(1, count):
            base = table["offset"] + i * entsize
            if is64:
                st_name, st_info, _other, st_shndx = reader.unpack("IBBH", base)
            else:
                st_name, = reader.unpack("I", base)
                st_info, _other, st_shndx = reader.unpack("BBH", base + 12)
            name = reader.cstring(strtab + st_name, 512) if strtab is not None and st_name else ""
            entries.append((name, st_info, st_shndx))
        return max(count - 1, 0), entries

    symtab_count, _ = symbol_table(SHT_SYMTAB)
    dynsym_count, dynamic_symbols = symbol_table(SHT_DYNSYM)
    if dynsym_count is not None:
        imports = sum(1 for name, _info, shndx in dynamic_symbols if name and shndx == 0)
        exports = sum(1 for name, info, shndx in dynamic_symbols
                      if name and shndx != 0 and (info >> 4) in (1, 2) and (info & 0xF) not in (3, 4))
        metrics["imports"].update({"count": imports, "source": "ELF .dynsym undefined symbols"})
        metrics["exports"].update({"count": exports, "named": exports, "source": "ELF .dynsym defined global/weak symbols"})
    else:
        # A static executable has no dynamic imports; that is an observed zero.
        metrics["imports"].update({"count": 0, "source": "ELF without .dynsym (static or stripped of dynamic symbols)"})
        metrics["exports"].update({"count": 0, "named": 0, "source": "ELF without .dynsym"})
    dynamic = next((h for h in headers if h["type"] == SHT_DYNAMIC), None)
    if dynamic is not None:
        entsize = 16 if is64 else 8
        needed = 0
        for i in range(min(dynamic["size"] // entsize, MAX_DYNAMIC_ENTRIES)):
            tag, = reader.unpack("q" if is64 else "i", dynamic["offset"] + i * entsize)
            if tag == 0:
                break
            if tag == DT_NEEDED:
                needed += 1
        metrics["imports"]["libraries"] = needed
    else:
        metrics["imports"]["libraries"] = 0
    metrics["debug"] = {
        "debug_sections_present": any(n.startswith((".debug_", ".zdebug_")) for n in names),
        "symbol_table_present": symtab_count is not None,
        "dynamic_symbols_present": dynsym_count is not None,
        "build_id_present": ".note.gnu.build-id" in names,
        "compiler_comment_present": ".comment" in names,
    }
    metrics["symbols"].update({"elf_symbols": symtab_count, "elf_dynamic_symbols": dynsym_count})


# ---------------------------------------------------------------------- PE

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def _pe_metrics(data: bytes, metrics: dict[str, Any], budget: _EntropyBudget) -> None:
    reader = _Reader(data, "<")
    pe_offset, = reader.unpack("I", 0x3C)
    if reader.unpack("4s", pe_offset)[0] != b"PE\0\0":
        raise ValueError("Invalid PE signature.")
    _machine, section_count, _stamp, symbol_ptr, symbol_count, optional_size, _chars = reader.unpack("HHIIIHH", pe_offset + 4)
    optional = pe_offset + 24
    magic, = reader.unpack("H", optional)
    if magic == 0x10B:
        pe32_plus, dir_count_offset = False, 92
    elif magic == 0x20B:
        pe32_plus, dir_count_offset = True, 108
    else:
        raise ValueError("Unknown PE optional-header magic.")
    size_of_headers, = reader.unpack("I", optional + 60)
    directories = []
    if optional_size >= dir_count_offset + 4:
        count, = reader.unpack("I", optional + dir_count_offset)
        for index in range(min(count, 16, (optional_size - dir_count_offset - 4) // 8)):
            directories.append(reader.unpack("II", optional + dir_count_offset + 4 + index * 8))
    string_table = symbol_ptr + symbol_count * 18 if symbol_ptr else None
    section_table = optional + optional_size
    sections = []
    for index in range(min(section_count, 96)):
        raw = reader.unpack("8sIIIIIIHHI", section_table + index * 40)
        raw_name, vsize, vaddr, raw_size, raw_ptr = raw[0], raw[1], raw[2], raw[3], raw[4]
        characteristics = raw[9]
        name = raw_name.split(b"\0", 1)[0].decode("ascii", "replace")
        if name.startswith("/") and name[1:].isdigit() and string_table is not None:
            # MinGW stores long section names (e.g. .debug_info) in the COFF string table.
            resolved = reader.cstring(string_table + int(name[1:]), 256)
            name = resolved or name
        sections.append({"name": name or f"section{index + 1}", "vsize": vsize, "vaddr": vaddr,
                         "raw_size": raw_size, "raw_ptr": raw_ptr, "characteristics": characteristics})
    items = [{
        "index": i + 1, "name": s["name"], "size": max(s["vsize"], s["raw_size"]),
        "executable": bool(s["characteristics"] & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)),
        "writable": bool(s["characteristics"] & IMAGE_SCN_MEM_WRITE),
        "entropy": budget.measure(data, s["raw_ptr"], min(s["raw_size"], s["vsize"] or s["raw_size"])) if s["raw_size"] else None,
    } for i, s in enumerate(sections)]
    names = [item["name"] for item in items]
    metrics["sections"].update({
        "count": len(items), "executable": sum(i["executable"] for i in items),
        "writable": sum(i["writable"] for i in items), "items": items,
        "header_count_truncated": section_count > 96,
    })

    def rva_to_offset(rva: int) -> int | None:
        for s in sections:
            span = max(s["vsize"], s["raw_size"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                delta = rva - s["vaddr"]
                return s["raw_ptr"] + delta if delta < s["raw_size"] else None
        return rva if rva < size_of_headers else None

    def directory(index: int) -> tuple[int, int] | None:
        if index < len(directories) and directories[index][0] and directories[index][1]:
            return directories[index]
        return None

    # Import directory (index 1).
    imports = directory(1)
    if imports is None:
        metrics["imports"].update({"count": 0, "libraries": 0, "source": "PE import directory (absent)"})
    else:
        base = rva_to_offset(imports[0])
        if base is None:
            raise ValueError("PE import directory points outside the file.")
        libraries = functions = 0
        truncated = False
        thunk_size = 8 if pe32_plus else 4
        for i in range(MAX_IMPORT_DESCRIPTORS):
            original_first, _stamp, _chain, name_rva, first_thunk = reader.unpack("IIIII", base + i * 20)
            if not (original_first or name_rva or first_thunk):
                break
            libraries += 1
            thunk = rva_to_offset(original_first or first_thunk)
            while thunk is not None:
                value, = reader.unpack("Q" if pe32_plus else "I", thunk)
                if not value:
                    break
                functions += 1
                if functions >= MAX_IMPORT_FUNCTIONS:
                    truncated = True
                    break
                thunk += thunk_size
            if truncated:
                break
        else:
            truncated = True
        metrics["imports"].update({"count": functions, "libraries": libraries,
                                   "source": "PE import directory", "truncated": truncated})
    # Export directory (index 0).
    exports = directory(0)
    if exports is None:
        metrics["exports"].update({"count": 0, "named": 0, "source": "PE export directory (absent)"})
    else:
        base = rva_to_offset(exports[0])
        if base is None:
            raise ValueError("PE export directory points outside the file.")
        function_count, name_count = reader.unpack("II", base + 20)
        metrics["exports"].update({"count": min(function_count, MAX_IMPORT_FUNCTIONS),
                                   "named": min(name_count, MAX_IMPORT_FUNCTIONS),
                                   "source": "PE export directory",
                                   "truncated": function_count > MAX_IMPORT_FUNCTIONS})
    # Debug directory (index 6) and CodeView/PDB reference.
    debug = directory(6)
    pdb_reference = False
    if debug is not None:
        base = rva_to_offset(debug[0])
        for i in range(min(debug[1] // 28, MAX_DEBUG_ENTRIES) if base is not None else 0):
            kind, = reader.unpack("I", base + i * 28 + 12)
            pointer, = reader.unpack("I", base + i * 28 + 24)
            if kind == 2 and 0 < pointer < len(data) - 4 and data[pointer:pointer + 4] in (b"RSDS", b"NB10"):
                pdb_reference = True
    metrics["debug"] = {
        "debug_sections_present": any(n.lower().startswith((".debug", ".zdebug", ".pdb")) for n in names),
        "symbol_table_present": bool(symbol_ptr and symbol_count),
        "debug_directory_present": debug is not None,
        "pdb_reference_present": pdb_reference,
        "compiler_comment_present": ".comment" in names,
    }
    metrics["symbols"].update({"pe_coff_symbols": symbol_count if symbol_ptr else 0})


def content_metrics(path: str | Path) -> dict[str, Any]:
    """Compute bounded metrics from one ELF/PE file. Never raises on bad input."""
    target = Path(path)
    with target.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    truncated = len(data) > MAX_FILE_BYTES
    data = data[:MAX_FILE_BYTES]
    file_format = "ELF" if data[:4] == b"\x7fELF" else "PE" if data[:2] == b"MZ" and len(data) >= 64 else None
    metrics = _empty_metrics(file_format)
    metrics["size_bytes"] = len(data)
    metrics["input_truncated"] = truncated
    budget = _EntropyBudget()
    whole = data[:ENTROPY_TOTAL_BYTES]
    metrics["file_entropy"] = shannon_entropy(whole)
    metrics["file_entropy_truncated"] = len(whole) < len(data)
    try:
        if file_format == "ELF":
            _elf_metrics(data, metrics, budget)
        elif file_format == "PE":
            _pe_metrics(data, metrics, budget)
        else:
            metrics["errors"].append("Unsupported format: metrics require ELF or PE bytes.")
    except (ValueError, struct.error, IndexError) as exc:
        metrics["errors"].append(f"Structure parse stopped: {exc}")
    metrics["sections"]["entropy_truncated"] = budget.truncated
    metrics["strings"] = scan_strings(data)
    return metrics
