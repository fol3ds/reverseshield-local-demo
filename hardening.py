"""Static exploit-mitigation checks for ELF and PE binaries.

This module reads the file as data. It does not launch, map, emulate or trace
the target. Results are **properties observed in the binary**, not a security
score and not proof that the program is exploitable or safe.

ELF checks: NX (PT_GNU_STACK), PIE (ET_DYN / DF_1_PIE), RELRO
(PT_GNU_RELRO + BIND_NOW), stack canary (__stack_chk_fail/guard) and FORTIFY
(*_chk / __fortify_fail imports).

PE checks: DEP/NX_COMPAT, ASLR/DYNAMICBASE, high-entropy VA, Control Flow
Guard and a security-cookie string check. RELRO and FORTIFY are not applicable
to PE and are reported as such.
"""
from __future__ import annotations

import struct
from pathlib import Path

MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 512
MAX_SYMBOLS = 50000

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2
PF_X = 0x1
ET_EXEC = 2
ET_DYN = 3
SHT_SYMTAB = 2
SHT_DYNSYM = 11
DT_NULL = 0
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_PIE = 0x08000000

PE_DLL_DYNAMIC_BASE = 0x0040
PE_DLL_HIGH_ENTROPY_VA = 0x0020
PE_DLL_NX_COMPAT = 0x0100
PE_DLL_GUARD_CF = 0x4000


class _Reader:
    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.endian = endian

    def unpack(self, fmt: str, offset: int):
        full = self.endian + fmt
        size = struct.calcsize(full)
        if offset < 0 or offset + size > len(self.data):
            raise ValueError("Read outside file bounds.")
        return struct.unpack_from(full, self.data, offset)

    def cstring(self, offset: int, limit: int = 512) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\0", offset, min(len(self.data), offset + limit))
        raw = self.data[offset:end if end >= 0 else min(len(self.data), offset + limit)]
        return raw.decode("utf-8", "replace")


def _check(label: str, state: str, evidence: str) -> dict:
    return {"label": label, "state": state, "evidence": evidence}


def _mask_summary(checks: dict) -> dict:
    counts = {"present": 0, "absent": 0, "partial": 0, "unknown": 0, "not_applicable": 0}
    for item in checks.values():
        state = item.get("state", "unknown")
        counts[state] = counts.get(state, 0) + 1
    return counts


def _elf_sections(reader: _Reader, is64: bool, offset: int, count: int, entsize: int) -> list[dict]:
    sections = []
    expected = 64 if is64 else 40
    if entsize != expected:
        raise ValueError("Unexpected ELF section-header size.")
    for index in range(min(max(count, 0), MAX_SECTIONS)):
        base = offset + index * expected
        if is64:
            name, kind, _flags, _addr, file_offset, size, link, _info, _align, entry_size = reader.unpack(
                "IIQQQQIIQQ", base
            )
        else:
            name, kind, _flags, _addr, file_offset, size, link, _info, _align, entry_size = reader.unpack(
                "IIIIIIIIII", base
            )
        sections.append({
            "name_offset": name, "type": kind, "offset": file_offset, "size": size,
            "link": link, "entsize": entry_size,
        })
    return sections


def _symbol_names(reader: _Reader, sections: list[dict], is64: bool) -> tuple[list[str], bool]:
    names: list[str] = []
    parsed = False
    for section in sections:
        if section["type"] not in (SHT_DYNSYM, SHT_SYMTAB):
            continue
        expected = 24 if is64 else 16
        entsize = section["entsize"] or expected
        if entsize != expected or section["link"] >= len(sections):
            continue
        string_section = sections[section["link"]]
        count = min(section["size"] // expected, MAX_SYMBOLS)
        parsed = True
        for index in range(1, count):
            base = section["offset"] + index * expected
            if is64:
                name_offset, _info, _other, _shndx = reader.unpack("IBBH", base)
            else:
                name_offset, = reader.unpack("I", base)
            if name_offset:
                name = reader.cstring(string_section["offset"] + name_offset, 256)
                if name:
                    names.append(name)
    return names, parsed


def _elf_hardening(data: bytes) -> dict:
    if len(data) < 52:
        raise ValueError("Truncated ELF header.")
    elf_class, elf_data = data[4], data[5]
    if elf_class not in (1, 2) or elf_data not in (1, 2):
        raise ValueError("Unknown ELF class or byte order.")
    is64 = elf_class == 2
    endian = "<" if elf_data == 1 else ">"
    reader = _Reader(data, endian)
    e_type, = reader.unpack("H", 16)
    if is64:
        e_phoff, = reader.unpack("Q", 0x20)
        e_shoff, = reader.unpack("Q", 0x28)
        e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx = reader.unpack("HHHHH", 0x36)
    else:
        e_phoff, = reader.unpack("I", 0x1C)
        e_shoff, = reader.unpack("I", 0x20)
        e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx = reader.unpack("HHHHH", 0x2A)

    segments = []
    if e_phoff and e_phnum:
        expected = 56 if is64 else 32
        if e_phentsize != expected:
            raise ValueError("Unexpected ELF program-header size.")
        for index in range(min(e_phnum, 512)):
            base = e_phoff + index * expected
            if is64:
                p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = reader.unpack(
                    "IIQQQQQQ", base
                )
            else:
                p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = reader.unpack(
                    "IIIIIIII", base
                )
            segments.append({"type": p_type, "flags": p_flags, "offset": p_offset,
                             "filesz": p_filesz, "memsz": p_memsz, "vaddr": p_vaddr})

    dynamic = None
    stack = None
    relro = None
    for segment in segments:
        if segment["type"] == PT_GNU_STACK:
            stack = segment
        elif segment["type"] == PT_GNU_RELRO:
            relro = segment
        elif segment["type"] == PT_DYNAMIC:
            dynamic = segment
    for item in segments:
        if item["offset"] + item["filesz"] > len(data):
            raise ValueError("ELF segment exceeds file bounds.")

    flags = 0
    flags1 = 0
    bind_now = False
    if dynamic is not None:
        entry_size = 16 if is64 else 8
        count = min(dynamic["filesz"] // entry_size, 10000)
        for index in range(count):
            base = dynamic["offset"] + index * entry_size
            if is64:
                tag, value = reader.unpack("qQ", base)
            else:
                tag, value = reader.unpack("iI", base)
            if tag == DT_NULL:
                break
            if tag == DT_BIND_NOW:
                bind_now = True
            elif tag == DT_FLAGS:
                flags = value
            elif tag == DT_FLAGS_1:
                flags1 = value
        bind_now = bind_now or bool(flags & DF_BIND_NOW) or bool(flags1 & DF_BIND_NOW)

    sections = []
    if e_shoff and e_shnum:
        sections = _elf_sections(reader, is64, e_shoff, e_shnum, e_shentsize)
        for section in sections:
            if section["offset"] + section["size"] > len(data):
                raise ValueError("ELF section exceeds file bounds.")
    names, symbols_parsed = _symbol_names(reader, sections, is64)

    # NX / DEP.
    if stack is None:
        nx_state = "unknown"
        nx_evidence = "PT_GNU_STACK is missing; the kernel default is not treated as evidence."
    elif stack["flags"] & PF_X:
        nx_state = "absent"
        nx_evidence = "PT_GNU_STACK is executable (PF_X set)."
    else:
        nx_state = "present"
        nx_evidence = "PT_GNU_STACK is non-executable (PF_X clear)."

    # PIE / ASLR.
    if e_type == ET_DYN:
        if flags1 & DF_1_PIE:
            pie_state, pie_evidence = "present", "ET_DYN with DF_1_PIE set."
        else:
            pie_state, pie_evidence = "partial", "ET_DYN without DF_1_PIE; position-independent, but not marked as PIE."
    elif e_type == ET_EXEC:
        pie_state, pie_evidence = "absent", "ET_EXEC is a fixed-address executable."
    else:
        pie_state, pie_evidence = "unknown", f"ELF type {e_type} is not classified as an executable PIE."

    # RELRO.
    if relro is None:
        relro_state, relro_evidence = "absent", "PT_GNU_RELRO is missing."
    elif bind_now:
        relro_state, relro_evidence = "present", "PT_GNU_RELRO and BIND_NOW are present (full RELRO)."
    else:
        relro_state, relro_evidence = "partial", "PT_GNU_RELRO is present, but BIND_NOW is not set."

    blob = data
    canary_names = {"__stack_chk_fail", "__stack_chk_guard"}
    canary_found = sorted(canary_names.intersection(names)) or [name for name in ("__stack_chk_fail", "__stack_chk_guard")
                                                               if name.encode() in blob]
    if canary_found:
        canary_state, canary_evidence = "present", "Found " + ", ".join(sorted(set(canary_found))[:3])
    elif symbols_parsed:
        canary_state, canary_evidence = "absent", "No stack-canary symbol found in the parsed symbol tables."
    else:
        canary_state, canary_evidence = "unknown", "No symbol table was available for the canary check."

    fortify_found = sorted({name for name in names if name.endswith("_chk") or name == "__fortify_fail"})
    if fortify_found:
        fortify_state = "present"
        fortify_evidence = "Found " + ", ".join(fortify_found[:4]) + ("…" if len(fortify_found) > 4 else "")
    elif symbols_parsed:
        fortify_state, fortify_evidence = "absent", "No *_chk or __fortify_fail symbol found in the parsed symbol tables."
    else:
        fortify_state, fortify_evidence = "unknown", "No symbol table was available for the FORTIFY check."

    checks = {
        "nx": _check("NX / DEP", nx_state, nx_evidence),
        "pie": _check("PIE / ASLR", pie_state, pie_evidence),
        "relro": _check("RELRO", relro_state, relro_evidence),
        "canary": _check("Stack canary", canary_state, canary_evidence),
        "fortify": _check("FORTIFY", fortify_state, fortify_evidence),
    }
    return {
        "format": "ELF",
        "checks": checks,
        "summary": _mask_summary(checks),
        "evidence": {
            "elf_type": e_type,
            "dynamic": dynamic is not None,
            "bind_now": bind_now,
            "symbols_parsed": symbols_parsed,
            "stack_segment": stack is not None,
            "relro_segment": relro is not None,
        },
        "limitations": _limitations(),
    }


def _pe_hardening(data: bytes) -> dict:
    if len(data) < 64 or data[:2] != PE_MAGIC:
        raise ValueError("Not a PE file.")
    reader = _Reader(data, "<")
    pe_offset, = reader.unpack("I", 0x3C)
    if reader.unpack("4s", pe_offset)[0] != b"PE\0\0":
        raise ValueError("Invalid PE signature.")
    _machine, _count, _stamp, _symptr, _symcount, optional_size, _chars = reader.unpack("HHIIIHH", pe_offset + 4)
    optional = pe_offset + 24
    if optional + optional_size > len(data):
        raise ValueError("PE optional header exceeds file bounds.")
    magic, = reader.unpack("H", optional)
    if magic not in (0x10B, 0x20B):
        raise ValueError("Unknown PE optional-header magic.")
    if optional_size < 72:
        raise ValueError("PE optional header is too small for DllCharacteristics.")
    dll_characteristics, = reader.unpack("H", optional + 70)
    names_blob = data
    canary_names = [name for name in (b"__security_check_cookie", b"__security_cookie")
                    if name in names_blob]

    checks = {
        "nx": _check("DEP / NX_COMPAT", "present" if dll_characteristics & PE_DLL_NX_COMPAT else "absent",
                     f"DllCharacteristics=0x{dll_characteristics:04x}; NX_COMPAT "
                     f"{'set' if dll_characteristics & PE_DLL_NX_COMPAT else 'clear'}."),
        "pie": _check("ASLR / DYNAMICBASE", "present" if dll_characteristics & PE_DLL_DYNAMIC_BASE else "absent",
                      f"DllCharacteristics=0x{dll_characteristics:04x}; DYNAMICBASE "
                      f"{'set' if dll_characteristics & PE_DLL_DYNAMIC_BASE else 'clear'}; "
                      f"HIGH_ENTROPY_VA {'set' if dll_characteristics & PE_DLL_HIGH_ENTROPY_VA else 'clear'}."),
        "cfg": _check("Control Flow Guard", "present" if dll_characteristics & PE_DLL_GUARD_CF else "absent",
                      f"GUARD_CF {'set' if dll_characteristics & PE_DLL_GUARD_CF else 'clear'}."),
        "canary": _check("Security cookie", "present" if canary_names else "unknown",
                         "Found " + ", ".join(item.decode() for item in canary_names)
                         if canary_names else "No security-cookie import string found; this bounded scan is not proof of absence."),
        "relro": _check("RELRO", "not_applicable", "RELRO is an ELF loader property; not applicable to PE."),
        "fortify": _check("FORTIFY", "not_applicable", "FORTIFY_SOURCE is a glibc/ELF build feature; not applicable to PE."),
    }
    return {
        "format": "PE",
        "checks": checks,
        "summary": _mask_summary(checks),
        "evidence": {"dll_characteristics": dll_characteristics,
                     "high_entropy_va": bool(dll_characteristics & PE_DLL_HIGH_ENTROPY_VA),
                     "security_cookie_strings": [item.decode() for item in canary_names]},
        "limitations": _limitations(),
    }


def _limitations() -> list[str]:
    return [
        "These are static properties of the file, not a security score; presence or absence does not prove exploitability.",
        "A missing mitigation is not a vulnerability by itself, and a present mitigation is not a security guarantee.",
        "Compiler, linker, loader and kernel defaults vary by platform and build configuration.",
        "This check does not execute, fuzz or dynamically test the target.",
    ]


def analyze_hardening(path) -> dict:
    """Return observed exploit-mitigation properties for one ELF/PE file."""
    target = Path(path)
    with target.open("rb") as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    truncated = len(data) > MAX_FILE_BYTES
    data = data[:MAX_FILE_BYTES]
    if data[:4] == ELF_MAGIC:
        result = _elf_hardening(data)
    elif data[:2] == PE_MAGIC and len(data) >= 64:
        result = _pe_hardening(data)
    else:
        return {"format": None, "checks": {}, "summary": _mask_summary({}), "evidence": {},
                "errors": ["Unsupported format: hardening checks require ELF or PE bytes."],
                "limitations": _limitations()}
    result["input_truncated"] = truncated
    result.setdefault("errors", [])
    return result
