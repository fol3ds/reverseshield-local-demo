"""Bounded static adapters for ELF and PE inputs.

Inputs are validated file snapshots and selected tool names; outputs are
structured reports, artifacts and streamed progress events. Tools inspect
target bytes as data; the selected target is never executed, mapped or
emulated. Extend through argv-only adapters, bounded parsers and inventory
entries, with explicit format skips for tools such as ELF-only ``readelf``.
"""
from __future__ import annotations

import codecs
import hashlib
import stat
import shutil
import tempfile

from analysis import detect_format, has_elf_magic, parse_elf_header, parse_pe_header, parse_sections
from platform_support import IS_WINDOWS, command_for, local_tool_dirs, popen_kwargs, terminate_tree, which_tool
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import threading
import time

OUTPUT_LIMIT = 1024 * 1024


def _run(tool, arguments, *, label=None, version=None, emit=None,
         cancel_event=None, timeout=20, output_limit=OUTPUT_LIMIT, env=None, cwd=None):
    """Drain both streams with a reader thread.

    A thread works with anonymous pipes on Windows and POSIX; ``selectors``
    does not support Windows pipes. The target is still never executed: this
    only reads output from a static-analysis tool.
    """
    started = time.monotonic()
    result = {"tool": tool, "label": label or tool, "command": shlex.join(arguments),
              "status": "ok", "return_code": None, "output": "", "truncated": False,
              "duration_seconds": 0.0, "version": version, "output_bytes": 0,
              "output_limit_bytes": output_limit, "timeout_seconds": timeout}
    def send(kind, message, **extra):
        if emit:
            emit({"type": kind, "tool": tool, "message": message, **extra})
    send("tool_start", result["command"], command=result["command"])
    captured = bytearray()
    truncated = False
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    proc = None
    reader = None
    try:
        if cancel_event is not None and cancel_event.is_set():
            result["status"] = "cancelled"
        else:
            kwargs = dict(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, shell=False, cwd=cwd,
                          env=env or {**os.environ, "LC_ALL": "C"})
            kwargs.update(popen_kwargs())
            proc = subprocess.Popen(arguments, **kwargs)

            def read_stream():
                nonlocal truncated
                try:
                    while True:
                        chunk = proc.stdout.read1(8192) if hasattr(proc.stdout, "read1") else proc.stdout.read(8192)
                        if not chunk:
                            break
                        result["output_bytes"] += len(chunk)
                        room = max(0, output_limit - len(captured))
                        kept = chunk[:room]
                        captured.extend(kept)
                        if kept:
                            send("log", decoder.decode(kept))
                        if len(chunk) > room:
                            truncated = True
                except (OSError, ValueError):
                    pass

            reader = threading.Thread(target=read_stream, name=f"reverse-{tool}", daemon=True)
            reader.start()
            stopped = None
            while proc.poll() is None:
                now = time.monotonic()
                if stopped is None:
                    if cancel_event is not None and cancel_event.is_set():
                        result["status"] = "cancelled"
                        stopped = now
                    elif now - started >= timeout:
                        result["status"] = "timeout"
                        stopped = now
                    if stopped is not None:
                        terminate_tree(proc)
                elif now - stopped >= 1.5:
                    terminate_tree(proc)
                    break
                time.sleep(0.05)
            try:
                result["return_code"] = proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                terminate_tree(proc)
                result["return_code"] = proc.wait(timeout=2)
            if reader is not None:
                reader.join(timeout=2)
            if result["status"] == "ok" and result["return_code"]:
                result["status"] = "tool_error"
    except (OSError, subprocess.SubprocessError) as exc:
        result["status"] = "tool_error"
        result["error"] = str(exc)
        send("log", str(exc))
    finally:
        if proc is not None:
            # Also terminate children retaining a pipe after their launcher exits.
            terminate_tree(proc)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            try:
                proc.stdout.close()
            except (OSError, AttributeError):
                pass
    result["output"] = captured.decode("utf-8", "replace")
    result["truncated"] = truncated
    result["duration_seconds"] = round(time.monotonic() - started, 4)
    send("tool_end", result["status"], status=result["status"], return_code=result["return_code"],
         duration_seconds=result["duration_seconds"], truncated=result["truncated"])
    return result

ROOT = Path(__file__).resolve().parent
LABELS = {
    "file": "File identification",
    "readelf": "ELF headers, sections and symbols",
    "objdump": "Static disassembly",
    "strings": "Printable strings",
    "nm": "Named symbols",
    "ghidra_headless": "Ghidra decompiler and control-flow graphs",
}


def inventory() -> dict:
    """Report supported executables; version probing never opens a target."""
    result = {}
    extra = tuple(local_tool_dirs(ROOT))
    for name, label in LABELS.items():
        path = which_tool(name if name != "ghidra_headless" else "analyzeHeadless", extra)
        version = None
        if name == "ghidra_headless":
            candidates = []
            if os.environ.get("GHIDRA_HOME"):
                home = Path(os.environ["GHIDRA_HOME"]) / "support"
                if IS_WINDOWS:
                    candidates.extend([home / "analyzeHeadless.bat", home / "analyzeHeadless"])
                else:
                    candidates.extend([home / "analyzeHeadless", home / "analyzeHeadless.bat"])
            patterns = (("*/support/analyzeHeadless.bat", "*/support/analyzeHeadless") if IS_WINDOWS
                        else ("*/support/analyzeHeadless", "*/support/analyzeHeadless.bat"))
            for pattern in patterns:
                candidates.extend(sorted((ROOT / "tools/ghidra").glob(pattern), reverse=True))
            if IS_WINDOWS and path and not path.lower().endswith((".bat", ".cmd", ".exe")):
                batch_path = Path(path + ".bat")
                if batch_path.is_file():
                    path = str(batch_path)
            if not path:
                path = next((str(p) for p in candidates if p.is_file()), None)
            if path:
                props = Path(path).resolve().parents[1] / "Ghidra/application.properties"
                if props.is_file():
                    match = re.search(r"^application.version=(.+)$", props.read_text(), re.M)
                    if match:
                        version = "Ghidra " + match[1]
        elif path:
            try:
                probe = subprocess.run(command_for(path, "--version"), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       timeout=3, env={**os.environ, "LC_ALL": "C"}, check=False)
                version = probe.stdout.decode("utf-8", "replace").splitlines()[0][:500]
            except (OSError, subprocess.TimeoutExpired, IndexError):
                version = "Version unavailable"
        result[name] = {"available": bool(path), "path": path,
                        "version": version or ("Version unavailable" if path else None), "label": label,
                        "format": "ELF/PE" if name in {"file", "objdump", "strings", "ghidra_headless"} else "ELF"}
    return result


MAX_FILE_BYTES = 64 * 1024 * 1024
FUNCTION_LIMIT = 1000
SYMBOL_LIMIT = 10000
STRING_LIMIT = 10000
CALL_EDGE_LIMIT = 10000
GHIDRA_TIMEOUT = 240


def _ghidra_environment(workdir=None):
    """Use a project-local JDK and writable per-run Ghidra profile."""
    env = {**os.environ, "LC_ALL": "C"}
    candidates = [ROOT / "tools/jdk25", ROOT / "tools/windows/jdk25"]
    for jdk in candidates:
        java = jdk / ("bin/java.exe" if IS_WINDOWS else "bin/java")
        if java.is_file():
            env["JAVA_HOME"] = str(jdk)
            env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
            break
    if IS_WINDOWS and workdir is not None:
        profile = Path(workdir) / "ghidra-user-profile"
        roaming = profile / "Roaming"
        local = profile / "Local"
        roaming.mkdir(parents=True, exist_ok=True)
        local.mkdir(parents=True, exist_ok=True)
        env["APPDATA"] = str(roaming)
        env["LOCALAPPDATA"] = str(local)
    return env


def _analyze_ghidra(target, *, workdir, emit=None, cancel_event=None, info=None):
    """Run bounded Ghidra headless import and export static artifacts as JSON."""
    import json
    import tempfile
    workdir = Path(workdir or tempfile.mkdtemp(prefix="engine-", dir=ROOT / "runs")).resolve()
    workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    project = workdir / "ghidra_project"
    project.mkdir(mode=0o700, exist_ok=True)
    output = workdir / "ghidra-export.json"
    command = command_for(
        info["path"], str(project), "ReverseShield", "-import", str(target),
        "-scriptPath", str(ROOT / "ghidra_scripts"),
        "-postScript", "ReverseShieldExport.java", str(output),
        "-deleteProject", "-analysisTimeoutPerFile", "150", "-max-cpu", "2",
        "-loader-loadLibraries", "false",
        "-log", str(workdir / "ghidra.log"),
        "-scriptlog", str(workdir / "ghidra-script.log"),
    )
    record = _run("ghidra_headless", command, label=info["label"], version=info["version"],
                  emit=emit, cancel_event=cancel_event, timeout=GHIDRA_TIMEOUT,
                  env=_ghidra_environment(workdir), cwd=str(workdir))
    record["timeout_seconds"] = GHIDRA_TIMEOUT
    record["work_directory"] = str(workdir)
    payload, coverage, limitations = {}, {}, []
    try:
        if not output.is_file():
            raise ValueError("Ghidra did not produce the artifact export.")
        payload = json.loads(output.read_text(encoding="utf-8"))
        coverage = payload.get("coverage") or {}
        limitations = payload.get("limitations") or []
    except (OSError, ValueError) as exc:
        record["status"] = "tool_error" if record["status"] == "ok" else record["status"]
        record["output"] = (record.get("output", "") + f"\n[ReverseShield] Could not read Ghidra export: {exc}").strip()
    finally:
        # -deleteProject removes the database; drop the empty scaffolding too.
        shutil.rmtree(project, ignore_errors=True)
    return record, payload, coverage, limitations



def parse_readelf_symbols(text):
    symbols = []
    seen = set()
    for line in text.splitlines():
        match = re.match(r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+?)\s*$", line)
        if not match:
            continue
        address, size, kind, binding, visibility, section, name = match.groups()
        key = (name, address, kind)
        if key in seen:
            continue
        seen.add(key)
        symbols.append({"name": name, "address": "0x" + address, "size": int(size),
                        "type": kind, "binding": binding, "visibility": visibility,
                        "section": section, "external": section == "UND"})
    return symbols


def parse_nm_symbols(text):
    symbols = []
    for line in text.splitlines():
        match = re.match(r"^(\S+)\s+([A-Za-z?])(?:\s+([0-9a-fA-F]+))?(?:\s+([0-9a-fA-F]+))?\s*$", line)
        if match:
            name, kind, address, size = match.groups()
            symbols.append({"name": name, "type": kind,
                            "address": "0x" + address if address else None,
                            "size": int(size, 16) if size else None,
                            "external": kind in ("U", "w", "v") and address is None})
    return symbols


def parse_disassembly(text):
    functions, edges, seen_edges = [], [], set()
    current = None
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-fA-F]+) <(.+)>:$", line)
        if match:
            current = {"name": match[2], "address": "0x" + match[1], "size": None}
            functions.append(current)
            continue
        # Direct calls only; unresolved indirect calls are deliberately not inferred.
        call = re.search(r"\b(?:callq?|bl|blx|jal)\s+(?:0x)?([0-9a-fA-F]+)\s+<([^>]+)>", line)
        if current and call:
            target = re.sub(r"\+0x[0-9a-fA-F]+$", "", call[2])
            key = (current["name"], target)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"source": current["name"], "target": target})
    return functions, edges


def _merge(existing, incoming, limit, fields=("name", "address")):
    def key_of(item):
        parts = []
        for field in fields:
            value = item.get(field)
            if field == "address" and isinstance(value, str):
                try:
                    value = int(value, 16)  # 0x00400482 and 0x400482 are one address.
                except ValueError:
                    pass
            parts.append(value)
        return tuple(parts)

    indexed = {key_of(item): dict(item) for item in existing}
    for item in incoming:
        key = key_of(item)
        if key in indexed:
            indexed[key].update({k: v for k, v in item.items() if v is not None})
        elif len(indexed) < limit:
            indexed[key] = dict(item)
    return list(indexed.values())


def analyze(path, *, tools=None, emit=None, workdir=None, cancel_event=None) -> dict:
    """Inspect a single ELF or PE snapshot with static tools.

    The selected file is data only. No target is launched, mapped, emulated or
    dynamically traced.
    """
    target = Path(path).resolve()
    if not target.is_file():
        raise ValueError("Select a regular ELF or PE file.")
    size = target.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError("Selected file exceeds the 64 MiB limit.")
    with target.open("rb") as stream:
        header = stream.read(64)
        file_format = detect_format(header)
        if file_format is None:
            raise ValueError("Unsupported input: select a Linux ELF or Windows PE file.")
        stream.seek(0)
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    pe_header = parse_pe_header(target) if file_format == "PE" else {}
    available = inventory()
    if tools is not None and not isinstance(tools, (list, tuple)):
        raise ValueError("tools must be a list of adapter names.")
    selected = list(tools) if tools is not None else [k for k, v in available.items() if v["available"]]
    if not selected:
        raise ValueError("Select at least one available static tool.")
    for name in selected:
        if not isinstance(name, str) or name not in available:
            raise ValueError(f"Unknown static tool: {name!r}")
        if not available[name]["available"]:
            raise ValueError(f"Static tool is unavailable: {name}")
    selected = list(dict.fromkeys(selected))
    if file_format == "PE":
        pe_sections = pe_header.get("sections", [])
        metadata = {k: v for k, v in pe_header.items() if k != "sections"}
        metadata["file_type"] = f"{pe_header['class']} {pe_header['type']} ({pe_header['machine']}), for MS Windows"
    else:
        pe_sections = []
        metadata = {"file_type": "Unknown", **parse_elf_header(""), "format": "ELF"}
    result = {"filename": target.name, "size_bytes": size, "sha256": digest,
              "analysis_mode": "static_only", "metadata": metadata,
              "sections": pe_sections, "tools": [], "artifacts": {"functions": [], "symbols": [], "strings": [], "call_edges": []},
              "coverage": {"selected_tools": selected, "function_limit": FUNCTION_LIMIT,
                           "symbol_limit": SYMBOL_LIMIT, "string_limit": STRING_LIMIT,
                           "call_edge_limit": CALL_EDGE_LIMIT, "raw_output_limit_bytes": OUTPUT_LIMIT},
              "limitations": ["Static analysis only: the selected target was never executed or emulated.",
                              "Static tools are not a malware sandbox; use only authorized inputs.",
                              "Metadata and tool failures do not establish reverse-engineering resistance."]}
    specs = {"file": ["-b", "--"], "readelf": ["-h", "-S", "-s", "-l", "-W", "--"],
             "objdump": ["-d", "--no-show-raw-insn", "--"],
             "strings": ["-a", "-n", "4", "--"], "nm": ["-P", "-S", "-n", "--"]}
    # PE/COFF is not an ELF container: keep PE-aware adapters and make the
    # readelf skip explicit instead of reporting a tool failure.
    if file_format == "PE":
        specs["objdump"] = ["-x", "-p", "-d", "--no-show-raw-insn", "--"]
    for name in selected:
        info = available[name]
        if file_format == "PE" and name == "readelf":
            # Record a deliberate skip; the UI treats "skipped" differently
            # from a failed tool.
            record = {"tool": "readelf", "label": info["label"], "command": "(not applicable)",
                      "status": "skipped", "return_code": None, "output": "readelf does not parse PE/COFF files.",
                      "truncated": False, "duration_seconds": 0.0, "version": info.get("version")}
            if emit:
                emit({"type": "tool_start", "tool": "readelf", "message": "readelf skipped for PE/COFF."})
                emit({"type": "tool_end", "tool": "readelf", "message": "skipped", "status": "skipped",
                      "return_code": None, "duration_seconds": 0.0, "truncated": False})
            result["tools"].append(record)
            continue
        if name == "ghidra_headless":
            record, payload, coverage, limitations = _analyze_ghidra(
                target, workdir=workdir, emit=emit, cancel_event=cancel_event, info=info)
            result["tools"].append(record)
            if payload:
                artifact = result["artifacts"]
                artifact["functions"] = _merge(artifact["functions"], payload.get("functions") or [], FUNCTION_LIMIT)
                artifact["symbols"] = _merge(artifact["symbols"], payload.get("symbols") or [], SYMBOL_LIMIT)
                artifact["strings"] = list(dict.fromkeys([*artifact["strings"], *(payload.get("strings") or [])]))[:STRING_LIMIT]
                artifact["call_edges"] = (artifact["call_edges"] + (payload.get("call_edges") or []))[:CALL_EDGE_LIMIT]
                result["coverage"]["ghidra"] = coverage
                result["limitations"].extend(limitations)
            if emit:
                emit({"type": "artifact", "tool": name, "message": "Parsed Ghidra artifacts",
                      "counts": {k: len(v) for k, v in result["artifacts"].items()}})
            continue
        record = _run(name, [info["path"], *specs[name], str(target)], label=info["label"],
                      version=info["version"], emit=emit, cancel_event=cancel_event)
        result["tools"].append(record)
        artifact = result["artifacts"]
        if name == "readelf" and file_format == "ELF":
            result["metadata"].update(parse_elf_header(record["output"]))
            result["sections"] = parse_sections(record["output"])
            symbols = parse_readelf_symbols(record["output"])
            artifact["symbols"] = _merge(artifact["symbols"], symbols, SYMBOL_LIMIT)
            artifact["functions"] = _merge(artifact["functions"], [
                {"name": s["name"], "address": s["address"], "size": s["size"]}
                for s in symbols if s["type"] == "FUNC" and not s["external"]], FUNCTION_LIMIT)
        elif name == "file":
            result["metadata"]["file_type"] = record["output"].strip()
        elif name == "strings":
            artifact["strings"] = list(dict.fromkeys(record["output"].splitlines()))[:STRING_LIMIT]
        elif name == "nm":
            symbols = parse_nm_symbols(record["output"])
            artifact["symbols"] = _merge(artifact["symbols"], symbols, SYMBOL_LIMIT)
            artifact["functions"] = _merge(artifact["functions"], [
                {"name": s["name"], "address": s["address"], "size": s["size"]}
                for s in symbols if s["type"] in ("T", "t", "W", "w") and not s["external"]], FUNCTION_LIMIT)
        elif name == "objdump":
            functions, edges = parse_disassembly(record["output"])
            artifact["functions"] = _merge(artifact["functions"], functions, FUNCTION_LIMIT)
            artifact["call_edges"] = edges[:CALL_EDGE_LIMIT]
        if emit:
            emit({"type": "artifact", "tool": name, "message": "Parsed static artifacts",
                  "counts": {k: len(v) for k, v in result["artifacts"].items()}})
    names = [s["name"] for s in result["sections"]]
    result["metadata"].update({"sections_count": len(names), "section_names": names,
                               "symbol_entries": len(result["artifacts"]["symbols"]),
                               "debug_info_present": any(n.startswith((".debug_", ".zdebug_")) for n in names),
                               "symbol_table_present": ".symtab" in names})
    return result
