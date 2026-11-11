"""OLLVM source-protection adapter for the bundled samples.

This module builds a *copy* of a self-authored sample with the xollvm
obfuscator. It never executes the resulting binary. Behaviour verification is
performed separately by :mod:`behavior_qemu` inside a QEMU guest.

The toolchain is project-local and deliberately excluded from Git. When the
toolchain or a required host tool is missing, the caller gets a clear
``OllvmUnavailable`` error instead of a partial build.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from samples import get_sample
from platform_support import IS_WINDOWS

TOOLCHAIN_REL = Path("tools") / "xollvm" / "linux-llvm22"
PASS_SPEC = "flattening(minBlocks=3),bcf(prob=30),substitution(loop=2),strenc,adec"
DEFAULT_SEED = 1
MAX_BUILD_SECONDS = 180


class OllvmUnavailable(RuntimeError):
    """Raised when the project-local xollvm toolchain is not usable."""


class OllvmBuildError(RuntimeError):
    """Raised when a protected copy cannot be produced."""


def toolchain_paths(root) -> dict:
    base = Path(root).resolve() / TOOLCHAIN_REL
    return {
        "root": base,
        "clang": base / "bin" / "clang",
        "opt": base / "bin" / "opt",
        "strip": shutil.which("strip") or "",
    }


def available(root) -> bool:
    if IS_WINDOWS:
        return False
    paths = toolchain_paths(root)
    return all(Path(paths[key]).is_file() for key in ("clang", "opt")) and bool(paths["strip"])


def _run(command, *, cwd, timeout=MAX_BUILD_SECONDS):
    env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    proc = subprocess.run(command, cwd=str(cwd), capture_output=True, text=True,
                          timeout=timeout, check=False, env=env)
    return {
        "command": [str(item) for item in command],
        "return_code": proc.returncode,
        "output": ((proc.stdout or "") + (proc.stderr or ""))[-4000:],
    }


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _source_paths(root: Path, sample: dict) -> list[Path]:
    sources = []
    for relative in sample.get("sources", []):
        path = (root / relative).resolve()
        if path.is_file() and path.suffix.lower() == ".c":
            sources.append(path)
    if not sources:
        raise OllvmBuildError("The sample has no C source files to compile.")
    return sources


def _include_dirs(root: Path, sources: list[Path]) -> list[Path]:
    includes = []
    for source in sources:
        parent = source.parent
        if parent not in includes:
            includes.append(parent)
    return includes


def _compile_ir(root: Path, sources: list[Path], output_dir: Path, *, redefine_main: bool, extra_defines=()) -> list[Path]:
    paths = toolchain_paths(root)
    includes = _include_dirs(root, sources)
    results = []
    for index, source in enumerate(sources):
        target = output_dir / f"{index:02d}-{source.stem}.ll"
        command = [str(paths["clang"]), "-S", "-emit-llvm", "-O0", "-g0"]
        if redefine_main:
            command.append("-Dmain=rs_sample_main")
        command.extend(extra_defines)
        for include in includes:
            command.extend(["-I", str(include)])
        command.extend([str(source), "-o", str(target)])
        result = _run(command, cwd=output_dir)
        if result["return_code"] or not target.is_file():
            raise OllvmBuildError(f"LLVM IR build failed for {source.name}: {result['output'][:800]}")
        results.append(target)
    return results


def _obfuscate(root: Path, ir_files: list[Path], output_dir: Path, *, seed: int) -> tuple[list[Path], list[dict]]:
    paths = toolchain_paths(root)
    results = []
    commands = []
    for index, ir_file in enumerate(ir_files):
        target = output_dir / f"{index:02d}-{ir_file.stem}.obf.ll"
        command = [
            str(paths["opt"]),
            "-passes=obfuscation",
            str(ir_file),
            "-S",
            "-o",
            str(target),
            f"-obf-all={PASS_SPEC}",
            f"-obf-seed={seed}",
            "-obf-deterministic",
        ]
        result = _run(command, cwd=output_dir)
        commands.append(result)
        if result["return_code"] or not target.is_file():
            raise OllvmBuildError(f"OLLVM pass failed for {ir_file.name}: {result['output'][:800]}")
        results.append(target)
    return results, commands


def _link(root: Path, ir_files: list[Path], output: Path, output_dir: Path, *, strip: bool) -> list[dict]:
    paths = toolchain_paths(root)
    commands = []
    link = [str(paths["clang"]), "-O1", *(str(path) for path in ir_files), "-o", str(output)]
    result = _run(link, cwd=output_dir)
    commands.append(result)
    if result["return_code"] or not output.is_file():
        raise OllvmBuildError(f"Protected link failed: {result['output'][:800]}")
    if strip:
        stripped = output.with_name(output.name + ".stripping")
        shutil.copyfile(output, stripped)
        strip_cmd = [paths["strip"], "--strip-all", str(stripped)]
        result = _run(strip_cmd, cwd=output_dir)
        commands.append(result)
        if result["return_code"] or not stripped.is_file():
            raise OllvmBuildError(f"strip failed: {result['output'][:800]}")
        os.replace(stripped, output)
    output.chmod(0o600)
    return commands


def _versions(root: Path) -> dict:
    paths = toolchain_paths(root)
    versions = {}
    for name in ("clang", "opt"):
        result = _run([str(paths[name]), "--version"], cwd=Path(root), timeout=15)
        versions[name] = (result["output"].splitlines() or ["Unknown"])[0][:200]
    strip = _run([paths["strip"], "--version"], cwd=Path(root), timeout=15) if paths["strip"] else None
    versions["strip"] = (strip["output"].splitlines() or ["Unknown"])[0][:200] if strip else "Unavailable"
    return versions


def build_protected(root, sample_id: str, output_dir, *, seed: int = DEFAULT_SEED,
                    strip: bool = True) -> dict:
    """Build an OLLVM-protected copy of one bundled sample.

    The source must belong to one of the project's own samples. No selected
    application, external ELF/PE, or arbitrary path is accepted.
    """
    root = Path(root).resolve()
    sample = get_sample(sample_id)
    if sample is None or sample.get('source_transform_supported') is False:
        raise OllvmBuildError("OLLVM protection is limited to the five original source-transformable samples.")
    if not available(root):
        raise OllvmUnavailable("The project-local xollvm toolchain is missing or incomplete.")
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    sources = _source_paths(root, sample)
    ir_files = _compile_ir(root, sources, output_dir, redefine_main=False, extra_defines=("-DRS_OLLVM_STRINGS",))
    obf_files, obf_commands = _obfuscate(root, ir_files, output_dir, seed=seed)
    protected = output_dir / "protected.elf"
    link_commands = _link(root, obf_files, protected, output_dir, strip=strip)
    return {
        "path": str(protected),
        "sha256": _sha256(protected),
        "sample_id": sample_id,
        "passes": PASS_SPEC,
        "seed": seed,
        "sources": [str(path.relative_to(root)) for path in sources],
        "commands": [*obf_commands, *link_commands],
        "versions": _versions(root),
        "stripped": bool(strip),
    }


def build_behavior_variants(root, sample_id: str, output_dir, *, seed: int = DEFAULT_SEED) -> dict:
    """Build original and protected source variants for a QEMU behavior test.

    The source is compiled with ``main`` renamed so a small test driver can
    call exported functions as well as the sample entry point. The returned
    ``*.ll`` files are for the protected variant; the caller supplies the
    driver and links it.
    """
    root = Path(root).resolve()
    sample = get_sample(sample_id)
    if sample is None or sample.get('source_transform_supported') is False:
        raise OllvmBuildError("Behaviour testing is limited to the five original source-transformable samples.")
    if not available(root):
        raise OllvmUnavailable("The project-local xollvm toolchain is missing or incomplete.")
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    sources = _source_paths(root, sample)
    original_dir = output_dir / "original-ir"
    protected_dir = output_dir / "protected-ir"
    original_dir.mkdir(mode=0o700, exist_ok=True)
    protected_dir.mkdir(mode=0o700, exist_ok=True)
    original_ir = _compile_ir(root, sources, original_dir, redefine_main=True)
    protected_ir_source = _compile_ir(root, sources, protected_dir, redefine_main=True,
                                      extra_defines=("-DRS_OLLVM_STRINGS",))
    protected_ir, obf_commands = _obfuscate(root, protected_ir_source, protected_dir, seed=seed)
    return {
        "sources": sources,
        "original_ir": original_ir,
        "protected_ir": protected_ir,
        "obfuscation_commands": obf_commands,
        "include_dirs": _include_dirs(root, sources),
    }
