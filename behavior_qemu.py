"""QEMU behaviour checks for OLLVM-protected sample copies.

The protected program is never launched on the host. A small test driver and
an init program are packed into a temporary initramfs and booted under QEMU
with no disk and no network. The guest runs the original and protected drivers
and prints their deterministic output; Python compares the two transcripts.
"""
from __future__ import annotations

import gzip
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ollvm_protection import build_behavior_variants, OllvmBuildError, OllvmUnavailable, _run, toolchain_paths

DRIVER_TEMPLATES = {
    "level-1": r"""
#include <stdint.h>
#include <stdio.h>
extern uint32_t badge_value(uint32_t input);
extern int rs_sample_main(void);
int main(void) {
    const uint32_t values[] = {0u, 1u, 41u, 42u, 100u, 65535u};
    for (unsigned i = 0; i < sizeof(values)/sizeof(values[0]); ++i)
        printf("badge(%u)=%u\n", values[i], badge_value(values[i]));
    printf("main=%d\n", rs_sample_main());
    return 0;
}
""",
    "level-2": r"""
#include <stdint.h>
#include <stdio.h>
extern uint32_t calculate_badge_score(uint32_t points, uint32_t tier);
extern int rs_sample_main(void);
int main(void) {
    const uint32_t points[] = {0u, 31u, 100u, 250u};
    const uint32_t tiers[] = {0u, 1u, 2u, 3u, 99u};
    for (unsigned i = 0; i < sizeof(points)/sizeof(points[0]); ++i)
        for (unsigned j = 0; j < sizeof(tiers)/sizeof(tiers[0]); ++j)
            printf("score(%u,%u)=%u\n", points[i], tiers[j], calculate_badge_score(points[i], tiers[j]));
    printf("main=%d\n", rs_sample_main());
    return 0;
}
""",
    "level-3": r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
extern uint32_t transform_score(const uint8_t *data, size_t length);
extern int rs_sample_main(void);
int main(void) {
    const uint8_t a[] = {0x21u, 0x43u, 0x65u, 0x87u};
    const uint8_t b[] = {0x00u, 0xffu, 0x10u, 0x01u, 0x7fu};
    const uint8_t c[] = {0x52u, 0x53u};
    printf("score(a)=%u\n", transform_score(a, sizeof a));
    printf("score(b)=%u\n", transform_score(b, sizeof b));
    printf("score(c)=%u\n", transform_score(c, sizeof c));
    printf("main=%d\n", rs_sample_main());
    return 0;
}
""",
    "level-4": r"""
#include <stdio.h>
extern int rs_sample_main(void);
int main(void) {
    printf("main=%d\n", rs_sample_main());
    return 0;
}
""",
    "level-5": r"""
#include "policy.h"
#include <stdio.h>
extern int rs_sample_main(void);
static void show(const char *label, enum resource_kind resource, enum access_role role,
                 uint32_t tenant, uint32_t flags) {
    struct access_request request = {resource, role, flags, tenant};
    printf("%s allow=%d reason=%s\n", label, policy_allows(&request), policy_reason(&request));
}
int main(void) {
    show("archive-editor", RESOURCE_ARCHIVE, ROLE_EDITOR, 7u, 0u);
    show("archive-viewer", RESOURCE_ARCHIVE, ROLE_VIEWER, 7u, 0u);
    show("export-owner", RESOURCE_EXPORT, ROLE_OWNER, 7u, 0u);
    show("report-viewer", RESOURCE_REPORT, ROLE_VIEWER, 7u, 0u);
    show("no-tenant", RESOURCE_ARCHIVE, ROLE_EDITOR, 0u, 0u);
    show("bad-role", RESOURCE_ARCHIVE, (enum access_role)9, 7u, 0u);
    show("blocked-flag", RESOURCE_ARCHIVE, ROLE_EDITOR, 7u, 0x80000000u);
    show("unknown-resource", (enum resource_kind)99, ROLE_OWNER, 7u, 0u);
    printf("main=%d\n", rs_sample_main());
    return 0;
}
""",
}

INIT_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/reboot.h>

static int run(const char *name, const char *path) {
    printf("BEGIN %s\n", name);
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        execl(path, path, (char *)0);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    printf("END %s %d\n", name, code);
    fflush(stdout);
    return code;
}

int main(void) {
    printf("INIT\n");
    run("original", "/original");
    run("protected", "/protected");
    printf("DONE\n");
    fflush(stdout);
    sync();
    reboot(RB_POWER_OFF);
    return 0;
}
"""


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _find_kernel() -> Path | None:
    current = Path("/boot") / f"vmlinuz-{os.uname().release}"
    if current.is_file():
        return current
    matches = sorted(Path("/boot").glob("vmlinuz-*"))
    return matches[-1] if matches else None


# Fixed system locations only: never use a target's RPATH/RUNPATH, environment
# search paths, dynamic loader, or any dependency-discovery tool that loads it.
RUNTIME_LIBRARY_DIRS = tuple(map(Path, (
    "/lib64", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
)))
RUNTIME_INTERPRETERS = frozenset((
    "/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
))
RUNTIME_LIBRARY_NAMES = frozenset(("libc.so.6", "libm.so.6", "libgcc_s.so.1", "ld-linux-x86-64.so.2"))


def _copy_runtime_libs(binary: Path, root: Path) -> None:
    """Inspect ELF metadata and copy only known system runtime libraries."""
    readelf = shutil.which("readelf")
    if readelf is None:
        raise OllvmUnavailable("readelf is unavailable; runtime discovery was not run.")
    pending = [binary]
    inspected = set()
    while pending:
        current = pending.pop()
        identity = current.resolve()
        if identity in inspected:
            continue
        inspected.add(identity)
        try:
            result = subprocess.run(
                [readelf, "-W", "-l", "-d", "--", str(current)],
                capture_output=True, text=True, timeout=10, check=False,
                shell=False, env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired):
            raise OllvmBuildError("Static runtime dependency inspection failed.") from None
        if result.returncode:
            raise OllvmBuildError("Static runtime dependency inspection failed.")
        output = result.stdout or ""
        candidates = []
        for interpreter in re.findall(r"\[Requesting program interpreter:\s*([^\]]+)\]", output):
            if interpreter not in RUNTIME_INTERPRETERS:
                raise OllvmBuildError("Unsupported guest ELF interpreter.")
            candidates.append(Path(interpreter))
        for name in re.findall(r"\(NEEDED\)[^\n]*\[([^\]]+)\]", output):
            if name not in RUNTIME_LIBRARY_NAMES:
                raise OllvmBuildError("Unsupported guest runtime dependency.")
            source = next((directory / name for directory in RUNTIME_LIBRARY_DIRS
                           if (directory / name).is_file()), None)
            if source is None:
                raise OllvmBuildError("A required guest runtime library is unavailable.")
            candidates.append(source)
        for source in candidates:
            if not source.is_file():
                raise OllvmBuildError("A required guest runtime library is unavailable.")
            try:
                relative = source.relative_to("/")
            except ValueError:
                # Windows test paths have no POSIX guest root; names are unique
                # for the supported runtime libraries and this branch is unused
                # by the Linux-only QEMU workflow.
                relative = Path(source.name)
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(source, destination)
            pending.append(source)


def _build_driver(sample_id: str, output_dir: Path) -> Path:
    source = output_dir / "driver.c"
    source.write_text(DRIVER_TEMPLATES[sample_id], encoding="utf-8")
    return source


def _run_build(command: list[str], *, cwd: Path) -> dict:
    """Normalize build-tool launch/timeout failures without echoing host paths."""
    try:
        return _run(command, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired):
        raise OllvmBuildError("Behaviour build tool failed or exceeded its time limit.") from None


def run_behavior(root, sample_id: str, output_dir, *, timeout: int = 120) -> dict:
    """Build and compare original/protected sample behaviour inside QEMU."""
    root = Path(root).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = toolchain_paths(root)
    if not paths["clang"].is_file():
        raise OllvmUnavailable("The xollvm toolchain is unavailable.")
    if shutil.which("qemu-system-x86_64") is None:
        raise OllvmUnavailable("QEMU is unavailable; behaviour verification was not run.")
    kernel = _find_kernel()
    if kernel is None:
        raise OllvmUnavailable("No host kernel image was found for the QEMU micro-VM.")

    try:
        variants = build_behavior_variants(root, sample_id, output_dir)
    except (OSError, subprocess.TimeoutExpired):
        raise OllvmBuildError("Behaviour variant build failed or exceeded its time limit.") from None

    driver = _build_driver(sample_id, output_dir)
    include_args = [item for include in variants["include_dirs"] for item in ("-I", str(include))]
    clang = str(paths["clang"])

    original = output_dir / "original-driver"
    protected = output_dir / "protected-driver"
    original_cmd = [clang, "-O1", str(driver), *include_args, *(str(p) for p in variants["original_ir"]), "-o", str(original)]
    protected_cmd = [clang, "-O1", str(driver), *include_args, *(str(p) for p in variants["protected_ir"]), "-o", str(protected)]
    commands = []
    for command in (original_cmd, protected_cmd):
        result = _run_build(command, cwd=output_dir)
        commands.append(result)
        if result["return_code"]:
            raise OllvmBuildError(f"Behaviour driver link failed: {result['output'][:800]}")

    init_c = output_dir / "init.c"
    init_c.write_text(INIT_SOURCE, encoding="utf-8")
    init = output_dir / "init"
    result = _run_build([clang, "-O1", str(init_c), "-o", str(init)], cwd=output_dir)
    commands.append(result)
    if result["return_code"]:
        raise OllvmBuildError(f"QEMU init build failed: {result['output'][:800]}")

    guest = output_dir / "guest"
    if guest.exists():
        shutil.rmtree(guest)
    guest.mkdir()
    shutil.copy2(init, guest / "init")
    shutil.copy2(original, guest / "original")
    shutil.copy2(protected, guest / "protected")
    _copy_runtime_libs(init, guest)
    _copy_runtime_libs(original, guest)
    _copy_runtime_libs(protected, guest)
    for name in ("init", "original", "protected"):
        (guest / name).chmod(0o755)

    cpio = shutil.which("cpio")
    if cpio is None:
        raise OllvmUnavailable("cpio is unavailable; cannot create the QEMU initramfs.")
    initramfs = output_dir / "initramfs.cpio.gz"
    # Python enumerates paths; NUL-delimited input preserves all filename bytes.
    # cpio receives argv only and gzip runs in-process, never through a shell.
    names = [".", *("./" + str(path.relative_to(guest)) for path in sorted(guest.rglob("*")))]
    filenames = b"\0".join(os.fsencode(name) for name in names) + b"\0"
    try:
        with tempfile.TemporaryFile(dir=output_dir) as uncompressed:
            archive = subprocess.run(
                [cpio, "--null", "-o", "--format=newc", "--quiet"],
                input=filenames, stdout=uncompressed, stderr=subprocess.PIPE,
                cwd=str(guest), shell=False, timeout=30, check=False,
            )
            if archive.returncode:
                raise OllvmBuildError("Could not create the QEMU initramfs.")
            uncompressed.seek(0)
            with initramfs.open("wb") as target:
                with gzip.GzipFile(filename="", fileobj=target, mode="wb", compresslevel=1, mtime=0) as compressed:
                    shutil.copyfileobj(uncompressed, compressed)
    except (OSError, subprocess.TimeoutExpired):
        raise OllvmBuildError("Could not create the QEMU initramfs.") from None

    command = [
        "qemu-system-x86_64", "-m", "256", "-kernel", str(kernel),
        "-initrd", str(initramfs), "-append", "console=ttyS0 rdinit=/init panic=-1 quiet",
        "-nographic", "-no-reboot", "-net", "none",
    ]
    started = time.monotonic()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, shell=False)
        output = (proc.stdout or "") + (proc.stderr or "")
        return_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        def as_text(value):
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else (value or "")
        output = as_text(exc.stdout) + as_text(exc.stderr)
        return_code = -9
    except OSError:
        raise OllvmBuildError("QEMU could not start; behaviour verification was not run.") from None
    duration = round(time.monotonic() - started, 2)

    def section(name: str) -> str | None:
        match = re.search(rf"^BEGIN {re.escape(name)}\s*$(.*?)^END {re.escape(name)} (-?\d+)\s*$", output, re.M | re.S)
        return match.group(1).strip() if match else None

    original_output = section("original")
    protected_output = section("protected")
    ended = re.findall(r"^END (original|protected) (-?\d+)\s*$", output, re.M)
    codes = {name: int(code) for name, code in ended}
    passed = (return_code == 0 and original_output is not None and protected_output is not None
              and original_output == protected_output
              and codes.get("original") == 0 and codes.get("protected") == 0)
    return {
        "available": True,
        "passed": bool(passed),
        "scope": "separate_deterministic_drivers",
        "artifact_behavior_verified": False,
        "driver_sha256": {"original": _sha256(original), "protected": _sha256(protected)},
        "transcript_sha256": {
            name: hashlib.sha256(transcript.encode("utf-8")).hexdigest() if transcript is not None else None
            for name, transcript in (("original", original_output), ("protected", protected_output))
        },
        "original_output": original_output,
        "protected_output": protected_output,
        "exit_codes": codes,
        "qemu_return_code": return_code,
        "duration_seconds": duration,
        "kernel": str(kernel),
        "commands": commands,
        "initramfs_sha256": _sha256(initramfs) if initramfs.is_file() else None,
        "raw_output_tail": output[-4000:],
        "limitations": [
            "The guest runs only deterministic sample drivers with no disk and no network.",
            "These separate drivers are NOT the downloadable protected.elf; that artifact was not executed or behavior-verified.",
            "A matching transcript is evidence for these test vectors, not proof of behavioural equivalence.",
        ],
    }
