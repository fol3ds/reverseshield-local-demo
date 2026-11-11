"""Day 2 tests: content metrics, coverage, Ghidra options and comparison.

Inputs are the bundled sample binaries, the synthetic PE fixture, synthetic
in-memory PE/ELF bytes and fake tool scripts. Every metric is computed from
file bytes; no target, sample or fixture is executed. The Ghidra cancel and
timeout probes launch a fake shell script in place of ``analyzeHeadless``.
"""
import hashlib
import importlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = sorted(path for path in (ROOT / "samples/bin").glob("level-*.elf")
                 if path.stem != "level-5-hardened")
HARDENED_SAMPLE = ROOT / "samples/bin/level-5-hardened.elf"
PE_FIXTURE = ROOT / "tests/fixtures/minimal-pe64.exe"


def synthetic_pe(imports=("CreateFileW", "ReadFile"), exports=3, named=2):
    """Build an inert PE32+ image with one import descriptor and an export directory."""
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 60, 0x200)            # SizeOfHeaders
    struct.pack_into("<I", data, optional + 108, 16)              # NumberOfRvaAndSizes
    struct.pack_into("<II", data, optional + 112, 0x1100, 40)     # export directory
    struct.pack_into("<II", data, optional + 120, 0x1000, 40)     # import directory
    section = optional + 240
    struct.pack_into("<8sIIIIIIHHI", data, section, b".rdata", 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)
    base = 0x200  # file offset of RVA 0x1000
    struct.pack_into("<IIIII", data, base, 0x1040, 0, 0, 0x1080, 0x1040)
    for index, _ in enumerate(imports):
        struct.pack_into("<Q", data, base + 0x40 + index * 8, 0x10A0 + index * 16)
    data[base + 0x80:base + 0x8D] = b"KERNEL32.dll\0"
    struct.pack_into("<II", data, base + 0x100 + 20, exports, named)
    return bytes(data)


def process_alive(pid):
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0]
        return state not in {"Z", "X"}
    except FileNotFoundError:
        return False
    except OSError:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False


class MetricParserTests(unittest.TestCase):
    def setUp(self):
        self.metrics = importlib.import_module("metrics")

    def test_entropy_bounds_and_known_values(self):
        entropy = self.metrics.shannon_entropy
        self.assertIsNone(entropy(b""))
        self.assertEqual(entropy(b"\0" * 64), 0.0)
        self.assertEqual(entropy(bytes(range(256))), 8.0)
        self.assertEqual(entropy(b"ab" * 50), 1.0)

    def test_string_categories_are_deterministic(self):
        categorize = self.metrics.categorize_string
        self.assertEqual(categorize("see https://example.invalid/help"), "urls")
        self.assertEqual(categorize("/usr/lib/debug/app.so"), "paths")
        self.assertEqual(categorize(r"C:\Users\builder\src\main.c"), "paths")
        self.assertEqual(categorize("main.c"), "paths")
        self.assertEqual(categorize("GCC: (GNU) 14.2.1 20250110"), "compiler_notes")
        self.assertEqual(categorize("Policy denied: missing badge"), "messages")
        self.assertEqual(categorize("x7Q#"), "other")

    @unittest.skipUnless(SAMPLES, "bundled ELF samples are not built")
    def test_five_samples_have_sections_entropy_imports_and_debug_flags(self):
        readelf = shutil.which("readelf")
        for sample in SAMPLES:
            with self.subTest(sample=sample.name):
                first = self.metrics.content_metrics(sample)
                self.assertEqual(first, self.metrics.content_metrics(sample), "metrics must be deterministic")
                self.assertEqual(first["format"], "ELF")
                self.assertEqual(first["errors"], [])
                sections = first["sections"]
                self.assertGreater(sections["count"], 10)
                self.assertGreaterEqual(sections["executable"], 1)
                self.assertGreaterEqual(sections["writable"], 1)
                for item in sections["items"]:
                    if item["entropy"] is not None:
                        self.assertTrue(0.0 <= item["entropy"] <= 8.0)
                self.assertTrue(0.0 < first["file_entropy"] <= 8.0)
                self.assertGreaterEqual(first["imports"]["count"], 1)
                self.assertGreaterEqual(first["imports"]["libraries"], 1)
                strings = first["strings"]
                self.assertEqual(sum(strings["categories"].values()), strings["total"])
                self.assertGreater(strings["categories"]["compiler_notes"], 0)
                self.assertTrue(first["debug"]["debug_sections_present"])
                self.assertTrue(first["debug"]["symbol_table_present"])
                self.assertGreater(first["symbols"]["elf_symbols"], 0)
                if readelf:
                    out = subprocess.run([readelf, "-S", "-W", "--", str(sample)], capture_output=True,
                                         text=True, check=True, env={**os.environ, "LC_ALL": "C"}).stdout
                    rows = [line for line in out.splitlines() if line.strip().startswith("[") and "]" in line
                            and not line.strip().startswith("[Nr]")]
                    self.assertEqual(sections["count"], len(rows) - 1)  # minus the NULL section
                    dyn = subprocess.run([readelf, "--dyn-syms", "-W", "--", str(sample)], capture_output=True,
                                         text=True, check=True, env={**os.environ, "LC_ALL": "C"}).stdout
                    undefined = [line for line in dyn.splitlines() if " UND " in line and len(line.split()) >= 8]
                    self.assertEqual(first["imports"]["count"], len(undefined))

    @unittest.skipUnless(HARDENED_SAMPLE.is_file(), "hardened sample is not built")
    def test_hardened_sample_has_no_debug_sections(self):
        first = self.metrics.content_metrics(HARDENED_SAMPLE)
        self.assertEqual(first['format'], 'ELF')
        self.assertFalse(first['debug']['debug_sections_present'])

    def test_pe_fixture_and_synthetic_import_export_tables(self):
        fixture = self.metrics.content_metrics(PE_FIXTURE)
        self.assertEqual(fixture["format"], "PE")
        self.assertEqual(fixture["errors"], [])
        self.assertEqual(fixture["sections"]["count"], 1)
        self.assertEqual(fixture["sections"]["executable"], 1)
        self.assertEqual(fixture["imports"]["count"], 0)
        self.assertEqual(fixture["exports"]["count"], 0)
        self.assertFalse(fixture["debug"]["symbol_table_present"])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "synthetic.dll"
            path.write_bytes(synthetic_pe())
            result = self.metrics.content_metrics(path)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["imports"]["count"], 2)
        self.assertEqual(result["imports"]["libraries"], 1)
        self.assertEqual(result["exports"]["count"], 3)
        self.assertEqual(result["exports"]["named"], 2)
        self.assertEqual(result["sections"]["executable"], 0)
        self.assertEqual(result["sections"]["writable"], 0)

    def test_malformed_inputs_record_errors_instead_of_raising(self):
        with tempfile.TemporaryDirectory() as temp:
            cases = {
                "truncated.elf": b"\x7fELF\x02\x01\x01" + b"\0" * 20,
                "bad-sections.elf": (SAMPLES[0].read_bytes()[:64] if SAMPLES else b"\x7fELF\x02\x01" + b"\0" * 58),
                "bad-offset.exe": b"MZ" + b"\0" * 58 + struct.pack("<I", 0x7FFFFFF0),
                "bad-import.dll": bytearray(synthetic_pe()),
            }
            struct.pack_into("<II", cases["bad-import.dll"], 0x98 + 120, 0x7FFF0000, 40)
            for name, data in cases.items():
                with self.subTest(case=name):
                    path = Path(temp) / name
                    path.write_bytes(bytes(data))
                    result = self.metrics.content_metrics(path)
                    self.assertTrue(result["errors"], f"{name} should record a parse error")
                    self.assertIsNotNone(result["strings"])


class EngineMetricTests(unittest.TestCase):
    def setUp(self):
        self.engine = importlib.import_module("engine")

    def test_pe_report_keeps_readelf_skip_reason_and_separate_symbol_sources(self):
        available = [name for name, info in self.engine.inventory().items()
                     if info["available"] and name != "ghidra_headless"]
        if not available:
            self.skipTest("no lightweight static tool is installed")
        report = self.engine.analyze(PE_FIXTURE, tools=available)
        metrics = report["content_metrics"]
        self.assertEqual(metrics["format"], "PE")
        self.assertIn("pe_coff_symbols", metrics["symbols"])
        self.assertIn("ghidra_symbols", metrics["symbols"])
        self.assertIsNone(metrics["symbols"]["ghidra_symbols"], "Ghidra did not run, so its count is N/A")
        self.assertIsNone(metrics["ghidra"])
        coverage = report["coverage"]
        for key in ("tools_ran", "tools_skipped", "tools_failed", "tools_unavailable", "tools_not_selected", "outputs_truncated"):
            self.assertIn(key, coverage)
        if "readelf" in available:
            skip = next(item for item in coverage["tools_skipped"] if item["tool"] == "readelf")
            self.assertIn("PE", skip["reason"])
            self.assertNotIn("readelf", coverage["tools_ran"])
        if self.engine.inventory()["ghidra_headless"]["available"]:
            self.assertIn("ghidra_headless", coverage["tools_not_selected"])

    @unittest.skipUnless(SAMPLES, "bundled ELF samples are not built")
    def test_elf_symbols_and_tool_counts_are_not_merged(self):
        inventory = self.engine.inventory()
        if not inventory["readelf"]["available"]:
            self.skipTest("readelf is not installed")
        report = self.engine.analyze(ROOT / "samples/bin/level-5.elf", tools=["readelf"])
        symbols = report["content_metrics"]["symbols"]
        self.assertGreater(symbols["elf_symbols"], 0)
        self.assertGreater(symbols["readelf_symbols"], 0)
        self.assertIsNone(symbols["nm_symbols"])
        self.assertIsNone(symbols["ghidra_symbols"])
        self.assertEqual(symbols["merged_symbol_entries"], len(report["artifacts"]["symbols"]))

    def test_options_are_validated(self):
        normalize = self.engine.normalize_options
        defaults = normalize(None)
        self.assertEqual(defaults["ghidra_timeout_seconds"], self.engine.GHIDRA_TIMEOUT)
        self.assertEqual(defaults["ghidra_max_cpu"], min(self.engine.GHIDRA_MAX_CPU, os.cpu_count() or 1))
        self.assertEqual(normalize(defaults), defaults, "normalized options must be idempotent")
        self.assertLess(normalize({"ghidra_timeout_seconds": 60})["ghidra_analysis_timeout_seconds"], 60)
        for bad in ({"ghidra_timeout_seconds": 5}, {"ghidra_timeout_seconds": "240"}, {"ghidra_max_cpu": 0},
                    {"ghidra_max_cpu": 10_000}, {"allow_large_ghidra": "yes"}, {"shell": "rm -rf /"}, []):
            with self.subTest(options=bad):
                with self.assertRaises(ValueError):
                    normalize(bad)


class GhidraProcessTests(unittest.TestCase):
    """Cancel/timeout probes with a fake analyzeHeadless; no real target runs."""

    def setUp(self):
        self.engine = importlib.import_module("engine")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.pidfile = root / "child.pid"
        self.script = root / ("analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless")
        if os.name == 'nt':
            probe = root / 'probe.py'
            probe.write_text("import os, subprocess, sys, time\nfrom pathlib import Path\n"
                             "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                             "Path(os.environ['RS_TEST_PIDFILE']).write_text(str(child.pid))\n"
                             "print('ready', flush=True)\nchild.wait()\n", encoding='utf-8')
            self.script.write_text(f'@"{sys.executable}" "{probe}"\n', encoding='utf-8')
        else:
            self.script.write_text("#!/bin/sh\nsleep 60 &\necho $! > \"$RS_TEST_PIDFILE\"\necho ready\nwait\n")
        self.script.chmod(0o700)
        self.target = root / "inert.bin"
        self.target.write_bytes(b"\x7fELF" + b"\0" * 60)
        self.workdir = root / "work"
        self.info = {"path": str(self.script), "label": "Fake Ghidra", "version": "probe"}

    def run_probe(self, *, cancel_after_ready, options):
        cancel = threading.Event()
        def emit(event):
            if cancel_after_ready and event["type"] == "log" and "ready" in event["message"]:
                cancel.set()
        started = time.monotonic()
        with mock.patch.dict(os.environ, {"RS_TEST_PIDFILE": str(self.pidfile)}):
            record, payload, _coverage, _limitations = self.engine._analyze_ghidra(
                self.target, workdir=self.workdir, emit=emit, cancel_event=cancel, info=self.info, options=options)
        return record, payload, time.monotonic() - started

    def assert_cleaned(self, record):
        child = int(self.pidfile.read_text().strip())
        deadline = time.monotonic() + 3
        while process_alive(child) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertFalse(process_alive(child), "child of the Ghidra launcher was left running")
        self.assertFalse((self.workdir / "ghidra_project").exists(), "temporary Ghidra project was not removed")
        self.assertTrue(record["cleanup"]["project_removed"])
        self.assertTrue(record["cleanup"]["process_tree_terminated"])

    def test_cancel_stops_process_tree_and_removes_project(self):
        record, payload, elapsed = self.run_probe(cancel_after_ready=True, options={"ghidra_max_cpu": 1})
        self.assertEqual(record["status"], "cancelled")
        self.assertEqual(payload, {})
        self.assertLess(elapsed, 10)
        self.assertEqual(record["settings"]["max_cpu"], 1)
        self.assert_cleaned(record)

    def test_timeout_is_recorded_and_process_tree_is_stopped(self):
        with mock.patch.object(self.engine, "GHIDRA_TIMEOUT_RANGE", (1, 1800)):
            record, _payload, elapsed = self.run_probe(cancel_after_ready=False,
                                                       options={"ghidra_timeout_seconds": 1})
        self.assertEqual(record["status"], "timeout")
        self.assertEqual(record["timeout_seconds"], 1)
        self.assertIn("time limit", record["output"])
        self.assertLess(elapsed, 10)
        self.assert_cleaned(record)


class LargeTargetAndComparisonTests(unittest.TestCase):
    def setUp(self):
        self.workflow = importlib.import_module("workflow")
        self.engine = importlib.import_module("engine")

    def inventory(self):
        return {name: {"available": True, "label": name} for name in
                ("file", "readelf", "objdump", "strings", "nm", "ghidra_headless")}

    def test_large_target_requires_explicit_ghidra_confirmation_and_passes_options(self):
        seen = {}
        def analyzer(path, **kwargs):
            seen.update(kwargs)
            return {"filename": path.name, "metadata": {}, "tools": [], "artifacts": {}, "coverage": {}}
        with tempfile.TemporaryDirectory() as temp:
            big = Path(temp) / "big.elf"
            with big.open("wb") as stream:
                stream.write(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
                stream.truncate(self.engine.LARGE_TARGET_BYTES + 1)
            service = self.workflow.Workbench(ROOT, runs_root=Path(temp) / "runs", analyzer=analyzer,
                                              inventory_provider=self.inventory)
            try:
                selection = service.add_selection({"app": {"name": "big"}, "targets": [
                    {"target_id": "big", "absolute_path": str(big), "relative_path": big.name, "analyzable": True}]})
                with self.assertRaisesRegex(ValueError, "Large target"):
                    service.start_job(selection["selection_id"], ["big"], ["readelf", "ghidra_headless"], "analyze", authorized=True)
                lightweight = service.start_job(selection["selection_id"], ["big"], ["readelf"], "analyze", authorized=True)
                service.wait(lightweight, timeout=10)
                self.assertNotIn("options", seen, "options are only passed when Ghidra is selected")
                job = service.start_job(selection["selection_id"], ["big"], ["readelf", "ghidra_headless"], "analyze",
                                        authorized=True, options={"allow_large_ghidra": True, "ghidra_timeout_seconds": 600,
                                                                  "ghidra_max_cpu": 1})
                service.wait(job, timeout=10)
                self.assertEqual(service.get_job(job)["status"], "completed")
                self.assertEqual(seen["options"]["ghidra_timeout_seconds"], 600)
                self.assertEqual(service.get_job(job)["options"]["ghidra_max_cpu"], 1)
                with self.assertRaises(ValueError):
                    service.start_job(selection["selection_id"], ["big"], ["readelf"], "analyze", authorized=True,
                                      options={"ghidra_timeout_seconds": 1})
            finally:
                service.close()

    def test_functions_match_by_address_then_name_and_unmatched_are_listed(self):
        before = [{"name": "main", "address": "0x401000"}, {"name": "check_policy", "address": "0x401100"},
                  {"name": "helper", "address": "0x401200"}, {"name": "gone", "address": "0x401300"}]
        after = [{"name": "FUN_00401000", "address": "0x00401000"}, {"name": "check_policy", "address": "0x402000"},
                 {"name": "helper", "address": "0x401200"}, {"name": "rs_guard", "address": "0x403000"}]
        result = self.workflow.match_functions(before, after)
        self.assertEqual(result["matched_by_address"], 2)
        self.assertEqual(result["matched_by_name"], 1)
        self.assertEqual(result["unmatched_before"], ["gone @ 0x401300"])
        self.assertEqual(result["unmatched_after"], ["rs_guard @ 0x403000"])
        self.assertEqual(result["renamed_at_same_address"], ["main → FUN_00401000 @ 0x401000"])

    def test_missing_metrics_stay_na_and_summary_lists_changes(self):
        before = {"size_bytes": 100, "metadata": {"symbol_entries": 10, "sections_count": 30},
                  "coverage": {"selected_tools": ["readelf"]},
                  "artifacts": {"functions": [{"name": "main", "address": "0x10"}], "symbols": [], "strings": []},
                  "content_metrics": {"format": "ELF", "file_entropy": 3.5, "sections": {"executable": 3, "writable": 7},
                                      "imports": {"count": 2, "libraries": 1}, "exports": {"count": 0},
                                      "symbols": {"elf_symbols": 35, "ghidra_symbols": None},
                                      "strings": {"total": 100, "categories": {"paths": 4, "urls": 0, "compiler_notes": 7, "messages": 20}},
                                      "debug": {"debug_sections_present": True, "symbol_table_present": True,
                                                "build_id_present": True, "compiler_comment_present": True}}}
        after = {"size_bytes": 80, "metadata": {"symbol_entries": 2, "sections_count": 26},
                 "coverage": {"selected_tools": ["readelf"]},
                 "artifacts": {"functions": [{"name": "main", "address": "0x10"}], "symbols": [], "strings": []},
                 "content_metrics": {"format": "ELF", "file_entropy": 3.9, "sections": {"executable": 3, "writable": 7},
                                     "imports": {"count": 2, "libraries": 1}, "exports": {"count": 0},
                                     "symbols": {"elf_symbols": None, "ghidra_symbols": None},
                                     "strings": {"total": 60, "categories": {"paths": 0, "urls": 0, "compiler_notes": 0, "messages": 20}},
                                     "debug": {"debug_sections_present": False, "symbol_table_present": False,
                                               "build_id_present": False, "compiler_comment_present": False}}}
        result = self.workflow.compare_reports(before, after)
        by_name = {metric["name"]: metric for metric in result["metrics"]}
        self.assertEqual(by_name["ELF/PE symbol-table entries"]["after"], 0, "stripped ELF symtab is an observed zero")
        self.assertIsNone(by_name["Strings reported by selected tools"]["before"], "strings tool not selected: N/A, not zero")
        self.assertIsNone(by_name["Strings reported by selected tools"]["delta"])
        self.assertEqual(by_name["Debug sections"]["before"], "present")
        self.assertEqual(by_name["Debug sections"]["after"], "absent")
        self.assertEqual(by_name["File entropy (bits/byte)"]["delta"], 0.4)
        self.assertNotIn("Ghidra symbols", by_name)
        summary = result["summary"]
        self.assertTrue(any(line.startswith("Debug sections") for line in summary["changed"]))
        self.assertTrue(any(line.startswith("Imported functions") for line in summary["unchanged"]))
        self.assertIn("Strings reported by selected tools", summary["not_collected"])
        self.assertIn("Names reported by selected tools (includes Ghidra labels)", by_name)
        self.assertNotIn("Parsed symbol entries", by_name)
        self.assertTrue(result["functions"]["available"])
        self.assertEqual(result["functions"]["matched_by_address"], 1)
        self.assertIn("N/A", " ".join(result["limitations"]))
        self.assertNotIn("protected", " ".join(result["limitations"]).lower())


if __name__ == "__main__":
    unittest.main()
