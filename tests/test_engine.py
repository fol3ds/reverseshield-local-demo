"""Test bounded process adapters and reports for inert ELF/PE fixture files.

The child processes are test probes or static-inspection tools; the selected
target is never executed. Inputs are fixture paths and tool selections; outputs
are bounded report and event assertions. Extend through fake processes or
static analyzers only.
"""
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "samples/bin/level-1.elf"


def engine_module():
    return importlib.import_module("engine")


class EngineTests(unittest.TestCase):
    def test_streaming_without_newline_can_cancel_running_tool(self):
        engine = engine_module()
        self.assertTrue(callable(getattr(engine, "_run", None)), "bounded streaming runner missing")
        cancel = threading.Event()
        events = []
        def emit(event):
            events.append(event)
            if event["type"] == "log" and "ready" in event["message"]:
                cancel.set()
        start = time.monotonic()
        result = engine._run("probe", [sys.executable, "-u", "-c",
            "import time; print('ready', end='', flush=True); time.sleep(30)"],
            emit=emit, cancel_event=cancel, timeout=5)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(result["output"], "ready")
        self.assertEqual(events[0]["type"], "tool_start")
        self.assertEqual(events[-1]["type"], "tool_end")
        self.assertTrue(all(isinstance(event, dict) and "tool" in event and "message" in event for event in events))

    def test_output_cap_drains_stderr_and_reports_real_bytes(self):
        engine = engine_module()
        result = engine._run("probe", [sys.executable, "-c",
            "import os; os.write(1,b'x'*1500000); os.write(2,b'y'*1500000)"], timeout=3)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["output"]), 1024 * 1024)
        self.assertEqual(result.get("output_bytes"), 3000000)
        self.assertEqual(result.get("output_limit_bytes"), 1024 * 1024)

    def test_readelf_analysis_returns_real_static_metadata_and_functions(self):
        engine = engine_module()
        self.assertTrue(callable(getattr(engine, "analyze", None)), "analysis API missing")
        events = []
        report = engine.analyze(SAMPLE, tools=["readelf"], emit=events.append)
        self.assertEqual(report["analysis_mode"], "static_only")
        self.assertEqual(report["filename"], SAMPLE.name)
        self.assertEqual(report["sha256"], hashlib.sha256(SAMPLE.read_bytes()).hexdigest())
        self.assertEqual(report["size_bytes"], SAMPLE.stat().st_size)
        self.assertEqual(report["metadata"]["class"], "ELF64")
        self.assertIn(".text", report["metadata"]["section_names"])
        self.assertTrue(report["sections"])
        self.assertEqual([t["tool"] for t in report["tools"]], ["readelf"])
        self.assertEqual(report["tools"][0]["status"], "ok")
        self.assertIn("main", [f["name"] for f in report["artifacts"]["functions"]])
        self.assertIn("main", [s["name"] for s in report["artifacts"]["symbols"]])
        self.assertIn("coverage", report)
        self.assertTrue(report["limitations"])
        self.assertIn("artifact", [event["type"] for event in events])
        json.dumps(report)

    def test_invalid_tool_selection_is_rejected_before_execution(self):
        engine = engine_module()
        inventory = engine.inventory()
        inventory["readelf"]["available"] = False
        with mock.patch.object(engine, "inventory", return_value=inventory), mock.patch.object(engine, "_run", side_effect=AssertionError("must not start")):
            for selected in ([], ["unknown"], ["readelf"], "file", [None]):
                with self.subTest(selected=selected), self.assertRaises(ValueError):
                    engine.analyze(SAMPLE, tools=selected)

    def test_lightweight_adapters_produce_real_disassembly_strings_and_symbols(self):
        engine = engine_module()
        requested = ("file", "objdump", "strings", "nm")
        reports = {name: engine.analyze(SAMPLE, tools=[name]) for name in requested
                   if engine.inventory()[name]["available"]}
        self.assertIn("objdump", reports)
        self.assertIn("strings", reports)
        self.assertIn("nm", reports)
        for name, report in reports.items():
            self.assertEqual([t["tool"] for t in report["tools"]], [name])
            self.assertEqual(report["tools"][0]["status"], "ok")
            self.assertTrue(report["tools"][0]["output"])
        if "file" in reports:
            self.assertIn("ELF", reports["file"]["metadata"]["file_type"])
        self.assertIn("<main>", reports["objdump"]["tools"][0]["output"])
        self.assertIn("main", [f["name"] for f in reports["objdump"]["artifacts"]["functions"]])
        self.assertTrue(reports["objdump"]["artifacts"]["call_edges"])
        self.assertIn("main", [s["name"] for s in reports["nm"]["artifacts"]["symbols"]])
        self.assertTrue(reports["strings"]["artifacts"]["strings"])

    @unittest.skipUnless(os.environ.get("RUN_GHIDRA_TESTS") == "1", "set RUN_GHIDRA_TESTS=1 for real headless smoke")
    def test_ghidra_exports_real_pseudocode_cfg_and_caps(self):
        engine = engine_module()
        self.assertTrue(engine.inventory()["ghidra_headless"]["available"])
        events = []
        base = ROOT / "runs/engine-smoke"
        report = engine.analyze(SAMPLE, emit=events.append, workdir=base)
        base.mkdir(parents=True, exist_ok=True)
        (base / "last-report.json").write_text(json.dumps(report, indent=2))
        available_tools = {name for name, item in engine.inventory().items() if item["available"]}
        self.assertEqual({t["tool"] for t in report["tools"]}, available_tools)
        ghidra = next(t for t in report["tools"] if t["tool"] == "ghidra_headless")
        self.assertEqual(ghidra["status"], "ok", ghidra["output"][-10000:])
        self.assertIn("-deleteProject", ghidra["command"])
        self.assertIn("-loader-loadLibraries false", ghidra["command"])
        self.assertIn("-analysisTimeoutPerFile 150", ghidra["command"])
        self.assertIn("-max-cpu 2", ghidra["command"])
        self.assertEqual(ghidra["timeout_seconds"], 240)
        main = next(f for f in report["artifacts"]["functions"] if f["name"] == "main")
        self.assertIn("main", main["pseudocode"])
        self.assertTrue(main["cfg_nodes"])
        self.assertTrue(report["artifacts"]["call_edges"])
        self.assertLessEqual(len(report["artifacts"]["functions"]), 1000)
        self.assertLessEqual(sum("pseudocode" in f for f in report["artifacts"]["functions"]), 40)
        for f in report["artifacts"]["functions"]:
            self.assertLessEqual(len(f.get("cfg_nodes", [])), 100)
            ids = {n["id"] for n in f.get("cfg_nodes", [])}
            self.assertTrue(all(e["source"] in ids and e["target"] in ids for e in f.get("cfg_edges", [])))
        coverage = report["coverage"]["ghidra"]
        self.assertEqual(coverage["decompile_limit"], 40)
        self.assertEqual(coverage["decompile_timeout_seconds"], 3)
        self.assertEqual(coverage["decompile_budget_seconds"], 40)
        self.assertGreater(coverage["functions_decompiled"], 0)
        self.assertFalse(coverage["analysis_timed_out"])
        self.assertTrue(any(e["tool"] == "ghidra_headless" and e["type"] == "log" and "Decompiling main" in e["message"] for e in events))
        self.assertFalse(list(Path(ghidra["work_directory"]).glob("*.gpr")))

    def test_inventory_reports_six_real_adapters_with_versions(self):
        self.assertTrue((ROOT / "engine.py").is_file(), "engine inventory is not implemented")
        inventory = engine_module().inventory()
        self.assertEqual(set(inventory), {"file", "readelf", "objdump", "strings", "nm", "ghidra_headless"})
        for name, item in inventory.items():
            self.assertIsInstance(item["available"], bool)
            self.assertTrue(item["label"])
            self.assertIn("version", item)
            self.assertIn("path", item)
            if name != "ghidra_headless":
                self.assertEqual(item["available"], engine_module().which_tool(name, tuple(
                    path for path in (ROOT / "tools/windows/mingw64/bin", ROOT / "tools/windows/w64devkit/bin",
                                      ROOT / "tools/windows/binutils/bin", ROOT / "tools/jdk25/bin")
                    if path.is_dir())) is not None)
            if item["available"]:
                self.assertTrue(Path(item["path"]).is_file())
                self.assertTrue(item["version"])
        local = ROOT / "tools/ghidra/ghidra_12.2_PUBLIC/support/analyzeHeadless"
        if local.is_file():
            self.assertTrue(inventory["ghidra_headless"]["available"])
            self.assertIn("12.2", inventory["ghidra_headless"]["version"])


if __name__ == "__main__":
    unittest.main()
