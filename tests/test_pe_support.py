"""PE/COFF parser, discovery and static-tool acceptance tests.

Inputs are self-authored inert PE32+ bytes; outputs are parsed header fields,
discovery records and static reports. No fixture is ever executed. Extend with
well-bounded data fixtures and assertions for truthful report claims.
"""
import shutil
import os
import hashlib
import tempfile
import unittest
from pathlib import Path

import analysis
import discovery
import engine

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "tests/fixtures/minimal-pe64.exe"


class PeSupportTests(unittest.TestCase):
    def test_minimal_pe_is_detected_and_parsed_without_execution(self):
        self.assertTrue(PE.is_file())
        self.assertEqual(analysis.detect_format(PE.read_bytes()[:64]), "PE")
        header = analysis.parse_pe_header(PE)
        self.assertEqual(header["format"], "PE")
        self.assertEqual(header["class"], "PE32+")
        self.assertEqual(header["machine"], "x86-64")
        self.assertEqual(header["sections_count"], 1)
        self.assertEqual(header["section_names"], [".text"])
        self.assertTrue(header["entry_point"].startswith("0x"))

    def test_discovery_accepts_pe_as_a_target(self):
        target = discovery._file_target(PE, PE.name)
        self.assertIsNotNone(target)
        self.assertEqual(target["format"], "PE")
        self.assertTrue(target["analyzable"])

    @unittest.skipUnless(engine.inventory()["objdump"]["available"], "GNU objdump is required for PE disassembly")
    def test_engine_analyzes_pe_with_objdump(self):
        selected = ["objdump", "strings"]
        if engine.inventory()["readelf"]["available"]:
            selected.insert(0, "readelf")
        report = engine.analyze(PE, tools=selected)
        self.assertEqual(report["metadata"]["format"], "PE")
        self.assertEqual(report["metadata"]["class"], "PE32+")
        self.assertEqual(report["metadata"]["sections_count"], 1)
        records = {item["tool"]: item for item in report["tools"]}
        self.assertEqual(records["objdump"]["status"], "ok")
        if "readelf" in selected:
            self.assertEqual(records["readelf"]["status"], "skipped")
        self.assertGreaterEqual(len(report["artifacts"]["functions"]), 1)
        self.assertEqual(report["sha256"], hashlib.sha256(PE.read_bytes()).hexdigest())
        self.assertEqual(report["metadata"]["machine"], "x86-64")
        self.assertTrue(report["metadata"]["entry_point"].startswith("0x"))
        self.assertIn("never executed", " ".join(report["limitations"]).lower())

    @unittest.skipUnless(os.name == "nt" and engine.inventory()["objdump"]["available"],
                         "Windows PE walker and objdump acceptance test requires native Windows objdump")
    def test_windows_directory_walker_discovers_pe_fixture_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "safe-app"
            (folder / "bin").mkdir(parents=True)
            (folder / "bin" / "fixture.exe").write_bytes(PE.read_bytes())
            (folder / "bin" / "library.dll").write_bytes(PE.read_bytes())

            targets, scan = discovery._scan_directory_windows(folder)

            self.assertTrue(scan["complete"], scan["errors"])
            self.assertEqual([item["relative_path"] for item in targets], ["bin/fixture.exe", "bin/library.dll"])
            self.assertTrue(all(item["format"] == "PE" and item["analyzable"] for item in targets))
            header = analysis.parse_pe_header(folder / "bin" / "fixture.exe")
            self.assertEqual((header["class"], header["machine"], header["sections_count"]), ("PE32+", "x86-64", 1))
            self.assertTrue(header["entry_point"].startswith("0x"))
            report = engine.analyze(folder / "bin" / "fixture.exe", tools=["objdump"])
            self.assertEqual(report["metadata"]["format"], "PE")
            self.assertEqual(report["sha256"], hashlib.sha256(PE.read_bytes()).hexdigest())
            self.assertEqual(report["tools"][0]["status"], "ok")
            self.assertIn("never executed", " ".join(report["limitations"]).lower())


if __name__ == "__main__":
    unittest.main()
