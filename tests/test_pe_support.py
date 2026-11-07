"""PE/COFF support tests; the fixture is a self-authored minimal PE32+ file."""
import shutil
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

    @unittest.skipUnless(shutil.which("objdump"), "GNU objdump is required for PE disassembly")
    def test_engine_analyzes_pe_with_objdump(self):
        report = engine.analyze(PE, tools=["objdump", "strings"])
        self.assertEqual(report["metadata"]["format"], "PE")
        self.assertEqual(report["metadata"]["class"], "PE32+")
        self.assertEqual(report["metadata"]["sections_count"], 1)
        self.assertEqual(report["tools"][0]["tool"], "objdump")
        self.assertEqual(report["tools"][0]["status"], "ok")
        self.assertGreaterEqual(len(report["artifacts"]["functions"]), 1)


if __name__ == "__main__":
    unittest.main()
