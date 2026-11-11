"""PE/COFF parser, discovery and static-tool acceptance tests.

Inputs are self-authored inert PE32+ bytes; outputs are parsed header fields,
discovery records and static reports. No fixture is ever executed. Extend with
well-bounded data fixtures and assertions for truthful report claims.
"""
import os
import hashlib
import shutil
import struct
import tempfile
import unittest
from unittest import mock
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

    def _parse_temp_payload(self, payload):
        temporary = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        try:
            with temporary:
                temporary.write(payload)
            return analysis.parse_pe_header(temporary.name)
        finally:
            Path(temporary.name).unlink(missing_ok=True)

    def test_truncated_dos_header_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Not a PE file"):
            self._parse_temp_payload(b"MZ")

    def test_invalid_pe_signature_is_rejected(self):
        payload = bytearray(PE.read_bytes())
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        payload[pe_offset] = ord("X")
        with self.assertRaisesRegex(ValueError, "Invalid PE signature"):
            self._parse_temp_payload(payload)

    def test_truncated_coff_and_optional_headers_are_rejected(self):
        payload = PE.read_bytes()
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        with self.subTest(header="COFF"), self.assertRaisesRegex(ValueError, "Truncated PE COFF"):
            self._parse_temp_payload(payload[:pe_offset + 4 + 8])
        with self.subTest(header="optional"), self.assertRaisesRegex(ValueError, "Truncated PE optional"):
            self._parse_temp_payload(payload[:pe_offset + 4 + 20 + 2])

    def test_excessive_section_count_is_bounded_by_file_data(self):
        payload = bytearray(PE.read_bytes())
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        struct.pack_into("<H", payload, pe_offset + 6, 0xFFFF)
        with self.assertRaisesRegex(ValueError, "section count"):
            self._parse_temp_payload(payload)

    def test_section_table_and_data_must_fit_file(self):
        payload = PE.read_bytes()
        pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
        optional_size = struct.unpack_from("<H", payload, pe_offset + 20)[0]
        with self.assertRaisesRegex(ValueError, "section table"):
            self._parse_temp_payload(payload[:pe_offset + 24 + optional_size + 5])
        with self.assertRaisesRegex(ValueError, "section data"):
            self._parse_temp_payload(payload[:-1])

    def test_missing_objdump_is_reported_as_unavailable(self):
        with mock.patch.object(engine, "which_tool", return_value=None):
            self.assertFalse(engine.inventory()["objdump"]["available"])
            with self.assertRaisesRegex(ValueError, "unavailable"):
                engine.analyze(PE, tools=["objdump"])

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
