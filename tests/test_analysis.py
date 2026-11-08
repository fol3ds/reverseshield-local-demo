"""Unit tests for ELF/PE metadata parsers.

Inputs are inert fixture bytes and bounded text; outputs are parser assertions.
Fixture executables are never launched. Extend with malformed-but-bounded byte
fixtures and verify fail-closed metadata behavior.
"""
import unittest

try:
    import analysis
except ImportError:
    analysis = None


class AnalysisMetadataTests(unittest.TestCase):
    def test_elf_magic_is_checked_without_running_the_file(self):
        self.assertIsNotNone(analysis, "static analyzer module is not implemented yet")
        checker = getattr(analysis, "has_elf_magic", None)
        self.assertTrue(callable(checker), "has_elf_magic should exist")
        self.assertTrue(checker(b"\x7fELF\x02\x01\x01"))
        self.assertFalse(checker(b"PK\x03\x04not-an-elf"))
        self.assertFalse(checker(b"\x7fEL"))

    def test_elf_header_parser_returns_readable_summary_fields(self):
        self.assertIsNotNone(analysis, "static analyzer module is not implemented yet")
        parser = getattr(analysis, "parse_elf_header", None)
        self.assertTrue(callable(parser), "parse_elf_header should exist")
        raw = """ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Type:                              DYN (Position-Independent Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Entry point address:               0x1040
"""
        parsed = parser(raw)
        self.assertEqual(parsed["class"], "ELF64")
        self.assertEqual(parsed["endianness"], "Little endian")
        self.assertIn("X86-64", parsed["machine"])
        self.assertEqual(parsed["entry_point"], "0x1040")

    def test_section_parser_handles_standard_readelf_rows(self):
        self.assertIsNotNone(analysis, "static analyzer module is not implemented yet")
        parser = getattr(analysis, "parse_sections", None)
        self.assertTrue(callable(parser), "parse_sections should exist")
        raw = """There are 3 section headers:
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000001040 001040 000020 00  AX  0   0 16
  [ 2] .debug_info        PROGBITS        0000000000000000 001060 000060 00      0   0  1
"""
        sections = parser(raw)
        self.assertEqual([item["name"] for item in sections], [".text", ".debug_info"])
        self.assertTrue(any(item["name"] == ".debug_info" for item in sections))


if __name__ == "__main__":
    unittest.main()
