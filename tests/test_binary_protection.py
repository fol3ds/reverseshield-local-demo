"""Tests for copy-only metadata hygiene on inert ELF data.

Inputs are the bundled ELF fixture and temporary output directories; outputs
are metadata and immutability assertions. No target is executed. Extend with
static tool checks and explicit platform capability skips.
"""
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import binary_protection
from platform_support import local_tool_dirs, which_tool

ROOT = Path(__file__).resolve().parents[1]
TOOLS_AVAILABLE = all(which_tool(name, tuple(local_tool_dirs(ROOT))) for name in ("strip", "objcopy", "readelf", "strings"))


class BinaryHygieneTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt" and not TOOLS_AVAILABLE,
                     "ELF metadata utilities are unavailable on Windows")
    def test_copy_is_stripped_and_original_is_unchanged(self):
        source = ROOT / "samples/bin/level-5.elf"
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            result = binary_protection.build_binary_hygiene(source, Path(temporary))
            output = Path(result["path"])
            self.assertTrue(output.is_file())
            self.assertEqual(output.parent, Path(temporary))
            self.assertEqual(result["before_sha256"], digest)
            self.assertNotEqual(result["sha256"], digest)
            self.assertLess(result["after_size"], result["before_size"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            else:
                self.assertTrue(output.is_file())
            self.assertEqual(result["strength"], "metadata_only")
            self.assertFalse(result["obfuscation"])
            self.assertFalse(result["behavior_verified"])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
            self.assertEqual([item["return_code"] for item in result["commands"]], [0, 0])

            sections = subprocess.run([binary_protection._tool("readelf"), "-S", str(output)], capture_output=True, text=True, check=True).stdout
            for name in (".symtab", ".debug_info", ".comment", ".annobin.notes",
                         ".gnu.build.attributes", ".note.gnu.build-id"):
                self.assertNotIn(name, sections)
            strings = subprocess.run([binary_protection._tool("strings"), "-a", str(output)], capture_output=True, text=True, check=True).stdout
            self.assertNotIn("/home/", strings)
            self.assertTrue(output.read_bytes().startswith(b"\x7fELF"))

    def test_non_elf_is_rejected_without_touching_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "not-elf.bin"
            source.write_bytes(b"not an elf")
            with self.assertRaisesRegex(ValueError, "ELF"):
                binary_protection.build_binary_hygiene(source, Path(temporary) / "out")
            self.assertEqual(source.read_bytes(), b"not an elf")


if __name__ == "__main__":
    unittest.main()
