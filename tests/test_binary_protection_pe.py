"""Copy-only metadata hygiene tests for an inert self-authored PE fixture.

Inputs are fixture bytes and a temporary output directory; outputs are hashes
and metadata-only copies. The original and output are never executed. Extend
with additional format fixtures while checking source immutability.
"""
import tempfile
import unittest
from pathlib import Path

import binary_protection

ROOT = Path(__file__).resolve().parents[1]
PE = ROOT / "tests/fixtures/minimal-pe64.exe"


class BinaryProtectionPeTests(unittest.TestCase):
    def test_pe_copy_is_supported_and_original_is_unchanged(self):
        before = PE.read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            result = binary_protection.build_binary_hygiene(PE, Path(tmp))
            output = Path(result["path"])
            self.assertEqual(result["format"], "PE")
            self.assertEqual(output.name, "binary-hygiene.exe")
            self.assertTrue(output.is_file())
            self.assertGreater(output.stat().st_size, 0)
            self.assertEqual(PE.read_bytes(), before)
            self.assertFalse(result["obfuscation"])
            self.assertFalse(result["behavior_verified"])
            self.assertEqual(result["strength"], "metadata_only")


if __name__ == "__main__":
    unittest.main()
