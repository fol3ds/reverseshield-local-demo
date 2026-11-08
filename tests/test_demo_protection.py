"""Tests for the sample-only demonstration transformer.

Inputs are C source snippets and bundled sample IDs; outputs are transformed
source and compiled artifact metadata. Compilation is covered; resulting
executables are never run. Extend only against the self-authored sample corpus.
"""
import tempfile
import os
import unittest
from pathlib import Path

import demo_protection

ROOT = Path(__file__).resolve().parents[1]


class TransformTests(unittest.TestCase):
    def test_blinding_skips_case_labels_and_static_initializers(self):
        text = (
            "static const uint32_t BASE = 120u;\n"
            "static uint32_t f(uint32_t x) {\n"
            "  switch (x) { case 2u: return 5u; }\n"
            "  return x + 1009u;\n"
            "}\n")
        out = demo_protection.blind_constants(text, 0x12345678)
        self.assertIn("case 2u:", out)
        self.assertIn("BASE = 120u", out)
        self.assertIn("rs_key", out)
        self.assertNotIn("1009u", out)
        self.assertNotIn("5u;", out)

    def test_guard_is_added_to_integer_functions_only(self):
        text = "uint32_t a(uint32_t x) {\n return x;\n}\nstruct s b(void) {\n return (struct s){0};\n}\n"
        out = demo_protection.add_guards(text)
        self.assertEqual(out.count("rs_key ^ rs_key"), 1)
        self.assertIn("uint32_t a(uint32_t x) {\n    if", out)

    def test_protected_sample_builds_without_running_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = demo_protection.build_protected("level-2", Path(temporary))
            binary = Path(result["path"])
            self.assertTrue(binary.is_file())
            self.assertGreater(binary.stat().st_size, 0)
            if os.name == "nt":
                self.assertEqual(binary.read_bytes()[:2], b"MZ")
            else:
                self.assertEqual(binary.read_bytes()[:4], b"\x7fELF")
            self.assertTrue(result["sha256"])
            if os.name != "nt":
                self.assertEqual(binary.stat().st_mode & 0o111, 0)


if __name__ == "__main__":
    unittest.main()
