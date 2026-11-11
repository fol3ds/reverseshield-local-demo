"""Static hardening-property tests for ELF and PE files."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def hardening_module():
    import hardening
    return hardening


class HardeningTests(unittest.TestCase):
    def test_hardened_level_5_is_a_selectable_sixth_sample(self):
        from samples import get_sample
        sample = get_sample('level-5-hardened')
        self.assertIsNotNone(sample)
        self.assertFalse(sample['source_transform_supported'])
        self.assertEqual(sample['binary'], 'samples/bin/level-5-hardened.elf')
        result = hardening_module().analyze_hardening(ROOT / sample['binary'])
        self.assertEqual(result['format'], 'ELF')
        for name in ('nx', 'pie', 'relro', 'canary', 'fortify'):
            with self.subTest(name=name):
                self.assertEqual(result['checks'][name]['state'], 'present', result['checks'][name])

    def test_hardened_builder_compiles_without_executing(self):
        if sys.platform != 'linux':
            self.skipTest('Hardened sample compilation requires native Linux ELF linker flags')
        import tempfile
        from build_samples import build_hardened_sample, local_tool_dirs, which_tool
        search_dirs = tuple(local_tool_dirs(ROOT))
        if not (which_tool('gcc', search_dirs) or which_tool('clang', search_dirs)):
            self.skipTest('Hardened sample compilation requires a C compiler (gcc or clang)')
        with tempfile.TemporaryDirectory() as tmp:
            target = build_hardened_sample(Path(tmp))
            self.assertTrue(target.exists())
            self.assertEqual(target.stat().st_mode & 0o111, 0)
            self.assertEqual(hardening_module().analyze_hardening(target)['checks']['fortify']['state'], 'present')

    def test_hardened_builder_rejects_native_windows_before_compiler_or_writes(self):
        import tempfile
        import build_samples
        # Exercise the rejection branch on any host; this is not Windows execution.
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'unsupported'
            with mock.patch.object(build_samples, 'os', SimpleNamespace(name='nt')), \
                    mock.patch.object(build_samples, 'sys', SimpleNamespace(platform='win32')), \
                    mock.patch.object(build_samples, 'which_tool',
                                      side_effect=AssertionError('Windows attempted compiler discovery')), \
                    mock.patch.object(build_samples.subprocess, 'run',
                                      side_effect=AssertionError('Windows attempted compilation')):
                with self.assertRaisesRegex(RuntimeError, 'Linux ELF'):
                    build_samples.build_hardened_sample(output)
            self.assertFalse(output.exists())

    def test_elf_level_5_reports_observed_properties(self):
        hardening = hardening_module()
        result = hardening.analyze_hardening(ROOT / 'samples/bin/level-5.elf')
        self.assertEqual(result['format'], 'ELF')
        self.assertEqual(result['errors'], [])
        checks = result['checks']
        self.assertEqual(checks['nx']['state'], 'present')
        self.assertEqual(checks['pie']['state'], 'absent')
        self.assertIn(checks['relro']['state'], {'partial', 'present'})
        self.assertEqual(checks['canary']['state'], 'absent')
        self.assertEqual(checks['fortify']['state'], 'absent')
        self.assertIn('not a security score', ' '.join(result['limitations']))
        self.assertIn('does not execute', ' '.join(result['limitations']))

    def test_pe_fixture_reports_pe_properties(self):
        hardening = hardening_module()
        result = hardening.analyze_hardening(ROOT / 'tests/fixtures/minimal-pe64.exe')
        self.assertEqual(result['format'], 'PE')
        checks = result['checks']
        self.assertEqual(checks['nx']['state'], 'absent')
        self.assertEqual(checks['pie']['state'], 'absent')
        self.assertEqual(checks['relro']['state'], 'not_applicable')
        self.assertEqual(checks['fortify']['state'], 'not_applicable')
        self.assertEqual(checks['canary']['state'], 'unknown')

    def test_malformed_input_returns_an_error_not_an_exception(self):
        hardening = hardening_module()
        result = hardening.analyze_hardening(__file__)
        self.assertIsNone(result['format'])
        self.assertTrue(result['errors'])

    def test_engine_includes_hardening_evidence(self):
        from engine import analyze
        result = analyze(ROOT / 'samples/bin/level-1.elf', tools=['readelf'])
        self.assertIn('hardening', result)
        self.assertEqual(result['hardening']['format'], 'ELF')
        self.assertIn('nx', result['hardening']['checks'])


if __name__ == '__main__':
    unittest.main()
