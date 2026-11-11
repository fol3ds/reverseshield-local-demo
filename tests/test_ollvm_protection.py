"""Tests for the project-local xollvm source-protection adapter.

These tests compile a bundled sample and run the deterministic behaviour
drivers inside QEMU. They are skipped when the project-local toolchain or QEMU
is unavailable, and they never execute a sample on the host.
"""
import hashlib
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def modules():
    try:
        import behavior_qemu
        import ollvm_protection
    except ImportError:
        return None, None
    return ollvm_protection, behavior_qemu


class OllvmProtectionTests(unittest.TestCase):
    def setUp(self):
        self.protection, self.behavior = modules()
        if self.protection is None:
            self.skipTest('OLLVM modules are unavailable.')
        if not self.protection.available(ROOT):
            self.skipTest('The project-local xollvm toolchain is unavailable.')
        if shutil.which('qemu-system-x86_64') is None:
            self.skipTest('QEMU is unavailable.')

    def test_builds_protected_level_5_and_matches_original_behaviour(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'build'
            built = self.protection.build_protected(ROOT, 'level-5', output)
            protected = Path(built['path'])
            self.assertTrue(protected.is_file())
            self.assertEqual(protected.stat().st_mode & 0o111, 0)
            self.assertEqual(built['sample_id'], 'level-5')
            self.assertIn('strenc', built['passes'])
            self.assertIn('flattening', built['passes'])
            strings = protected.read_bytes()
            for message in (b'missing request', b'tenant is not set', b'unknown role',
                            b'blocked by policy flag', b'allowed by sample policy',
                            b'role is below the required level'):
                self.assertNotIn(message, strings, f'plaintext message remained: {message!r}')
            behavior = self.behavior.run_behavior(ROOT, 'level-5', Path(temp) / 'behavior')
            self.assertTrue(behavior['passed'], behavior.get('raw_output_tail'))
            self.assertEqual(behavior.get('scope'), 'separate_deterministic_drivers')
            self.assertIs(behavior.get('artifact_behavior_verified'), False)
            self.assertIn('NOT the downloadable protected.elf', ' '.join(behavior['limitations']))
            self.assertNotEqual(built['sha256'], behavior.get('driver_sha256', {}).get('protected'))
            self.assertEqual(behavior['exit_codes'], {'original': 0, 'protected': 0})
            self.assertEqual(behavior['original_output'], behavior['protected_output'])
            self.assertIn('allowed by sample policy', behavior['original_output'])

    def test_all_five_original_samples_match_qemu_deterministic_drivers(self):
        with tempfile.TemporaryDirectory() as temp:
            for sample_id in ('level-1', 'level-2', 'level-3', 'level-4', 'level-5'):
                with self.subTest(sample=sample_id):
                    result = self.behavior.run_behavior(ROOT, sample_id, Path(temp) / sample_id)
                    self.assertTrue(result['passed'], result.get('raw_output_tail'))
                    self.assertEqual(result['scope'], 'separate_deterministic_drivers')
                    self.assertIs(result['artifact_behavior_verified'], False)
                    self.assertEqual(result['qemu_return_code'], 0)
                    self.assertEqual(result['exit_codes'], {'original': 0, 'protected': 0})
                    self.assertEqual(result['original_output'], result['protected_output'])
                    for name in ('original', 'protected'):
                        binary = Path(temp) / sample_id / f'{name}-driver'
                        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
                        self.assertEqual(result['driver_sha256'][name], digest)
                        self.assertEqual(hashlib.sha256((binary.parent / 'guest' / name).read_bytes()).hexdigest(), digest)
                        self.assertEqual(result['transcript_sha256'][name],
                                         hashlib.sha256(result[f'{name}_output'].encode('utf-8')).hexdigest())

    def test_rejects_hardened_analysis_only_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(self.protection.OllvmBuildError, 'five original'):
                self.protection.build_protected(ROOT, 'level-5-hardened', Path(temp) / 'build')

    def test_rejects_non_sample_source(self):
        if not self.protection.available(ROOT):
            self.skipTest('The project-local xollvm toolchain is unavailable.')
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(Exception):
                self.protection.build_protected(ROOT, 'not-a-sample', Path(temp) / 'build')

    def test_workflow_rejects_external_target_for_ollvm(self):
        import workflow
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp))
            target = ROOT / 'samples/bin/level-5.elf'
            selection = service.add_selection({'app': {'name': 'external'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name,
                 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]})
            try:
                with self.assertRaises(ValueError):
                    service.start_job(selection['selection_id'], ['one'], ['readelf'],
                                      'ollvm_compare', authorized=True, profile='ollvm_source')
            finally:
                service.close()



class OllvmPlatformAvailabilityTests(unittest.TestCase):
    """Runs on Windows too, even when xollvm and QEMU are absent."""

    def test_native_windows_cannot_report_ollvm_available(self):
        import ollvm_protection
        with mock.patch.object(ollvm_protection, 'IS_WINDOWS', True):
            self.assertFalse(ollvm_protection.available(ROOT))


if __name__ == '__main__':
    unittest.main()
