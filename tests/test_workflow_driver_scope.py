"""Scope synthetic workflow evidence to separate QEMU driver builds."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from workflow import Workbench

ROOT = Path(__file__).resolve().parents[1]


class DriverEvidenceScopeTests(unittest.TestCase):
    def test_matching_driver_vectors_do_not_verify_downloadable_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = Workbench(ROOT, runs_root=Path(temporary),
                analyzer=lambda path, **kwargs: {'tools': [], 'artifacts': {}, 'metadata': {}},
                inventory_provider=lambda: {'readelf': {'available': True}})
            target = ROOT / 'samples/bin/level-1.elf'
            selection = service.add_selection({'app': {'name': 'self-authored fixture'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target),
                 'relative_path': target.name, 'analyzable': True}
            ]}, sample_id='level-1')

            def fake_build(root, sample_id, directory):
                directory.mkdir()
                artifact = directory / 'protected.elf'
                artifact.write_bytes(b'synthetic unit-test artifact; never executed')
                return {'path': str(artifact), 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                        'passes': 'synthetic test only', 'seed': 1, 'sources': [],
                        'versions': {}, 'commands': []}

            behavior = {'passed': True, 'available': True,
                        'scope': 'separate_deterministic_drivers',
                        'artifact_behavior_verified': False,
                        'exit_codes': {'original': 0, 'protected': 0}}
            try:
                with mock.patch('ollvm_protection.available', return_value=True), \
                     mock.patch('ollvm_protection.build_protected', side_effect=fake_build), \
                     mock.patch('behavior_qemu.run_behavior', return_value=behavior):
                    job = service.start_job(selection['selection_id'], ['one'], ['readelf'],
                                            'ollvm_compare', authorized=True, profile='ollvm_source')
                    service.wait(job, timeout=10)
                record = service.get_job(job)
                self.assertEqual(record['status'], 'completed', record['error'])
                protection = record['result']['protection']
                self.assertFalse(protection['behavior_verified'],
                                 'Separate driver builds cannot verify the downloadable artifact')
                self.assertTrue(protection['driver_vectors_matched'])
                self.assertEqual(protection['behavior_scope'], 'separate_deterministic_drivers')
                self.assertIn('downloadable', ' '.join(record['result']['limitations']))
            finally:
                service.close()


if __name__ == '__main__':
    unittest.main()
