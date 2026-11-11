"""An analysis-labelled job must never reach a transformation branch."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from workflow import Workbench

ROOT = Path(__file__).resolve().parents[1]


class OperationProfileTests(unittest.TestCase):
    def test_all_explicit_mismatches_are_rejected_not_silently_rewritten(self):
        operations = {'analyze': None, 'strip_compare': 'symbol_removal',
                      'protect_compare': 'constant_blinding',
                      'binary_compare': 'binary_hygiene', 'ollvm_compare': 'ollvm_source'}
        with tempfile.TemporaryDirectory() as temporary:
            service = Workbench(ROOT, runs_root=Path(temporary))
            try:
                for operation, expected in operations.items():
                    for profile in ('symbol_removal', 'constant_blinding', 'binary_hygiene', 'ollvm_source', 'unknown'):
                        if profile == expected:
                            continue
                        with self.subTest(operation=operation, profile=profile):
                            with self.assertRaisesRegex(ValueError, 'operation/profile'):
                                service.start_job('not-a-selection', ['one'], ['readelf'], operation,
                                                  authorized=True, profile=profile)
                self.assertEqual(service.jobs, {})
            finally:
                service.close()

    def test_analyze_rejects_transform_profile_before_queuing(self):
        with tempfile.TemporaryDirectory() as temporary:
            service = Workbench(ROOT, runs_root=Path(temporary),
                                inventory_provider=lambda: {'readelf': {'available': True}})
            target = ROOT / 'samples/bin/level-1.elf'
            selection = service.add_selection({'app': {'name': 'external selection'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target),
                 'relative_path': target.name, 'analyzable': True}
            ]})
            try:
                # Do not launch even a static worker if the validation is broken.
                with mock.patch.object(service.pool, 'submit') as submit:
                    with self.assertRaisesRegex(ValueError, 'operation/profile'):
                        service.start_job(selection['selection_id'], ['one'], ['readelf'],
                                          'analyze', authorized=True, profile='symbol_removal')
                    submit.assert_not_called()
                self.assertEqual(service.jobs, {})
                self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                service.close()


if __name__ == '__main__':
    unittest.main()
