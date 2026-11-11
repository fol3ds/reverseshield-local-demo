"""Test asynchronous selection, snapshot, report and transformation workflows.

Inputs are temporary fixture files and injected analyzer responses; outputs
are checked job states and report data. Neither a target ELF nor PE is
executed. Extend using fake analyzers or static tools only.
"""
import hashlib
import importlib.util
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def workflow_module():
    spec = importlib.util.find_spec('workflow')
    if spec is None:
        return None
    import workflow
    return workflow


class ComparisonTests(unittest.TestCase):
    def test_compare_reports_preserves_unknown_and_reports_observed_deltas(self):
        workflow = workflow_module()
        self.assertIsNotNone(workflow, 'workflow comparison module is not implemented')
        before = {'size_bytes': 100, 'metadata': {'symbol_entries': 10},
                  'artifacts': {'strings': ['same', 'old'], 'symbols': [{'name': 'named_fn'}]}}
        after = {'size_bytes': 80, 'metadata': {'symbol_entries': 3},
                 'artifacts': {'strings': ['same', 'new'], 'symbols': []}}
        result = workflow.compare_reports(before, after)
        metric = next(m for m in result['metrics'] if m['name'] == 'File size (bytes)')
        self.assertEqual(metric, {'name': 'File size (bytes)', 'before': 100, 'after': 80, 'delta': -20})
        self.assertEqual(result['strings']['removed'], ['old'])
        self.assertEqual(result['strings']['added'], ['new'])
        self.assertEqual(result['symbols']['removed'], ['named_fn'])
        functions = next(m for m in result['metrics'] if m['name'] == 'Functions identified by selected tools')
        self.assertIsNone(functions['before'])
        self.assertIsNone(functions['delta'])
        self.assertIn('not a resistance score', ' '.join(result['limitations']))


def static_baseline(path, **kwargs):
    from engine import analyze
    return analyze(path, **kwargs)


def inventory_baseline():
    from engine import inventory
    return inventory()


class JobTests(unittest.TestCase):
    def test_hardened_fixture_rejects_source_transforms_but_allows_analysis(self):
        workflow = workflow_module()
        target = ROOT / 'samples/bin/level-5-hardened.elf'
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=static_baseline, inventory_provider=inventory_baseline)
            selection = service.add_selection({'app': {'name': 'Hardened Level 5'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name,
                 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]}, sample_id='level-5-hardened')
            try:
                for operation, profile in [('protect_compare', 'constant_blinding'), ('ollvm_compare', 'ollvm_source')]:
                    with self.subTest(operation=operation):
                        with self.assertRaisesRegex(ValueError, 'analysis-only'):
                            service.start_job(selection['selection_id'], ['one'], ['readelf'], operation,
                                              authorized=True, profile=profile)
                job = service.start_job(selection['selection_id'], ['one'], ['readelf'], 'analyze', authorized=True)
                service.wait(job, timeout=30)
                self.assertEqual(service.get_job(job)['status'], 'completed')
            finally:
                service.close()

    def test_demo_obfuscation_builds_protected_sample_and_preserves_original(self):
        workflow = workflow_module()
        target = ROOT / 'samples/bin/level-2.elf'
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=static_baseline, inventory_provider=inventory_baseline)
            selection = service.add_selection({'app': {'name': 'Level 2'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]}, sample_id='level-2')
            try:
                job = service.start_job(selection['selection_id'], ['one'], ['readelf', 'objdump'], 'protect_compare', authorized=True, profile='constant_blinding')
                service.wait(job, timeout=60)
                record = service.get_job(job)
                self.assertEqual(record['status'], 'completed', record['error'])
                result = record['result']
                self.assertEqual(result['protection']['state'], 'demo_obfuscation_applied')
                self.assertEqual(result['protection']['strength'], 'demonstration_only')
                self.assertFalse(result['protection']['behavior_verified'])
                self.assertNotEqual(result['before']['sha256'], result['after']['sha256'])
                expected_class = 'PE32+' if os.name == 'nt' else 'ELF64'
                self.assertEqual(result['after']['metadata']['class'], expected_class)
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
                artifact = service.artifact_path(job)
                self.assertTrue(artifact.is_file())
                if os.name != 'nt':
                    self.assertEqual(artifact.stat().st_mode & 0o111, 0)
            finally:
                service.close()

    def test_binary_hygiene_accepts_external_selection_and_preserves_original(self):
        workflow = workflow_module()
        target = ROOT / 'samples/bin/level-1.elf'
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=static_baseline, inventory_provider=inventory_baseline)
            selection = service.add_selection({'app': {'name': 'external folder'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name,
                 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]})
            try:
                job = service.start_job(selection['selection_id'], ['one'], ['readelf'], 'binary_compare', authorized=True)
                service.wait(job, timeout=30)
                record = service.get_job(job)
                self.assertEqual(record['status'], 'completed', record['error'])
                result = record['result']
                self.assertEqual(result['operation'], 'binary_compare')
                self.assertEqual(result['protection']['state'], 'binary_metadata_hygiene_applied')
                self.assertEqual(result['protection']['strength'], 'metadata_only')
                self.assertFalse(result['protection']['obfuscation'])
                self.assertFalse(result['protection']['behavior_verified'])
                self.assertNotEqual(result['before']['sha256'], result['after']['sha256'])
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
                artifact = service.artifact_path(job)
                self.assertTrue(artifact.is_file())
                self.assertEqual(artifact.stat().st_mode & 0o111, 0)
                self.assertEqual(artifact.name, 'binary-hygiene.elf')
            finally:
                service.close()

    def test_strip_comparison_creates_copy_and_retains_original_sample(self):
        workflow = workflow_module()
        target = ROOT / 'samples/bin/level-1.elf'
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=static_baseline, inventory_provider=inventory_baseline)
            selected = service.add_selection({'app': {'name': 'Level 1'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]}, sample_id='level-1')
            try:
                job_id = service.start_job(selected['selection_id'], ['one'], ['readelf'], 'strip_compare', authorized=True)
                service.wait(job_id, timeout=15)
                job = service.get_job(job_id)
                self.assertEqual(job['status'], 'completed', job['error'])
                result = job['result']
                self.assertEqual(result['protection']['state'], 'symbol_removal_applied')
                self.assertFalse(result['protection']['behavior_verified'])
                self.assertNotEqual(result['before']['sha256'], result['after']['sha256'])
                self.assertTrue(result['before']['metadata']['debug_info_present'])
                self.assertFalse(result['after']['metadata']['debug_info_present'])
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
                self.assertTrue(service.artifact_path(job_id).is_file())
                self.assertEqual(service.artifact_path(job_id).stat().st_mode & 0o111, 0)
            finally:
                service.close()

    def test_failed_reanalysis_keeps_baseline_and_applied_transformation_state(self):
        workflow = workflow_module()
        calls = 0
        def fail_after(path, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('Deliberate reanalysis failure')
            return static_baseline(path, **kwargs)
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=fail_after, inventory_provider=inventory_baseline)
            target = ROOT / 'samples/bin/level-1.elf'
            selection = service.add_selection({'app': {'name': 'sample'}, 'targets': [{'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'analyzable': True}]}, sample_id='level-1')
            try:
                job = service.start_job(selection['selection_id'], ['one'], ['readelf'], 'strip_compare', authorized=True)
                service.wait(job, timeout=10)
                record = service.get_job(job)
                self.assertEqual(record['status'], 'failed')
                self.assertIsNotNone(record['result'], 'A failed reanalysis must not discard baseline evidence')
                self.assertEqual(record['result']['protection']['state'], 'symbol_removal_applied')
                expected_class = 'PE32+' if target.read_bytes()[:2] == b'MZ' else 'ELF64'
                self.assertEqual(record['result']['before']['metadata']['class'], expected_class)
                self.assertIsNone(record['result']['after'])
            finally:
                service.close()

    def test_cancel_live_job_returns_cancelled_and_retains_event_log(self):
        workflow = workflow_module()
        self.assertTrue(hasattr(workflow.Workbench, 'cancel'), 'Job cancellation is not implemented')
        entered = threading.Event()
        def cancellable(path, **kwargs):
            entered.set()
            self.assertTrue(kwargs['cancel_event'].wait(5))
            raise InterruptedError('Cancelled in test adapter before any target execution')
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=cancellable, inventory_provider=inventory_baseline)
            target = ROOT / 'samples/bin/level-1.elf'
            selection = service.add_selection({'app': {'name': 'sample'}, 'targets': [{'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'analyzable': True}]})
            try:
                job = service.start_job(selection['selection_id'], ['one'], ['readelf'], 'analyze', authorized=True)
                self.assertTrue(entered.wait(3))
                service.cancel(job)
                service.wait(job, timeout=6)
                self.assertEqual(service.get_job(job)['status'], 'cancelled')
                self.assertTrue(service.report_path(job).is_file())
            finally:
                service.close()

    def test_external_selection_cannot_be_transformed(self):
        workflow = workflow_module()
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=static_baseline, inventory_provider=inventory_baseline)
            target = ROOT / 'samples/bin/level-1.elf'
            selection = service.add_selection({'app': {'name': 'folder'}, 'targets': [{'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'analyzable': True}]})
            try:
                with self.assertRaisesRegex(ValueError, 'bundled'):
                    service.start_job(selection['selection_id'], ['one'], ['readelf'], 'strip_compare', authorized=True)
                with self.assertRaisesRegex(ValueError, 'authorized'):
                    service.start_job(selection['selection_id'], ['one'], ['readelf'], 'analyze')
                with self.assertRaisesRegex(ValueError, 'unavailable'):
                    service.start_job(selection['selection_id'], ['one'], ['arbitrary-command'], 'analyze', authorized=True)
            finally:
                service.close()

    def test_async_run_emits_events_before_completion_and_preserves_original(self):
        workflow = workflow_module()
        self.assertTrue(hasattr(workflow, 'Workbench'), 'asynchronous workbench is not implemented')
        entered, release = threading.Event(), threading.Event()
        target = ROOT / 'samples/bin/level-1.elf'
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        def analyzer(path, **kwargs):
            kwargs['emit']({'type': 'log', 'tool': 'readelf', 'message': 'Test gate before real static inspection'})
            entered.set()
            release.wait(5)
            return static_baseline(path, **kwargs)
        with tempfile.TemporaryDirectory() as temp:
            service = workflow.Workbench(ROOT, runs_root=Path(temp), analyzer=analyzer, inventory_provider=inventory_baseline)
            selected = service.add_selection({'app': {'name': 'Level 1'}, 'targets': [
                {'target_id': 'one', 'absolute_path': str(target), 'relative_path': target.name, 'size_bytes': target.stat().st_size, 'analyzable': True}
            ]}, sample_id='level-1')
            job_id = service.start_job(selected['selection_id'], ['one'], ['readelf'], 'analyze', authorized=True)
            try:
                self.assertTrue(entered.wait(3))
                live = service.get_job(job_id)
                self.assertEqual(live['status'], 'running')
                self.assertTrue(live['events'])
                self.assertIsNone(live['result'])
            finally:
                release.set()
            service.wait(job_id, timeout=10)
            result = service.get_job(job_id)
            self.assertEqual(result['status'], 'completed')
            expected_class = 'PE32+' if target.read_bytes()[:2] == b'MZ' else 'ELF64'
            self.assertEqual(result['result']['reports'][0]['analysis']['metadata']['class'], expected_class)
            self.assertEqual(service.get_job(job_id, after=result['next_seq'])['events'], [])
            self.assertTrue(service.report_path(job_id).is_file())
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), digest)
            service.close()


if __name__ == '__main__':
    unittest.main()
