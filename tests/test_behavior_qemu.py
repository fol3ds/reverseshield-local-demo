"""Host safety and exact evidence scope for self-authored QEMU drivers.

Synthetic subprocess results keep unit tests from ever launching a driver.
The real five-sample guest integration is in test_ollvm_protection.py.
"""
import gzip
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import behavior_qemu


class RuntimeLibrarySafetyTests(unittest.TestCase):
    def test_runtime_resolution_follows_transitive_dependencies_without_loading_them(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            system = base / 'known system libs'
            system.mkdir()
            driver = base / 'driver'
            driver.write_bytes(b'driver is inspection input only')
            guest = base / 'guest'
            guest.mkdir()
            loader = system / 'ld-linux-x86-64.so.2'
            libm = system / 'libm.so.6'
            libc = system / 'libc.so.6'
            for path in (loader, libm, libc):
                path.write_bytes(path.name.encode())
            metadata = {
                driver: f'[Requesting program interpreter: {loader}]\n (NEEDED) Shared library: [libm.so.6]\n',
                libm: '(NEEDED) Shared library: [libc.so.6]\n',
                libc: '(NEEDED) Shared library: [ld-linux-x86-64.so.2]\n',
                loader: '(NEEDED) Shared library: [libc.so.6]\n',  # cycle must terminate
            }
            inspected = []

            def inspect(command, **kwargs):
                self.assertFalse(kwargs.get('shell', False))
                self.assertEqual(Path(command[0]).stem.lower(), 'readelf')
                path = Path(command[-1])
                inspected.append(path)
                return subprocess.CompletedProcess(command, 0, stdout=metadata[path], stderr='')

            with (mock.patch.object(behavior_qemu, 'RUNTIME_LIBRARY_DIRS', (system,)),
                  mock.patch.object(behavior_qemu, 'RUNTIME_INTERPRETERS', {str(loader)}),
                  mock.patch.object(behavior_qemu.subprocess, 'run', side_effect=inspect)):
                behavior_qemu._copy_runtime_libs(driver, guest)
            copied = {path.name for path in guest.rglob('*') if path.is_file()}
            self.assertEqual(copied, {loader.name, libm.name, libc.name})
            self.assertCountEqual(inspected, list(metadata))
            for path in (loader, libm, libc):
                try:
                    relative = path.relative_to('/')
                except ValueError:
                    relative = Path(path.name)
                self.assertEqual((guest / relative).read_bytes(), path.read_bytes())

    def test_dependency_discovery_only_inspects_elf_with_readelf(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            driver = base / 'driver'
            driver.write_bytes(b'not executable')
            guest = base / 'guest'
            guest.mkdir()
            calls = []

            def inspect(command, **kwargs):
                calls.append((command, kwargs))
                self.assertIsInstance(command, (list, tuple))
                self.assertEqual(Path(command[0]).stem.lower(), 'readelf',
                                 'dependency discovery must never load or run a target')
                self.assertFalse(kwargs.get('shell', False))
                self.assertIn('-l', command)
                self.assertIn('-d', command)
                self.assertGreater(kwargs.get('timeout', 0), 0)
                return subprocess.CompletedProcess(command, 0, stdout='There is no dynamic section in this file.\n', stderr='')

            with mock.patch.object(behavior_qemu.subprocess, 'run', side_effect=inspect):
                behavior_qemu._copy_runtime_libs(driver, guest)
            self.assertTrue(calls, 'static dependency inspection was not performed')


class BehaviorHarnessSafetyTests(unittest.TestCase):
    transcript = 'INIT\nBEGIN original\nvector=42\nEND original 0\nBEGIN protected\nvector=42\nEND protected 0\nDONE\n'

    def exercise_harness(self, base, *, qemu_return_code=0, qemu_output=None,
                         qemu_error=None, process_override=None, compile_failure=None,
                         variants_failure=None):
        """Build synthetic files, run real cpio, never execute a guest file."""
        base = Path(base)
        clang = base / 'fake-clang'
        clang.write_bytes(b'not executable')
        kernel = base / 'fake-kernel'
        kernel.write_bytes(b'not a kernel')
        output = base / 'build'
        native_run = subprocess.run
        native_which = shutil.which
        calls = []

        def compile_only(command, **kwargs):
            target = Path(command[command.index('-o') + 1])
            if compile_failure is not None and target.name == compile_failure[0]:
                raise compile_failure[1]
            target.write_bytes(('synthetic ' + target.name).encode())
            return {'return_code': 0, 'output': '', 'command': command}

        def run_host_tool(command, **kwargs):
            calls.append((command, kwargs))
            self.assertFalse(kwargs.get('shell', False), 'archive creation must never invoke a shell')
            self.assertIsInstance(command, (list, tuple), 'host subprocesses must receive argv')
            name = Path(command[0]).name
            self.assertIn(name, ('cpio', 'qemu-system-x86_64'), 'a driver must never execute on the host')
            if process_override is not None:
                overridden = process_override(command, kwargs)
                if overridden is not None:
                    return overridden
            if name == 'qemu-system-x86_64':
                if qemu_error is not None:
                    raise qemu_error
                return subprocess.CompletedProcess(command, qemu_return_code,
                                                   stdout=self.transcript if qemu_output is None else qemu_output,
                                                   stderr='')
            return native_run(command, **kwargs)

        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(behavior_qemu, 'toolchain_paths', return_value={'clang': clang}))
            patches.enter_context(mock.patch.object(behavior_qemu, '_find_kernel', return_value=kernel))
            patches.enter_context(mock.patch.object(behavior_qemu, 'build_behavior_variants',
                side_effect=variants_failure, return_value={
                    'include_dirs': [], 'original_ir': [], 'protected_ir': [],
                }))
            patches.enter_context(mock.patch.object(behavior_qemu, '_run', side_effect=compile_only))
            patches.enter_context(mock.patch.object(behavior_qemu, '_copy_runtime_libs'))
            patches.enter_context(mock.patch.object(behavior_qemu.shutil, 'which', side_effect=lambda name:
                '/synthetic/qemu-system-x86_64' if name == 'qemu-system-x86_64' else native_which(name)))
            patches.enter_context(mock.patch.object(behavior_qemu.subprocess, 'run', side_effect=run_host_tool))
            result = behavior_qemu.run_behavior(base, 'level-1', output)
        return result, calls, output

    def test_build_process_errors_are_bounded_at_every_compile_stage(self):
        for stage in ('variants', 'original-driver', 'protected-driver', 'init'):
            for error_type in ('oserror', 'timeout'):
                with self.subTest(stage=stage, error=error_type), tempfile.TemporaryDirectory() as temp:
                    failure = (OSError('/private/host/path/' + 'x' * 2000) if error_type == 'oserror' else
                               subprocess.TimeoutExpired(['compiler', '/private/host/path'], 1))
                    options = ({'variants_failure': failure} if stage == 'variants' else
                               {'compile_failure': (stage, failure)})
                    caught = None
                    try:
                        self.exercise_harness(temp, **options)
                    except (behavior_qemu.OllvmBuildError, OSError, subprocess.TimeoutExpired) as exc:
                        caught = exc
                    self.assertTrue(isinstance(caught, behavior_qemu.OllvmBuildError),
                                    'build tool exceptions must be normalized, not leaked')
                    self.assertLessEqual(len(str(caught)), 256)
                    self.assertNotIn('/private/', str(caught))

    @unittest.skipUnless(shutil.which('cpio'), 'cpio is unavailable')
    def test_host_process_failures_have_bounded_path_free_errors(self):
        cases = (
            ('cpio', OSError('/private/host/path/' + 'x' * 20000)),
            ('cpio', subprocess.TimeoutExpired(['cpio', '/private/host/path'], 30, output=b'x' * 20000)),
            ('qemu-system-x86_64', OSError('/private/host/path/' + 'x' * 20000)),
        )
        for tool, failure in cases:
            with self.subTest(tool=tool, failure=type(failure).__name__), tempfile.TemporaryDirectory() as temp:
                def fail_tool(command, kwargs):
                    if Path(command[0]).name == tool:
                        raise failure
                    return None

                try:
                    self.exercise_harness(temp, process_override=fail_tool)
                except (behavior_qemu.OllvmBuildError, OSError, subprocess.TimeoutExpired) as exc:
                    self.assertTrue(isinstance(exc, behavior_qemu.OllvmBuildError),
                                    'host errors must be normalized to bounded build errors')
                    self.assertLessEqual(len(str(exc)), 256)
                    self.assertNotIn('/private/', str(exc))
                else:
                    self.fail('host process failure was not reported')

    @unittest.skipUnless(shutil.which('cpio'), 'cpio is unavailable')
    def test_scope_and_hashes_describe_only_actual_separate_drivers(self):
        with tempfile.TemporaryDirectory() as temp:
            result, _, output = self.exercise_harness(temp)
            self.assertEqual(result.get('scope'), 'separate_deterministic_drivers')
            self.assertIs(result.get('artifact_behavior_verified'), False)
            self.assertIn('NOT the downloadable protected.elf', ' '.join(result['limitations']))
            expected = {name: hashlib.sha256((output / f'{name}-driver').read_bytes()).hexdigest()
                        for name in ('original', 'protected')}
            self.assertEqual(result.get('driver_sha256'), expected)
            for name in ('original', 'protected'):
                self.assertEqual(expected[name], hashlib.sha256((output / 'guest' / name).read_bytes()).hexdigest())
            transcripts = {name: hashlib.sha256(result[f'{name}_output'].encode()).hexdigest()
                           for name in ('original', 'protected')}
            self.assertEqual(result.get('transcript_sha256'), transcripts)

    @unittest.skipUnless(shutil.which('cpio'), 'cpio is unavailable')
    def test_nonzero_qemu_exit_rejects_matching_zero_exit_transcripts(self):
        for code in (1, -15):
            with self.subTest(qemu_return_code=code), tempfile.TemporaryDirectory() as temp:
                result, _, _ = self.exercise_harness(temp, qemu_return_code=code)
                self.assertEqual(result['exit_codes'], {'original': 0, 'protected': 0})
                self.assertEqual(result['original_output'], result['protected_output'])
                self.assertEqual(result['qemu_return_code'], code)
                self.assertFalse(result['passed'], 'matching guest output cannot override a failed QEMU process')

    @unittest.skipUnless(shutil.which('cpio'), 'cpio is unavailable')
    def test_qemu_timeout_rejects_matching_partial_transcripts(self):
        failure = subprocess.TimeoutExpired(['qemu-system-x86_64'], 1,
                                            output=self.transcript.encode(), stderr=b'late shutdown')
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self.exercise_harness(temp, qemu_error=failure)
            self.assertEqual(result['qemu_return_code'], -9)
            self.assertFalse(result['passed'])

    @unittest.skipUnless(shutil.which('cpio'), 'cpio is unavailable')
    def test_archive_is_safe_for_spaces_and_shell_metacharacters(self):
        with tempfile.TemporaryDirectory() as temp:
            hostile = Path(temp) / 'space ; $(touch PWNED) \' " & [glob]'
            hostile.mkdir()
            result, calls, output = self.exercise_harness(hostile)
            self.assertTrue(result['passed'])
            self.assertFalse(any(Path(temp).rglob('PWNED')))
            archive = gzip.decompress((output / 'initramfs.cpio.gz').read_bytes())
            listing = subprocess.run([shutil.which('cpio'), '-it', '--quiet'], input=archive,
                                     capture_output=True, check=True, timeout=10, shell=False)
            entries = set(listing.stdout.decode().splitlines())
            self.assertTrue({'init', 'original', 'protected'}.issubset(
                {name.removeprefix('./') for name in entries}))
            qemu = next(command for command, _ in calls if Path(command[0]).name == 'qemu-system-x86_64')
            self.assertEqual(qemu[qemu.index('-initrd') + 1], str(output / 'initramfs.cpio.gz'))


class EvidenceSummaryTests(unittest.TestCase):
    def test_five_sample_evidence_is_hash_only_and_explicitly_not_downloaded_artifact_proof(self):
        path = Path(__file__).resolve().parents[1] / 'docs/evidence/ollvm-five-qemu.json'
        evidence = json.loads(path.read_text(encoding='utf-8'))
        self.assertEqual(evidence.get('scope'), 'separate_deterministic_drivers')
        self.assertIs(evidence.get('artifact_behavior_verified'), False)
        self.assertIn('NOT the downloadable protected.elf', evidence['interpretation'])
        self.assertEqual(set(evidence), {'observed_at', 'scope', 'artifact_behavior_verified',
                                         'samples', 'interpretation'})
        self.assertEqual(len(evidence['samples']), 5)
        self.assertCountEqual([record['sample_id'] for record in evidence['samples']],
                              [f'level-{number}' for number in range(1, 6)])
        allowed = {'sample_id', 'matched', 'scope', 'artifact_behavior_verified', 'exit_codes',
                   'qemu_return_code', 'output_sha256', 'initramfs_sha256', 'duration_seconds',
                   'driver_sha256', 'transcript_sha256'}
        for record in evidence['samples']:
            with self.subTest(sample=record['sample_id']):
                self.assertEqual(set(record), allowed)
                self.assertEqual(record['scope'], evidence['scope'])
                self.assertIs(record['artifact_behavior_verified'], False)
                self.assertIs(record['matched'], True)
                self.assertEqual(record['exit_codes'], {'original': 0, 'protected': 0})
                self.assertEqual(record['qemu_return_code'], 0)
                for field in ('driver_sha256', 'transcript_sha256'):
                    self.assertEqual(set(record[field]), {'original', 'protected'})
                    for digest in record[field].values():
                        self.assertRegex(digest, r'\A[0-9a-f]{64}\Z')
                self.assertEqual(record['output_sha256'], record['transcript_sha256']['original'])
                self.assertEqual(record['transcript_sha256']['original'], record['transcript_sha256']['protected'])
                self.assertNotEqual(record['driver_sha256']['original'], record['driver_sha256']['protected'])
                self.assertRegex(record['initramfs_sha256'], r'\A[0-9a-f]{64}\Z')
        self.assertNotRegex(json.dumps(evidence), r'/home/|/Users/|/tmp/|[A-Za-z]:\\\\|raw_output|commands')


if __name__ == '__main__':
    unittest.main()
