"""Host-independent checks of Day 4 test prerequisites, not a Windows run."""
import ast
import re
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

if __package__:
    from . import document_tools
    from . import test_day4_documents as document_tests
    from . import test_demo_video as demo_tests
    from . import test_hardening as hardening_tests
else:  # unittest discover -s tests imports these as top-level modules.
    import document_tools
    import test_day4_documents as document_tests
    import test_demo_video as demo_tests
    import test_hardening as hardening_tests


class DocumentCommandPortabilityTests(unittest.TestCase):
    def test_document_tests_do_not_embed_a_personal_home_path(self):
        source = document_tests.Path(document_tests.__file__).read_text(encoding='utf-8')
        literals = [node.value for node in ast.walk(ast.parse(source))
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        private_paths = [value for value in literals if re.search(r'/(?:home|Users)/[^/\s]+', value)]
        self.assertEqual(private_paths, [])

    def test_package_style_test_imports_work(self):
        result = subprocess.run(
            [sys.executable, '-c',
             'import tests.test_day4_documents; import tests.test_day4_test_portability'],
            cwd=document_tests.ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_document_case_uses_the_selected_interpreter(self):
        selected = r'C:\Python\python.exe'

        class BuilderReached(Exception):
            pass

        def check_command(command, **kwargs):
            self.assertEqual(command[0], selected)
            raise BuilderReached

        # Only the command selection is simulated; no Windows process is run.
        names = unittest.defaultTestLoader.getTestCaseNames(document_tests.Day4DocumentTests)
        cases = [document_tests.Day4DocumentTests(name) for name in names]
        with mock.patch.object(document_tests, 'docx_python', return_value=selected), \
                mock.patch.object(document_tests.subprocess, 'run', side_effect=check_command):
            for case in cases:
                with self.subTest(case=case._testMethodName), self.assertRaises(BuilderReached):
                    getattr(case, case._testMethodName)()


class DocumentDependencyTests(unittest.TestCase):
    def test_broken_docx_import_is_an_error_not_an_optional_dependency_skip(self):
        current = r'C:\Python\python.exe'
        failure = subprocess.CompletedProcess([current], 1, '', 'ImportError: broken installed docx')
        with mock.patch.object(document_tools, 'sys', SimpleNamespace(executable=current, platform='win32')), \
                mock.patch.object(document_tools.subprocess, 'run', return_value=failure):
            try:
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    document_tools.docx_python()
            except unittest.SkipTest as error:
                self.fail(f'Broken docx import was skipped: {error}')
        self.assertIn('broken installed docx', raised.exception.stderr)

    def test_native_windows_missing_docx_skips_without_discovery(self):
        current = r'C:\Python\python.exe'
        runner = mock.Mock(return_value=subprocess.CompletedProcess([current], 3))
        finder = mock.Mock(side_effect=AssertionError('Windows must use the current interpreter'))
        with mock.patch.object(document_tools, 'sys', SimpleNamespace(executable=current, platform='win32')), \
                mock.patch.object(document_tools.shutil, 'which', finder), \
                mock.patch.object(document_tools.subprocess, 'run', runner):
            with self.assertRaisesRegex(unittest.SkipTest, r'optional python-docx.*requirements-docs\.txt'):
                document_tools.docx_python()
        runner.assert_called_once()
        self.assertEqual(runner.call_args.args[0][0], current)
        finder.assert_not_called()

    def test_posix_discovers_an_existing_docx_interpreter(self):
        current, fallback = '/venv/bin/python', '/system/bin/python3'

        def which(name, path=None):
            return (fallback if path is not None else current) if name == 'python3' else None

        def probe(command, **kwargs):
            return subprocess.CompletedProcess(command, 3 if command[0] == current else 0)

        runner = mock.Mock(side_effect=probe)
        with mock.patch.object(document_tools, 'sys', SimpleNamespace(executable=current, platform='linux')), \
                mock.patch.object(document_tools, 'shutil', SimpleNamespace(which=which)), \
                mock.patch.object(document_tools, 'subprocess', SimpleNamespace(run=runner)):
            self.assertEqual(document_tools.docx_python(), fallback)
        self.assertEqual([call.args[0][0] for call in runner.call_args_list], [current, fallback])


class HardenedCompilePortabilityTests(unittest.TestCase):
    def test_linux_compile_case_skips_when_no_compiler_is_available(self):
        import build_samples
        with mock.patch.object(hardening_tests, 'sys', SimpleNamespace(platform='linux')), \
                mock.patch.object(build_samples, 'which_tool', return_value=None), \
                mock.patch.object(build_samples, 'build_hardened_sample',
                                  side_effect=AssertionError('Builder called without a compiler')):
            case = hardening_tests.HardeningTests('test_hardened_builder_compiles_without_executing')
            with self.assertRaisesRegex(unittest.SkipTest, 'C compiler'):
                case.test_hardened_builder_compiles_without_executing()

    def test_linux_compile_case_skips_on_other_native_platforms(self):
        import build_samples
        for platform in ('win32', 'darwin'):
            with self.subTest(platform=platform), \
                    mock.patch.object(hardening_tests, 'sys', SimpleNamespace(platform=platform)), \
                    mock.patch.object(build_samples, 'build_hardened_sample',
                                      side_effect=AssertionError('Linux-only builder was invoked')):
                case = hardening_tests.HardeningTests('test_hardened_builder_compiles_without_executing')
                with self.assertRaisesRegex(unittest.SkipTest, 'Linux'):
                    case.test_hardened_builder_compiles_without_executing()


class DemoDependencyTests(unittest.TestCase):
    def test_missing_pillow_skips_with_an_explicit_optional_dependency_reason(self):
        with mock.patch.object(demo_tests.importlib.util, 'find_spec', return_value=None):
            with self.assertRaisesRegex(unittest.SkipTest, r'optional Pillow.*requirements-docs\.txt'):
                demo_tests.load_module()


if __name__ == '__main__':
    unittest.main()
