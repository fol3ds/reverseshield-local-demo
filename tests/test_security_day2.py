"""Regression tests for the Day 2 security fixes (see docs/security/DAY2_SECURITY_REVIEW.md).

Inputs are fake paths, patched platform flags and a loopback test server;
outputs are refusals and safe argv lists. Nothing here launches cmd.exe, a
batch file or any target.
"""
import http.client
import json
import os
import secrets
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import app
import discovery
import platform_support
from workflow import Workbench
from test_workflow import inventory_baseline, static_baseline

ROOT = Path(__file__).resolve().parents[1]


class WindowsLauncherTests(unittest.TestCase):
    """RS-01/RS-02: search-path hijack and cmd.exe argument injection."""

    def test_system_tools_resolve_to_system32(self):
        with tempfile.TemporaryDirectory() as temp:
            system32 = Path(temp) / "System32"
            system32.mkdir()
            (system32 / "cmd.exe").write_bytes(b"")
            with mock.patch.object(platform_support, "IS_WINDOWS", True), \
                 mock.patch.dict(os.environ, {"SystemRoot": temp}):
                self.assertEqual(platform_support.system_executable("cmd.exe"), str(system32 / "cmd.exe"))
                argv = platform_support.command_for(r"C:\RS\tools\ghidra\support\analyzeHeadless.bat", r"C:\RS\runs\a b\project")
        self.assertEqual(argv[0], str(system32 / "cmd.exe"))
        self.assertEqual(argv[1:3], ["/d", "/c"], "AutoRun commands must be disabled with /d")
        if os.name != "nt":
            self.assertEqual(platform_support.system_executable("cmd.exe"), "cmd.exe", "POSIX never rewrites names")

    def test_batch_arguments_with_cmd_metacharacters_are_refused(self):
        with mock.patch.object(platform_support, "IS_WINDOWS", True):
            for unsafe in (r"C:\Users\R&D\rs\runs\x", r"C:\rs\100%done", r"C:\rs\a|b", r'C:\rs\"q"', "C:\\rs\\line\nbreak", r"C:\rs\wow!"):
                with self.subTest(argument=unsafe):
                    with self.assertRaisesRegex(ValueError, "cmd.exe"):
                        platform_support.command_for(r"C:\rs\support\analyzeHeadless.bat", unsafe)
            # Non-batch executables are launched directly and need no cmd.exe parsing.
            self.assertEqual(platform_support.command_for(r"C:\tools\objdump.exe", r"C:\R&D\x"),
                             [r"C:\tools\objdump.exe", r"C:\R&D\x"])


class RefusedGhidraLaunchTests(unittest.TestCase):
    def test_refused_launch_is_a_tool_error_not_a_job_failure(self):
        import engine
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(platform_support, "IS_WINDOWS", True):
            unsafe = Path(temp) / "R&D"
            record, payload, _coverage, _limits = engine._analyze_ghidra(
                Path(temp) / "inert.bin", workdir=unsafe, info={"path": r"C:\g\analyzeHeadless.bat", "label": "Ghidra", "version": "x"})
            self.assertEqual(record["status"], "tool_error")
            self.assertIn("cmd.exe", record["output"])
            self.assertEqual(payload, {})
            self.assertFalse((unsafe / "ghidra_project").exists())


class JunctionTests(unittest.TestCase):
    """RS-04: links and reparse points are not followed during discovery."""

    def test_symlinks_and_junctions_are_link_like(self):
        with tempfile.TemporaryDirectory() as temp:
            real = Path(temp) / "real"
            real.mkdir()
            self.assertFalse(discovery._is_link_like(real))
            if hasattr(os, "symlink"):
                link = Path(temp) / "link"
                try:
                    os.symlink(real, link, target_is_directory=True)
                except OSError:
                    pass
                else:
                    self.assertTrue(discovery._is_link_like(link))
            with mock.patch.object(os.path, "isjunction", create=True, return_value=True):
                self.assertTrue(discovery._is_link_like(real))


class UncPathTests(unittest.TestCase):
    """RS-03: network paths are refused before Windows contacts another host."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.ReverseShieldHandler)
        cls.server.workbench = Workbench(ROOT, runs_root=Path(cls.temp.name), analyzer=static_baseline,
                                         inventory_provider=inventory_baseline)
        cls.server.api_token = secrets.token_urlsafe(24)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.workbench.close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def test_unc_paths_are_rejected(self):
        port = self.server.server_address[1]
        for raw in (r"\\attacker.invalid\share\app", "//attacker.invalid/share/app"):
            with self.subTest(path=raw):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
                conn.request("POST", "/api/discover", json.dumps({"kind": "path", "path": raw}).encode(),
                             {"Content-Type": "application/json", "X-ReverseShield-Token": self.server.api_token,
                              "Host": f"127.0.0.1:{port}"})
                response = conn.getresponse()
                body = json.loads(response.read())
                conn.close()
                self.assertEqual(response.status, 400)
                if os.name == "nt" or raw.startswith("//"):
                    self.assertNotIn("attacker.invalid", body["error"])


if __name__ == "__main__":
    unittest.main()
