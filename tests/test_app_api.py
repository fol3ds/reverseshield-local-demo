"""Legacy HTTP API tests for ELF uploads, sample metadata and Flatpak routes.

Inputs are local HTTP requests and inert fixtures; outputs are JSON responses.
The API reads files as data and never executes uploaded or installed targets.
Extend Windows coverage in the PE-capable upgraded API test module.
"""
import http.client
import json
import os
import secrets
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

try:
    import app
except ImportError:
    app = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(os.name == "nt", "legacy API only analyzes ELF and Flatpak; Windows PE uses the upgraded API")
class LocalWorkbenchApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if app is None:
            return
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), app.ReverseShieldHandler)
        cls.server.api_token = secrets.token_urlsafe(32)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        if app is not None:
            cls.server.shutdown()
            cls.server.server_close()
            cls.thread.join(timeout=2)

    def request(self, method, path, body=None, headers=None):
        self.assertIsNotNone(app, "local HTTP workbench API is not implemented yet")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request(method, path, body=body, headers={"X-ReverseShield-Token": self.server.api_token, **(headers or {})})
        response = connection.getresponse()
        data = response.read()
        status = response.status
        connection.close()
        return status, data

    def test_status_keeps_dynamic_analysis_disabled(self):
        status, body = self.request("GET", "/api/status")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["mode"], "static_only")
        self.assertFalse(payload["dynamic_analysis"]["enabled"])

    def test_sample_catalog_contains_six_separate_levels(self):
        status, body = self.request("GET", "/api/samples")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["samples"]), 6)
        self.assertEqual(len({item["id"] for item in payload["samples"]}), 6)
        hardened = next(item for item in payload["samples"] if item["id"] == "level-5-hardened")
        self.assertFalse(hardened["source_transform_supported"])
        self.assertTrue(hardened["available"])

    @patch("app.list_flatpak_apps", return_value=[{
        "app_id": "com.example.App",
        "name": "Example App",
        "version": "1.2",
        "branch": "stable",
        "installation": "system",
    }])
    def test_apps_endpoint_lists_installed_flatpaks(self, list_apps):
        status, body = self.request("GET", "/api/apps")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["apps"][0]["app_id"], "com.example.App")
        self.assertEqual(payload["apps"][0]["source"], "flatpak")

    @patch("app.discover_flatpak_targets", return_value={
        "app": {"app_id": "com.example.App", "name": "Example App", "version": "1.2", "branch": "stable", "installation": "system"},
        "payload_root": "/local/path/files",
        "targets": [{"target_id": "abc123", "relative_path": "bin/example", "absolute_path": "/local/path/files/bin/example", "size_bytes": 4096, "analyzable": True, "reason": None}],
        "runtime": {"listed": True, "scanned": False, "message": "runtime not scanned"},
    })
    def test_flatpak_targets_endpoint_hides_internal_paths(self, discover):
        status, body = self.request("GET", "/api/apps/com.example.App/targets")
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["targets"][0]["relative_path"], "bin/example")
        self.assertNotIn("absolute_path", payload["targets"][0])
        self.assertFalse(payload["runtime"]["scanned"])

    def test_workbench_page_is_served_by_the_local_app(self):
        status, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"ReverseShield", body)
        self.assertIn(b"workbench", body.lower())

    def test_non_elf_upload_is_rejected_before_static_tools_run(self):
        status, body = self.request(
            "POST",
            "/api/analyze/upload?filename=package.apk",
            body=b"PK\x03\x04not-an-elf",
            headers={"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 415)
        self.assertIn(b"Linux ELF", body)

    def test_sample_analysis_returns_real_elf_metadata_without_execution(self):
        sample = ROOT / "samples" / "bin" / "level-1.elf"
        self.assertTrue(sample.is_file(), "build_samples.py must build the test fixture before API tests")
        status, body = self.request("POST", "/api/analyze/sample/level-1", body=b'{"detail":"summary"}', headers={"Content-Type": "application/json"})
        payload = json.loads(body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["analysis_mode"], "static_only")
        self.assertEqual(payload["metadata"]["class"], "ELF64")
        self.assertGreater(payload["metadata"]["sections_count"], 0)
        self.assertTrue(any(tool["label"] == "ELF header" and tool["status"] == "ok" for tool in payload["tools"]))

    def test_unknown_sample_is_not_resolved_from_arbitrary_paths(self):
        status, body = self.request("POST", "/api/analyze/sample/../../etc/passwd")
        self.assertEqual(status, 404)
        self.assertIn(b"Unknown sample", body)


if __name__ == "__main__":
    unittest.main()
