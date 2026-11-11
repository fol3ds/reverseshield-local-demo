"""Local HTTP negative tests and sanitized-export regressions; targets never run."""
import copy
import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import tempfile
import threading
import unittest
from pathlib import Path

import app
from sanitize_report import sanitize_report
from workflow import Workbench

ROOT = Path(__file__).resolve().parents[1]


class SanitizerTests(unittest.TestCase):
    def test_private_text_removed_and_measurements_preserved_without_mutation(self):
        digest = hashlib.sha256(b'evidence').hexdigest()
        original = {'sha256': digest, 'size_bytes': 1024, 'count': 7,
                    'command': ['tool', '/home/alice/input'], 'output': 'unknown private text',
                    'windows': r'C:\Users\bob\private\file.exe',
                    'linux': '/home/alice/.cache/tool', 'names': 'alice and bob',
                    'key': '0x9E3779B9', 'env': {'SECRET': 'private'},
                    'artifacts': {'strings': ['confidential']}, 'rs_key': 123,
                    'note': 'rs_key=123; user@example.test',
                    'tools': [{'tool': 'readelf', 'status': 'ok', 'truncated': True}],
                    'coverage': {'symbols': 'collected'}}
        before = copy.deepcopy(original)
        clean = sanitize_report(original)
        text = json.dumps(clean)
        for private in ('/home/', 'C:\\\\Users', 'alice', 'bob', '0x9E3779B9',
                        'unknown private text', 'confidential', 'user@example.test'):
            self.assertNotIn(private, text)
        self.assertEqual(clean['sha256'], digest)
        self.assertEqual(clean['size_bytes'], 1024)
        self.assertEqual(clean['count'], 7)
        self.assertEqual(clean['tools'], before['tools'])
        self.assertEqual(clean, sanitize_report(clean))
        self.assertEqual(original, before)

    def test_secret_patterns_and_unix_windows_temp_paths(self):
        value = {'a': '/tmp/private/a', 'b': r'C:\Temp\private\b',
                 'c': '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
                 'd': 'ghp_' + 'a' * 30}
        clean = json.dumps(sanitize_report(value))
        self.assertNotIn('private', clean.lower())
        self.assertNotIn('ghp_', clean)


class ApiSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = app.WorkbenchServer(('127.0.0.1', 0), app.ReverseShieldHandler)
        cls.server.api_token = secrets.token_urlsafe(32)
        def analyzer(path, **kwargs):
            return {'analysis_mode': 'static_only', 'tools': [], 'artifacts': {}}
        cls.server.workbench = Workbench(ROOT, runs_root=Path(cls.temp.name),
            analyzer=analyzer, inventory_provider=lambda: {'readelf': {'available': True}})
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(self, method, path, body=None, token=True, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        fields = {'Content-Type': 'application/json'}
        if token:
            fields['X-ReverseShield-Token'] = self.server.api_token
        fields.update(headers or {})
        conn.request(method, path, body=body, headers=fields)
        response = conn.getresponse()
        result = (response.status, response.read(), dict(response.getheaders()))
        conn.close()
        return result

    def test_http_analyze_refuses_transform_profile_before_job_creation(self):
        target = ROOT / 'samples/bin/level-1.elf'
        selection = self.server.workbench.add_selection({'app': {'name': 'external'}, 'targets': [
            {'target_id': 'profile-test', 'absolute_path': str(target),
             'relative_path': target.name, 'analyzable': True}
        ]})
        before = set(self.server.workbench.jobs)
        for profile in ('symbol_removal', 'constant_blinding', 'ollvm_source', 'binary_hygiene'):
            payload = {'selection_id': selection['selection_id'], 'target_ids': ['profile-test'],
                       'tools': ['readelf'], 'authorized': True,
                       'operation': 'analyze', 'profile': profile}
            status, body, _ = self.request('POST', '/api/jobs', json.dumps(payload).encode())
            self.assertEqual(status, 400)
            self.assertIn('Invalid request', json.loads(body)['error'])
        self.assertEqual(set(self.server.workbench.jobs), before)

    def test_every_api_read_and_write_needs_token(self):
        for method, path in [('GET', '/api/status'), ('GET', '/api/jobs'),
                             ('GET', '/api/samples'), ('POST', '/api/discover'),
                             ('POST', '/api/analyze/upload'), ('PUT', '/api/jobs'),
                             ('DELETE', '/api/jobs')]:
            for headers in ({}, {'X-ReverseShield-Token': 'wrong'}):
                with self.subTest(method=method, path=path, headers=headers):
                    self.assertEqual(self.request(method, path, token=False, headers=headers)[0], 403)

    def test_browser_bootstrap_and_status_do_not_mix(self):
        status, html, headers = self.request('GET', '/', token=False)
        self.assertEqual(status, 200)
        self.assertIn(b'name="reverseshield-token"', html)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        status, raw, _ = self.request('GET', '/api/status')
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.api_token.encode(), raw)

    def test_foreign_origin_referer_fetch_site_and_host(self):
        for header in [{'Origin': 'https://example.test'}, {'Referer': 'https://example.test/private'},
                       {'Sec-Fetch-Site': 'cross-site'}, {'Host': 'example.test'}]:
            self.assertEqual(self.request('GET', '/', headers=header)[0], 403)
            self.assertEqual(self.request('POST', '/api/discover', b'{}', headers=header)[0], 403)

    def test_traversal_unknown_methods_and_malformed_json(self):
        for route in ['/api/jobs/../../etc/passwd/report', '/api/jobs/%2e%2e/report',
                      '/api/jobs/' + 'a' * 24 + '/artifact/../../secret']:
            self.assertEqual(self.request('GET', route)[0], 404)
        for method in ('PUT', 'DELETE', 'PATCH', 'OPTIONS'):
            self.assertEqual(self.request(method, '/api/jobs')[0], 405)
        status, body, _ = self.request('BREW', '/api/jobs')
        self.assertEqual(status, 501)
        self.assertIn('error', json.loads(body))
        for body in (b'{', b'[]', b'{"selection_id": []}'):
            status, raw, _ = self.request('POST', '/api/jobs', body)
            self.assertEqual(status, 400)
            self.assertNotIn(b'Traceback', raw)

    def test_malformed_inputs_and_oversize_fail_without_path_leak(self):
        for body in (b'MZ' + b'\0' * 62, b'\x7fELF' + b'\0' * 60):
            status, raw, _ = self.request('POST', '/api/ingest', body)
            self.assertEqual(status, 400)
            self.assertNotIn(str(ROOT).encode(), raw)
        self.assertEqual(self.request('POST', '/api/ingest', b'', headers={'Content-Length': str(300*1024*1024)})[0], 400)
        self.assertEqual(self.request('POST', '/api/jobs', b'{}', headers={'Transfer-Encoding': 'chunked'})[0], 400)

    def test_short_body_fails_closed(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=5) as sock:
            request = (f'POST /api/jobs HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n'
                       f'X-ReverseShield-Token: {self.server.api_token}\r\n'
                       'Content-Type: application/json\r\nContent-Length: 10\r\n\r\n{}')
            sock.sendall(request.encode())
            sock.shutdown(socket.SHUT_WR)
            data = b''
            while chunk := sock.recv(4096):
                data += chunk
        self.assertIn(b'400', data.split(b'\r\n')[0])
        self.assertNotIn(b'Traceback', data)

    def test_download_preserves_original_and_poll_cancel_are_repeatable(self):
        _, body, _ = self.request('POST', '/api/discover', json.dumps({'kind': 'sample', 'sample_id': 'level-5'}))
        selection = json.loads(body)
        payload = {'selection_id': selection['selection_id'], 'target_ids': ['level-5'],
                   'tools': ['readelf'], 'authorized': True}
        status, body, _ = self.request('POST', '/api/jobs', json.dumps(payload))
        self.assertEqual(status, 202, body)
        job = json.loads(body)['job_id']
        self.server.workbench.wait(job, timeout=5)
        path = self.server.workbench.report_path(job)
        raw = path.read_bytes()
        status, clean, _ = self.request('GET', f'/api/jobs/{job}/report-sanitized')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(clean), sanitize_report(json.loads(raw)))
        self.assertEqual(path.read_bytes(), raw)
        for _ in range(3):
            self.assertEqual(self.request('GET', f'/api/jobs/{job}?after=0')[0], 200)
            self.assertEqual(self.request('POST', f'/api/jobs/{job}/cancel', b'{}')[0], 200)

    def test_linked_storage_and_targets_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)/'real'; target.mkdir()
            link = Path(temp)/'link'
            try:
                link.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest('Creating symlinks requires Windows developer mode or privilege.')
            with self.assertRaises(ValueError):
                Workbench(ROOT, runs_root=link)
            with self.assertRaises(ValueError):
                self.server.workbench.safe_run_file(link/'report.json')
            status, _, _ = self.request('POST', '/api/discover', json.dumps({'kind': 'path', 'path': str(link)}))
            self.assertEqual(status, 400)


if __name__ == '__main__':
    unittest.main()
