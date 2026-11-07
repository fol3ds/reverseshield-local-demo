"""HTTP orchestration tests; target files are read, never executed."""
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import app
from workflow import Workbench
from test_workflow import inventory_baseline, static_baseline

ROOT = Path(__file__).resolve().parents[1]


class UpgradeApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), app.ReverseShieldHandler)
        cls.server.workbench = Workbench(ROOT, runs_root=Path(cls.temp.name), analyzer=static_baseline, inventory_provider=inventory_baseline)
        cls.server.api_token = secrets.token_urlsafe(24)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server.workbench.close()
        cls.thread.join(timeout=2)
        cls.temp.cleanup()

    def request(self, method, path, payload=None, headers=None, token=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'Content-Type': 'application/json'}
        if token:
            h['X-ReverseShield-Token'] = self.server.api_token
        h.update(headers or {})
        conn.request(method, path, json.dumps(payload).encode() if payload is not None else None, h)
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        conn.close()
        return status, json.loads(raw)

    def test_new_discovery_requires_token_and_rejects_foreign_origin(self):
        status, _ = self.request('POST', '/api/discover', {'kind': 'sample', 'sample_id': 'level-1'}, token=False)
        self.assertEqual(status, 403)
        status, _ = self.request('GET', '/api/status', headers={'Origin': 'https://foreign.example'})
        self.assertEqual(status, 403)
        status, _ = self.request('GET', '/api/status', headers={'Host': 'foreign.example'})
        self.assertEqual(status, 403)

    def test_sample_selection_starts_real_static_job_and_can_be_read(self):
        status, state = self.request('GET', '/api/status')
        self.assertEqual(status, 200)
        self.assertEqual(state.get('token'), self.server.api_token)
        status, selection = self.request('POST', '/api/discover', {'kind': 'sample', 'sample_id': 'level-1'})
        self.assertEqual(status, 200, selection)
        self.assertEqual(selection['sample_id'], 'level-1')
        self.assertNotIn('absolute_path', selection['targets'][0])
        status, created = self.request('POST', '/api/jobs', {
            'selection_id': selection['selection_id'], 'target_ids': [selection['targets'][0]['target_id']],
            'tools': ['readelf'], 'operation': 'analyze', 'authorized': True})
        self.assertEqual(status, 202, created)
        self.server.workbench.wait(created['job_id'], timeout=10)
        status, job = self.request('GET', '/api/jobs/' + created['job_id'])
        self.assertEqual(status, 200)
        self.assertEqual(job['status'], 'completed')
        self.assertEqual(job['result']['reports'][0]['analysis']['analysis_mode'], 'static_only')


if __name__ == '__main__':
    unittest.main()
