"""Integration tests for the token-protected loopback API.

Inputs are local JSON requests and inert fixture uploads; outputs are discovery
records, events and static reports. The test harness and application never
execute target files. Add API coverage through bounded request bodies and
assert that private filesystem paths remain internal.
"""
import http.client
import json
import secrets
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

import app
import engine
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

    def request_bytes(self, method, path, body, headers=None, token=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        h = {'Content-Type': 'application/octet-stream'}
        if token:
            h['X-ReverseShield-Token'] = self.server.api_token
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
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
        self.assertNotIn('token', state)
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

    def test_pe_upload_is_discovered_and_generates_static_report(self):
        fixture = ROOT / 'tests/fixtures/minimal-pe64.exe'
        available = engine.inventory()
        preferred = 'objdump' if available['objdump']['available'] else 'ghidra_headless'
        tools = [preferred] if available[preferred]['available'] else [
            name for name in ('strings', 'file') if available[name]['available']]
        if not tools:
            self.skipTest('No PE-capable static analysis adapter is installed.')

        old_analyzer = self.server.workbench.analyzer
        old_inventory = self.server.workbench.inventory_provider
        self.server.workbench.analyzer = engine.analyze
        self.server.workbench.inventory_provider = engine.inventory
        try:
            status, selection = self.request_bytes(
                'POST', '/api/ingest?filename=minimal-pe64.exe', fixture.read_bytes())
            self.assertEqual(status, 200, selection)
            target = selection['targets'][0]
            self.assertEqual(target['format'], 'PE')
            self.assertTrue(target['analyzable'])
            self.assertNotIn('absolute_path', target)

            status, created = self.request('POST', '/api/jobs', {
                'selection_id': selection['selection_id'], 'target_ids': [target['target_id']],
                'tools': tools, 'operation': 'analyze', 'authorized': True})
            self.assertEqual(status, 202, created)
            self.server.workbench.wait(created['job_id'], timeout=120)
            status, job = self.request('GET', '/api/jobs/' + created['job_id'])
            self.assertEqual(status, 200, job)
            self.assertEqual(job['status'], 'completed', job)
            report = job['result']['reports'][0]['analysis']
            self.assertEqual(report['metadata']['format'], 'PE')
            self.assertEqual(report['sha256'], __import__('hashlib').sha256(fixture.read_bytes()).hexdigest())
            self.assertIn('never executed', ' '.join(report['limitations']).lower())
            self.assertFalse(any('target was executed' in item.lower() for item in report['limitations']))
            if 'readelf' in tools:
                self.assertEqual(next(t for t in report['tools'] if t['tool'] == 'readelf')['status'], 'skipped')
        finally:
            self.server.workbench.analyzer = old_analyzer
            self.server.workbench.inventory_provider = old_inventory


if __name__ == '__main__':
    unittest.main()
