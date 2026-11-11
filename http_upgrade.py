"""Same-origin local API for discovery, asynchronous jobs, and reports.

Inputs are same-origin loopback JSON or bounded upload bytes; outputs are
discovery selections, job events and report/artifact downloads. All API
routes require the per-session token. Uploads are written to run-local input
workspaces and never executed on the host. The optional OLLVM profile uses a QEMU micro-VM for deterministic sample drivers. Add routes with the same authorization checks,
format validation and run-local storage boundary.
"""
import json
import os
import re
import secrets
import shutil
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from sanitize_report import sanitize_report
from analysis import detect_format, parse_pe_header
from engine import GHIDRA_MAX_CPU, GHIDRA_TIMEOUT, GHIDRA_TIMEOUT_RANGE, LARGE_TARGET_BYTES
from samples import ROOT, SAMPLES, get_sample
from workflow import Workbench

INIT_LOCK = threading.Lock()
DEMO_SAMPLE_ID = 'level-5'
UPLOAD_LIMIT = 256 * 1024 * 1024


def _ollvm_available():
    try:
        from ollvm_protection import available
        return bool(available(ROOT))
    except Exception:
        return False


class UpgradeApiMixin:
    server_version = 'ReverseShieldLocalDemo/0.5.0-team'

    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def log_message(self, format, *args):
        pass  # Do not log local paths or uploaded filenames.

    def version_string(self):
        return 'ReverseShield'

    @property
    def service(self):
        with INIT_LOCK:
            if not hasattr(self.server, 'workbench'):
                self.server.workbench = Workbench(ROOT)
            if not hasattr(self.server, 'api_token'):
                self.server.api_token = secrets.token_urlsafe(32)
        return self.server.workbench

    def _send(self, body, content_type='application/json; charset=utf-8', status=200, download=None):
        self.send_response(status)
        for name, value in {
            'Content-Type': content_type, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
            'Cross-Origin-Resource-Policy': 'same-origin', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        }.items():
            self.send_header(name, value)
        if download:
            self.send_header('Content-Disposition', f'attachment; filename="{download}"')
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _check_access(self, require_token=False):
        port = self.server.server_address[1]
        host = self.headers.get('Host', '')
        origin = self.headers.get('Origin')
        if host not in {f'127.0.0.1:{port}', f'localhost:{port}'} or (origin is not None and origin != 'http://' + host) or self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin', 'none'):
            self._json({'error': 'Only same-origin loopback requests are accepted.'}, 403)
            return False
        referer = self.headers.get('Referer')
        if referer and urlsplit(referer).netloc != host:
            self._json({'error': 'Foreign Referer is not accepted.'}, 403)
            return False
        if referer and urlsplit(referer).scheme != 'http':
            self._json({'error': 'Foreign Referer is not accepted.'}, 403)
            return False
        if require_token:
            self.service
            supplied = self.headers.get('X-ReverseShield-Token', '').encode('utf-8')
            if not secrets.compare_digest(supplied, self.server.api_token.encode('ascii')):
                self._json({'error': 'Missing or invalid local request token. Reload the workbench.'}, 403)
                return False
        return True

    def _content_length(self, limit):
        if len(self.headers.get_all('Content-Length', [])) > 1:
            raise ValueError('Ambiguous request length.')
        if self.headers.get('Transfer-Encoding'):
            raise ValueError('Chunked request bodies are not supported.')
        try:
            size = int(self.headers.get('Content-Length', '0'))
        except ValueError as exc:
            raise ValueError('Invalid Content-Length.') from exc
        if size < 0 or size > limit:
            raise ValueError(f'Request exceeds the {limit // (1024 * 1024)} MiB limit.')
        return size

    def _read_body(self, limit):
        size = self._content_length(limit)
        data = self.rfile.read(size)
        if len(data) != size:
            raise ValueError('Incomplete request body.')
        return data

    def _payload(self):
        if self.headers.get_content_type() != 'application/json':
            raise ValueError('Expected application/json.')
        data = json.loads(self._read_body(16384))
        if not isinstance(data, dict):
            raise ValueError('Expected a JSON object.')
        return data

    def do_GET(self):
        if not self._check_access(require_token=urlsplit(self.path).path.startswith('/api/')):
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            assets = {'/workbench.js': 'text/javascript; charset=utf-8', '/workbench.css': 'text/css; charset=utf-8',
                      '/static/workbench.js': 'text/javascript; charset=utf-8', '/static/workbench.css': 'text/css; charset=utf-8'}
            if path in ('/', '/index.html'):
                self.service
                page = (ROOT / 'static/index.html').read_text(encoding='utf-8')
                page = page.replace('</head>', '<meta name="reverseshield-token" content="' + self.server.api_token + '"></head>')
                self._send(page.encode('utf-8'), 'text/html; charset=utf-8')
            elif path in assets:
                self._send((ROOT / 'static' / path.rsplit('/', 1)[-1]).read_bytes(), assets[path])
            elif path == '/api/status':
                tools = self.service.inventory()
                self._json({'application': 'ReverseShield Local Workbench', 'version': '0.5.0-team',
                            'mode': 'static_only', 'tools': tools,
                            'dynamic_analysis': {'enabled': False, 'state': 'disabled_future_extension'},
                            'protection': {'available': bool(shutil.which('strip')), 'tool': 'GNU strip', 'scope': 'bundled_samples_only', 'obfuscation': False,
                                           'binary_hygiene': bool(shutil.which('strip') and shutil.which('objcopy')),
                                           'binary_scope': 'one_selected_elf_or_pe_copy',
                                           'ollvm': {'available': _ollvm_available(), 'tool': 'xollvm',
                                                     'scope': 'bundled_sample_sources_only',
                                                     'method': 'control-flow + string obfuscation',
                                                     'behavior': 'qemu_microvm_no_network'}},
                            'package_formats': {'ELF': 'supported', 'PE': 'supported', 'RPM': 'supported' if os.name != 'nt' else 'unsupported_on_windows', 'DEB': 'unsupported', 'APK': 'unsupported'},
                            'platform': 'windows' if os.name == 'nt' else 'linux',
                            'ghidra': {'large_target_bytes': LARGE_TARGET_BYTES, 'default_timeout_seconds': GHIDRA_TIMEOUT,
                                       'timeout_range_seconds': list(GHIDRA_TIMEOUT_RANGE), 'default_max_cpu': GHIDRA_MAX_CPU,
                                       'max_cpu_limit': max(1, os.cpu_count() or 1)},
                            'demo': {'sample_id': DEMO_SAMPLE_ID},
                            'sample_count': len(SAMPLES), 'upload_limit_bytes': UPLOAD_LIMIT, 'elf_limit_bytes': 64 * 1024 * 1024,
                            'storage': 'Inputs, snapshots, logs and reports stay in the project runs folder until manually removed.'})
            elif path == '/api/jobs':
                self._json({'jobs': self.service.list_jobs()})
            elif path.startswith('/api/jobs/'):
                parts = path.split('/')
                job_id = parts[3]
                if not re.fullmatch(r'[0-9a-f]{24}', job_id):
                    raise KeyError('Run not found.')
                if len(parts) == 4:
                    after = int(parse_qs(parsed.query).get('after', ['0'])[0])
                    self._json(self.service.get_job(job_id, after=max(0, after)))
                elif len(parts) == 5 and parts[4] in {'report', 'report-sanitized'}:
                    report = self.service.report_path(job_id)
                    if not report.is_file():
                        self._json({'error': 'Report is not finished yet.'}, 409)
                    else:
                        payload = json.loads(report.read_text(encoding='utf-8'))
                        if parts[4] == 'report-sanitized':
                            payload = sanitize_report(payload)
                        self._send(json.dumps(payload, ensure_ascii=False).encode('utf-8'), 'application/json', download=f'reverseshield-{job_id}-{parts[4]}.json')
                elif len(parts) == 5 and parts[4] == 'artifact':
                    artifact = self.service.artifact_path(job_id)
                    self._send(artifact.read_bytes(), 'application/octet-stream', download=artifact.name)
                else:
                    self._json({'error': 'Route not found.'}, 404)
            else:
                super().do_GET()
        except KeyError as exc:
            self._json({'error': 'Requested resource was not found.'}, 404)
        except (ValueError, OSError, TypeError, RecursionError) as exc:
            self._json({'error': 'Invalid request or unavailable local input. Check the format, size and selection.'}, 400)
        except RuntimeError as exc:
            self._json({'error': 'Required local service or tool is unavailable.'}, 503)

    def _json(self, value, status=200):
        if status >= 400 and isinstance(value, dict) and "error" in value:
            value = {"error": sanitize_report(str(value["error"]))}
        super()._json(value, status)

    def do_POST(self):
        path = urlsplit(self.path).path
        if not self._check_access(require_token=True):
            return
        try:
            if path == '/api/discover':
                self._discover(self._payload())
            elif path == '/api/ingest':
                self._ingest()
            elif path == '/api/jobs':
                data = self._payload()
                job_id = self.service.start_job(data.get('selection_id'), data.get('target_ids'), data.get('tools'),
                                                data.get('operation', 'analyze'), authorized=data.get('authorized', False),
                                                profile=data.get('profile'), options=data.get('options'))
                self._json({'job_id': job_id}, 202)
            elif path.startswith('/api/jobs/') and path.endswith('/cancel'):
                self._payload()
                parts = path.split('/')
                if len(parts) != 5:
                    raise KeyError('Route not found.')
                self._json(self.service.cancel(parts[3]))
            else:
                super().do_POST()
        except KeyError as exc:
            self._json({'error': 'Requested resource was not found.'}, 404)
        except (ValueError, OSError, TypeError, RecursionError) as exc:
            self._json({'error': 'Invalid request or unavailable local input. Check the format, size and selection.'}, 400)
        except RuntimeError as exc:
            self._json({'error': 'Required local service or tool is unavailable.'}, 503)

    def send_error(self, code, message=None, explain=None):
        self._json({'error': 'Unsupported request.'}, code)

    def _unsupported(self):
        if self._check_access(require_token=True):
            self._json({'error': 'Method not allowed.'}, 405)

    do_PUT = _unsupported
    do_DELETE = _unsupported
    do_PATCH = _unsupported
    do_OPTIONS = _unsupported

    def _discover(self, data):
        kind = data.get('kind')
        sample_id = None
        if kind == 'sample':
            sample_id = data.get('sample_id')
            sample = get_sample(sample_id)
            if sample is None:
                raise KeyError('Unknown sample id.')
            binary = ROOT / sample['binary']
            with binary.open('rb') as stream:
                sample_format = detect_format(stream.read(64))
            discovered = {'app': {'name': sample['name'], 'source': 'sample'},
                          'targets': [{'target_id': sample['id'], 'relative_path': binary.name,
                                       'absolute_path': str(binary.resolve()), 'size_bytes': binary.stat().st_size, 'format': sample_format,
                                       'analyzable': True, 'reason': None}]}
        elif kind == 'flatpak':
            from discovery import discover_flatpak_targets
            app_id = data.get('app_id')
            if not isinstance(app_id, str):
                raise ValueError('Choose an installed Flatpak application.')
            discovered = discover_flatpak_targets(app_id)
        elif kind == 'path':
            from discovery import discover_path
            raw = data.get('path')
            if not isinstance(raw, str) or not raw or not Path(raw).is_absolute():
                raise ValueError('Enter an absolute local path to an app folder, ELF/PE file, or RPM package.')
            if raw.startswith(('\\\\', '//')) or (os.name == 'nt' and raw.startswith('\\')):
                # UNC/device paths would make Windows connect to another host
                # and offer the user's credentials (forced authentication).
                raise ValueError('Network (UNC) and device paths are not supported. Copy the files to a local folder first.')
            from discovery import _is_link_like
            candidate = Path(raw)
            if any(_is_link_like(item) for item in (candidate, *candidate.parents)):
                raise ValueError('Linked input paths are not supported.')
            chosen = candidate.resolve(strict=True)
            if chosen == Path('/') or any(chosen.is_relative_to(Path(p)) for p in ('/proc', '/sys', '/dev')):
                raise ValueError('Choose an application folder or ELF/PE/RPM file, not a system pseudo-filesystem.')
            workspace = self.service.runs_root / 'inputs' / secrets.token_hex(12)
            workspace.mkdir(parents=True, mode=0o700)
            discovered = discover_path(chosen, workspace=workspace)
        else:
            raise ValueError('Choose sample, flatpak, or path input.')
        self._json(self.service.add_selection(discovered, sample_id=sample_id))

    def _ingest(self):
        size = self._content_length(UPLOAD_LIMIT)
        if size < 4:
            raise ValueError('Input must be a Linux ELF, Windows PE, or RPM package.')
        header = self.rfile.read(min(64, size))
        if header[:4] == b'\x7fELF':
            suffix = '.elf'
            if size > 64 * 1024 * 1024:
                raise ValueError('ELF exceeds the 64 MiB analysis limit.')
        elif header[:2] == b'MZ':
            suffix = '.exe'
            if size > 64 * 1024 * 1024:
                raise ValueError('PE exceeds the 64 MiB analysis limit.')
        elif header[:4] == b'\xed\xab\xee\xdb':
            suffix = '.rpm'
        else:
            self._json({'error': 'Unsupported input: Linux ELF, Windows PE, or RPM only. DEB and APK are not enabled.'}, 415)
            return
        workspace = self.service.runs_root / 'inputs' / secrets.token_hex(12)
        workspace.mkdir(parents=True, mode=0o700)
        try:
            target = workspace / ('input' + suffix)
            with target.open('xb') as stream:
                stream.write(header)
                remaining = size - len(header)
                while remaining:
                    chunk = self.rfile.read(min(remaining, 1024 * 1024))
                    if not chunk:
                        raise ValueError('Incomplete upload.')
                    stream.write(chunk)
                    remaining -= len(chunk)
            target.chmod(0o600)
            if suffix == '.exe':
                parse_pe_header(target)
            elif suffix == '.elf' and (len(header) < 52 or header[4] not in (1, 2) or header[5] not in (1, 2) or header[6] != 1 or (header[4] == 2 and len(header) < 64)):
                raise ValueError('Malformed ELF header.')
            from discovery import discover_path
            discovered = discover_path(target, workspace=workspace)
            query = parse_qs(urlsplit(self.path).query)
            display = Path(query.get('filename', ['uploaded' + suffix])[0].replace('\\', '/')).name[:120]
            discovered['app']['name'] = ''.join(c for c in display if c.isprintable()) or 'Uploaded input'
            self._json(self.service.add_selection(discovered))
        except Exception:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
