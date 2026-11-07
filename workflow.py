"""Local, static-only job orchestration. Target executables are always data."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from analysis import has_elf_magic, has_pe_magic
from samples import get_sample

MAX_TARGET_BYTES = 64 * 1024 * 1024
TERMINAL_STATES = {'completed', 'partial', 'failed', 'cancelled'}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _identity(path):
    info = Path(path).stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('Only regular files can be selected.')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _snapshot(source, destination, expected):
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    with os.fdopen(os.open(source, flags), 'rb') as input_file:
        info = os.fstat(input_file.fileno())
        identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if not stat.S_ISREG(info.st_mode) or identity != expected:
            raise ValueError('Selected file changed; rediscover the application before analysis.')
        if info.st_size > MAX_TARGET_BYTES:
            raise ValueError('Target exceeds the 64 MiB analysis limit.')
        header = input_file.read(64)
        if not (has_elf_magic(header) or has_pe_magic(header)):
            raise ValueError('Selected file is not a supported ELF or PE executable.')
        input_file.seek(0)
        with destination.open('xb') as output:
            total = 0
            while chunk := input_file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_TARGET_BYTES:
                    raise ValueError('Target grew beyond the analysis limit.')
                output.write(chunk)
        end = os.fstat(input_file.fileno())
        if (end.st_dev, end.st_ino, end.st_size, end.st_mtime_ns) != expected:
            raise ValueError('Target changed while copying; run was stopped.')
    destination.chmod(0o600)  # Data only; never an executable permission.


class Workbench:
    def __init__(self, root, *, runs_root=None, analyzer=None, inventory_provider=None):
        self.root = Path(root).resolve()
        self.runs_root = Path(runs_root or self.root / 'runs').resolve()
        self.runs_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.analyzer = analyzer
        self.inventory_provider = inventory_provider
        self.selections = {}
        self.jobs = {}
        self.lock = threading.RLock()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='reverseshield')

    def inventory(self):
        if self.inventory_provider:
            return self.inventory_provider()
        from engine import inventory
        return inventory()

    def add_selection(self, discovered, *, sample_id=None):
        selection = copy.deepcopy(discovered)
        selection['selection_id'] = secrets.token_hex(12)
        selection['sample_id'] = sample_id
        selection.setdefault('runtime', {'dependencies': [], 'scanned': False})
        selection.setdefault('warnings', [])
        for target in selection['targets']:
            target['_identity'] = _identity(target['absolute_path'])
        with self.lock:
            if len(self.selections) >= 64:
                raise ValueError('Selection limit reached. Restart the workbench before adding more inputs.')
            self.selections[selection['selection_id']] = selection
        public = copy.deepcopy(selection)
        public.pop('payload_root', None)
        for item in public['targets']:
            item.pop('absolute_path', None)
            item.pop('_identity', None)
        return public

    def start_job(self, selection_id, target_ids, tools, operation, *, authorized=False, profile=None):
        if authorized is not True:
            raise ValueError('Confirm that the input is benign and you are authorized to analyze it.')
        if operation not in {'analyze', 'strip_compare', 'protect_compare', 'binary_compare'}:
            raise ValueError('Unsupported operation. Dynamic execution is disabled.')
        if operation == 'strip_compare':
            profile = 'symbol_removal'
        elif operation == 'protect_compare':
            profile = profile or 'constant_blinding'
        elif operation == 'binary_compare':
            profile = 'binary_hygiene'
        if operation != 'analyze' and profile not in {'symbol_removal', 'constant_blinding', 'binary_hygiene'}:
            raise ValueError('Unknown protection profile.')
        if not isinstance(target_ids, list) or not target_ids or len(target_ids) > 16 or not all(isinstance(x, str) for x in target_ids):
            raise ValueError('Choose between 1 and 16 ELF/PE targets.')
        if not isinstance(tools, list) or not tools or not all(isinstance(x, str) for x in tools):
            raise ValueError('Choose at least one analysis tool.')
        inventory = self.inventory()
        if any(t not in inventory or not inventory[t]['available'] for t in tools):
            raise ValueError('An unknown or unavailable analysis tool was selected.')
        with self.lock:
            selection = self.selections.get(selection_id)
            if selection is None:
                raise ValueError('Selection expired or was not found; discover the input again.')
            requested = set(target_ids)
            targets = [t for t in selection['targets'] if t['target_id'] in requested]
            if len(targets) != len(requested) or any(not t.get('analyzable', False) for t in targets):
                raise ValueError('One or more selected targets are unavailable or too large.')
            if operation == 'strip_compare':
                sample = get_sample(selection.get('sample_id'))
                if sample is None or len(targets) != 1 or Path(targets[0]['absolute_path']).resolve() != (self.root / sample['binary']).resolve():
                    raise ValueError('Symbol removal is restricted to the bundled self-authored samples.')
                if not shutil.which('strip'):
                    raise ValueError('GNU strip is not available.')
            elif operation == 'protect_compare':
                sample = get_sample(selection.get('sample_id'))
                if sample is None or len(targets) != 1 or Path(targets[0]['absolute_path']).resolve() != (self.root / sample['binary']).resolve():
                    raise ValueError('Demo protection is restricted to the bundled self-authored samples.')
            elif operation == 'binary_compare':
                if len(targets) != 1:
                    raise ValueError('Binary hygiene requires exactly one selected ELF/PE target.')
            if len(self.jobs) >= 32:
                raise ValueError('Session job limit reached. Export reports and restart before another run.')
            if sum(j['status'] not in TERMINAL_STATES for j in self.jobs.values()) >= 4:
                raise ValueError('Job queue is full; wait or cancel an existing run.')
            job_id = secrets.token_hex(12)
            directory = self.runs_root / job_id
            directory.mkdir(mode=0o700)
            job = {'job_id': job_id, 'status': 'queued', 'operation': operation,
                   'profile': profile, 'sample_id': selection.get('sample_id'),
                   'label': selection['app'].get('name', 'Selected application'),
                   'events': [], 'next_seq': 0, 'result': None, 'error': None,
                   '_directory': directory, '_cancel': threading.Event()}
            self.jobs[job_id] = job
            self._emit(job, {'type': 'queued', 'message': 'Queued for local static analysis.'})
            job['_future'] = self.pool.submit(self._run, job, targets, list(dict.fromkeys(tools)))
            return job_id

    def _emit(self, job, event):
        with self.lock:
            job['next_seq'] += 1
            public = {**event, 'seq': job['next_seq'], 'time': _now()}
            public['message'] = str(public.get('message', ''))[:2000]
            job['events'].append(public)
            if len(job['events']) > 10000:
                del job['events'][:1000]
            # Keep disk logs bounded too; final report preserves full bounded tool output.
            log_path = job['_directory'] / 'events.jsonl'
            if not log_path.exists() or log_path.stat().st_size < 12 * 1024 * 1024:
                with log_path.open('a', encoding='utf-8') as log:
                    log.write(json.dumps(public, ensure_ascii=False) + '\n')

    def _analyze(self, job, path, tools, phase, label):
        analyzer = self.analyzer
        if analyzer is None:
            from engine import analyze
            analyzer = analyze
        workdir = job['_directory'] / (phase + '-' + secrets.token_hex(4))
        workdir.mkdir(mode=0o700)
        def emit(event):
            self._emit(job, {**event, 'phase': phase, 'target': label})
        emit({'type': 'phase', 'message': f'{phase}: static inspection; target will not be executed.'})
        result = analyzer(path, tools=tools, emit=emit, workdir=workdir, cancel_event=job['_cancel'])
        result['filename'] = label
        result['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result

    def _run(self, job, targets, tools):
        try:
            with self.lock:
                job['status'] = 'running'
            reports = []
            for index, target in enumerate(targets):
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled by user.')
                snapshot = job['_directory'] / f'original-{index}.elf'
                self._emit(job, {'type': 'phase', 'message': 'Copying selected ELF to a run-local snapshot.', 'target': target['relative_path']})
                _snapshot(target['absolute_path'], snapshot, target['_identity'])
                result = self._analyze(job, snapshot, tools, 'before' if job['operation'] != 'analyze' else 'analysis', target['relative_path'])
                reports.append({'target_id': target['target_id'], 'label': target['relative_path'], 'analysis': result})
            if job['profile'] == 'symbol_removal':
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled before symbol removal.')
                before = reports[0]['analysis']
                original = job['_directory'] / 'original-0.elf'
                transformed = job['_directory'] / 'symbols-removed.elf'
                tool = shutil.which('strip')
                command = [tool, '--strip-unneeded', '-o', str(transformed), str(original)]
                self._emit(job, {'type': 'tool_start', 'tool': 'strip', 'phase': 'transform', 'message': 'GNU strip: remove unneeded symbols into a separate sample copy.'})
                stripped = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False,
                                          env={**os.environ, 'LC_ALL': 'C'})
                self._emit(job, {'type': 'tool_end', 'tool': 'strip', 'phase': 'transform',
                                 'message': f'GNU strip exit {stripped.returncode}: ' + (stripped.stderr or stripped.stdout)[:1000]})
                if stripped.returncode or not transformed.is_file():
                    raise RuntimeError('Symbol-removal tool failed: ' + (stripped.stderr or '')[:1000])
                transformed.chmod(0o600)
                if hashlib.sha256(original.read_bytes()).hexdigest() != before['sha256']:
                    raise RuntimeError('Original run snapshot changed unexpectedly; comparison stopped.')
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled after symbol removal; reanalysis was not started.')
                version = subprocess.run([tool, '--version'], capture_output=True, text=True, timeout=5, check=False).stdout.splitlines()
                # Persist the applied transformation before reanalysis so a later
                # analysis failure cannot erase the baseline or protection state.
                job['result'] = {
                    'operation': 'strip_compare', 'before': before, 'after': None,
                    'protection': {'state': 'symbol_removal_applied', 'tool': 'GNU strip',
                                   'version': version[0] if version else 'Unknown', 'command': command,
                                   'original_sha256': before['sha256'],
                                   'transformed_sha256': hashlib.sha256(transformed.read_bytes()).hexdigest(),
                                   'behavior_verified': False, 'obfuscation': False},
                    'comparison': None,
                    'artifacts': {'original': original.name, 'transformed': transformed.name},
                    'limitations': ['Symbol removal is a baseline transformation, not code obfuscation.',
                                    'Only a copy of a bundled sample was changed. Target behavior was not tested.']}
                after = self._analyze(job, transformed, tools, 'after', targets[0]['relative_path'] + ' [symbols removed]')
                reports.append({'analysis': after})
                job['result']['after'] = after
                job['result']['comparison'] = compare_reports(before, after)
            # Any selected ELF/PE copy is allowed here; source profiles above
            # remain restricted to the bundled self-authored samples.
            elif job['profile'] == 'binary_hygiene':
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled before binary hygiene.')
                from binary_protection import build_binary_hygiene
                before = reports[0]['analysis']
                self._emit(job, {'type': 'tool_start', 'tool': 'binary_hygiene', 'phase': 'transform',
                                 'message': 'Binary metadata hygiene on a copy: strip symbols/debug and remove compiler notes.'})
                built = build_binary_hygiene(job['_directory'] / 'original-0.elf', job['_directory'] / 'binary-hygiene')
                transformed = Path(built['path'])
                self._emit(job, {'type': 'tool_end', 'tool': 'binary_hygiene', 'phase': 'transform',
                                 'message': f"Binary hygiene copy created ({built['sha256'][:16]}…); the target was not executed."})
                job['result'] = {
                    'operation': 'binary_compare', 'before': before, 'after': None,
                    'protection': {'state': 'binary_metadata_hygiene_applied', 'tool': 'GNU strip + objcopy',
                                   'method': built['method'], 'strength': built['strength'],
                                   'obfuscation': False, 'behavior_verified': False,
                                   'original_sha256': before['sha256'], 'transformed_sha256': built['sha256'],
                                   'commands': built['commands'], 'removed_sections': built['removed_sections']},
                    'comparison': None,
                    'artifacts': {'original': 'original-0.elf', 'transformed': transformed.name},
                    'limitations': ['Binary hygiene removes metadata from a copy; it is not code obfuscation or a protection guarantee.',
                                    'No target or transformed copy was executed; functional equivalence was not verified.']}
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled after binary hygiene; reanalysis was not started.')
                after = self._analyze(job, transformed, tools, 'after', targets[0]['relative_path'] + ' [binary hygiene]')
                reports.append({'analysis': after})
                job['result']['after'] = after
                job['result']['comparison'] = compare_reports(before, after)
            elif job['profile'] == 'constant_blinding':
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled before demo protection.')
                from demo_protection import build_protected
                before = reports[0]['analysis']
                self._emit(job, {'type': 'tool_start', 'tool': 'demo_transformer', 'phase': 'transform',
                                 'message': 'Demo transformer: blind integer constants and add an opaque guard in a source copy.'})
                built = build_protected(job['sample_id'], job['_directory'] / 'protected')
                protected = Path(built['path'])
                self._emit(job, {'type': 'tool_end', 'tool': 'demo_transformer', 'phase': 'transform',
                                 'message': f"Protected build created ({built['sha256'][:16]}…); sample sources were compiled but not executed."})
                job['result'] = {
                    'operation': 'protect_compare', 'before': before, 'after': None,
                    'protection': {'state': 'demo_obfuscation_applied', 'tool': 'ReverseShield demo transformer',
                                   'method': built['method'], 'key': built['key'],
                                   'strength': 'demonstration_only', 'obfuscation': True,
                                   'behavior_verified': False,
                                   'original_sha256': before['sha256'], 'transformed_sha256': built['sha256'],
                                   'sources': built['sources']},
                    'comparison': None,
                    'artifacts': {'original': 'original-0.elf', 'transformed': protected.name},
                    'limitations': ['Demo-grade source transformation for the bundled samples only; it is not a production obfuscator.',
                                    'Constants are blinded with a volatile key and an opaque guard is added; a determined analyst can still recover behavior.',
                                    'The protected program was compiled but not executed, so functional equivalence was not verified.']}
                if job['_cancel'].is_set():
                    raise InterruptedError('Cancelled after protection; reanalysis was not started.')
                after = self._analyze(job, protected, tools, 'after', targets[0]['relative_path'] + ' [demo-protected]')
                reports.append({'analysis': after})
                job['result']['after'] = after
                job['result']['comparison'] = compare_reports(before, after)
            else:
                job['result'] = {'operation': 'analyze', 'reports': reports,
                                 'limitations': ['Static inspection only; selected applications were not executed.',
                                                 'Local tools are not a malware sandbox. Use authorized benign inputs only.']}
            if job['_cancel'].is_set():
                job['status'] = 'cancelled'
            else:
                job['status'] = 'partial' if any(t.get('status') not in {'ok', 'skipped'}
                    for r in reports for t in r['analysis'].get('tools', [])) else 'completed'
        except InterruptedError as exc:
            job['status'], job['error'] = 'cancelled', str(exc)
        except Exception as exc:
            job['status'], job['error'] = 'failed', str(exc)
        finally:
            self._emit(job, {'type': job['status'], 'message': job['error'] or f"Run {job['status']} — no target execution."})
            record = {k: v for k, v in job.items() if not k.startswith('_')}
            report = job['_directory'] / 'report.json'
            report.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')

    def get_job(self, job_id, after=0):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                raise KeyError('Run not found in this server session.')
            result = {k: v for k, v in job.items() if not k.startswith('_') and k != 'events'}
            result['events'] = [event for event in job['events'] if event['seq'] > after]
            result['events_truncated'] = bool(job['events'] and after < job['events'][0]['seq'] - 1)
            return copy.deepcopy(result)

    def list_jobs(self):
        with self.lock:
            return [{k: j[k] for k in ('job_id', 'status', 'operation', 'label')} for j in reversed(list(self.jobs.values()))]

    def report_path(self, job_id):
        self.get_job(job_id)
        return self.jobs[job_id]['_directory'] / 'report.json'

    def artifact_path(self, job_id):
        record = self.get_job(job_id)
        if record['operation'] not in {'strip_compare', 'protect_compare', 'binary_compare'} or not record.get('result') or record['status'] not in {'completed', 'partial'}:
            raise ValueError('No completed protection artifact is available.')
        if record['operation'] == 'strip_compare':
            return self.jobs[job_id]['_directory'] / 'symbols-removed.elf'
        if record['operation'] == 'binary_compare':
            directory = self.jobs[job_id]['_directory'] / 'binary-hygiene'
            for name in ('binary-hygiene.elf', 'binary-hygiene.exe'):
                candidate = directory / name
                if candidate.is_file():
                    return candidate
            raise ValueError('Binary hygiene artifact is not available.')
        protected = sorted((self.jobs[job_id]['_directory'] / 'protected').glob('*-protected.elf'))
        if not protected:
            raise ValueError('Protected artifact is not available.')
        return protected[0]

    def wait(self, job_id, timeout=None):
        self.jobs[job_id]['_future'].result(timeout=timeout)

    def cancel(self, job_id):
        with self.lock:
            self.get_job(job_id)
            job = self.jobs[job_id]
            if job['status'] not in TERMINAL_STATES:
                job['_cancel'].set()
                self._emit(job, {'type': 'cancel_requested', 'message': 'Cancellation requested; active analysis tools will be stopped.'})
        return self.get_job(job_id)

    def close(self):
        for job in self.jobs.values():
            if job['status'] not in TERMINAL_STATES:
                job['_cancel'].set()
        self.pool.shutdown(wait=True)


def compare_reports(before: dict, after: dict) -> dict:
    providers = {'functions': {'readelf', 'nm', 'objdump', 'ghidra_headless'},
                 'symbols': {'readelf', 'nm', 'ghidra_headless'},
                 'strings': {'strings', 'ghidra_headless'},
                 'call_edges': {'objdump', 'ghidra_headless'}}

    def collected(report, key):
        selected = set(report.get('coverage', {}).get('selected_tools') or [])
        return bool(selected & providers[key])

    def count(report, key):
        value = report.get('artifacts', {}).get(key)
        return len(value) if collected(report, key) and isinstance(value, list) else None

    pairs = [
        ('File size (bytes)', before.get('size_bytes'), after.get('size_bytes')),
        ('Parsed symbol entries', before.get('metadata', {}).get('symbol_entries'), after.get('metadata', {}).get('symbol_entries')),
        ('Parsed sections', before.get('metadata', {}).get('sections_count'), after.get('metadata', {}).get('sections_count')),
        ('Exported functions', count(before, 'functions'), count(after, 'functions')),
        ('Extracted strings', count(before, 'strings'), count(after, 'strings')),
        ('Exported call edges', count(before, 'call_edges'), count(after, 'call_edges')),
    ]
    metrics = [{'name': name, 'before': a, 'after': b,
                'delta': b - a if isinstance(a, (int, float)) and isinstance(b, (int, float)) else None}
               for name, a, b in pairs]

    def differences(key):
        def names(report):
            values = report.get('artifacts', {}).get(key)
            if not isinstance(values, list):
                return None
            return {str(v.get('name', '')) if isinstance(v, dict) else str(v) for v in values}
        a, b = names(before), names(after)
        if a is None or b is None:
            return {'available': False, 'added': [], 'removed': [], 'reason': 'Not collected on both sides.'}
        return {'available': True, 'added': sorted(b - a), 'removed': sorted(a - b)}

    return {'metrics': metrics, 'strings': differences('strings'), 'symbols': differences('symbols'),
            'limitations': [
                'Observed artifact differences are not a resistance score.',
                'Counts describe exported data and may be partial; inspect each report coverage and tool status.',
                'Names and addresses may change; functions are not automatically claimed to match.',
                'Target behavior and functional equivalence were not tested.']}
