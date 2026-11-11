#!/usr/bin/env python3
"""Record the exact outcome of a full test-suite log for Day 4 evidence.

Parses a unittest log written by
    RUN_GHIDRA_TESTS=1 python3 -m unittest discover -s tests -v
and writes docs/evidence/verification.json. No target binary is executed.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import platform
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOG = ROOT / 'runs' / 'day4-qa' / 'full-suite.log'
OUTPUT = ROOT / 'docs' / 'evidence' / 'verification.json'


def main(log_path: Path = DEFAULT_LOG) -> int:
    text = Path(log_path).read_text(encoding='utf-8', errors='replace')
    ran = re.search(r'^Ran (\d+) tests? in ', text, re.M)
    if not ran:
        raise SystemExit('log has no unittest summary line')
    count = int(ran.group(1))
    skipped = re.search(r'OK \(skipped=(\d+)\)', text)
    failed = re.search(r'^FAILED \((.*)\)$', text, re.M)
    errors = len(re.findall(r'^ERROR: ', text, re.M))
    failures = len(re.findall(r'^FAIL: ', text, re.M))
    status = 'passed' if 'OK' in text and not failed else 'failed'
    document = {
        'observed_at': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
        'command': 'RUN_GHIDRA_TESTS=1 python3 -m unittest discover -s tests -v',
        'platform': f'{platform.system()} {platform.release()} {platform.machine()}',
        'python': platform.python_version(),
        'tests': {'count': count, 'run': 'Ghidra-enabled tests',
                  'skipped': int(skipped.group(1)) if skipped else 0,
                  'status': status, 'failures': failures, 'errors': errors},
        'log_sha256': hashlib.sha256(Path(log_path).read_bytes()).hexdigest(),
        'scope': ('Automated project tests only. Ghidra integration is enabled; native-Windows manual '
                  'acceptance was not run. Tests do not execute bundled samples or third-party targets '
                  'on the host; the OLLVM suite boots separate deterministic drivers in a no-network QEMU guest.'),
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(document, indent=2))
    if status != 'passed':
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LOG))
