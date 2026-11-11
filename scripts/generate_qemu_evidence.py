#!/usr/bin/env python3
"""Regenerate the sanitized five-sample QEMU evidence summary.

Runs the deterministic self-authored sample drivers in the QEMU guest and
writes hash-only, path-free results to docs/evidence/ollvm-five-qemu.json.
The downloadable protected.elf is never executed; only separate driver builds
are compared. Host targets are never launched.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from behavior_qemu import run_behavior
OUTPUT = ROOT / 'docs' / 'evidence' / 'ollvm-five-qemu.json'
SAMPLES = ('level-1', 'level-2', 'level-3', 'level-4', 'level-5')


def main() -> int:
    rows = []
    with tempfile.TemporaryDirectory(dir=ROOT / 'runs', prefix='qemu-evidence-') as temp:
        for sample_id in SAMPLES:
            result = run_behavior(ROOT, sample_id, Path(temp) / sample_id)
            if not result['passed']:
                raise SystemExit(f'{sample_id}: QEMU driver comparison did not pass')
            rows.append({
                'sample_id': sample_id,
                'matched': True,
                'scope': result['scope'],
                'artifact_behavior_verified': result['artifact_behavior_verified'],
                'exit_codes': result['exit_codes'],
                'qemu_return_code': result['qemu_return_code'],
                'output_sha256': result['transcript_sha256']['original'],
                'initramfs_sha256': result['initramfs_sha256'],
                'duration_seconds': result['duration_seconds'],
                'driver_sha256': result['driver_sha256'],
                'transcript_sha256': result['transcript_sha256'],
            })
    document = {
        'observed_at': dt.datetime.now().astimezone().isoformat(timespec='seconds'),
        'scope': 'separate_deterministic_drivers',
        'artifact_behavior_verified': False,
        'samples': rows,
        'interpretation': ('Five original self-authored sample drivers only, inside a '
                           'no-disk/no-network QEMU guest. These separate driver builds are '
                           'NOT the downloadable protected.elf; that artifact was not executed '
                           'or behavior-verified. Matching deterministic vectors do not prove '
                           'full behavioral equivalence or security.'),
    }
    OUTPUT.write_text(json.dumps(document, indent=2, sort_keys=False) + '\n', encoding='utf-8')
    print(f'wrote {OUTPUT.relative_to(ROOT)} ({len(rows)} samples)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
