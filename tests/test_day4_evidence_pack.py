"""Local-only Day 4 evidence-archive allowlist and sanitization tests."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.package_evidence_day4 import build_pack, REQUIRED_EVIDENCE


class EvidencePackTests(unittest.TestCase):
    def source(self, root: Path, *, tainted: bool = False):
        for relative in REQUIRED_EVIDENCE:
            file = root / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b'file:///home/private/file' if tainted and relative.suffix == '.json'
                             else b'checked evidence')
        raw = root / 'runs' / 'private' / 'report.json'
        raw.parent.mkdir(parents=True)
        raw.write_text('secret', encoding='utf-8')

    def test_only_allowlisted_evidence_and_manifest_are_in_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.source(root)
            destination = root / 'dist' / 'evidence.zip'
            checksum = root / 'dist' / 'evidence.sha256'
            build_pack(root, destination, checksum)
            expected = hashlib.sha256(destination.read_bytes()).hexdigest()
            self.assertEqual(checksum.read_text(encoding='ascii'),
                             f'{expected}  {destination.name}\n')
            with zipfile.ZipFile(destination) as archive:
                names = archive.namelist()
                self.assertEqual(sorted(names),
                                 sorted([p.as_posix() for p in REQUIRED_EVIDENCE]
                                        + ['EVIDENCE_MANIFEST.json', 'README_EVIDENCE.md']))
                self.assertFalse(any(name.startswith('runs/') for name in names))
                manifest = json.loads(archive.read('EVIDENCE_MANIFEST.json'))
                self.assertEqual(set(manifest['files']),
                                 {p.as_posix() for p in REQUIRED_EVIDENCE})
                for name, digest in manifest['files'].items():
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_private_path_in_text_evidence_refuses_pack(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.source(root, tainted=True)
            with self.assertRaisesRegex(ValueError, 'private path'):
                build_pack(root, root / 'dist' / 'evidence.zip',
                           root / 'dist' / 'evidence.sha256')

    def test_missing_required_evidence_refuses_pack(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.source(root)
            (root / REQUIRED_EVIDENCE[0]).unlink()
            with self.assertRaisesRegex(FileNotFoundError, 'evidence'):
                build_pack(root, root / 'dist' / 'evidence.zip',
                           root / 'dist' / 'evidence.sha256')


if __name__ == '__main__':
    unittest.main()
