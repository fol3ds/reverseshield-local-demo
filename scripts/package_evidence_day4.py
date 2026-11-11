"""Package only specifically reviewed local Day 4 evidence; never publish it."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_EVIDENCE = (
    Path('docs/evidence/hardening-level5.json'),
    Path('docs/evidence/ollvm-five-qemu.json'),
    Path('docs/evidence/verification.json'),
    Path('docs/evidence/security-day4.json'),
    Path('docs/evidence/SECURITY_REVIEW_DAY4.md'),
    Path('docs/evidence/ACCEPTANCE_MATRIX_DAY4.md'),
    Path('docs/evidence/CLAIM_EVIDENCE_DAY4.md'),
    Path('docs/ReverseShield_Day4_Technical_Report.pdf'),
    Path('docs/ReverseShield_Day4_Readiness_Plan.pdf'),
)
OUTPUT = ROOT / 'dist' / 'ReverseShield_Evidence_v0.5.0-team.zip'
CHECKSUM = ROOT / 'dist' / 'EVIDENCE_SHA256SUMS.txt'
# A guardrail, not a comprehensive secrets detector; PDFs require a text
# extraction and human review before sharing the resulting archive.
PRIVATE_PATH = re.compile(rb'(?i)(?:/home/[\w.-]+/|/Users/[\w.-]+/|[A-Z]:\\Users\\[^\\]+\\)')
README = ("# ReverseShield Day 4 evidence — LOCAL REVIEW CANDIDATE\n\n"
          "No event submission or public release is implied. The hardened sample\n"
          "shows static mitigation properties, not security or equivalence. Five\n"
          "deterministic self-authored QEMU drivers matched limited test vectors,\n"
          "not arbitrary behavior. Clean native-Windows manual acceptance is\n"
          "pending; OLLVM/QEMU is Linux-only. PDFs and every extracted file must\n"
          "be reviewed by the owner before sharing. Do not include raw runs/.\n")


def _zip_entry(archive: zipfile.ZipFile, name: str, data: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(2026, 11, 11, 0, 0, 0))
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED,
                     compresslevel=6)


def build_pack(root: Path = ROOT, destination: Path = OUTPUT,
               checksum: Path = CHECKSUM) -> None:
    root, destination, checksum = Path(root), Path(destination), Path(checksum)
    payloads: dict[str, bytes] = {}
    for relative in REQUIRED_EVIDENCE:
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f'required reviewed evidence missing: {relative}')
        data = path.read_bytes()
        if PRIVATE_PATH.search(data):
            raise ValueError(f'private path detected in evidence: {relative}')
        payloads[relative.as_posix()] = data
    manifest = {
        'candidate': 'v0.5.0-team / local-only',
        'files': {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(payloads.items())},
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    checksum.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, 'w') as archive:
        for name, data in sorted(payloads.items()):
            _zip_entry(archive, name, data)
        _zip_entry(archive, 'README_EVIDENCE.md', README.encode('utf-8'))
        _zip_entry(archive, 'EVIDENCE_MANIFEST.json',
                   (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    checksum.write_text(f'{hashlib.sha256(destination.read_bytes()).hexdigest()}  '
                        f'{destination.name}\n', encoding='ascii')


if __name__ == '__main__':
    build_pack()
    print(f'Local candidate: {OUTPUT}')
    print(f'Checksum: {CHECKSUM}')
