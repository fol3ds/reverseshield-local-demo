"""Generated Day 4 documents must describe measured work, not old plans."""
import json
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

if __package__:
    from .document_tools import docx_python
else:  # unittest discover -s tests imports this as a top-level module.
    from document_tools import docx_python

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'


def document_text(path):
    with zipfile.ZipFile(path) as archive:
        xml = ET.fromstring(archive.read('word/document.xml'))
    return ' '.join(node.text or '' for node in xml.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'))


def footer_text(path):
    with zipfile.ZipFile(path) as archive:
        xml = ET.fromstring(archive.read('word/footer1.xml'))
    return ' '.join(node.text or '' for node in xml.iter('{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t'))


class Day4DocumentTests(unittest.TestCase):
    def test_report_uses_six_samples_and_current_verified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'report.docx'
            subprocess.run([docx_python(), str(DOCS / 'build_report.py'), str(output)],
                           cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
            text = document_text(output)
            for item in ('Day 4 technical report', 'Ghidra-enabled tests', 'level-5-hardened',
                         'five original samples', 'QEMU', 'Windows manual test pending'):
                self.assertIn(item, text)
            for stale in ('54 tests', 'final draft for submission', '0x9E3779B9',
                          str(Path.home()), '/home/', '/Users/'):
                self.assertNotIn(stale, text)

    def test_report_embeds_measured_artifacts_and_marks_pending_verification(self):
        hard = json.loads((DOCS / 'evidence/hardening-level5.json').read_text(encoding='utf-8'))
        qemu = json.loads((DOCS / 'evidence/ollvm-five-qemu.json').read_text(encoding='utf-8'))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'report.docx'
            subprocess.run([docx_python(), str(DOCS / 'build_report.py'), str(output)],
                           cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
            text = document_text(output)
        for record in hard['samples']:
            self.assertIn(record['sha256'], text)
            self.assertIn(str(record['bytes']), text)
        for record in qemu['samples']:
            self.assertIn(record['output_sha256'], text)
        self.assertIn('static property', text)
        self.assertIn('not a security score', text)
        self.assertIn('not a behavioral equivalence proof', text)
        self.assertIn('no source-transform eligibility', text)
        self.assertNotIn('Previous Ghidra-enabled tests passed', text)
        if not (DOCS / 'evidence/verification.json').is_file():
            self.assertIn('final suite outcome pending', text)
            self.assertIn('final test count pending', text)
            self.assertNotIn('114 tests', text)  # historical run predates document tests

    def test_report_qualifies_claims_and_gate_with_specific_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'report.docx'
            subprocess.run([docx_python(), str(DOCS / 'build_report.py'), str(output)],
                           cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
            text = document_text(output)
        for item in ('Observed claim', 'Evidence boundary', 'Release disposition',
                     'No GitHub publication', 'Windows manual test pending'):
            self.assertIn(item, text)

    def test_builders_accept_static_contents_page_maps(self):
        cases = [('build_report.py', ['1. Executive summary', '5. Claims, gaps and next gate']),
                 ('build_plan.py', ['1. Decision and scope', '4. Review and hand-off'])]
        with tempfile.TemporaryDirectory() as tmp:
            for script, titles in cases:
                with self.subTest(script=script):
                    output = Path(tmp) / f'{script}.docx'
                    page_map = Path(tmp) / f'{script}.json'
                    page_map.write_text(json.dumps({titles[0]: '03', titles[1]: '05'}), encoding='utf-8')
                    subprocess.run([docx_python(), str(DOCS / script), str(output), str(page_map)],
                                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
                    text = document_text(output)
                    self.assertIn(titles[0] + ' 03', text)
                    self.assertIn(titles[1] + ' 05', text)

    def test_local_drafts_do_not_call_themselves_submission_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            for script in ('build_report.py', 'build_plan.py'):
                with self.subTest(script=script):
                    output = Path(tmp) / f'{script}.docx'
                    subprocess.run([docx_python(), str(DOCS / script), str(output)],
                                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
                    self.assertIn('local draft', footer_text(output))
                    self.assertNotIn('submission copy', footer_text(output))

    def test_covers_separate_host_targets_from_optional_qemu_drivers(self):
        expected = ('Analyzed targets are never executed on the host; optional QEMU runs only '
                    'separate self-authored deterministic drivers.')
        with tempfile.TemporaryDirectory() as tmp:
            for script in ('build_report.py', 'build_plan.py'):
                with self.subTest(script=script):
                    output = Path(tmp) / f'{script}.docx'
                    subprocess.run([docx_python(), str(DOCS / script), str(output)],
                                   cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
                    text = document_text(output)
                    self.assertIn(expected, text)
                    self.assertNotIn('protected samples are compiled but never executed', text)

    def test_plan_requires_owner_and_windows_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'plan.docx'
            subprocess.run([docx_python(), str(DOCS / 'build_plan.py'), str(output)],
                           cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
            text = document_text(output)
            for item in ('Day 4 readiness plan', 'D4-12', 'Windows manual test pending',
                         'Owner approval required', 'No event sign-in or upload'):
                self.assertIn(item, text)
            self.assertNotIn('54 tests', text)
            self.assertNotIn('0x9E3779B9', text)

    def test_plan_separates_ready_evidence_from_release_gates(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'plan.docx'
            subprocess.run([docx_python(), str(DOCS / 'build_plan.py'), str(output)],
                           cwd=ROOT, check=True, capture_output=True, text=True, timeout=60)
            text = document_text(output)
        for item in ('five original samples', 'sixth', 'level-5-hardened',
                     'Linux-only', 'QEMU', 'owner review', 'checksums',
                     'No GitHub publication', 'static-only', 'analysis-only',
                     'Owner decision (G6)', 'G1', 'G5',
                     'D4-12: native Windows OLLVM/QEMU unavailable'):
            self.assertIn(item, text)
        for stale in ('3-Day Execution Plan', '10 November 2026',
                      'release published', 'event submitted'):
            self.assertNotIn(stale, text)


if __name__ == '__main__':
    unittest.main()
