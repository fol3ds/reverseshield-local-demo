#!/usr/bin/env python3
"""Build the local Day 4 readiness plan; this script never runs a target.

Use a supplied page map for the final PDF-bound static contents table:
    /usr/bin/python3 docs/build_plan.py OUTPUT.docx /path/to/pages.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from docx_helpers import (AMBER, CYAN, add_callout, add_cover, add_static_toc,
                          add_table, bullets, h1, h2, para, setup_document)

HERE = Path(__file__).resolve().parent
OUT = HERE / 'ReverseShield_Day4_Readiness_Plan.docx'
TOC = ('1. Decision and scope', '2. Evidence already in hand',
       '3. Remaining readiness gates', '4. Review and hand-off')


def build(output: Path = OUT, toc_pages: dict[str, str] | None = None) -> Path:
    verification_path = HERE / 'evidence' / 'verification.json'
    verification = (json.loads(verification_path.read_text(encoding='utf-8'))
                    if verification_path.is_file() else {})
    tests = verification.get('tests', {})
    suite_line = (f"Recorded Ghidra-enabled run: {tests['count']} tests, {tests['skipped']} skipped, "
                  f"outcome {tests['status']}."
                  if isinstance(tests.get('count'), int) else
                  'Final suite outcome and count pending a recorded run.')
    doc = setup_document('ReverseShield · Day 4 readiness plan', 'Local draft · 11 Nov 2026')
    next(run for run in doc.sections[0].footer.paragraphs[0].runs
         if 'submission copy' in run.text).text = 'ReverseShield · local draft'
    add_cover(doc, 'Day 4 readiness plan',
              'Evidence-led release gates and owner decision points',
              'ReverseShield · local candidate · 11 November 2026',
              [('Status', 'Draft for owner review; no publication or submission'),
               ('Environment', 'Fedora 43 local verification; Windows manual test pending'),
               ('Decision', 'Hold release and external submission pending the gates below'),
               ('Related', 'Day 4 technical report: measured scope and limitations')])
    add_static_toc(doc, [(title, str((toc_pages or {}).get(title, '—'))) for title in TOC])

    h1(doc, '1. Decision and scope')
    para(doc, 'This is a readiness plan, not a record of a finished launch. The workbench '
         'inspects authorized ELF/PE inputs using static tools and does not launch analyzed '
         'targets. It is not a malware sandbox or a security certification. Source transforms '
         'apply only to the five original samples. The separately selectable sixth fixture, '
         'level-5-hardened, is an analysis-only Linux ELF for mitigation-property comparison; '
         'it is not eligible for source transforms. Copy-only binary metadata hygiene is a '
         'different feature and does not protect code.')
    add_callout(doc, 'Hold point',
                'No GitHub publication, release, push, event sign-in or upload before owner '
                'review and explicit approval. No event sign-in or upload is authorized by '
                'this document. Windows manual test pending.', fill='FFFBEB', accent=AMBER)

    h1(doc, '2. Evidence already in hand')
    add_table(doc, ['Observation', 'Evidence and scope', 'What it does not prove'], [
        ['Hardening fixture', 'docs/evidence/hardening-level5.json: original Level 5 versus '
         'level-5-hardened ELF. NX present in both; PIE, full RELRO, canary and FORTIFY '
         'indications in the hardened build.',
         'Static properties are not a vulnerability verdict, behavior test or security score.'],
        ['OLLVM vectors', 'docs/evidence/ollvm-five-qemu.json: separate deterministic driver builds '
         'matched for five original samples in no-disk/no-network QEMU.',
         'Not full equivalence, the downloadable protected ELF, broad tamper resistance or a test of the sixth fixture.'],
        ['Fedora UI', 'Local static analysis and Compare-view flow were exercised on Fedora.',
         'Not a clean native Windows GUI/PE/Ghidra smoke test.'],
    ], widths=[32, 83, 57], font_size=8.1)
    para(doc, 'OLLVM is Linux-only and optional; the QEMU harness runs only self-authored '
         'sample drivers in a guest. The workbench never runs an arbitrary analyzed target. '
         'These evidence files are sanitized measurements, not raw run logs.')

    para(doc, 'D4-12: native Windows OLLVM/QEMU unavailable. This limitation is '
         'explicit in the UI and backend and must not be mistaken for a passed '
         'native-Windows manual acceptance test. The Windows static workbench '
         'requires the separate clean-machine gate G5.')

    h1(doc, '3. Remaining readiness gates')
    para(doc, 'The following are acceptance checks, not completed outcomes. Record the '
         'result and evidence for each after the final source freeze; a failing check '
         'blocks external claims based on it.')
    add_table(doc, ['Gate', 'Owner action', 'Pass evidence'], [
        ['G1', 'Freeze source and run the complete opt-in Ghidra test suite.',
         suite_line + ' Re-run after any further change.'],
        ['G2', 'Rebuild both Day 4 DOCX/PDF documents after evidence capture; '
         'check each claim, hashes and rendered pages.',
         'No stale counts, private paths, demonstration keys, unresolved contents '
         'or planned-as-completed phrasing.'],
        ['G3', 'Inspect proposed package contents and privacy boundaries.',
         'No raw runs, credentials, personal paths or internal tool payload in the '
         'Lite bundle. Archive shape and exclusions checked locally.'],
        ['G4', 'Build the final local package and verify checksums from the frozen sources.',
         'A fresh extraction reproduces the artifact manifest; checksum verification '
         'passes. No upload or publication.'],
        ['G5', 'Run a clean native Windows setup.bat/run.bat and GUI smoke test.',
         'Real PE/static analysis, Ghidra availability or explicit unavailable state, '
         'Compare and sanitized export observed. Windows manual test pending.'],
    ], widths=[18, 78, 76], font_size=8.0)
    h2(doc, 'Owner decision (G6)')
    add_callout(doc, 'Final go / no-go',
                'Owner reviews the final test, privacy, Windows and package evidence. '
                'Written approval must identify precisely what may be published or '
                'submitted; otherwise remain local-only.', fill='FFFBEB', accent=AMBER)
    h2(doc, 'Failure and scope discipline')
    bullets(doc, [
        'If a gate fails, retain the draft locally, describe the limitation and rerun after a fix.',
        'Use N/A for unmeasured metrics, not zero; counts of generated labels and strings are not protection scores.',
        'Keep external targets static-only; never execute third-party files or use the sample QEMU path on arbitrary inputs.',
        'A Windows CI or unit/API pass does not replace a clean native manual test.',
    ])

    h1(doc, '4. Review and hand-off')
    add_table(doc, ['Artifact', 'Reviewer check'], [
        ['Technical report', 'Cross-check hardening hashes and QEMU sample rows against '
         'the two measured evidence JSON files. Suite counts come from verification.json.'],
        ['Readiness plan', 'Confirm gates G1–G6 remain open until evidence and '
         'owner decisions are recorded; do not label release or submission complete.'],
        ['Local release candidate', 'Recompute package checksums only after final source '
         'freeze; inspect contents and verify fresh-extract instructions.'],
    ], widths=[44, 128], font_size=8.3)
    para(doc, 'Owner approval required for any later push, pull request, release, event '
         'sign-in, upload or submission. This silent captioned draft is a local review '
         'artifact; it authorizes no external action.')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output)
    return output


if __name__ == '__main__':
    pages = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')) if len(sys.argv) > 2 else None
    print(build(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT, pages))
