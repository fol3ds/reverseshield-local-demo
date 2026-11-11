#!/usr/bin/env python3
"""Build the current Day 4 technical report from sanitized measured evidence.

The pre-Day-4 long report is historical; this replaces its stale planned claims.
No target is launched, and no raw job report or host path is embedded.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
from docx_helpers import (CYAN, add_callout, add_cover, add_static_toc,
                          add_table, bullets, h1, h2, para, setup_document)

OUT = HERE / 'ReverseShield_Day4_Technical_Report.docx'


def evidence(name: str) -> dict:
    return json.loads((HERE / 'evidence' / name).read_text(encoding='utf-8'))


TOC = ('1. Executive summary', '2. System and trust boundary',
       '3. Reproducible results', '4. Cross-platform status',
       '5. Claims, gaps and next gate')


def build(output: Path = OUT, toc_pages: dict[str, str] | None = None) -> Path:
    hard = evidence('hardening-level5.json')
    qemu = evidence('ollvm-five-qemu.json')
    verification_path = HERE / 'evidence' / 'verification.json'
    verification = json.loads(verification_path.read_text(encoding='utf-8')) if verification_path.is_file() else {}
    doc = setup_document('ReverseShield · Day 4 technical report', 'v0.5.0-team · 11 Nov 2026')
    next(run for run in doc.sections[0].footer.paragraphs[0].runs
         if 'submission copy' in run.text).text = 'ReverseShield · local draft'
    add_cover(doc, 'Day 4 technical report',
              'Local, static reverse-engineering exposure workbench',
              'ReverseShield · local candidate · 11 November 2026',
              [('Status', 'Draft for owner review; not published or submitted'),
               ('Version', '0.5.0-team (local feature branch)'),
               ('Host verified', 'Fedora Workstation 43, x86-64'),
               ('Windows', 'Windows manual test pending'),
               ('Scope', 'Authorized static ELF/PE inspection; samples only for source transforms')])
    add_static_toc(doc, [(title, str((toc_pages or {}).get(title, '—'))) for title in TOC])
    h1(doc, '1. Executive summary')
    para(doc, 'ReverseShield discovers selected ELF/PE files, snapshots them, runs bounded static tools, '
         'and presents coverage, tool output, decompiled code where available, and qualified before/after '
         'measurements. It does not launch an analyzed target. The optional OLLVM path builds copies of five '
         'self-authored sample sources and checks deterministic drivers only inside a no-disk/no-network QEMU guest.')
    tests = verification.get('tests', {})
    summary = (f"{tests.get('run', 'Ghidra-enabled tests')}: {tests['count']} tests, "
               f"{tests.get('skipped', 'skip count not recorded')} skipped; "
               f"recorded outcome: {tests.get('status', 'not recorded')}."
               if isinstance(tests.get('count'), int) else
               'Ghidra-enabled tests: final test count pending evidence capture; '
               'final suite outcome pending.')
    add_callout(doc, 'Measured, not certified', summary +
                ' Static mitigation presence and changed artifact counts are not a security score. '
                'The QEMU checks cover only listed deterministic sample vectors.',
                fill='ECFEFF', accent=CYAN)
    h1(doc, '2. System and trust boundary')
    add_table(doc, ['Area', 'Implementation / scope', 'Boundary'], [
        ['Inputs', 'Bundled samples, local files/folders, PE and ELF uploads; Linux Flatpak/RPM discovery',
         'Only benign or authorized material; no third-party transformation'],
        ['Static tools', 'Bounded binutils adapters and optional project-local Ghidra headless',
         'Untrusted parsers are not a malware sandbox'],
        ['Copy operations', 'Sample-only source transforms; copy-only ELF/PE metadata hygiene',
         'Originals unchanged; metadata removal is not code protection'],
        ['Isolation', 'Optional QEMU guest for five separate deterministic driver builds, no disk/network',
         'Never run samples or other targets on the host'],
        ['Reporting', 'Raw reports private in runs/; sanitized exports for sharing',
         'Inspect every proposed external artifact before release'],
    ], widths=[28, 88, 56], font_size=8.2)
    h2(doc, 'What the sixth sample means')
    para(doc, 'The separately selectable level-5-hardened ELF reuses the original Level 5 policy code '
         'but is built with PIE, full RELRO, stack protection and FORTIFY flags. It is a static property '
         'comparison, not a same-bytes before/after transform. It is not a behavioral equivalence proof. '
         'It has no source-transform eligibility; copy-only binary hygiene remains a separate feature.')
    h1(doc, '3. Reproducible results')
    h2(doc, '3.1 Level 5 mitigation-property comparison')
    original, hardened = hard['samples']
    add_table(doc, ['ELF property', 'Original Level 5', 'Hardened Level 5', 'Byte-level indication'], [
        [original['hardening']['checks'][key]['label'],
         original['hardening']['checks'][key]['state'].title(),
         hardened['hardening']['checks'][key]['state'].title(),
         hardened['hardening']['checks'][key]['evidence']]
        for key in ('nx', 'pie', 'relro', 'canary', 'fortify')
    ], widths=[34, 35, 35, 68], font_size=8.2)
    add_table(doc, ['Artifact', 'Bytes', 'SHA-256'], [
        [s['sample_id'] + '.elf', str(s['bytes']), s['sha256']] for s in hard['samples']
    ], widths=[42, 20, 110], font_size=7.9)
    para(doc, 'These checks inspect ELF headers, dynamic tags and symbol evidence. Canary and FORTIFY '
         'imports indicate presence, not complete coverage of all functions. NX was already present in '
         'the original. The new binary was compiled, never executed, and has mode 0600.')
    h2(doc, '3.2 Five original sample QEMU checks')
    add_table(doc, ['Sample', 'Transcript match', 'Original / protected exit', 'Transcript SHA-256'], [
        [r['sample_id'], 'Yes' if r['matched'] else 'No',
         f"{r['exit_codes'].get('original', 'N/A')} / {r['exit_codes'].get('protected', 'N/A')}",
         r['output_sha256']] for r in qemu['samples']
    ], widths=[24, 30, 39, 79], font_size=7.7)
    para(doc, 'All five original samples matched on their deterministic driver builds in the isolated '
         'QEMU guest. These drivers are separate builds, not the downloadable protected.elf; that '
         'artifact was not executed and its behavior is not verified. These vectors do not establish '
         'general behavioral equivalence, resistance to analysis, or coverage of the sixth hardening '
         'fixture. Raw guest transcripts and tool paths remain local.')
    h2(doc, '3.3 Compare semantics and live workbench')
    para(doc, 'A local Fedora browser session discovered and analyzed level-5-hardened, and a Level 5 '
         'symbol-removal comparison reached Done. The Compare view displayed qualified names for '
         'tool-reported labels, identified functions, reported strings and mapped call relationships. '
         'N/A means not measured, never zero. Generated code and Ghidra labels can increase counts; '
         'neither direction proves stronger or weaker protection.')
    h1(doc, '4. Cross-platform status')
    add_table(doc, ['Platform', 'Verified', 'Not established'], [
        ['Fedora 43', 'Ghidra-enabled suite, sample analyze, Compare UI, five QEMU drivers',
         'No hostile-input sandbox guarantee'],
        ['Windows (native)', 'PE support and launch scripts have tests; CI may exercise unit/API paths',
         'Windows manual test pending: clean setup.bat/run.bat, GUI, real Ghidra/PE and export'],
        ['OLLVM / QEMU', 'Linux-local on five self-authored samples',
         'Unavailable on native Windows; not included in lite ZIP tool payload'],
    ], widths=[30, 65, 77], font_size=8.2)
    h1(doc, '5. Claims, gaps and next gate', page_break=True)
    add_table(doc, ['Observed claim', 'Evidence boundary', 'Release disposition'], [
        ['Mitigation-property difference',
         'ELF headers, dynamic tags and parsed symbol imports in the two measured fixtures.',
         'Static-only; not a security score, vulnerability verdict or exploitability test.'],
        ['Five QEMU transcript matches',
         'Separate deterministic driver builds in a no-disk/no-network guest; not the downloadable protected ELF.',
         'Not behavioral equivalence of all inputs or proof for level-5-hardened.'],
        ['Fedora UI path',
         'One local hardened-sample analysis and Level 5 symbol-removal comparison.',
         'Windows manual test pending. Do not imply native Windows acceptance.'],
        ['Tool and document verification',
         'Recorded Ghidra-enabled suite counts and outcome in docs/evidence/verification.json for this working tree.',
         'Re-run after any further code or document change; not a clean-Windows result.'],
    ], widths=[38, 71, 63], font_size=8.2)
    bullets(doc, [
        'No mitigation state is a vulnerability verdict or security certification.',
        'Ghidra may still reconstruct logic after names or metadata are removed.',
        'Only a clean native Windows session can close the Windows manual acceptance gate.',
        'Local package/checksum must be verified after the final source freeze.',
        'Owner approval required before push, pull request, release, event sign-in, upload or submission.',
    ])
    add_callout(doc, 'External release remains blocked',
                'No GitHub publication or event action in this draft. Verify a clean Windows '
                'manual run, package contents and checksums, document rendering and a final '
                'test suite after the source freeze; then request explicit owner approval.',
                fill='FFFBEB', accent='B45309')
    para(doc, 'Measured inputs: docs/evidence/hardening-level5.json and '
         'docs/evidence/ollvm-five-qemu.json. A final suite count is reported only when '
         'docs/evidence/verification.json contains one. Rebuild after final verification.')
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    doc.save(output)
    return output


if __name__ == '__main__':
    pages = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')) if len(sys.argv) > 2 else None
    print(build(Path(sys.argv[1]) if len(sys.argv) > 1 else OUT, pages))
