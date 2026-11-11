#!/usr/bin/env python3
"""Build the full IS CyberNext project report (Word + PDF), DRAFT.

The report is generated from recorded evidence, not from hand-copied numbers:
test counts, hardening results, QEMU rows, security scans, package hashes and
sample hashes are read at build time. It never executes a sample or target.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

from docx_helpers import (  # noqa: E402
    AMBER, CYAN, GREEN, LINE, MUTED, NAVY, RED,
    add_callout, add_caption, add_code, add_cover, add_image, add_static_toc,
    add_table, bullets, h1, h2, para, setup_document, spacer,
)

OUT = HERE / 'ReverseShield_Full_Project_Report_DRAFT_v0.5.0.docx'

TOC = (
    '1. Executive Summary',
    '2. Problem, Users and Scope',
    '3. Threat Model and Safety Boundary',
    '4. Solution Overview',
    '5. Architecture',
    '6. Analysis Engine and Evidence Model',
    '7. Protection Profiles and Transformations',
    '8. Behaviour Verification in QEMU',
    '9. Interface and Operator Experience',
    '10. Security Engineering of the Workbench',
    '11. Evaluation and Measured Evidence',
    '12. Related Work and Differentiation',
    '13. Limitations and Non-Claims',
    '14. Roadmap and Release Gates',
    '15. Team, Workflow and Handover',
    '16. Conclusion',
    'Appendix A. Test Inventory',
    'Appendix B. Evidence Register',
    'Appendix C. Reproduction Commands',
    'Appendix D. Security Scan Details',
    'Appendix E. Acceptance Matrix Summary',
    'Appendix F. Glossary',
)


def load(name: str) -> dict:
    return json.loads((HERE / 'evidence' / name).read_text(encoding='utf-8'))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def test_counts() -> list[tuple[str, int]]:
    import unittest
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py')
    counts: Counter[str] = Counter()

    def walk(item):
        for test in item:
            if isinstance(test, unittest.TestSuite):
                walk(test)
            else:
                counts[test.__class__.__module__] += 1

    walk(suite)
    return sorted(counts.items())


def meta_table(doc, rows):
    add_table(doc, ['Item', 'Value'], rows, widths=[45, 127], font_size=9.2)


def build(out: Path = OUT, toc_pages: dict[str, str] | None = None) -> Path:
    hard = load('hardening-level5.json')
    qemu = load('ollvm-five-qemu.json')
    verification = load('verification.json')
    security = load('security-day4.json')
    tests = verification['tests']
    bandit = security['bandit']
    lite = ROOT / 'dist' / 'ReverseShield_Lite_Windows_v0.5.0-team.zip'
    evidence_zip = ROOT / 'dist' / 'ReverseShield_Evidence_v0.5.0-team.zip'
    checks = {row['sample_id']: {k: v['state'] for k, v in row['hardening']['checks'].items()}
              for row in hard['samples']}
    samples = {row['sample_id']: row for row in hard['samples']}

    doc = setup_document('ReverseShield — Full Project Report', header_right='DRAFT · v0.5.0-team')
    props = doc.core_properties
    props.author = 'ReverseShield Team'
    props.last_modified_by = 'ReverseShield Team'
    props.title = 'ReverseShield — Full Project Report (DRAFT)'
    props.subject = 'Reverse-engineering exposure workbench'
    props.keywords = 'ReverseShield, static analysis, ELF, PE, OLLVM, QEMU, evidence'
    props.comments = 'DRAFT — owner review; not for submission'
    props.category = 'IS CyberNext 2026'
    # The shared footer says "submission copy"; this document is explicitly a draft.
    footer = doc.sections[0].footer
    for run in footer.paragraphs[0].runs:
        if 'submission copy' in run.text:
            run.text = 'DRAFT — owner review · not for submission'

    add_cover(
        doc,
        'ReverseShield',
        'Reverse-engineering exposure workbench — complete project report',
        'IS CyberNext 2026 · Cybersecurity track',
        [
            ('Version', '0.5.0-team'),
            ('Date', '11 November 2026'),
            ('Status', 'DRAFT — owner review; not submitted'),
            ('Prepared by', 'Naser · Zayed · Nomai · Faisal'),
            ('Scope', 'Local static-analysis workbench for Linux ELF and Windows PE'),
            ('Evidence basis', 'Recorded Day 4 runs, 11 November 2026'),
        ],
        note_title='How to read this report',
        note_text=(
            'This report explains the prototype and separates measured evidence from claims. '
            'Numbers name their source and scope. The project never executes a target, installed '
            'application or bundled sample on the host; the only guest execution is a separate '
            'deterministic sample-driver check in QEMU.'
        ),
    )

    h1(doc, 'Document Control')
    para(doc, 'This document is the complete technical explanation of the ReverseShield prototype as it '
              'exists in the local Day 4 workspace. It is written for the IS CyberNext evaluation: a '
              'technical judge should be able to understand the problem, the design, the measured '
              'evidence, and the limits without reading the source first.')
    meta_table(doc, [
        ('Document', 'Full project report (DRAFT)'),
        ('Audience', 'IS CyberNext judges, technical reviewers, team handover'),
        ('Language', 'English; Arabic explanation available verbally'),
        ('Software version', '0.5.0-team, branch feature/ollvm-protection'),
        ('Primary platform', 'Fedora Workstation 43, Python 3.14, loopback UI'),
        ('Secondary platform', 'Windows 10/11 workbench subset; manual acceptance pending'),
        ('What this is', 'A static-analysis and evidence workbench, demonstrated on self-authored samples'),
        ('What this is not', 'A production protector, antivirus, CVE scanner, or dynamic malware sandbox'),
    ])
    add_callout(doc, 'Status of this document',
                'Both this report and the accompanying slide deck are marked DRAFT. They are generated '
                'locally for owner review and are not the submission copy. GitHub publication, release '
                'tagging and IS CyberNext registration remain separate owner decisions.', AMBER)
    h2(doc, 'How to read the evidence')
    para(doc, 'Numbers in this report are either (a) produced by the project test suite, (b) recorded in '
              '`docs/evidence/*.json` with timestamps and hashes, or (c) measured by a live workbench run '
              'on 11 November 2026. Where a number is a count of tool output rather than a security '
              'property, the report says so. `N/A` means unmeasured, never zero.')
    add_static_toc(doc, [(title, (toc_pages or {}).get(title, '—')) for title in TOC])

    # 1
    h1(doc, TOC[0], page_break=False)
    para(doc, 'ReverseShield is a local, browser-based workbench that shows what a compiled program '
              'reveals to a reverse engineer, then lets an operator change a **copy** and measure what '
              'the change actually removed. It analyzes Linux ELF and Windows PE files with established '
              'static tools, presents the result in plain language, and compares before/after reports '
              'using qualified metrics rather than a single score.')
    para(doc, 'The project exists because two questions are surprisingly hard to answer together: '
              '“What does our build expose?” and “Did the change we made actually reduce that exposure?” '
              'Commercial protectors usually answer with a claim. Vulnerability scanners answer a '
              'different question. Manual reverse engineering can answer both, but it is expert-only and '
              'hard to reproduce. ReverseShield turns that work into a repeatable local workflow with '
              'visible evidence and explicit limits.')
    h2(doc, 'What was built')
    bullets(doc, [
        'A Python standard-library server and a dark, terminal-inspired web interface served on loopback only.',
        'Static analysis adapters for `readelf`, `objdump`, `strings`, `nm` and optional project-local Ghidra headless.',
        'Discovery for uploaded files, folders, Flatpak applications and RPM payloads, plus six bundled self-authored samples.',
        'Four clearly bounded transformation profiles: symbol removal, demo constant blinding, binary metadata hygiene, and OLLVM source obfuscation for the five original samples.',
        'Exploit-mitigation checks for ELF and PE, reported as observed properties rather than a score.',
        'A QEMU micro-VM harness that checks separate deterministic driver builds without disk or network.',
        'A Day 4 evidence chain: acceptance matrix, claim map, security review, measured hardening results, package checksums and a silent demo.',
    ])
    h2(doc, 'Measured results at a glance')
    add_table(doc, ['Result', 'Value', 'Where it is recorded'], [
        ('Automated tests', f"{tests['count']} tests, {tests['skipped']} skipped, passed", 'docs/evidence/verification.json'),
        ('Test suite with Ghidra enabled', 'Run on Fedora, 0 failures, 0 errors', 'verification.json (RUN_GHIDRA_TESTS=1)'),
        ('Extracted Lite ZIP', '167 tests, 7 skipped, passed', 'package extraction check, Day 4'),
        ('Deterministic QEMU vectors', f"{len(qemu['samples'])} of {len(qemu['samples'])} matched", 'docs/evidence/ollvm-five-qemu.json'),
        ('Hardened fixture', 'NX, PIE, full RELRO, canary and FORTIFY present', 'docs/evidence/hardening-level5.json'),
        ('Bandit', f"{bandit['severity_counts'].get('HIGH', 0)} high · {bandit['severity_counts'].get('MEDIUM', 0)} medium · {bandit['severity_counts'].get('LOW', 0)} low", 'docs/evidence/security-day4.json'),
        ('Lite package', f'{lite.stat().st_size:,} bytes' if lite.is_file() else 'not built in this tree', 'dist/'),
    ], widths=[52, 60, 60], font_size=8.8)
    h2(doc, 'What the project does not claim')
    para(doc, 'ReverseShield does not claim that any binary is secure, unhackable or free of '
              'vulnerabilities. It does not detect CVEs, score exploitability or prove behavioural '
              'equivalence. Its OLLVM profile applies only to the five original self-authored sample '
              'sources; arbitrary third-party binaries are analysis-only. Native Windows manual '
              'acceptance has not been performed. These boundaries are repeated in the report because '
              'they are part of the engineering, not a disclaimer added at the end.')
    add_callout(doc, 'One-sentence summary',
                'ReverseShield is an evidence-first static workbench: it makes binary exposure visible, '
                'measures the effect of a bounded change, and states clearly what the evidence cannot prove.', GREEN)

    # 2
    h1(doc, TOC[1])
    para(doc, 'A compiled program is not opaque. Even without source code, a binary carries names, '
              'paths, messages, library imports, function boundaries and sometimes full debug '
              'information. A reverse engineer uses those artefacts to reconstruct behaviour. The same '
              'artefacts are often invisible to the team that shipped the build, because release '
              'engineering, security review and product development look at different outputs.')
    h2(doc, 'The practical problem')
    para(doc, 'Consider a small policy engine. The original Level 5 sample used in this project ships '
              'with 35 ELF symbol-table entries, debug information, compiler notes, source-folder names '
              'and six plaintext policy messages. `strings` alone reveals the message text; `readelf` '
              'shows the symbol table and debug sections; Ghidra recovers the policy function and its '
              'decision logic. None of this is a software vulnerability in the CVE sense, but all of it '
              'lowers the cost of understanding the program.')
    para(doc, 'Teams usually respond in one of three ways. They buy a protector and trust a claim; they '
              'run a vulnerability scanner and receive a different kind of answer; or they ask an expert '
              'to look at the binary once. None of these produces a repeatable before/after record that a '
              'non-specialist can inspect. ReverseShield is aimed at that gap.')
    h2(doc, 'Who the workbench is for')
    bullets(doc, [
        'Student and small product teams that need to see their own build without hiring a reverse-engineering specialist.',
        'Maintainers who want a defensible record of what changed after a stripping or obfuscation step.',
        'Security reviewers who need a local, auditable workflow that does not upload proprietary binaries.',
        'Judges and reviewers who want claims tied to artefacts rather than adjectives.',
    ])
    h2(doc, 'Scope of this version')
    para(doc, 'The current release is deliberately narrow. It supports ELF and PE static analysis, a '
              'set of local transformations on copies, and a bounded QEMU check for self-authored sample '
              'drivers. It does not support live process analysis, kernel modules, firmware, managed '
              'code, mobile packages, or automatic exploitation. Source transformations are restricted '
              'to the bundled sample corpus. The sixth sample, `level-5-hardened`, is selectable for '
              'analysis but excluded from source transformation because it exists to demonstrate '
              'mitigation properties, not to be rebuilt.')
    add_table(doc, ['In scope', 'Out of scope'], [
        ('ELF and PE static inspection', 'Executing external targets on the host'),
        ('Symbols, strings, sections, imports, functions, call graph', 'CVE/CWE detection or exploit generation'),
        ('Copy-only stripping, constant blinding, metadata hygiene', 'Protecting arbitrary third-party binaries'),
        ('OLLVM source passes for five self-authored samples', 'Full behavioural equivalence or fuzzing'),
        ('Hardening property observations', 'A security score or certificate'),
        ('Separate deterministic driver checks in QEMU', 'Dynamic analysis of installed applications'),
    ], widths=[86, 86], font_size=8.8)

    # 3
    h1(doc, TOC[2])
    para(doc, 'The safety model is the most important design decision in the project. ReverseShield '
              'analyzes untrusted bytes with static parsers, never loads a target into the host process, '
              'and never executes a target, an installed application or a downloaded sample. The only '
              'execution path is a separate QEMU guest running deterministic drivers compiled from the '
              'project’s own sample sources.')
    h2(doc, 'Assets and adversary')
    para(doc, 'The asset under study is the information content of a build: names, debug paths, strings, '
              'imports, structure and readable logic. The modelled adversary is a reverse engineer with '
              'the binary and commonly available tools. The project does not model a remote attacker, a '
              'memory-corruption exploit, a supply-chain compromise or a privileged local attacker. Those '
              'are different problems and would need different evidence.')
    add_table(doc, ['Boundary', 'Rule enforced in this version'], [
        ('Host execution', 'No target, installed app, EasyEffects process or sample is executed on the host.'),
        ('Modification', 'Original files are copied into a job directory; transformations write new files.'),
        ('Third-party input', 'Installed applications and RPM payloads are discovered and read, not run or modified.'),
        ('Source transforms', 'Only the five original self-authored sample sources; the sixth hardened fixture is analysis-only.'),
        ('Guest execution', 'Separate deterministic drivers, no disk, no network, serial output only.'),
        ('Network', 'The server binds 127.0.0.1; no upload to a cloud service and no remote analysis API.'),
        ('Authorization', 'Jobs require an explicit confirmation that the input is benign and the operator is authorized.'),
        ('Publication', 'Private paths, raw reports, keys and credentials are excluded from packages and evidence.'),
    ], widths=[45, 127], font_size=8.8)
    h2(doc, 'Why this is not a sandbox')
    para(doc, 'A static parser still processes hostile input. The project uses bounded subprocess calls, '
              'timeouts, output caps, argv-only invocation and no shell interpolation, but it does not '
              'claim process isolation for `readelf`, Ghidra or the Python parsers. A production system '
              'would add containerisation, seccomp and resource limits. For the event prototype, the '
              'honest statement is: static parsing of untrusted bytes, with bounded commands, inside a '
              'single-user loopback service.')
    add_callout(doc, 'Authorization is not a technical control',
                'The confirmation checkbox records operator intent; it does not prove ownership. The '
                'project is intended for benign, authorized analysis only. This limitation is stated in '
                'the interface and in the acceptance matrix.', AMBER)

    # 4
    h1(doc, TOC[3])
    para(doc, 'The workflow is a five-step loop: select an input, analyze it, transform a copy, '
              'reanalyze the copy with the same tools, and compare the two reports. The loop is visible '
              'in the interface and reproducible from the job record. Nothing is hidden behind a single '
              '“protect” button, because the interesting question is not whether a button ran but what '
              'changed.')
    add_code(doc,
             'Select input  ->  Analyze original  ->  Transform a copy\n'
             '      ^                                        |\n'
             '      |                                        v\n'
             '   Evidence  <-  Compare qualified metrics  <-  Reanalyze copy')
    h2(doc, 'Two report layers')
    para(doc, 'The first layer is **exposure evidence**: what the selected tools recovered from the file. '
              'It includes names, debug information, strings grouped by kind, imports/exports, sections, '
              'functions, decompiled functions, call relationships and graph data. The second layer is '
              '**mitigation posture**: observed hardening properties such as NX, PIE, RELRO, stack canary '
              'and FORTIFY on ELF, and ASLR/DEP/CFG/cookie flags on PE. The interface keeps these layers '
              'visually separate so a mitigation flag is never mistaken for a vulnerability verdict.')
    h2(doc, 'Qualified comparison')
    para(doc, 'Every comparison metric names the tool that produced it, because a count without a source '
              'is easy to misread. For example, “names reported by selected tools” includes Ghidra labels, '
              'while “ELF/PE symbol-table entries” is a direct table count. Removing the symbol table can '
              'reduce the second to zero while Ghidra still recovers the function and generates new labels, '
              'so aggregate counts may rise. The report explains this instead of presenting a single '
              'percentage improvement.')
    add_table(doc, ['Principle', 'Implementation'], [
        ('Original untouched', 'Each job copies the selected target into its own directory.'),
        ('Same tools on both sides', 'The copy is reanalyzed with the same selected tools and options.'),
        ('Measured, not modelled', 'Metrics are computed from tool output and the actual bytes.'),
        ('N/A is not zero', 'Unmeasured fields display N/A with an explanation.'),
        ('Hashes anchor evidence', 'Original, copy, driver and transcript hashes are recorded.'),
        ('Limits stay visible', 'The report repeats scope and non-claims next to the numbers.'),
    ], widths=[55, 117], font_size=9)

    # 5
    h1(doc, TOC[4])
    para(doc, 'The system is intentionally small: one Python process, one loopback HTTP server, a static '
              'front end, a job engine, tool adapters and a per-job evidence directory. There is no '
              'database, no message broker, no cloud dependency and no external service. That keeps the '
              'trust boundary inspectable and the package runnable on a laptop.')
    add_code(doc,
             'Browser (static HTML/CSS/JS)\n'
             '   |  token-protected loopback HTTP\n'
             '   v\n'
             'Python server (app.py)\n'
             '   |-- discovery / sample catalog\n'
             '   |-- workflow job engine  -> runs/<job>/ events + report.json\n'
             '   |-- analysis adapters    -> readelf, objdump, strings, nm, Ghidra\n'
             '   |-- protection adapters  -> strip, constant blinding, hygiene, OLLVM\n'
             '   `-- behaviour adapter    -> QEMU micro-VM (sample drivers only)')
    add_table(doc, ['Component', 'Responsibility'], [
        ('app.py / HTTP layer', 'Serves the UI, enforces loopback binding, token, origin and CSP checks, exposes the JSON API.'),
        ('workflow.py', 'Creates jobs, validates operation/profile pairs, runs the worker, emits events, stores the result.'),
        ('analysis.py / engine.py', 'Invokes static tools with bounded argv commands and normalises their output.'),
        ('metrics.py', 'Computes counts, entropy, symbol/string categories and comparison deltas.'),
        ('hardening.py', 'Reads ELF/PE headers and imports to report mitigation properties.'),
        ('demo_protection.py / binary_protection.py / ollvm_protection.py', 'Builds transformed copies and records hashes and scope.'),
        ('behavior_qemu.py', 'Builds a minimal initramfs, boots QEMU without disk/network, compares deterministic drivers.'),
        ('sanitize_report.py', 'Produces a report copy with private paths and sensitive fields removed.'),
    ], widths=[55, 117], font_size=8.6)
    h2(doc, 'Job lifecycle')
    para(doc, 'A job is created only after target selection and authorization. It receives a private '
              'directory under `runs/<job_id>`, a copy of each target, a queued state and a monotonically '
              'increasing event log. The worker moves through running to completed, failed or cancelled. '
              'The UI polls the job endpoint; the final result is written as JSON and rendered into the '
              'report. Cancellation is cooperative and checked between tool invocations.')
    h2(doc, 'Platform support')
    para(doc, 'Fedora Linux is the primary and fully exercised platform. The browser workbench, static '
              'analysis, ELF/PE reports, hardening checks and packaging run there. On native Windows the '
              'workbench subset is implemented but not manually accepted; the OLLVM toolchain and the QEMU workflow are not: the '
              'interface and backend report them as unavailable instead of failing late. Windows manual '
              'acceptance is an open release gate, not a completed claim.')

    # 6
    h1(doc, TOC[5])
    para(doc, 'The analysis engine is deliberately conservative. It calls established command-line '
              'tools, captures their output, and turns the output into both raw artefacts and normalised '
              'signals. It does not attempt to replace Ghidra or to infer intent. The value is the '
              'consistent evidence model around the tools.')
    h2(doc, 'Tool adapters')
    add_table(doc, ['Tool', 'Used for', 'Notes'], [
        ('readelf', 'ELF header, sections, symbols, dynamic tags, notes', 'Primary source for hardening and symbol counts.'),
        ('objdump', 'Disassembly and section contents', 'Bounded output; used for instruction-level context.'),
        ('strings', 'Byte-scan strings and categories', 'Reports URLs, paths, messages and compiler notes separately.'),
        ('nm', 'Symbol table inspection', 'Complements readelf for name recovery.'),
        ('Ghidra headless', 'Functions, decompiled C-like code, call graph, labels', 'Optional, project-local, enabled in the recorded full suite.'),
    ], widths=[32, 75, 65], font_size=8.8)
    h2(doc, 'Evidence model')
    para(doc, 'Each result keeps three levels of detail. Raw output is preserved for audit. Normalised '
              'fields drive the report and comparison. Human-readable findings explain why a signal '
              'matters, with references back to the raw evidence. This separation is what allows the same '
              'job to produce a judge-friendly summary, a technical table and a machine-readable record '
              'without duplicating analysis.')
    add_table(doc, ['Signal', 'What is measured', 'What it does not prove'], [
        ('Names / symbols', 'Symbol-table entries, recovered labels', 'That removing names removes logic'),
        ('Debug information', 'Section presence, paths, compiler notes', 'That the build is vulnerable'),
        ('Strings', 'Byte-scan text, categorised by path/message/URL', 'That a message is a secret'),
        ('Imports / exports', 'Dynamic symbols and libraries', 'Exploitability of an imported function'),
        ('Functions / pseudocode', 'Recovered routines and C-like bodies', 'That the recovery is complete'),
        ('Call graph / CFG', 'Tool-reported relationships', 'Runtime behaviour'),
        ('Hardening', 'NX, PIE, RELRO, canary, FORTIFY, PE flags', 'That the program is secure'),
    ], widths=[40, 70, 62], font_size=8.6)
    h2(doc, 'Hardening checks')
    para(doc, 'For ELF, the checker reads `PT_GNU_STACK` for NX, `ET_DYN` with `DF_1_PIE` for PIE, '
              '`PT_GNU_RELRO` plus `BIND_NOW` for RELRO, canary symbols such as `__stack_chk_fail`, and '
              'FORTIFY symbols such as `__printf_chk`. For PE, it reads `DllCharacteristics`, load-config '
              'fields and cookie symbols. Results are Present, Absent, Partial or Unknown, each with the '
              'evidence string that produced it. Presence is not a guarantee; absence is not proof of '
              'exploitability.')
    add_callout(doc, 'Design rule: no composite score',
                'The project deliberately refuses to collapse exposure and mitigation into one number. A '
                'score would hide which tool produced which signal and would invite claims the evidence '
                'cannot support.', GREEN)

    # 7
    h1(doc, TOC[6])
    para(doc, 'ReverseShield offers four transformation profiles. Each is a demonstration of a technique, '
              'not a production protection product. Each writes a new copy, records the exact command or '
              'compiler invocation, and compares the copy with the original using the same analysis tools.')
    add_table(doc, ['Profile', 'Operation', 'Inputs', 'What it demonstrates'], [
        ('Symbol removal', '`strip_compare`', 'ELF/PE copy', 'Removes symbol/debug tables; shows what remains recoverable.'),
        ('Constant blinding', '`protect_compare`', 'Five original sample sources', 'Replaces integer literals with XOR expressions and adds an opaque guard.'),
        ('Binary hygiene', '`binary_compare`', 'ELF/PE copy', 'Normalises selected build metadata without source.'),
        ('OLLVM source', '`ollvm_compare`', 'Five original sample sources', 'Flattening, bogus control flow, substitution, string encryption, anti-decompiler pass.'),
    ], widths=[36, 32, 40, 64], font_size=8.5)
    h2(doc, 'Symbol removal, measured')
    para(doc, 'On the Level 5 sample, symbol removal reduced ELF symbol-table entries from 35 to 0 and '
              'byte-scan strings from 134 to 60. File size fell from 15,904 to 10,784 bytes. The debug '
              'sections and symbol table changed from present to absent. Ghidra still recovered the policy '
              'function: decompiled functions moved from 10 to 8 and generated labels from 100 to 67, but '
              'the logic remained readable. That is the central lesson of the comparison: removing names '
              'raises cost modestly; it does not remove logic.')
    add_image(doc, str(HERE / 'deck-assets' / 'compare-metrics2.png'), width_mm=160)
    add_caption(doc, 'Figure 1. A real symbol-removal comparison in the local workbench, 11 November 2026. '
                     'Counts name their tool; N/A means unmeasured.')
    h2(doc, 'OLLVM source transformation, measured')
    para(doc, 'The OLLVM profile compiles the five original sample sources with a project-local xollvm '
              'build on LLVM 22. It applies control-flow flattening, bogus control flow, instruction '
              'substitution, string encryption and an anti-decompiler pass, then strips the output. On '
              'Level 5, the protected copy grew from 15,904 to 109,296 bytes. All six policy messages '
              'disappeared from plaintext, the ELF symbol table fell to zero, and file entropy rose from '
              '2.9213 to 6.4849 bits/byte. Ghidra labels rose from 100 to 594 and analysis took '
              'substantially longer. The copy is harder to read casually, not impossible to analyze.')
    add_callout(doc, 'Scope of source transformation',
                'OLLVM and constant blinding operate on the five original self-authored sample sources. '
                'A compiler pass cannot transform an arbitrary ELF or PE without source. The sixth '
                'sample, level-5-hardened, is analysis-only for this reason.', AMBER)
    h2(doc, 'Binary hygiene')
    para(doc, 'Binary hygiene changes only a copy of an authorized ELF or PE. It removes selected '
              'build metadata and records the resulting hashes. It is not a packer and does not claim to '
              'defeat a determined analyst. Its purpose is to show that metadata-level changes can be '
              'made and measured safely, without executing the artifact.')

    # 8
    h1(doc, TOC[7])
    para(doc, 'The QEMU check exists because a static report cannot show that a transformed program still '
              'produces the expected output for a deterministic input. It is intentionally narrow: the '
              'project compiles small driver programs from its own sample sources, boots a minimal Linux '
              'guest with no disk and no network, runs the original and protected drivers, and compares '
              'their serial transcripts and exit codes.')
    add_table(doc, ['Stage', 'Implementation detail'], [
        ('Inputs', 'Self-authored sample source; original and protected driver builds.'),
        ('Packaging', 'Static busybox/initramfs assembled with argv-only commands and in-process gzip.'),
        ('Guest', 'QEMU system emulation, host-provided kernel, no disk image, no network device.'),
        ('Comparison', 'Serial transcript SHA-256 and exit code for each side; QEMU return code must be zero.'),
        ('Evidence', 'Per-sample hashes, duration, matched flag and explicit scope field.'),
        ('Failure', 'A non-zero QEMU return code or a transcript mismatch fails the check.'),
    ], widths=[32, 140], font_size=8.8)
    rows = [('Sample', 'Matched', 'Exit original / protected', 'QEMU rc')]
    for row in qemu['samples']:
        rows.append((row['sample_id'], 'yes' if row['matched'] else 'no',
                     f"{row['exit_codes']['original']} / {row['exit_codes']['protected']}",
                     str(row['qemu_return_code'])))
    add_table(doc, rows[0], rows[1:], widths=[38, 25, 60, 25], font_size=8.8)
    para(doc, f"Recorded scope: `{qemu['scope']}`. Artifact behaviour verified: "
              f"`{str(qemu['artifact_behavior_verified']).lower()}`. The guest ran separate deterministic "
              'driver builds, not the downloadable protected ELF. Matching five vectors is evidence of '
              'regression safety for those vectors; it is not evidence of general behavioural equivalence.')
    add_callout(doc, 'Why this distinction matters',
                'It would be easy, and wrong, to say “the protected binary was tested and behaves the '
                'same”. The downloaded artifact was never executed. The UI and evidence records keep '
                '`behavior_verified` false for that artifact and report driver-vector matching separately.', AMBER)
    h2(doc, 'Harness hardening')
    para(doc, 'The harness resolves guest library dependencies statically with `readelf` instead of '
              '`ldd`, so it never loads a target on the host. It invokes `cpio` with an argument vector '
              'and compresses in Python rather than interpolating a shell pipeline. It requires the QEMU '
              'return code to be zero, records transcript and driver hashes, and omits raw commands and '
              'host paths from the evidence JSON. Spaces and shell metacharacters in output paths are '
              'covered by regression tests.')

    # 9
    h1(doc, TOC[8])
    para(doc, 'The interface is a single-page application served from the project. It is deliberately '
              'plain: static HTML, CSS and JavaScript, no framework, no build step, no external CDN. The '
              'visual language is a dark terminal-inspired palette with a cyan accent, matching the '
              'subject matter without pretending to be a commercial SOC console.')
    h2(doc, 'Four views')
    bullets(doc, [
        '**Operate** — choose a file, discover targets, authorize, select tools, run analysis or a transformation, read the report.',
        '**Compare** — original versus changed copy, with “what changed”, “what stayed the same”, scope and download actions.',
        '**Monitor** — live job events, tool starts/ends, timings, warnings and failure messages.',
        '**Read Me** — a short operator guide, sample catalog and limitations.',
    ])
    para(doc, 'The report uses collapsible sections for raw evidence, so a judge can read the plain-language '
              'findings first and open the technical detail only when needed. Screenshots used in the deck '
              'and this report come from the live local UI and were checked for private paths.')
    add_image(doc, str(HERE / 'deck-assets' / 'hardening3.png'), width_mm=160)
    add_caption(doc, 'Figure 2. Exploit-mitigation properties for the hardened Level 5 fixture, with the '
                     'evidence string for each observed property.')
    h2(doc, 'Accessibility and language')
    para(doc, 'The interface is English-only and has not received a formal accessibility audit. The '
              'terminal aesthetic uses high-contrast text, but keyboard-only operation and screen-reader '
              'behaviour should be tested before a public release. Arabic explanation is available '
              'verbally; the documents are intentionally English for the event.')

    # 10
    h1(doc, TOC[9])
    para(doc, 'Securing the workbench is a separate problem from analysing a binary. A tool that reads '
              'hostile files must not become the vulnerability. This section describes the controls that '
              'exist, the evidence behind them, and the controls that do not exist yet.')
    add_table(doc, ['Control', 'Implementation', 'Evidence'], [
        ('Loopback binding', 'Server listens on 127.0.0.1 only', 'app.py, API tests'),
        ('Session token', 'Random token required on API requests', 'API tests, UI contract'),
        ('Origin / referer / fetch-site', 'Rejects cross-site requests', 'test_security_day2/day3'),
        ('CSP and headers', 'Strict content-security policy; no inline scripts', 'UI contract tests'),
        ('No host execution', 'Static tools read bytes; copies only', 'Design + review'),
        ('Operation/profile pairing', 'Analysis cannot dispatch a transformation', 'test_operation_profile, live HTTP 400'),
        ('Path handling', 'Job directories under runs/; upload names sanitised', 'Discovery/API tests'),
        ('Sanitised export', 'Private paths and sensitive fields removed', 'test_security_day3'),
        ('Package allowlist', 'Git-index files only; excludes tools/, runs/, raw scans', 'test_package_selection'),
        ('Evidence allowlist', 'Eleven named files; private-path regex guard', 'test_day4_evidence_pack'),
    ], widths=[42, 80, 50], font_size=8.4)
    h2(doc, 'A real bug found by review')
    para(doc, 'The Day 4 review found that an `analyze` job could be created with a transformation '
              'profile attached. Because the worker dispatched on the normalized profile, a request that '
              'looked like analysis could carry a profile into execution. The fix validates the exact '
              'operation/profile pair before any job is created. A live request combining `analyze` with a '
              'transformation profile now returns HTTP 400, and the regression test asserts the rejection '
              'before job creation.')
    h2(doc, 'Privacy of the sample corpus')
    para(doc, 'The first sample builds embedded the developer home path in DWARF data. A read-only audit '
              'found the leak; the build now uses compiler prefix maps to emit stable synthetic '
              'project-relative paths, and all six samples were rebuilt without execution. A regression '
              'test fails if a private home path appears in the sample bytes.')
    h2(doc, 'Residual risk')
    bullets(doc, [
        'The token is CSRF protection, not authentication or multi-user authorization.',
        'Static parsers are not a sandbox; a malicious file is still parsed by complex native tools.',
        'Ghidra is optional and runs with the user’s privileges when enabled.',
        'The sanitizer is pattern-based and cannot inspect compressed PDF text or arbitrary binary encodings.',
        'No independent penetration test has been performed on the workbench.',
    ])

    # 11
    h1(doc, TOC[10])
    para(doc, 'This section separates what was measured from what was merely built. Every table names the '
              'source of the number and the scope in which it is valid.')
    h2(doc, 'Automated tests')
    para(doc, f"The recorded full suite ran {tests['count']} tests with {tests['skipped']} skipped on "
              f"{verification['platform']} with Ghidra enabled. Result: {tests['status']}, "
              f"{tests['failures']} failures, {tests['errors']} errors. The extracted Lite package, which "
              'does not bundle Ghidra or the OLLVM toolchain, ran 167 tests with 7 optional-dependency '
              'skips and no failures. The suite covers analysis, discovery, API security, PE support, RPM '
              'handling, hardening, OLLVM scope, QEMU harness safety, packaging, evidence packs, documents '
              'and the silent demo.')
    h2(doc, 'Hardening evidence')
    rows = [('Property', 'Level 5 original', 'Level 5 hardened')]
    for key, label in (('nx', 'NX / DEP'), ('pie', 'PIE / ASLR'), ('relro', 'RELRO'),
                       ('canary', 'Stack canary'), ('fortify', 'FORTIFY')):
        rows.append((label, checks['level-5'][key].title(), checks['level-5-hardened'][key].title()))
    add_table(doc, rows[0], rows[1:], widths=[55, 55, 55], font_size=9)
    para(doc, f"Both files were built non-executable (0600 in the build workspace) and were never "
              f"executed on the host; a fresh Git checkout may normalise the mode, so the enforced "
              f"safety property is non-executable. Original: "
              f"{samples['level-5']['bytes']:,} bytes, SHA-256 `{samples['level-5']['sha256'][:16]}…`. "
              f"Hardened: {samples['level-5-hardened']['bytes']:,} bytes, SHA-256 "
              f"`{samples['level-5-hardened']['sha256'][:16]}…`. Full hashes are in Appendix B.")
    h2(doc, 'Comparison evidence')
    add_table(doc, ['Metric', 'Original', 'After symbol removal', 'Source'], [
        ('ELF symbol-table entries', '35', '0', 'readelf'),
        ('Byte-scan strings', '134', '60', 'strings'),
        ('File size', '15,904 B', '10,784 B', 'filesystem'),
        ('Debug sections', 'present', 'absent', 'readelf'),
        ('Symbol table', 'present', 'absent', 'readelf'),
        ('Ghidra labels', '100', '67', 'Ghidra'),
        ('Decompiled functions', '10', '8', 'Ghidra'),
        ('Entropy', '2.9213', '1.9108', 'metrics'),
    ], widths=[55, 32, 45, 38], font_size=8.6)
    h2(doc, 'Behaviour evidence')
    para(doc, f"Five self-authored samples were checked in QEMU with separate original and protected "
              f"driver builds. All five matched; every original and protected exit code was zero; every "
              f"QEMU return code was zero. Scope is `{qemu['scope']}` and the downloadable artifact is not "
              'behaviour-verified. The sixth hardened fixture is outside this row set.')
    h2(doc, 'Security scanning')
    para(doc, f"Bandit {bandit['version'].split()[-1]} scanned {bandit['lines_of_code']:,} lines and "
              f"reported {bandit['issues_total']} issues: 0 high, "
              f"{bandit['severity_counts'].get('MEDIUM', 0)} medium and "
              f"{bandit['severity_counts'].get('LOW', 0)} low. The three medium findings are in test code. "
              'detect-secrets reported checksums in evidence/setup files and deliberate sanitizer fixtures; '
              'no live credential was found. Semgrep and ZAP were not re-run on this tree, so no freshness '
              'claim is made for them.')
    h2(doc, 'Packaging evidence')
    if lite.is_file() and evidence_zip.is_file():
        add_table(doc, ['Artifact', 'Size', 'SHA-256 prefix'], [
            ('Lite Windows/source ZIP', f'{lite.stat().st_size:,} B', sha256(lite)[:16] + '…'),
            ('Evidence ZIP', f'{evidence_zip.stat().st_size:,} B', sha256(evidence_zip)[:16] + '…'),
        ], widths=[80, 35, 55], font_size=9)
    para(doc, 'The Lite package contains 101 entries selected from the Git index only. It excludes '
              '`tools/`, `runs/`, raw security scans, demo frames, private handover notes and generated '
              'documents. Extraction and a full test run were performed on the extracted copy. The '
              'Evidence ZIP contains 11 allowlisted files and is not runnable; it is a review package.')

    # 12
    h1(doc, TOC[11])
    para(doc, 'ReverseShield sits between three established categories. It is not a better packer, not a '
              'vulnerability scanner, and not a replacement for an expert with Ghidra. Its contribution is '
              'the evidence loop around existing tools: a safe local workflow, qualified metrics, and '
              'explicit scope.')
    add_table(doc, ['Category', 'Typical output', 'What ReverseShield adds'], [
        ('Packers / obfuscators', 'A claimed protection level', 'Measured before/after evidence and visible residual logic'),
        ('Vulnerability scanners', 'CVE/CWE findings and severity', 'Binary exposure signals and mitigation posture, with no CVE claim'),
        ('Manual reverse engineering', 'Expert notes and screenshots', 'Repeatable jobs, hashes, reports and comparison'),
        ('Hardening checkers', 'A flag table', 'Context: the same toolchain also shows names, strings and logic'),
        ('Sandboxes', 'Runtime behaviour', 'Static-first safety; a separate, narrowly scoped QEMU check for sample drivers'),
    ], widths=[48, 55, 69], font_size=8.6)
    para(doc, 'The closest technical neighbours are Ghidra for recovery, binutils for metadata, checksec-'
              'style scripts for mitigation flags, OLLVM for source obfuscation, and QEMU for controlled '
              'execution. ReverseShield integrates them behind one local workflow and, importantly, keeps '
              'their different meanings separate.')
    h2(doc, 'What would count as validation')
    para(doc, 'A credible next step is a small benchmark with independent binaries and a blinded '
              'before/after review: can a reviewer identify what changed, and does the report change a '
              'release decision? The current evidence demonstrates that the workflow runs and measures '
              'consistently; it does not yet demonstrate decision impact with external users.')

    # 13
    h1(doc, TOC[12])
    para(doc, 'The project’s credibility depends on saying what it cannot do. The following statements '
              'are non-claims, not modest phrasing: they are enforced by scope or left as open gates.')
    add_table(doc, ['Not claimed', 'Why / current status'], [
        ('The binary is secure or unhackable', 'No static property or five-vector check can establish this.'),
        ('CVE/CWE detection or exploitability scoring', 'Not implemented; a vulnerability scanner is a different tool.'),
        ('Full behavioural equivalence', 'QEMU checks separate drivers, not the downloadable artifact or general inputs.'),
        ('Protection of arbitrary third-party binaries', 'OLLVM and constant blinding require the five original sample sources.'),
        ('Native-Windows full support', 'Workbench subset only; manual acceptance not performed.'),
        ('Production sandboxing', 'Static parsers run in the server process boundary, not a hardened sandbox.'),
        ('Multi-user or remote service', 'Loopback, single-user design with a CSRF token, not IAM.'),
        ('Fresh Semgrep/ZAP results', 'Bandit and detect-secrets were re-run; Semgrep/ZAP were not.'),
    ], widths=[70, 102], font_size=8.6)
    h2(doc, 'Open release gates')
    bullets(doc, [
        'Clean Windows 10/11 manual acceptance of the Lite package, including setup.bat, run.bat, PE analysis and report download.',
        'Independent review of the final PDFs and claim map before external release.',
        'A merge decision for PR #6; no tag, release publication or event submission is part of this branch.',
        'IS CyberNext account, eligibility, declaration and submission checks by the owner.',
        'A stable tag and release notes after submission if the owner chooses to publish.',
    ])
    add_callout(doc, 'Honesty as a feature',
                'Every limitation in this section maps to an acceptance-matrix row or a documented test '
                'boundary. A judge can ask “how do you know?” and receive a file, a hash or a test name.', GREEN)

    # 14
    h1(doc, TOC[13])
    para(doc, 'The near-term goal is trust, not feature count. A release is ready when a new operator can '
              'install it, run the six samples, read the report, and reproduce the evidence on a clean '
              'machine — and when the team can state the limits without hedging.')
    add_table(doc, ['Gate', 'Requirement', 'Status'], [
        ('G1', 'Fedora workbench runs from the packaged source', 'Passed locally'),
        ('G2', 'Full automated suite green with Ghidra enabled', '167 tests, 1 skipped, passed'),
        ('G3', 'Evidence regenerated after the final sample rebuild', 'Passed'),
        ('G4', 'Lite and Evidence ZIPs reproducible with checksums', 'Passed locally'),
        ('G5', 'Clean native-Windows manual acceptance', 'Open'),
        ('G6', 'Owner approval, event eligibility and submission', 'Open — owner action'),
    ], widths=[18, 105, 49], font_size=8.8)
    h2(doc, 'Next milestones')
    bullets(doc, [
        '**Release readiness:** Windows acceptance, signed/reproducible package, CI on every change.',
        '**Pilot:** two small teams use the report in a real release review; capture whether it changes a decision.',
        '**Research:** isolated dynamic lab, SBOM/CVE correlation, more formats, larger benchmark.',
        '**Product:** accessibility, multi-user separation, and a proper parser sandbox before any hosted use.',
    ])

    # 15
    h1(doc, TOC[14])
    para(doc, 'The project was built as a four-day relay by four students, with a different platform and '
              'focus each day. The handover is part of the engineering: each day had to leave a runnable '
              'tree, tests and written context for the next person.')
    add_table(doc, ['Member', 'Day / focus', 'Contribution'], [
        ('Naser', 'Day 1 · Windows and PE', 'Windows setup, PE acceptance path, first-run reliability.'),
        ('Zayed', 'Day 2 · Analysis accuracy', 'Metrics, Ghidra integration, one-click demo.'),
        ('Nomai', 'Day 3 · Security and API', 'Token/origin controls, sanitizer, SAST/DAST evidence.'),
        ('Faisal', 'Day 4 · Integration and release', 'OLLVM/QEMU scope, hardening evidence, packaging, documents, demo.'),
    ], widths=[28, 52, 92], font_size=8.8)
    para(doc, 'The repository uses day branches, pull requests and owner merges. The final Day 4 work is '
              'on `feature/ollvm-protection`, pushed to origin and opened as PR #6; it is not merged, '
              'tagged or released. Teammates use Windows, '
              'so the package includes `setup.bat` and `run.bat`, and the report distinguishes Windows '
              'support from Windows manual acceptance.')
    h2(doc, 'Handover artefacts')
    bullets(doc, [
        '`START_HERE.md`, `README.md`, `LITE_PACKAGE.md` — orientation and packaging.',
        '`docs/handoff/DAY4.md` — state, gates, decisions and next steps.',
        '`docs/evidence/ACCEPTANCE_MATRIX_DAY4.md` — platform and release columns.',
        '`docs/evidence/CLAIM_EVIDENCE_DAY4.md` — claim-to-evidence mapping.',
        '`docs/demo/` — silent draft video, narration script, storyboard and screenshots.',
    ])

    # 16
    h1(doc, TOC[15])
    para(doc, 'ReverseShield demonstrates a practical middle path between “trust the protector” and '
              '“reverse engineer it manually”. It makes binary exposure visible with established tools, '
              'changes only copies, measures the result with qualified evidence, and states the limits in '
              'the same report as the numbers.')
    para(doc, 'The prototype runs locally, has a green automated suite, produces a real before/after '
              'comparison, measures mitigation properties, and includes a narrow QEMU check that is '
              'carefully scoped. It is not a finished security product, and it does not claim to be. The '
              'remaining work is mostly trust work: Windows acceptance, independent review, pilot '
              'feedback, and the owner’s publication and event decisions.')
    add_callout(doc, 'Closing statement',
                'Evidence, not verdicts. ReverseShield shows what a build reveals, what a change removed, '
                'and what the team still does not know.', GREEN)

    # Appendix A
    h1(doc, TOC[16])
    para(doc, 'Test counts were collected with the standard library loader across `tests/test_*.py` in '
              'the current tree. The total matches the recorded suite result.')
    counts = test_counts()
    rows = [('Test module', 'Tests')]
    for module, count in counts:
        rows.append((module, str(count)))
    rows.append(('Total', str(sum(count for _, count in counts))))
    add_table(doc, rows[0], rows[1:], widths=[130, 30], font_size=8.2)
    para(doc, 'Optional-dependency tests skip when Ghidra or document tooling is unavailable; the '
              'extracted Lite package recorded seven such skips. The suite does not execute bundled '
              'samples or third-party targets on the host; the OLLVM tests boot separate deterministic '
              'drivers in QEMU.')

    # Appendix B
    h1(doc, TOC[17])
    para(doc, 'The evidence register lists the artefacts a reviewer can open directly. Hashes are '
              'SHA-256; prefixes are shown here to keep the table readable, with full values in the '
              'files themselves.')
    rows = [('Artefact', 'SHA-256 prefix', 'Proves')]
    for name, label in (
        ('hardening-level5.json', 'Measured ELF hardening and sample hashes'),
        ('ollvm-five-qemu.json', 'Five deterministic driver results and scope'),
        ('verification.json', 'Recorded full-suite result'),
        ('security-day4.json', 'Bandit and detect-secrets summary'),
        ('ACCEPTANCE_MATRIX_DAY4.md', 'Platform and release acceptance state'),
        ('CLAIM_EVIDENCE_DAY4.md', 'Claim-to-evidence mapping'),
    ):
        path = HERE / 'evidence' / name
        if path.is_file():
            rows.append((name, sha256(path)[:20] + '…', label))
    for row in qemu['samples']:
        rows.append((f"{row['sample_id']} driver (original)", row['driver_sha256']['original'][:20] + '…',
                     'Separate deterministic driver hash'))
    add_table(doc, rows[0], rows[1:], widths=[60, 52, 60], font_size=7.8)
    h2(doc, 'Bundled sample hashes')
    sample_rows = [('Sample', 'Bytes', 'SHA-256')]
    for path in sorted((ROOT / 'samples' / 'bin').glob('*.elf')):
        sample_rows.append((path.stem, f'{path.stat().st_size:,}', sha256(path)[:32] + '…'))
    add_table(doc, sample_rows[0], sample_rows[1:], widths=[42, 25, 105], font_size=8.2)

    # Appendix C
    h1(doc, TOC[18])
    para(doc, 'Commands assume the repository root. They are documentation, not an invitation to execute '
              'third-party targets. The only execution permitted by the project is the QEMU sample-driver '
              'path described in Section 8.')
    add_code(doc, 'python3 -m venv .venv && . .venv/bin/activate\n'
                  'pip install -r requirements.txt\n'
                  'python3 build_samples.py            # rebuild six self-authored samples, never run them\n'
                  'python3 app.py                      # http://127.0.0.1:8765/\n'
                  'python3 -m unittest discover -s tests -v\n'
                  'RUN_GHIDRA_TESTS=1 python3 -m unittest discover -s tests -v\n'
                  'python3 scripts/package_lite_windows.py\n'
                  'python3 scripts/package_evidence_day4.py\n'
                  'soffice --headless --convert-to pdf docs/*.docx --outdir docs')
    para(doc, 'The test suite is safe to run on a workstation: it uses temporary directories and does '
              'not launch the bundled samples. Ghidra tests require the project-local tools and are '
              'skipped otherwise. Packaging selects Git-index files only and refuses unstaged edits to '
              'indexed source, so a dirty tree must be reviewed before packaging.')

    # Appendix D
    h1(doc, TOC[19])
    para(doc, f"Bandit {bandit['version'].split()[-1]} scanned {bandit['lines_of_code']:,} lines of "
              f"project source, tests and scripts. Total issues: {bandit['issues_total']}; severity: "
              f"0 high, {bandit['severity_counts'].get('MEDIUM', 0)} medium, "
              f"{bandit['severity_counts'].get('LOW', 0)} low.")
    rows = [('Rule', 'Count', 'Interpretation')]
    interpretations = {
        'B404': 'subprocess module imported; expected for a tool that invokes static analysers.',
        'B603': 'subprocess call without shell; argument-vector use is the intended pattern.',
        'B607': 'partial executable path; resolved through a controlled tool inventory.',
        'B105': 'hard-coded password string in test fixtures.',
        'B405': 'XML import in tests/document tooling.',
        'B314': 'XML parsing in tests/document tooling.',
        'B101': 'assert used in tests.',
        'B108': 'hard-coded temporary directory in tests.',
    }
    for rule, count in sorted(bandit['rule_counts'].items()):
        rows.append((rule, str(count), interpretations.get(rule, 'Reviewed low-severity finding.')))
    add_table(doc, rows[0], rows[1:], widths=[22, 20, 130], font_size=8.4)
    h2(doc, 'detect-secrets disposition')
    para(doc, 'Six files produced findings. They are SHA-256 checksums in evidence/setup scripts, or '
              'deliberate fixtures used to test the sanitizer. No live credential, private key or token '
              'was found in the scanned tree. The scan excludes `tools/`, `runs/`, `backups/` and `.git/`.')
    add_callout(doc, 'Not re-run on this tree',
                'Semgrep and OWASP ZAP were used earlier in the project but were not re-run after the Day 4 '
                'changes. This report does not present them as fresh evidence.', AMBER)

    # Appendix E
    h1(doc, TOC[20])
    para(doc, 'The acceptance matrix records what has been demonstrated on which platform and what '
              'remains an owner or external gate. It is the authoritative short form of this report.')
    add_table(doc, ['Area', 'Fedora', 'Native Windows', 'Release gate'], [
        ('Workbench UI and static analysis', 'Verified', 'Not manually tested', 'Windows manual run'),
        ('ELF analysis and hardening', 'Verified', 'PE path only on Windows', 'Windows PE sample'),
        ('PE analysis', 'Verified with fixtures', 'Not manually tested', 'Windows manual run'),
        ('Symbol removal and hygiene', 'Verified', 'Not manually tested', 'Windows manual run'),
        ('OLLVM source transformation', 'Verified on five samples', 'Unavailable by design', 'Documented limitation'),
        ('QEMU driver checks', 'Verified, five rows', 'Unavailable by design', 'Documented limitation'),
        ('Packaging and checksums', 'Verified locally', 'Extraction not tested', 'Windows extraction'),
        ('Documents and demo', 'Built and reviewed', 'Not reviewed', 'Owner review'),
        ('Event submission', 'Not started', 'Not applicable', 'Owner action'),
    ], widths=[62, 40, 40, 40], font_size=8.0)

    # Appendix F
    h1(doc, TOC[21])
    add_table(doc, ['Term', 'Meaning in this report'], [
        ('ELF / PE', 'Executable and Linkable Format (Linux) / Portable Executable (Windows).'),
        ('Static analysis', 'Reading file bytes and metadata without running the program.'),
        ('Hardening', 'Build/linker properties such as NX, PIE, RELRO, canary and FORTIFY.'),
        ('OLLVM', 'Obfuscator-LLVM passes applied to source before compilation.'),
        ('QEMU', 'Emulator used here for a no-disk, no-network guest with deterministic drivers.'),
        ('Driver vector', 'A small program and input whose transcript is compared between builds.'),
        ('Behavior verified', 'Reserved for the artifact actually executed; false for the downloadable copy.'),
        ('N/A', 'Not measured in this run; never interpreted as zero.'),
        ('Scope', 'The exact claim boundary attached to a piece of evidence.'),
        ('DRAFT', 'Owner-review copy; not submitted, published or tagged.'),
    ], widths=[40, 132], font_size=9)
    para(doc, 'This report was generated from the project’s recorded evidence on 11 November 2026. '
              'It is a DRAFT for owner review.', italic=True)

    doc.save(out)
    return out


if __name__ == '__main__':
    from build_day4_documents import finalize
    result = finalize(sys.modules[__name__], TOC, 'full project report')
    print(json.dumps(result, indent=2))
