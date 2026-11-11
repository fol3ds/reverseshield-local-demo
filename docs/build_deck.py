#!/usr/bin/env python3
"""Build the ReverseShield IS CyberNext pitch deck (16:9, English, DRAFT).

Every number comes from the recorded Day 4 evidence files or from the live
workbench run captured on 11 November 2026. No target is executed here.
"""
from __future__ import annotations

import json
from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'
ASSETS = DOCS / 'deck-assets'
OUT = DOCS / 'ReverseShield_IS_CyberNext_Deck_DRAFT_v0.5.0.pptx'

BG = RGBColor(0x0B, 0x12, 0x20)
PANEL = RGBColor(0x11, 0x1A, 0x2B)
PANEL2 = RGBColor(0x0F, 0x17, 0x2A)
CYAN = RGBColor(0x22, 0xD3, 0xEE)
CYAN_DEEP = RGBColor(0x0E, 0x74, 0x90)
TEXT = RGBColor(0xE6, 0xED, 0xF3)
MUTED = RGBColor(0x94, 0xA3, 0xB8)
GREEN = RGBColor(0x34, 0xD3, 0x99)
AMBER = RGBColor(0xFB, 0xBF, 0x24)
LINE = RGBColor(0x1E, 0x29, 0x3B)
WHITE = RGBColor(0xF8, 0xFA, 0xFC)

SANS = 'Arial'
MONO = 'DejaVu Sans Mono'

W, H = Inches(13.333), Inches(7.5)


def load(name: str) -> dict:
    return json.loads((DOCS / 'evidence' / name).read_text(encoding='utf-8'))


def new_deck() -> Presentation:
    deck = Presentation()
    deck.slide_width, deck.slide_height = W, H
    props = deck.core_properties
    props.author = 'ReverseShield Team'
    props.last_modified_by = 'ReverseShield Team'
    props.title = 'ReverseShield — IS CyberNext 2026 Deck (DRAFT)'
    props.subject = 'Reverse-engineering exposure workbench'
    props.keywords = 'ReverseShield, static analysis, ELF, PE, OLLVM, QEMU'
    props.comments = 'DRAFT — owner review; not for submission'
    props.category = 'IS CyberNext 2026'
    return deck


def slide_base(deck: Presentation, number: int, label: str = '') -> object:
    slide = deck.slides.add_slide(deck.slide_layouts[6])
    fill = slide.background.fill
    fill.solid()
    fill.fore_color.rgb = BG
    # top hairline and section marker
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, W, Pt(2))
    bar.fill.solid(); bar.fill.fore_color.rgb = CYAN; bar.line.fill.background()
    if label:
        tx(slide, Inches(0.55), Inches(0.28), Inches(7), Inches(0.3), label.upper(),
           size=10.5, color=CYAN, bold=True)
    tx(slide, Inches(0.55), Inches(7.08), Inches(7.4), Inches(0.25),
       'DRAFT — owner review · not for submission', size=9, color=MUTED)
    tx(slide, Inches(10.2), Inches(7.08), Inches(2.6), Inches(0.25),
       f'ReverseShield 0.5.0-team   {number:02d}', size=9, color=MUTED, align=PP_ALIGN.RIGHT)
    return slide


def tx(slide, left, top, width, height, text, *, size=16, bold=False, color=TEXT,
       font=SANS, align=PP_ALIGN.LEFT, italic=False, spacing=None, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(left, top, width, height)
    frame = box.text_frame
    frame.word_wrap = True
    frame.vertical_anchor = anchor
    frame.margin_left = frame.margin_right = 0
    frame.margin_top = frame.margin_bottom = 0
    lines = text.split('\n')
    for index, line in enumerate(lines):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.alignment = align
        paragraph.space_after = Pt(2 if spacing is None else spacing)
        run = paragraph.add_run()
        run.text = line
        font_obj = run.font
        font_obj.size = Pt(size); font_obj.bold = bold; font_obj.italic = italic
        font_obj.color.rgb = color; font_obj.name = font
    return box


def bullets(slide, items, left, top, width, height, *, size=15.5, color=TEXT, gap=8, bullet_color=CYAN):
    box = slide.shapes.add_textbox(left, top, width, height)
    frame = box.text_frame
    frame.word_wrap = True
    frame.margin_left = frame.margin_right = frame.margin_top = frame.margin_bottom = 0
    for index, item in enumerate(items):
        paragraph = frame.paragraphs[0] if index == 0 else frame.add_paragraph()
        paragraph.space_after = Pt(gap)
        paragraph.line_spacing = 1.05
        dot = paragraph.add_run(); dot.text = '▸  '
        dot.font.size = Pt(size); dot.font.bold = True; dot.font.color.rgb = bullet_color; dot.font.name = SANS
        run = paragraph.add_run(); run.text = item
        run.font.size = Pt(size); run.font.color.rgb = color; run.font.name = SANS
    return box


def panel(slide, left, top, width, height, *, fill=PANEL, line=LINE, radius=True):
    shape_type = MSO_SHAPE.ROUNDED_RECTANGLE if radius else MSO_SHAPE.RECTANGLE
    shape = slide.shapes.add_shape(shape_type, left, top, width, height)
    shape.fill.solid(); shape.fill.fore_color.rgb = fill
    shape.line.color.rgb = line; shape.line.width = Pt(0.75)
    if radius:
        shape.adjustments[0] = 0.06
    shape.shadow.inherit = False
    return shape


def title(slide, text, *, size=30, top=Inches(0.72), width=Inches(11.9)):
    tx(slide, Inches(0.55), top, width, Inches(0.9), text, size=size, bold=True, color=WHITE)


def subtitle(slide, text, *, top=Inches(1.52), size=14.5, width=Inches(11.5)):
    tx(slide, Inches(0.55), top, width, Inches(0.6), text, size=size, color=MUTED)


def chip(slide, left, top, width, text, *, fill=PANEL, color=CYAN, size=11):
    shape = panel(slide, left, top, width, Inches(0.38), fill=fill, radius=True)
    tx(slide, left, top + Inches(0.055), width, Inches(0.28), text, size=size, bold=True,
       color=color, align=PP_ALIGN.CENTER)


def image_fit(slide, path: Path, left, top, max_w, max_h):
    with Image.open(path) as image:
        ratio = image.width / image.height
    width, height = max_w, int(max_w / ratio)
    if height > max_h:
        height, width = max_h, int(max_h * ratio)
    x = left + (max_w - width) // 2
    y = top + (max_h - height) // 2
    frame = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, x - Emu(9000), y - Emu(9000),
                                   width + Emu(18000), height + Emu(18000))
    frame.fill.solid(); frame.fill.fore_color.rgb = PANEL2; frame.line.color.rgb = LINE
    slide.shapes.add_picture(str(path), x, y, width=width, height=height)


def notes(slide, text):
    slide.notes_slide.notes_text_frame.text = text


def table(slide, left, top, width, rows, cols, *, col_widths=None, row_height=Inches(0.42),
          header=True, font=12, header_font=11):
    shape = slide.shapes.add_table(len(rows), cols, left, top, width, row_height * len(rows))
    table_obj = shape.table
    table_obj.first_row = header
    if col_widths:
        total = sum(col_widths)
        for index, weight in enumerate(col_widths):
            table_obj.columns[index].width = int(width * weight / total)
    for r, row in enumerate(rows):
        for c, value in enumerate(row):
            cell = table_obj.cell(r, c)
            cell.margin_left = cell.margin_right = Inches(0.08)
            cell.margin_top = cell.margin_bottom = Inches(0.04)
            cell.vertical_anchor = MSO_ANCHOR.MIDDLE
            cell.fill.solid()
            if header and r == 0:
                cell.fill.fore_color.rgb = PANEL2
            else:
                cell.fill.fore_color.rgb = PANEL if r % 2 else RGBColor(0x0D, 0x15, 0x25)
            frame = cell.text_frame
            frame.word_wrap = True
            paragraph = frame.paragraphs[0]
            run = paragraph.add_run(); run.text = str(value)
            run.font.name = SANS
            run.font.size = Pt(header_font if (header and r == 0) else font)
            run.font.bold = header and r == 0
            run.font.color.rgb = CYAN if (header and r == 0) else TEXT
    return table_obj


def build():
    deck = new_deck()
    hard = load('hardening-level5.json')
    qemu = load('ollvm-five-qemu.json')
    verification = load('verification.json')
    security = load('security-day4.json')
    checks = {row['sample_id']: {k: v['state'] for k, v in row['hardening']['checks'].items()}
              for row in hard['samples']}
    tests = verification['tests']

    # 1 ─ Title
    s = slide_base(deck, 1)
    tx(s, Inches(0.8), Inches(1.55), Inches(11.7), Inches(0.3),
       'IS CYBERNEXT 2026  ·  CYBERSECURITY TRACK', size=12, bold=True, color=CYAN)
    tx(s, Inches(0.75), Inches(1.95), Inches(11.8), Inches(1.5), 'ReverseShield',
       size=66, bold=True, color=WHITE)
    tx(s, Inches(0.8), Inches(3.25), Inches(11.5), Inches(0.6),
       'Reverse-Engineering Exposure Workbench', size=24, color=CYAN)
    tx(s, Inches(0.8), Inches(4.0), Inches(10.8), Inches(0.8),
       '“See what your build reveals — before an attacker does.”',
       size=19, italic=True, color=MUTED)
    for index, (label, width) in enumerate((('Local', 1.1), ('Static-only', 1.55),
                                            ('Evidence, not a verdict', 2.75))):
        chip(s, Inches(0.8) + sum(Inches(w + 0.18) for w in (1.1, 1.55)[:index]), Inches(4.95),
             Inches(width), label)
    tx(s, Inches(0.8), Inches(5.85), Inches(11.5), Inches(0.4),
       'Naser  ·  Zayed  ·  Nomai  ·  Faisal', size=15, bold=True, color=TEXT)
    tx(s, Inches(0.8), Inches(6.25), Inches(11.5), Inches(0.5),
       'Four-person student team  ·  working prototype, built and tested locally',
       size=12.5, color=MUTED)
    notes(s, 'Open with the problem, not the product: a compiled program is a readable document. '
             'ReverseShield is a local, static workbench that shows what a build exposes and measures '
             'what a change actually removed. Everything in this deck comes from recorded evidence.')

    # 2 ─ Problem
    s = slide_base(deck, 2, 'The problem')
    title(s, 'A shipped binary is a readable document')
    bullets(s, [
        'Symbols, debug information, build paths and plaintext messages often survive release.',
        'An attacker starts from the binary — no source code required.',
        'Ghidra-class decompilers recover structure, constants and readable logic.',
        'Teams rarely see their own build the way an attacker does.',
    ], Inches(0.55), Inches(1.95), Inches(6.6), Inches(3.4), size=16)
    panel(s, Inches(7.45), Inches(1.8), Inches(5.3), Inches(4.35), fill=RGBColor(0x07, 0x0D, 0x18))
    tx(s, Inches(7.75), Inches(2.0), Inches(4.7), Inches(0.3), 'WHAT A BUILD CAN LEAK', size=10,
       bold=True, color=CYAN, font=MONO)
    tx(s, Inches(7.75), Inches(2.45), Inches(4.7), Inches(3.3),
       '$ strings app\n'
       '  /home/dev/policy-engine/…\n'
       '  "tenant is not set"\n'
       '  "blocked by policy flag"\n\n'
       '$ readelf -s app\n'
       '  35 symbol-table entries\n'
       '  .debug_info present\n\n'
       '$ ghidra\n'
       '  policy_allows() reconstructed',
       size=12.5, color=RGBColor(0xCB, 0xD5, 0xE1), font=MONO, spacing=1)
    tx(s, Inches(0.55), Inches(5.55), Inches(11.9), Inches(0.5),
       'Not a hypothetical: the original Level 5 sample showed exactly these artefacts.',
       size=12.5, color=AMBER)
    notes(s, 'The Level 5 sample is self-authored and intentionally realistic. In its original build: '
             '35 ELF symbol entries, debug information present, source paths and six policy messages in '
             'plaintext, and readable decompiled logic. This is the exposure the workbench measures.')

    # 3 ─ Why the gap
    s = slide_base(deck, 3, 'Why now')
    title(s, 'Existing tools answer different questions')
    cards = [
        ('Packers & obfuscators', 'Claim protection. Rarely show what an analyst can still recover.'),
        ('Vulnerability scanners', 'Return CVE/CWE verdicts — not binary exposure evidence.'),
        ('Manual Ghidra work', 'Powerful, but expert-only, ad hoc and hard to reproduce.'),
    ]
    for index, (head, body) in enumerate(cards):
        left = Inches(0.55) + index * Inches(4.12)
        panel(s, left, Inches(1.95), Inches(3.85), Inches(2.7))
        tx(s, left + Inches(0.28), Inches(2.15), Inches(3.3), Inches(0.4), head, size=17, bold=True, color=WHITE)
        tx(s, left + Inches(0.28), Inches(2.72), Inches(3.3), Inches(1.7), body, size=13.5, color=MUTED)
    panel(s, Inches(0.55), Inches(5.0), Inches(12.2), Inches(1.35), fill=RGBColor(0x0A, 0x2A, 0x33),
          line=CYAN_DEEP)
    tx(s, Inches(0.85), Inches(5.22), Inches(11.6), Inches(0.95),
       'The gap: a safe, repeatable way to see binary exposure, change a copy, and verify what the change removed — without executing the target.',
       size=16.5, bold=True, color=WHITE)
    notes(s, 'This is the positioning. We do not claim to out-protect commercial packers or to replace a '
             'vulnerability scanner. The contribution is measurement: exposure evidence and a bounded '
             'before/after comparison, reproducible on a laptop.')

    # 4 ─ Idea / workflow
    s = slide_base(deck, 4, 'The idea')
    title(s, 'Analyze → transform a copy → reanalyze → compare')
    steps = [('1', 'Select', 'ELF/PE, package,\napp or sample'),
             ('2', 'Analyze', 'bounded static tools\n+ optional Ghidra'),
             ('3', 'Transform', 'a copy only —\noriginal untouched'),
             ('4', 'Reanalyze', 'same tools,\nsame settings'),
             ('5', 'Compare', 'qualified evidence,\nnot a score')]
    box_w = Inches(2.25)
    for index, (number, head, body) in enumerate(steps):
        left = Inches(0.55) + index * Inches(2.47)
        panel(s, left, Inches(2.0), box_w, Inches(2.25))
        tx(s, left + Inches(0.2), Inches(2.15), Inches(0.5), Inches(0.4), number, size=20, bold=True, color=CYAN, font=MONO)
        tx(s, left + Inches(0.2), Inches(2.6), box_w - Inches(0.4), Inches(0.4), head, size=17, bold=True, color=WHITE)
        tx(s, left + Inches(0.2), Inches(3.1), box_w - Inches(0.4), Inches(0.95), body, size=12, color=MUTED)
        if index < 4:
            tx(s, left + box_w + Inches(0.04), Inches(2.85), Inches(0.35), Inches(0.4), '→', size=20, bold=True, color=CYAN)
    bullets(s, [
        'Local loopback server; no cloud upload and no target execution on the host.',
        'Every job keeps a private snapshot, live event log and report under runs/<job>.',
        'Claims stay bounded: observations and hashes, never a universal protection score.',
    ], Inches(0.55), Inches(4.65), Inches(12.1), Inches(1.7), size=15)
    notes(s, 'Walk the five steps once. Emphasise step 3: the original is never modified. The comparison '
             'is between measured reports, not marketing claims. This loop is the product.')

    # 5 ─ Walkthrough
    s = slide_base(deck, 5, 'Product')
    title(s, 'Built as a local workbench, not a slide demo')
    bullets(s, [
        'Analyzes Linux ELF and Windows PE files; discovers Flatpak apps, folders, RPM payloads and uploads.',
        'Runs readelf, objdump, strings, nm and optional project-local Ghidra headless.',
        'Six self-authored samples ship with the project for reproducible demonstrations.',
        'Reports: plain-language findings, metrics, functions, pseudocode, call graphs and raw output.',
    ], Inches(0.55), Inches(1.95), Inches(5.55), Inches(3.9), size=14.5)
    image_fit(s, DOCS / 'demo' / 'ui-operate.png', Inches(6.35), Inches(1.75), Inches(6.45), Inches(4.55))
    tx(s, Inches(6.35), Inches(6.45), Inches(6.45), Inches(0.4),
       'Real local UI, 11 Nov 2026 · static analysis only', size=10.5, color=MUTED, align=PP_ALIGN.CENTER)
    notes(s, 'This is the actual interface, not a mockup. Point out the one-click demo, the six bundled '
             'samples and the explicit “static analysis by default” status. The UI is English and local.')

    # 6 ─ What the report reveals
    s = slide_base(deck, 6, 'Evidence')
    title(s, 'What the report actually reveals')
    rows = [
        ('Signal', 'Why an analyst cares'),
        ('Names & symbols', 'Function and variable names make logic easier to follow.'),
        ('Debug information', 'Source paths, build flags and compiler details.'),
        ('Strings & messages', 'URLs, internal messages, policy text, hardcoded values.'),
        ('Imports & exports', 'Capabilities and the public interface of the build.'),
        ('Functions & pseudocode', 'Recovered structure and readable C-like logic.'),
        ('Call graph & CFG', 'How execution flows between routines.'),
        ('Hardening properties', 'Observed NX, PIE, RELRO, canary, FORTIFY and PE flags.'),
    ]
    table(s, Inches(0.55), Inches(1.85), Inches(12.2), rows, 2, col_widths=[4.1, 8.1], row_height=Inches(0.48), font=12.5)
    tx(s, Inches(0.55), Inches(6.35), Inches(12.2), Inches(0.5),
       'Exposure evidence for a human decision — not a vulnerability verdict and not a security score.',
       size=13.5, bold=True, color=AMBER)
    notes(s, 'The report deliberately mixes static artefacts and hardening properties, but never merges '
             'them into a score. A name is not a vulnerability; a missing mitigation is not exploitability.')

    # 7 ─ Compare
    s = slide_base(deck, 7, 'Evidence')
    title(s, 'The comparison is the claim')
    bullets(s, [
        'ELF symbol-table entries: 35 → 0',
        'Byte-scan strings: 134 → 60',
        'File size: 15,904 → 10,784 bytes',
        'Debug sections and symbol table: present → absent',
    ], Inches(0.55), Inches(1.95), Inches(5.3), Inches(2.5), size=16)
    panel(s, Inches(0.55), Inches(4.55), Inches(5.3), Inches(1.55), fill=RGBColor(0x2A, 0x21, 0x0C), line=AMBER)
    tx(s, Inches(0.8), Inches(4.72), Inches(4.85), Inches(1.25),
       'Counts come from named tools. N/A means unmeasured, never zero. A smaller file is not automatically safer.',
       size=12, color=RGBColor(0xFD, 0xE6, 0x8A))
    image_fit(s, ASSETS / 'compare-metrics2.png', Inches(6.1), Inches(1.75), Inches(6.7), Inches(4.6))
    notes(s, 'This is a real symbol-removal comparison on Level 5, completed locally. The strongest line is '
             '35 → 0 ELF symbols, not the total file size. We explicitly warn that removing names does not '
             'remove logic: Ghidra still recovers the policy function.')

    # 8 ─ Hardening
    s = slide_base(deck, 8, 'Evidence')
    title(s, 'Static mitigation posture, with evidence')
    rows = [('Property', 'Level 5 original', 'Level 5 hardened'),
            ('NX / DEP', checks['level-5']['nx'].title(), checks['level-5-hardened']['nx'].title()),
            ('PIE / ASLR', checks['level-5']['pie'].title(), checks['level-5-hardened']['pie'].title()),
            ('RELRO', checks['level-5']['relro'].title(), 'Full'),
            ('Stack canary', checks['level-5']['canary'].title(), checks['level-5-hardened']['canary'].title()),
            ('FORTIFY', checks['level-5']['fortify'].title(), checks['level-5-hardened']['fortify'].title())]
    table(s, Inches(0.55), Inches(1.95), Inches(5.15), rows, 3, col_widths=[2.0, 1.6, 1.6],
          row_height=Inches(0.55), font=12.5)
    tx(s, Inches(0.55), Inches(5.9), Inches(5.15), Inches(0.8),
       'Observed file properties. Presence is not a guarantee; absence is not exploitability.',
       size=11.5, color=AMBER)
    image_fit(s, ASSETS / 'hardening3.png', Inches(6.0), Inches(1.75), Inches(6.8), Inches(4.7))
    notes(s, 'Two separately built ELF fixtures: the original Level 5 and a hardened build with PIE, full '
             'RELRO, stack protector and FORTIFY. The checker reads headers, dynamic tags and imports. '
             'This is static evidence, not a behaviour or exploitability test.')

    # 9 ─ OLLVM
    s = slide_base(deck, 9, 'Protection')
    title(s, 'A real source transformation — on our own samples only')
    stages = [('C source', 'self-authored'), ('LLVM IR', 'clang'), ('xollvm passes', 'flattening · BCF · subst. · strings'),
              ('Protected ELF', 'stripped, 0600')]
    for index, (head, body) in enumerate(stages):
        left = Inches(0.55) + index * Inches(3.08)
        panel(s, left, Inches(1.95), Inches(2.7), Inches(1.55))
        tx(s, left + Inches(0.18), Inches(2.12), Inches(2.35), Inches(0.35), head, size=15, bold=True, color=WHITE)
        tx(s, left + Inches(0.18), Inches(2.55), Inches(2.35), Inches(0.75), body, size=11, color=MUTED)
        if index < 3:
            tx(s, left + Inches(2.74), Inches(2.55), Inches(0.3), Inches(0.4), '→', size=18, bold=True, color=CYAN)
    bullets(s, [
        'Level 5: 15,904 → 109,296 bytes; all six policy messages removed from plaintext.',
        'ELF symbol table 35 → 0; Ghidra labels and generated code increase, so aggregate counts rise.',
        'Entropy 2.9213 → 6.4849 bits/byte; Ghidra still recovers the logic and takes longer.',
        'Obfuscation raises analysis cost — it is not proof of protection.',
    ], Inches(0.55), Inches(3.65), Inches(12.1), Inches(1.9), size=14.5)
    tx(s, Inches(0.55), Inches(6.05), Inches(12.1), Inches(0.55),
       'Scope: five original bundled sample sources. Arbitrary ELF/PE files remain analysis-only — a compiler pass cannot transform a binary without source.',
       size=11.5, color=AMBER)
    notes(s, 'This is a genuine compiler-level transformation, not a demo flag. Be precise: it only works '
             'on our self-authored sample sources. The protected copy is stripped and never executed on the '
             'host. Larger size and more Ghidra labels are expected effects, not a regression.')

    # 10 ─ QEMU
    s = slide_base(deck, 10, 'Verification')
    title(s, 'Behaviour check with a narrow, stated scope')
    panel(s, Inches(0.55), Inches(1.9), Inches(6.1), Inches(3.55))
    tx(s, Inches(0.8), Inches(2.1), Inches(5.6), Inches(0.35), 'WHAT RUNS', size=11, bold=True, color=CYAN, font=MONO)
    bullets(s, [
        'Separate original and protected driver builds.',
        'Packed into a minimal initramfs with a host kernel.',
        'QEMU micro-VM: no disk, no network, serial output only.',
        'Transcripts and exit codes compared; five self-authored samples.',
        'Every transcript and driver hash recorded in evidence.',
    ], Inches(0.82), Inches(2.5), Inches(5.55), Inches(2.8), size=13, gap=7)
    panel(s, Inches(6.95), Inches(1.9), Inches(5.85), Inches(3.55), fill=RGBColor(0x07, 0x1A, 0x14), line=GREEN)
    tx(s, Inches(7.2), Inches(2.1), Inches(5.3), Inches(0.35), 'RESULT', size=11, bold=True, color=GREEN, font=MONO)
    tx(s, Inches(7.2), Inches(2.5), Inches(5.3), Inches(0.9), '5 / 5', size=42, bold=True, color=WHITE)
    tx(s, Inches(7.2), Inches(3.35), Inches(5.3), Inches(0.35), 'deterministic driver vectors matched', size=13, color=TEXT)
    tx(s, Inches(7.2), Inches(3.85), Inches(5.3), Inches(0.35), 'exit codes 0 / 0   ·   QEMU return code 0', size=11.5, color=MUTED, font=MONO)
    tx(s, Inches(7.2), Inches(4.35), Inches(5.3), Inches(0.3), 'scope: separate_deterministic_drivers', size=10.5, color=MUTED, font=MONO)
    tx(s, Inches(7.2), Inches(4.75), Inches(5.3), Inches(0.3), 'artifact behaviour verified: false', size=10.5, color=AMBER, font=MONO)
    tx(s, Inches(0.55), Inches(6.1), Inches(12.1), Inches(0.75),
       'Critical scope: the guest ran separate driver builds, NOT the downloadable protected ELF. behavior_verified remains false for that artifact; matching vectors are not full equivalence.',
       size=11.5, color=AMBER)
    notes(s, 'This slide is deliberately conservative. The QEMU check is a bounded regression test for '
             'deterministic vectors. It does not execute the downloadable protected ELF and does not prove '
             'general behavioural equivalence. Saying this clearly is part of the engineering.')

    # 11 ─ Architecture
    s = slide_base(deck, 11, 'Architecture')
    title(s, 'Local architecture and trust boundary')
    boxes = [
        ('Browser UI', 'Operate · Compare · Monitor', 0.55, 2.0, 3.1, 1.25),
        ('Loopback API', 'token · origin checks · CSP', 4.05, 2.0, 3.1, 1.25),
        ('Job engine', 'queue · cancel · events', 7.55, 2.0, 3.1, 1.25),
        ('Evidence store', 'runs/<job>/ report.json', 10.35, 2.0, 2.4, 1.25),
        ('Tool adapters', 'readelf · objdump · strings · nm · Ghidra', 1.3, 3.95, 4.6, 1.2),
        ('Transform copies', 'strip · constant blind · OLLVM · hygiene', 6.3, 3.95, 4.6, 1.2),
        ('QEMU micro-VM', 'sample drivers only · no disk/network', 6.3, 5.35, 4.6, 1.05),
    ]
    for head, body, x, y, w, h in boxes:
        panel(s, Inches(x), Inches(y), Inches(w), Inches(h))
        tx(s, Inches(x + 0.18), Inches(y + 0.15), Inches(w - 0.3), Inches(0.35), head, size=14, bold=True, color=WHITE)
        tx(s, Inches(x + 0.18), Inches(y + 0.55), Inches(w - 0.3), Inches(0.6), body, size=10.5, color=MUTED)
    for x in (3.7, 7.2, 10.7):
        tx(s, Inches(x), Inches(2.45), Inches(0.35), Inches(0.35), '→', size=17, bold=True, color=CYAN)
    tx(s, Inches(5.95), Inches(4.35), Inches(0.35), Inches(0.35), '→', size=17, bold=True, color=CYAN)
    tx(s, Inches(8.45), Inches(5.15), Inches(0.35), Inches(0.3), '↓', size=16, bold=True, color=CYAN)
    tx(s, Inches(0.55), Inches(6.75), Inches(12.1), Inches(0.3),
       'Host targets are never executed. Only copies are transformed; QEMU is limited to separate deterministic sample drivers.',
       size=10.5, color=MUTED)
    notes(s, 'One Python process serves the loopback UI and runs bounded jobs. Tool adapters read the '
             'snapshot as data. Transformations always write a new copy. The only execution path is the '
             'sample-driver QEMU guest, and it is not reachable for external targets.')

    # 12 ─ Security
    s = slide_base(deck, 12, 'Security')
    title(s, 'Security posture and what backs it')
    rows = [
        ('Control / check', 'Evidence'),
        ('Loopback + session token', 'Every API read/write rejected without the per-session token'),
        ('Same-origin / CSP', 'Host, Origin, Referer and fetch-site checks; strict CSP'),
        ('No host target execution', 'Static tools read bytes; copies only; QEMU sample drivers isolated'),
        ('Operation/profile validation', 'Analysis jobs cannot dispatch a transformation (tested at HTTP level)'),
        ('Test suite', f"{tests['count']} tests, {tests['skipped']} skipped — Ghidra-enabled, passed"),
        ('SAST / secret scan', f"Bandit 0 high, 3 medium (tests only); detect-secrets: checksums/fixtures only"),
        ('Sample privacy & package', 'DWARF paths removed; 101-entry ZIP extracted and re-tested'),
    ]
    table(s, Inches(0.55), Inches(1.85), Inches(12.2), rows, 2, col_widths=[4.0, 8.2],
          row_height=Inches(0.5), font=11.5)
    tx(s, Inches(0.55), Inches(6.35), Inches(12.2), Inches(0.5),
       'Boundaries: the token is CSRF protection, not multi-user IAM; static parsers are not a malware sandbox.',
       size=11.5, color=AMBER)
    notes(s, 'Security of the workbench is separate from the security of the analysed binary. Give the '
             'concrete numbers: 167 tests, Bandit 0 high, token checks, operation/profile validation. '
             'Then state the boundaries before a judge asks.')

    # 13 ─ Differentiation
    s = slide_base(deck, 13, 'Positioning')
    title(s, 'Where ReverseShield fits')
    rows = [
        ('', 'Packer / protector', 'Vulnerability scanner', 'Manual Ghidra', 'ReverseShield'),
        ('Primary output', 'Claimed protection', 'CVE/CWE verdict', 'Expert notes', 'Exposure evidence'),
        ('Before / after', 'Rarely measured', 'Not applicable', 'Ad hoc', 'Bounded and repeatable'),
        ('Target execution', 'Runtime loader', 'Often none', 'Possible', 'Never on the host'),
        ('Works from binary', 'Yes', 'Yes', 'Yes', 'Yes (ELF/PE)'),
        ('States limits', 'Marketing copy', 'CVE database scope', 'Analyst judgement', 'Built into the report'),
    ]
    table(s, Inches(0.55), Inches(1.8), Inches(12.2), rows, 5,
          col_widths=[2.2, 2.6, 2.6, 2.2, 2.6], row_height=Inches(0.56), font=11)
    tx(s, Inches(0.55), Inches(6.25), Inches(12.1), Inches(0.6),
       'We do not claim to out-protect commercial tools. We make the comparison auditable and keep the limits visible.',
       size=13, bold=True, color=WHITE)
    notes(s, 'Keep this grounded. Commercial protectors and scanners are established products. The '
             'differentiation is transparent, reproducible comparison with explicit limits — not a claim '
             'of stronger obfuscation.')

    # 14 ─ Limits
    s = slide_base(deck, 14, 'Limits')
    title(s, 'What we do not claim')
    panel(s, Inches(0.55), Inches(1.9), Inches(5.95), Inches(3.6), fill=RGBColor(0x2A, 0x14, 0x14), line=RGBColor(0x7F, 0x1D, 0x1D))
    tx(s, Inches(0.8), Inches(2.08), Inches(5.4), Inches(0.4), 'NOT CLAIMED', size=12, bold=True, color=RGBColor(0xF8, 0x71, 0x71), font=MONO)
    bullets(s, [
        'That a build is “secure” or “unhackable”.',
        'CVE/CWE detection, risk scores or exploitability.',
        'Full behavioural equivalence from five vectors.',
        'Protection of arbitrary third-party binaries.',
        'Native-Windows OLLVM or a hardened sandbox.',
    ], Inches(0.85), Inches(2.55), Inches(5.4), Inches(3.6), size=13, gap=8, bullet_color=RGBColor(0xF8, 0x71, 0x71))
    panel(s, Inches(6.8), Inches(1.9), Inches(5.95), Inches(3.6), fill=RGBColor(0x0C, 0x22, 0x1B), line=RGBColor(0x16, 0x65, 0x4A))
    tx(s, Inches(7.05), Inches(2.08), Inches(5.4), Inches(0.4), 'KNOWN GAPS', size=12, bold=True, color=GREEN, font=MONO)
    bullets(s, [
        'Windows manual acceptance is still pending.',
        'QEMU tests separate drivers, not the downloadable ELF.',
        'Semgrep and ZAP were not re-run on this tree.',
        'Parser isolation and full dynamic analysis are future work.',
        'OLLVM is limited to the five original sample sources.',
    ], Inches(7.1), Inches(2.55), Inches(5.4), Inches(3.6), size=13, gap=8, bullet_color=GREEN)
    tx(s, Inches(0.55), Inches(5.8), Inches(12.1), Inches(0.5),
       'Every item above maps to an acceptance-matrix row or a documented test boundary — not a footnote added at the end.',
       size=12.5, color=MUTED)
    notes(s, 'Read this slide aloud. Judges trust teams that state limits before being asked. Every item '
             'here maps to an acceptance-matrix row or a documented limitation.')

    # 15 ─ Roadmap
    s = slide_base(deck, 15, 'Roadmap')
    title(s, 'From prototype to a repeatable release gate')
    phases = [
        ('NOW · 0.5', 'Evidence-first prototype', ['ELF/PE static analysis', 'Six samples', 'OLLVM + QEMU scope', 'Local release candidate']),
        ('NEXT', 'Release readiness', ['Windows manual acceptance', 'Signed, reproducible ZIP', 'CI on every change', 'Pilot with two teams']),
        ('RESEARCH', 'Deeper evidence', ['Isolated dynamic lab', 'SBOM / CVE correlation', 'More formats', 'Larger benchmark set']),
    ]
    for index, (phase, head, items) in enumerate(phases):
        left = Inches(0.55) + index * Inches(4.15)
        panel(s, left, Inches(1.95), Inches(3.9), Inches(3.85))
        tx(s, left + Inches(0.25), Inches(2.12), Inches(3.4), Inches(0.35), phase, size=11, bold=True, color=CYAN, font=MONO)
        tx(s, left + Inches(0.25), Inches(2.5), Inches(3.4), Inches(0.7), head, size=16, bold=True, color=WHITE)
        bullets(s, items, left + Inches(0.27), Inches(3.25), Inches(3.35), Inches(2.3), size=12, gap=6)
    tx(s, Inches(0.55), Inches(6.2), Inches(12.1), Inches(0.5),
       'The near-term goal is trust: reproducible builds, clean-platform evidence, and pilots that test whether the report changes release decisions.',
       size=12.5, color=MUTED)
    notes(s, 'Do not promise a commercial platform. The next milestone is release readiness and pilot '
             'feedback. Dynamic analysis is a research track because it changes the safety boundary.')

    # 16 ─ Team / close
    s = slide_base(deck, 16, 'Team')
    title(s, 'Four people, one evidence chain')
    team = [
        ('Naser', 'Day 1 · Windows & PE', 'Setup, PE acceptance, first-run reliability'),
        ('Zayed', 'Day 2 · Analysis accuracy', 'Metrics, Ghidra integration, one-click demo'),
        ('Nomai', 'Day 3 · Security & API', 'Token checks, sanitizer, SAST/DAST evidence'),
        ('Faisal', 'Day 4 · Integration', 'Release packaging, docs, evidence, demo'),
    ]
    for index, (name, role, detail) in enumerate(team):
        left = Inches(0.55) + (index % 2) * Inches(6.15)
        top = Inches(1.9) + (index // 2) * Inches(1.55)
        panel(s, left, top, Inches(5.85), Inches(1.35))
        tx(s, left + Inches(0.25), top + Inches(0.16), Inches(2.0), Inches(0.4), name, size=18, bold=True, color=CYAN)
        tx(s, left + Inches(0.25), top + Inches(0.58), Inches(2.4), Inches(0.35), role, size=10.5, color=MUTED, font=MONO)
        tx(s, left + Inches(0.25), top + Inches(0.92), Inches(5.3), Inches(0.35), detail, size=11.5, color=TEXT)
    tx(s, Inches(0.55), Inches(5.05), Inches(12.1), Inches(0.9), 'Evidence, not verdicts.', size=34, bold=True, color=WHITE)
    tx(s, Inches(0.55), Inches(5.9), Inches(12.1), Inches(0.5),
       'We are looking for technical feedback, a pilot team, and a reason to make the next build safer.',
       size=14, color=MUTED)
    notes(s, 'Close on the team and the ask. The project is a working local prototype with a documented '
             'evidence chain. We want feedback and a pilot, not a claim that the problem is finished.')

    deck.save(OUT)
    print(f'wrote {OUT.relative_to(ROOT)} ({len(deck.slides)} slides)')


if __name__ == '__main__':
    build()
