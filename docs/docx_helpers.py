"""Reusable formatting helpers for the submission DOCX files.

Inputs are document objects, text and layout values; outputs are formatted
document elements. Helpers do not inspect or execute target binaries. Extend
with document-only formatting functions shared by report and plan builders.
"""
from __future__ import annotations

import re
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_TAB_ALIGNMENT, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Mm, Pt, RGBColor

NAVY = "0B1220"
INK = "0F172A"
CYAN = "0E7490"
SLATE = "334155"
MUTED = "64748B"
LIGHT = "F8FAFC"
LINE = "CBD5E1"
AMBER = "B45309"
AMBER_BG = "FFFBEB"
GREEN = "15803D"
GREEN_BG = "F0FDF4"
RED = "B91C1C"
RED_BG = "FEF2F2"


def _shade(cell, fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _cell_border(cell, color: str = LINE, sz: int = 4, edges=("top", "left", "bottom", "right")) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    borders = OxmlElement("w:tcBorders")
    for edge in edges:
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(sz))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tc_pr.append(borders)


def _table_borders(table, color: str = LINE, sz: int = 4) -> None:
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), str(sz))
        el.set(qn("w:space"), "0")
        el.set(qn("w:color"), color)
        borders.append(el)
    tbl_pr.append(borders)


def _cell_margins(cell, top=60, bottom=60, left=90, right=90) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for edge, value in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:w"), str(value))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tc_pr.append(mar)


def _repeat_header(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def _cant_split(row) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:cantSplit")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def _row_height(row, mm: float) -> None:
    tr_pr = row._tr.get_or_add_trPr()
    height = OxmlElement("w:trHeight")
    height.set(qn("w:val"), str(int(mm * 56.7)))
    height.set(qn("w:hRule"), "atLeast")
    tr_pr.append(height)


def _field(paragraph, instruction: str, placeholder: str) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instr = OxmlElement("w:instrText")
    instr.set(qn("xml:space"), "preserve")
    instr.text = instruction
    separate = OxmlElement("w:fldChar")
    separate.set(qn("w:fldCharType"), "separate")
    text = OxmlElement("w:t")
    text.text = placeholder
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.append(begin)
    run._r.append(instr)
    run._r.append(separate)
    run._r.append(text)
    run._r.append(end)


def _add_rich(paragraph, text: str, base_size: float = 10.5) -> None:
    """Render **bold** and `code` spans without external markdown."""
    for part in re.split(r"(\*\*.*?\*\*|`.*?`)", text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            run = paragraph.add_run(part[1:-1])
            run.font.name = "Consolas"
            run.font.size = Pt(max(8.0, base_size - 1.0))
            run.font.color.rgb = RGBColor.from_string(CYAN)
        else:
            run = paragraph.add_run(part)
        run.font.size = Pt(base_size)


def setup_document(title: str, header_right: str = "v1.0 · November 2026") -> Document:
    doc = Document()
    section = doc.sections[0]
    section.page_width = Mm(210)
    section.page_height = Mm(297)
    section.top_margin = Mm(20)
    section.bottom_margin = Mm(18)
    section.left_margin = Mm(19)
    section.right_margin = Mm(19)
    section.header_distance = Mm(9)
    section.footer_distance = Mm(9)
    section.different_first_page_header_footer = True

    styles = doc.styles
    normal = styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string("1F2937")
    normal.paragraph_format.space_after = Pt(4)
    normal.paragraph_format.line_spacing = 1.12

    for name, size, color, before, after in (
        ("Heading 1", 18, NAVY, 14, 8),
        ("Heading 2", 13, CYAN, 12, 5),
        ("Heading 3", 11.5, SLATE, 9, 3),
    ):
        style = styles[name]
        style.font.name = "Calibri"
        style.font.size = Pt(size)
        style.font.bold = True
        style.font.color.rgb = RGBColor.from_string(color)
        style.paragraph_format.space_before = Pt(before)
        style.paragraph_format.space_after = Pt(after)
        style.paragraph_format.keep_with_next = True

    for name in ("List Bullet", "List Number"):
        style = styles[name]
        style.font.name = "Calibri"
        style.font.size = Pt(10.5)
        style.paragraph_format.space_after = Pt(2)
        style.paragraph_format.line_spacing = 1.08

    # Header and footer (not on the cover).
    header = section.header
    hp = header.paragraphs[0]
    hp.text = ""
    hp.paragraph_format.tab_stops.add_tab_stop(Mm(172), WD_TAB_ALIGNMENT.RIGHT)
    left = hp.add_run(title)
    left.font.name = "Calibri"
    left.font.size = Pt(8)
    left.font.color.rgb = RGBColor.from_string(MUTED)
    hp.add_run("\t")
    right = hp.add_run(header_right)
    right.font.name = "Calibri"
    right.font.size = Pt(8)
    right.font.color.rgb = RGBColor.from_string(MUTED)
    border = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "4")
    bottom.set(qn("w:space"), "4")
    bottom.set(qn("w:color"), LINE)
    border.append(bottom)
    hp._p.get_or_add_pPr().append(border)

    footer = section.footer
    fp = footer.paragraphs[0]
    fp.text = ""
    fp.paragraph_format.tab_stops.add_tab_stop(Mm(172), WD_TAB_ALIGNMENT.RIGHT)
    fp.add_run("ReverseShield · submission copy")
    fp.runs[0].font.size = Pt(8)
    fp.runs[0].font.color.rgb = RGBColor.from_string(MUTED)
    fp.add_run("\t")
    fp.add_run("Page ")
    _field(fp, " PAGE ", "1")
    fp.add_run(" of ")
    _field(fp, " NUMPAGES ", "1")
    for run in fp.runs:
        run.font.size = Pt(8)
        run.font.color.rgb = RGBColor.from_string(MUTED)

    return doc


def add_cover(doc: Document, title: str, subtitle: str, kicker: str, meta: list[tuple[str, str]],
              note_title: str = "How to read this document",
              note_text: str | None = None) -> None:
    bar = doc.add_table(rows=1, cols=1)
    bar.autofit = False
    bar.alignment = WD_TABLE_ALIGNMENT.LEFT
    cell = bar.rows[0].cells[0]
    cell.width = Mm(172)
    _shade(cell, NAVY)
    _row_height(bar.rows[0], 10)
    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    run = p.add_run("REVERSESHIELD  /  LOCAL SECURITY WORKBENCH")
    run.font.name = "Consolas"
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor.from_string("A5F3FC")
    run.bold = True

    spacer(doc, 18)
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(kicker.upper())
    run.font.name = "Consolas"
    run.font.size = Pt(9)
    run.font.color.rgb = RGBColor.from_string(CYAN)
    run.bold = True

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(title)
    run.font.name = "Calibri"
    run.font.size = Pt(30)
    run.font.bold = True
    run.font.color.rgb = RGBColor.from_string(NAVY)

    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(14)
    run = p.add_run(subtitle)
    run.font.name = "Calibri"
    run.font.size = Pt(13)
    run.font.color.rgb = RGBColor.from_string(SLATE)

    rule = doc.add_table(rows=1, cols=1)
    rule.autofit = False
    rule.alignment = WD_TABLE_ALIGNMENT.LEFT
    rc = rule.rows[0].cells[0]
    rc.width = Mm(172)
    _shade(rc, CYAN)
    _row_height(rule.rows[0], 1.2)
    rc.paragraphs[0].add_run("").font.size = Pt(1)

    spacer(doc, 10)
    add_table(doc, ["Document", "Value"], meta, widths=[38, 134], font_size=9.2, header_fill=NAVY)
    spacer(doc, 8)
    if note_text is None:
        note_text = (
            "This is an execution document, not a marketing description. Every task has an output and an acceptance check. "
            "Analyzed targets are never executed on the host; optional QEMU runs only "
            "separate self-authored deterministic drivers. "
            "Security claims are limited to observed artifact changes."
        )
    add_callout(
        doc,
        note_title,
        note_text,
        fill="ECFEFF",
        accent=CYAN,
    )
    doc.add_page_break()


def spacer(doc: Document, points: float = 4) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.line_spacing = 1.0
    run = p.add_run("")
    run.font.size = Pt(max(1, points))


def h1(doc: Document, text: str, page_break: bool = False) -> None:
    p = doc.add_heading(text, level=1)
    if page_break:
        p.paragraph_format.page_break_before = True
    p.paragraph_format.keep_with_next = True


def h2(doc: Document, text: str) -> None:
    doc.add_heading(text, level=2)


def h3(doc: Document, text: str) -> None:
    doc.add_heading(text, level=3)


def para(doc: Document, text: str, size: float = 10.5, after: float = 4, italic: bool = False) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(after)
    _add_rich(p, text, size)
    if italic:
        for run in p.runs:
            run.italic = True


def bullets(doc: Document, items: list[str]) -> None:
    for item in items:
        p = doc.add_paragraph(style="List Bullet")
        _add_rich(p, item)


def steps(doc: Document, items: list[str], start: int = 1) -> None:
    for i, item in enumerate(items, start):
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Mm(6)
        p.paragraph_format.first_line_indent = Mm(-6)
        p.paragraph_format.space_after = Pt(2)
        run = p.add_run(f"{i}. ")
        run.bold = True
        _add_rich(p, item)


def add_table(
    doc: Document,
    headers: list[str],
    rows: list[list[str]],
    widths: list[float] | None = None,
    font_size: float = 8.5,
    header_fill: str = NAVY,
    zebra: bool = True,
) -> None:
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = False
    _table_borders(table)
    hdr = table.rows[0]
    _repeat_header(hdr)
    _cant_split(hdr)
    for i, text in enumerate(headers):
        cell = hdr.cells[i]
        _shade(cell, header_fill)
        _cell_margins(cell)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        run = p.add_run(str(text))
        run.bold = True
        run.font.size = Pt(font_size)
        run.font.color.rgb = RGBColor.from_string("FFFFFF")
    for r_index, row in enumerate(rows):
        tr = table.add_row()
        _cant_split(tr)
        for i, value in enumerate(row):
            cell = tr.cells[i]
            _cell_margins(cell)
            if zebra and r_index % 2 == 1:
                _shade(cell, "F1F5F9")
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            run = p.add_run(str(value))
            run.font.size = Pt(font_size)
            run.font.color.rgb = RGBColor.from_string("1F2937")
    if widths:
        for row in table.rows:
            for i, width in enumerate(widths):
                if i < len(row.cells):
                    row.cells[i].width = Mm(width)
    spacer(doc, 3)


def add_code(doc: Document, text: str, size: float = 8.2) -> None:
    table = doc.add_table(rows=1, cols=1)
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.rows[0].cells[0]
    cell.width = Mm(172)
    _shade(cell, LIGHT)
    _cell_border(cell, LINE, 4)
    _cell_margins(cell, top=80, bottom=80, left=110, right=110)
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.space_before = Pt(0)
    p.paragraph_format.line_spacing = 1.0
    lines = text.splitlines() or [""]
    for i, line in enumerate(lines):
        if i:
            p.add_run().add_break(WD_BREAK.LINE)
        run = p.add_run(line if line else " ")
        run.font.name = "Consolas"
        run.font.size = Pt(size)
        run.font.color.rgb = RGBColor.from_string("0F172A")
        run._element.set(qn("xml:space"), "preserve")
    spacer(doc, 3)


def add_callout(doc: Document, title: str, text: str, fill: str = AMBER_BG, accent: str = AMBER) -> None:
    table = doc.add_table(rows=1, cols=1)
    table.autofit = False
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.rows[0].cells[0]
    cell.width = Mm(172)
    _shade(cell, fill)
    _cell_border(cell, accent, 10, edges=("left",))
    _cell_margins(cell, top=90, bottom=90, left=120, right=110)
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(2)
    run = p.add_run(title)
    run.bold = True
    run.font.size = Pt(9.5)
    run.font.color.rgb = RGBColor.from_string(accent)
    p2 = cell.add_paragraph()
    p2.paragraph_format.space_after = Pt(0)
    _add_rich(p2, text, 9.2)
    spacer(doc, 4)


def add_caption(doc: Document, text: str) -> None:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(6)
    run = p.add_run(text)
    run.italic = True
    run.font.size = Pt(8.5)
    run.font.color.rgb = RGBColor.from_string(MUTED)


def add_image(doc: Document, path: str, width_mm: float = 168) -> None:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(2)
    p.add_run().add_picture(path, width=Mm(width_mm))


def add_static_toc(doc: Document, entries: list[tuple[str, str]]) -> None:
    """A deterministic TOC table; page numbers are filled by the build script."""
    h1(doc, "Contents", page_break=True)
    para(doc, "Page numbers refer to this PDF build. The Word file uses the same section order.", size=8.5, italic=True)
    add_table(doc, ["Section", "Page"], [[title, str(page)] for title, page in entries],
              widths=[152, 20], font_size=9.2, header_fill=NAVY, zebra=False)
    table = doc.tables[-1]
    for row in table.rows:
        row.cells[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.RIGHT
    doc.add_page_break()


def add_page_break(doc: Document) -> None:
    doc.add_page_break()
