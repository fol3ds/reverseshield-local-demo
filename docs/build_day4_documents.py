#!/usr/bin/env python3
"""Build the Day 4 DOCX/PDF pair with verified static contents page numbers.

Two-pass layout: build without a page map, render with LibreOffice, detect the
page where each numbered heading actually appears, rebuild with those numbers,
then re-render and assert the contents table matches the detected pages.
No target binary is read or executed here.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import build_plan  # noqa: E402
import build_report  # noqa: E402


def norm(text: str) -> str:
    for dash in ("\u2014", "\u2013", "\u2011"):
        text = text.replace(dash, "-")
    return re.sub(r"\s+", " ", text).strip()


def page_text(pdf: Path, page: int) -> str:
    result = subprocess.run(
        ["pdftotext", "-layout", "-f", str(page), "-l", str(page), str(pdf), "-"],
        capture_output=True, text=True, check=False,
    )
    return result.stdout


def page_count(pdf: Path) -> int:
    result = subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True, check=False)
    match = re.search(r"^Pages:\s+(\d+)$", result.stdout, re.M)
    return int(match.group(1)) if match else 0


def convert(docx: Path) -> Path:
    subprocess.run(
        ["soffice", "--headless", "--convert-to", "pdf", str(docx), "--outdir", str(docx.parent)],
        capture_output=True, text=True, check=False,
    )
    pdf = docx.with_suffix(".pdf")
    if not pdf.is_file():
        raise RuntimeError(f"PDF conversion failed for {docx.name}")
    return pdf


def find_toc_page(pdf: Path, total: int) -> int:
    for page in range(1, min(total, 8) + 1):
        if "Contents" in page_text(pdf, page):
            return page
    raise RuntimeError("Contents page not found")


def map_pages(pdf: Path, titles: tuple[str, ...], toc_page: int, total: int) -> dict[str, str]:
    pages = {page: norm(page_text(pdf, page)) for page in range(1, total + 1)}
    mapping: dict[str, str] = {}
    for title in titles:
        needle = norm(title)
        found = next((page for page in range(toc_page + 1, total + 1) if needle in pages[page]), None)
        if found is None:
            raise RuntimeError(f"heading not found after contents page: {title}")
        mapping[title] = f"{found:02d}"
    return mapping


def verify_contents(pdf: Path, titles: tuple[str, ...], mapping: dict[str, str], toc_page: int) -> None:
    text = norm(page_text(pdf, toc_page))
    for title in titles:
        expected = f"{norm(title)} {mapping[title]}"
        if expected not in text:
            raise RuntimeError(f"contents entry mismatch, expected: {expected}")


def finalize(module, titles: tuple[str, ...], label: str) -> dict:
    docx = module.build()
    pdf = convert(docx)
    total = page_count(pdf)
    toc_page = find_toc_page(pdf, total)
    mapping = map_pages(pdf, titles, toc_page, total)

    final_total = total
    for _ in range(3):
        module.build(module.OUT, mapping)
        pdf = convert(module.OUT)
        final_total = page_count(pdf)
        toc_page = find_toc_page(pdf, final_total)
        detected = map_pages(pdf, titles, toc_page, final_total)
        if detected == mapping:
            verify_contents(pdf, titles, mapping, toc_page)
            return {"document": label, "docx": module.OUT.name, "pdf": pdf.name,
                    "pages": final_total, "contents": mapping}
        mapping = detected
    raise RuntimeError(f"{label}: contents page numbers did not stabilize")


if __name__ == "__main__":
    results = [
        finalize(build_report, build_report.TOC, "technical report"),
        finalize(build_plan, build_plan.TOC, "readiness plan"),
    ]
    print(json.dumps(results, indent=2))
