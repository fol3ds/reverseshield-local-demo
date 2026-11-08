#!/usr/bin/env python3
"""Finalize table-of-contents page numbers in generated ReverseShield DOCX files.

Inputs are DOCX files and LibreOffice page-layout output; output is updated
document fields. This document tool does not inspect or execute target
binaries. Extend only the submission document rendering workflow.
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
    text = text.replace("\u2014", "-").replace("\u2013", "-").replace("\u2011", "-")
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
    return docx.with_suffix(".pdf")


def find_toc_page(pdf: Path, total: int) -> int:
    for page in range(1, min(total, 8) + 1):
        if "Contents" in page_text(pdf, page):
            return page
    return 0


def map_pages(pdf: Path, titles: list[str], toc_page: int, total: int) -> dict[str, str]:
    pages = {page: norm(page_text(pdf, page)) for page in range(1, total + 1)}
    mapping: dict[str, str] = {}
    for title in titles:
        needle = norm(title)
        found = None
        for page in range(toc_page + 1, total + 1):
            if needle in pages[page]:
                found = page
                break
        if found is None:
            for page in range(1, total + 1):
                if needle in pages[page] and page != toc_page:
                    found = page
                    break
        mapping[title] = f"{found:02d}" if found else "??"
    return mapping


def finalize(module, titles: list[str], label: str) -> dict[str, str]:
    docx = module.build()
    pdf = convert(docx)
    total = page_count(pdf)
    toc_page = find_toc_page(pdf, total)
    mapping = map_pages(pdf, titles, toc_page, total)
    print(f"{label}: first pass {total} pages, TOC page {toc_page}")
    print(json.dumps(mapping, indent=2, ensure_ascii=False))

    for attempt in range(2):
        docx = module.build(mapping)
        pdf = convert(docx)
        total = page_count(pdf)
        toc_page = find_toc_page(pdf, total)
        new_mapping = map_pages(pdf, titles, toc_page, total)
        if new_mapping == mapping:
            print(f"{label}: stable at {total} pages")
            break
        # Keep the stable layout, but report what changed.
        changed = {k: (mapping.get(k), new_mapping.get(k)) for k in titles if mapping.get(k) != new_mapping.get(k)}
        print(f"{label}: page shifts on attempt {attempt + 1}: {changed}")
        mapping = new_mapping
    return mapping


if __name__ == "__main__":
    finalize(build_plan, build_plan.TOC_ENTRIES, "plan")
    finalize(build_report, build_report.TOC_ENTRIES, "report")
