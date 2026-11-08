# IS CyberNext — Application Draft (Day 1)

Working text only. The project owner should review the wording, confirm team
participation details and verify the live event requirements before submitting.
This draft intentionally contains no identity numbers or private contact data.

## Problem

Development teams often ship binaries containing readable functions, strings,
symbols, debug metadata or build paths without seeing what a static reviewer can
recover. Teams need a safe, local way to inspect that evidence before release.

## Solution

ReverseShield is a local workbench for authorized static inspection of Linux ELF
and Windows PE files. It discovers targets, records bounded tool output, parses
format metadata and compares selected changes on copies. It does not execute or
emulate targets, and it is not a malware sandbox or a production protection
product.

## Technology

Python standard library for the local API and workflow; HTML, CSS and
JavaScript for the loopback interface; bounded ELF/PE metadata parsers; GNU
binutils; and optional Ghidra headless analysis. Windows builds use project-local
JDK and MinGW tools when available.

## Stage

Working local prototype with Windows PE upload, discovery and static analysis
validated. The team is seeking technical feedback and further validation; the
prototype does not claim behavioral equivalence or reverse-engineering
resistance.

## Participation

Draft response: cybersecurity-track team application. Confirm the final
participant count (maximum four total), each participant's category, and
availability privately with the team owner before submission.

## Discovery

Placeholder: **[Confirm how the applicant learned about IS CyberNext.]**

## Main objective

Present a reproducible, safety-conscious prototype, receive feedback from
cybersecurity reviewers, and identify the next measurements needed to improve
analysis accuracy and evidence quality.

## Supporting files and links

- Project report PDF: **[Regenerate from `docs/build_report.py` and export a
  sanitized PDF before submission.]**
- Execution plan PDF: **[Regenerate from `docs/build_plan.py` and export a
  sanitized PDF before submission.]**
- Demo video: **[2–3 minute video link to be added after recording.]**
- Repository or Lite release: **[Owner to add the approved repository/release link.]**
- Optional source package: `ReverseShield_Lite_Windows_Day1.zip` (size and
  SHA-256 are recorded in `docs/handoff/DAY1.md`).

## Owner follow-up

- Official English FAQ reviewed 8 November 2026: teams must be actual project
  founders and may have up to four people; a representative must present if
  selected; finalists attend in person; application materials are in English;
  IP remains with original rights holders subject to the Terms & Conditions.
- Official source: <https://iscybernext.com/en>. Recheck the live Terms &
  Conditions and confirm eligibility, attendance availability, and the actual
  discovery source before submission.
- Confirm the actual discovery source and final participation details.
- Confirm current dates and eligibility again before submission.
- Replace placeholders only in the official event form or an approved shared
  location; never put private identity data in this repository.
