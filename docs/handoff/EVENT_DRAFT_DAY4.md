# D4-04 — IS CyberNext submission DRAFT / owner checklist

**Status:** Draft text only; **not registered, uploaded, submitted or published**. Official public pages checked 11 November 2026 (+03:00). The owner must review and approve the final text and materials first; submission is planned **only after that review**, by the owner through the official site. Do not put applicant/team identity numbers, private contacts, credentials, or local workstation paths in this repository.

## Official live requirements and timing

- The official English event page names three fields, including **Cybersecurity**, and calls the listed project examples illustrative rather than exhaustive.[1]
  Its FAQ accepts university students, recent graduates and innovators, from concept to developed project stages.[1]
  Teams may have **up to four people total, including the primary applicant**, and its team FAQ describes them as actual project/product founders.[1]
  The Terms also permit individual/team submissions from outside Saudi Arabia, with potential relevance to the Saudi market required for applicants based outside the Kingdom.[3]
- The homepage Timeline says **registration closes 12 November 2026** and explicitly says its dates are **Riyadh time**.[1] **Cutoff hour/minute and whether submissions remain open throughout 12 November are not published in the inspected public pages**; do not assume 23:59 or a different local timezone. Owner should verify the live form/organizer cutoff immediately, leave margin, and re-check the date just before any owner-authorized submission. This is a deadline, not permission to submit this draft.[1][2]
- The homepage marks the **1–3 December 2026 Black Hat final stage postponed** and says final-stage details will be updated.[1]
  It still lists finalist announcements for **23–24 November 2026**.[1]
  The Terms §11 and some FAQ text retain the earlier 1–3 December attendance wording; treat the final-stage **date as uncertain** pending an organizer update, not as a confirmed itinerary.[1][3]
  In-person attendance by at least one principal team representative is required if selected.[1][3]
- Project materials/introductory content must be in **English**; the live judging-presentation language is to be confirmed.[1] Evaluation criteria include innovation/technical value, clarity, industry relevance, and future implementation potential; no numerical weighting is stated in the inspected pages.[1][3]
- The public **Before You Start** screen shows five stages: **Your Information** (contact details, optional team members), **Your Project** (problem, solution, technologies, stage), **A Few Quick Questions** (participation, discovery, main objective), **File Uploads** (at least one supporting file or link; video optional), **Review & Submit** (review and declarations).[2] These are stage descriptions, **not verified inner-field labels, wording, choices, character limits, file types, or size limits**. This draft does not proceed past that public screen.
- The Terms §§4, 6, 8–10 require accurate lawful submissions, rights/permissions for third-party material and authorization for the principal applicant to supply team information; IP stays with original rights holders, while approved project names/descriptions/images/promotional materials can be used for event promotion. Acceptance, privacy, rights and publicity decisions belong to the owner and affected participants, not this document.[3]

## Suggested short answers — map to actual form only after owner review

**Project title / field (suggestion, not a verified form label):** ReverseShield — Reverse-Engineering Exposure Workbench; Cybersecurity. The event's cybersecurity examples are illustrative; do **not** describe the project as malware detection, a vulnerability scanner, incident response, DLP, or cyber recovery.[1] Local grounding: `README.md` §§What the workbench does, Scope and safety; `docs/event/DAY3_EVENT_REVIEW.md` §Project fit.

**Problem:** Software teams can distribute ELF/PE builds that expose symbol names, debug information, file paths, strings and recoverable logic without first examining what a static analyst can learn. They need a practical pre-release view of that evidence. Local grounding: `README.md` §§What the workbench does; `docs/event/PITCH_DECK_DRAFT.md` §§Slides 2, 6 (historical Day 2 sample measurements, not a general benchmark).

**Solution:** ReverseShield is a local, loopback workbench for authorized static inspection of Linux ELF and Windows PE files. It discovers/selects targets, runs available bounded static tools, shows evidence and tool coverage, and compares selected changes on a copy. It can export a reduced sanitized report for human review. Selected targets are not executed on the host; the product is not a malware sandbox or a protection guarantee. Local grounding: `README.md` §§What the workbench does, Scope and safety, Day 3 privacy and sharing; `docs/handoff/DAY3.md`.

**Technology:** Python standard-library server/workflow and ELF/PE parsing; browser HTML/CSS/JavaScript; available GNU static-analysis tools and optional Ghidra headless. Optional **Linux-only**, bundled-source OLLVM/xollvm comparison uses deterministic original/protected sample drivers inside a QEMU micro-VM without disk or network. No arbitrary target is transformed through the OLLVM source profile or executed for that check. Local grounding: `README.md` §§Quick start, What the workbench does, Scope and safety; `docs/evidence/ollvm-five-qemu.json`.

**Stage:** Working local prototype, not a released/validated product. The current `0.5.0-team` work is on a feature branch, **not merged or released**. Local Fedora evidence records matching deterministic QEMU transcripts for **five self-authored sample drivers**, which does not prove full behavioral equivalence or resistance; a sixth hardened Level 5 fixture has **static mitigation-property evidence only**, not a behavior check. A clean-machine native Windows manual test and owner-approved submission/release materials remain pending. Local grounding: `VERSION`, `CHANGELOG.md` §0.5.0-team, `docs/evidence/ollvm-five-qemu.json`, `docs/evidence/hardening-level5.json`, and the local branch state as reviewed on 11 November 2026. Do not substitute historical PDF claims for current proof.

**Participation (suggested narrative, not a verified form label):** We propose a cybersecurity-track project and can demonstrate an evidence-first local prototype. **[OWNER-ONLY: confirm whether applying individually or as an actual-founder team, count ≤4 total, eligible participant categories, principal representative and attendance capacity. Do not prefill private details here.]**[1][3]

**Discovery:** **[OWNER-ONLY UNKNOWN: how the applicant actually learned of IS CyberNext; do not invent a channel.]** The public introduction identifies discovery as a topic but does not show its exact input or options.[2]

**Main objective:** Present the prototype and its limitations honestly, obtain technical feedback from cybersecurity reviewers and potential users, and validate whether its local evidence/comparison workflow helps teams inspect build exposure before release. This is an objective, **not** a claim of existing customers, measured impact, certification, or commercial deployment.

## Owner-only pre-submission gates (nothing to upload now)

- [ ] Resolve the **12 November Riyadh-time cutoff hour** with the live form or organizer; do not infer 23:59. Recheck whether the final-stage schedule has changed and whether the proposed principal representative can attend in person if selected.[1][3]
- [ ] Confirm eligibility, actual-founder/team status, ≤4 participants including primary applicant, consent/authority for team data, Saudi-market relevance if applying from outside Saudi Arabia, and accurate private applicant details **in the official form only**.[1][3]
- [ ] Open the actual interactive form **only when the owner authorizes registration**; check the real field wording, constraints, declarations, upload limits/types and whether supporting links are accepted as described on the introduction. Unknowns remain unknown until verified.[2]
- [ ] Owner reviews English pitch against the current branch/release state. Verify any numerical result against its recorded evidence and don't imply Ghidra/OLLVM is always installed or Windows clean-machine testing is complete. Confirm whether a finalized, reviewed artifact exists before claiming release readiness.
- [ ] Choose **at least one** supporting file or accessible link; video is optional on the public introduction.[2] Inspect each candidate PDF, screenshot, archive, sanitized report and link for stale claims, personal paths, recovered strings, secrets, embedded binary metadata and reviewer accessibility. Older report PDFs and Day 2 slides are historical; do not upload them unreviewed. Do not publish raw `runs/`, toolchains, or an unreviewed release package.
- [ ] Owner and affected participants review Terms/Privacy Policy, IP/third-party licenses, promotional-use and photography provisions, and make any required declarations themselves. No acceptance or consent is recorded by this draft.[3]
- [ ] **After** owner approval and cutoff verification, owner may decide whether/how to complete the official registration. This file is not a submission confirmation; no event account, form, upload, or publication action has been taken here.

## Sources

[1] https://iscybernext.com/en — IS CyberNext — English event page (Timeline, Fields, FAQ)
[2] https://iscybernext.com/en/register — IS CyberNext — registration introduction (before Start Registration)
[3] https://iscybernext.com/en/terms — IS CyberNext — Terms & Conditions
