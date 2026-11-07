# IS CyberNext 2026 — Requirements and ReverseShield Gap Analysis

Source: <https://iscybernext.com/en> and <https://iscybernext.com/en/register>
Checked: 7 November 2026 (Riyadh time). This is a working summary, not legal or
organiser advice. Re-check the live site and the Terms & Conditions before
submitting; dates and FAQ answers can change.

## 1. What the event is

IS CyberNext is an initiative by **Innovative Solutions (IS)** for university
students, recent graduates and technical innovators. Selected projects present
at **Black Hat 2026** in Riyadh.

| Item | Published detail |
|---|---|
| Registration opens | 20 October 2026 |
| Registration closes | **12 November 2026** |
| Finalists announced | 23–24 November 2026 |
| Final stage | 1–3 December 2026 at Black Hat, Riyadh (published; Black Hat 2026 has been postponed and organisers say new dates are coming) |
| Tracks | Cybersecurity; Cloud Computing & Systems Integration; Data & Artificial Intelligence |
| Team size | Up to **4 participants total** (primary applicant + up to 3 additional members) |
| Prize pool | SAR 100,000 total: 50,000 / 30,000 / 20,000 |
| Contact | info@iscybernext.com |
| Language | FAQ asks about presentation language; prepare **English** (with Arabic optional) |

The event page currently shows an **Important update: Black Hat 2026
Postponed**. Registration still closes on 12 November 2026; the final-stage
dates may change. Submit on time and keep the team reachable.

## 2. Registration flow and fields

The registration wizard has five steps:

1. **Your Information** — full legal name, date of birth, nationality,
   National ID/Iqama/passport number, gender, mobile, email, LinkedIn,
   participant category, country/city of residence; optional additional team
   members (up to 3).
2. **Your Project** — problem, solution, technologies, stage.
3. **A Few Quick Questions** — participation, discovery and main objective.
4. **File Uploads** — at least one supporting file or link; optional video.
5. **Review & Submit** — review and declarations.

### Practical submission package

- [ ] Primary applicant details complete and consistent with ID.
- [ ] All team members added (maximum 4); each has a role and LinkedIn if
      available.
- [ ] Project title: **ReverseShield — Reverse-Engineering Exposure Workbench**.
- [ ] Problem statement (short, non-alarmist).
- [ ] Solution statement (what the workbench does and does not do).
- [ ] Technology list (Python stdlib, Ghidra headless, ELF/PE parsing, HTML/JS).
- [ ] Stage: working local prototype / demonstration, seeking validation.
- [ ] Supporting PDF: project report and 4-day plan.
- [ ] Demo video link (2–3 minutes, unlisted or public).
- [ ] Repository/release link or ZIP under the upload limit.
- [ ] Team roles and contact details.
- [ ] Declarations reviewed; IP/third-party rights confirmed.

## 3. What the event evaluates (and what the site does not state)

The extracted public page does **not** publish a numeric scoring rubric. Do not
invent one. The FAQ asks **"How are submissions evaluated?"** and the Terms &
Conditions govern declarations; read those answers in the live site before
submitting.

For a strong cybersecurity-track submission, assume reviewers will look for:

- a real problem and a clear affected user;
- a technically credible solution, not only slides;
- novelty or a defensible improvement over existing practice;
- feasibility and a working demonstration;
- security, safety and responsible-use awareness;
- measurable evidence or a clear evaluation plan;
- team capability and clear ownership;
- presentation quality and a realistic roadmap.

## 4. ReverseShield gap analysis

### What is already strong

| Area | Current evidence |
|---|---|
| Working local prototype | Loopback browser workbench; discovery, async jobs, live logs |
| Real static analysis | `file`, `readelf`, `objdump`, `strings`, `nm`, Ghidra headless |
| Linux and Windows formats | ELF and PE metadata/discovery; PE analysis path added for the team edition |
| Evidence trail | `runs/<job_id>/` snapshots, tool logs, JSON reports, hashes |
| Before/after comparison | Symbol removal, demo constant blinding, binary metadata hygiene |
| Safety model | No target execution; loopback only; token-protected state changes; sample-only source transforms |
| Documentation | Report, plan, architecture/pipeline diagrams, UI evidence, SAST baselines |
| Testing | 58 automated tests, 1 opt-in Ghidra skip; Ghidra opt-in test passes |

### Gaps that must be closed before submission

| # | Gap | Why it matters | Owner / day |
|---|---|---|---|
| 1 | Windows native validation | Three teammates use Windows; demo must run there normally | Naser / Day 1 |
| 2 | Analysis accuracy and coverage | Reviewers ask what the tool actually recovers | Zayed / Day 2 |
| 3 | One-click, polished demo | A live demo must work under time pressure | Zayed + Nomai / Day 2–3 |
| 4 | SAST/DAST and data-leak evidence | Security project must show its own security | Nomai / Day 3 |
| 5 | Sanitized reports | Reports currently contain local paths and demo keys | Nomai / Day 3 |
| 6 | Event narrative and pitch | The project must be understandable in 2–3 minutes | Zayed + Nomai / Day 2–3 |
| 7 | Video and screenshots | Required supporting evidence; remote reviewers | Faisal / Day 4 |
| 8 | Packaging and checksums | Reviewers/team must reproduce the run | Faisal / Day 4 |
| 9 | Registration and team data | Hard deadline 12 November | Naser draft; Faisal submit |
| 10 | Claims discipline | Demo protection is not real obfuscation | Everyone |

### What ReverseShield must not claim

- It is **not** a malware sandbox, antivirus, EDR or dynamic analysis platform.
- It does **not** execute or detonate targets.
- The source transformer is **demonstration-only**; `behavior_verified: false`.
- Binary hygiene removes metadata; it is **not** a binary rewriter, packer,
  virtualiser or anti-tamper product.
- A changed file size or missing symbols is **not** a security score.
- No claim of “unbypassable”, “military-grade” or “certified” protection.

## 5. Positioning for the cybersecurity track

**One-line pitch:** “ReverseShield is a local evidence workbench that shows a
software team what a reverse engineer can recover from its build, then measures
the effect of practical release-hygiene changes.”

**Problem:** Teams ship binaries with debug paths, symbols, compiler notes and
readable policy logic. They rarely see the attacker's view before release.

**Solution:** authorised static analysis of ELF/PE files, live evidence, and a
before/after comparison of copy-only transformations, with explicit limits.

**Why now:** software supply-chain scrutiny and reverse-engineering exposure are
increasing; teams need a lightweight pre-release check, not a heavyweight
reverse-engineering platform.

**Differentiation:** local-first, no target execution, no cloud upload, evidence
rather than a score, Windows/Linux team workflow, transparent limitations.

**Impact:** helps developers prioritise release hygiene (debug info, symbols,
paths, exposed constants) before distribution.

**Roadmap:** more formats (Mach-O, APK, DEB), richer import/export analysis,
sanitized evidence packs, CI integration, and a validated protection profile.

## 6. Three-minute demo script

| Time | Screen | Narration |
|---|---|---|
| 0:00–0:20 | Title / problem | “A build can reveal more than source. ReverseShield makes that exposure visible before release.” |
| 0:20–0:40 | Operate → Level 5 | “I select a bundled sample; nothing is executed.” |
| 0:40–1:20 | Live analysis | “Six static tools; Ghidra recovers functions and call edges; every event is recorded.” |
| 1:20–1:50 | Compare → symbol removal | “We copy the sample, remove symbols/debug metadata, reanalyse, and compare.” |
| 1:50–2:20 | Compare → demo blinding | “A demonstration-grade source transform changes constants and adds a guard; Ghidra can still recover the policy, so we do not call this real protection.” |
| 2:20–2:40 | Report / limitations | “Evidence, hashes, limitations, no target execution.” |
| 2:40–3:00 | Close | “Windows and Linux, local-first, built by a four-person team; next step is CI and broader formats.” |

Record at 1080p, no notifications, no personal paths, no terminal secrets. Use a
clean Windows machine for at least half the footage and Fedora for the rest.

## 7. Ten-slide pitch outline

1. Title, team, one-line pitch.
2. Problem: what binaries leak; who cares.
3. Current practice and why it is hard for small teams.
4. Solution: local evidence workbench.
5. Live architecture: discovery → snapshot → tools → compare.
6. Demo evidence: Level 5 before/after (real screenshots).
7. Safety and responsible use: no execution, loopback, authorised targets.
8. Validation: tests, SAST/DAST, Windows/Fedora matrix.
9. Impact and roadmap.
10. Team, ask, contact.

## 8. Submission-day checklist

- [ ] Registration fields complete, team added, IDs/contact consistent.
- [ ] PDF report + plan uploaded (under size limit).
- [ ] Video link works in a private browser window.
- [ ] Repository/release link accessible to reviewers, or ZIP under limit.
- [ ] No `tools/`, `runs/`, `backups/`, `.env`, keys or personal paths in the
      submitted archive.
- [ ] Checksums and `VERSION` included.
- [ ] English text proofread; Arabic optional.
- [ ] Declarations and IP/third-party rights reviewed.
- [ ] Submission confirmation screenshot saved.
- [ ] Team notified; final-stage availability checked.

## 9. Open questions to confirm with the organisers

- Is in-person attendance required for the final stage, and for how many team
  members?
- What is the exact presentation language and time limit?
- What are the evaluation criteria and weightings?
- Are projects from outside Saudi Arabia eligible, and are travel costs covered?
- What file size/type limits apply to uploads and video links?
- Who owns IP created during the event, and what licence do finalists grant?
- How does the Black Hat postponement affect final-stage dates and travel?

Ask via info@iscybernext.com or the official WhatsApp community; keep written
answers with the submission evidence.
