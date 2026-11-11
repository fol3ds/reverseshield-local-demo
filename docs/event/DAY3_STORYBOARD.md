# Three-minute English storyboard

Prepare: use the supplied self-authored Level 5 fixture. Finish one analysis and
comparison before recording. Confirm the tools available on the recording PC;
show actual coverage. Hide private folders, raw logs and notifications.

| Time | Exact view/action | Narration |
|---|---|---|
| 0:00–0:20 | Title / team slide | “ReverseShield helps security analysts and developers understand what their binaries expose.” |
| 0:20–0:35 | Operate → execution boundary | “We inspect Windows PE and Linux ELF as data. We never launch the selected program.” |
| 0:35–0:55 | Run demo · Level 5 | “This starts a static analysis of our own sample. Available tools and skipped coverage are explicit.” |
| 0:55–1:15 | Report on completed run; label any recording cut | “Hashes identify the input. Metadata, string categories and tool coverage explain what was measured.” |
| 1:15–1:40 | Compare → select prepared symbol-removal result | “This comparison changes a copy. Symbols and metadata can disappear while the program's logic remains recoverable.” |
| 1:40–2:00 | Compare → limitations | “These are exposure measurements, not a security score or proof of protection.” |
| 2:00–2:25 | Download sanitized report → open JSON summary | “The export preserves hashes and metrics, omits raw output and recovered code, and redacts local identifiers. The full original stays local.” |
| 2:25–2:45 | Validation slide | “We test access controls, malformed inputs and report integrity. These are the measured results, including skips and remaining platform checks.” |
| 2:45–3:00 | Team / roadmap slide | “Our four-person team seeks analyst and developer feedback. Next are hardening checks, CI integration and isolated adapters.” |

If Ghidra is slow: choose lightweight tools or use the labelled precomputed run.
Never substitute uncollected metrics with zero. Actual video recording, rehearsal
and final slide rendering belong to Faisal's Day 4 release gate.
