# Local silent demo draft

`reverseshield-d4-silent-draft.mp4` is a **2:36 silent, captioned evidence-based storyboard**, not footage of a complete live workflow. Its two real UI images are `ui-operate.png` (local Operate landing view) and `ui-level5-select.png` (Level 5 selected, without running it); remaining frames are Pillow-generated cards from the two local JSON evidence records. `contact-sheet.png` samples all nine scenes for review. The separate owner voiceover is in `narration-and-storyboard.md`.

Rebuild locally from the repository root:

```sh
python scripts/create_demo_video.py
ffprobe -v error -show_entries format=duration:stream=codec_name,codec_type,width,height,r_frame_rate -of json docs/demo/reverseshield-d4-silent-draft.mp4
python -m unittest tests.test_demo_video -v
```

Requires Pillow, ffmpeg with `libopenh264`, and the Montserrat fonts (falls back to DejaVu). With `--no-screenshot`, the UI scene becomes a caption card if screen capture is unavailable. The generator **does not execute binaries or rerun QEMU**; it reads `docs/evidence/hardening-level5.json` and `docs/evidence/ollvm-five-qemu.json`, then encodes still frames locally. QEMU evidence covers only the five original self-authored sample drivers; the sixth hardened fixture is analysis-only. The static hardening states are not a security score. No audio track, event upload, public link, or real target execution was created.
