#!/usr/bin/env python3
"""Render a local-only, silent evidence storyboard; no target is executed."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import subprocess
import tempfile

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
SIZE = (1280, 720)
BACKGROUND = '#10151c'
PANEL = '#1b222c'
WHITE = '#e9eef5'
MUTED = '#a9b4c3'
BLUE = '#79a9ff'
GREEN = '#65d092'
AMBER = '#f6bb6d'
FONT_REGULAR = Path('/usr/share/fonts/julietaula-montserrat-fonts/Montserrat-Regular.otf')
FONT_BOLD = Path('/usr/share/fonts/julietaula-montserrat-fonts/Montserrat-Bold.otf')


@dataclass(frozen=True)
class Scene:
    seconds: int
    tag: str
    title: str
    lines: tuple[str, ...]
    kind: str = 'text'


def load_evidence(folder: Path) -> dict:
    """Fail closed if evidence no longer supports the captions."""
    hard = json.loads((folder / 'hardening-level5.json').read_text(encoding='utf-8'))
    qemu = json.loads((folder / 'ollvm-five-qemu.json').read_text(encoding='utf-8'))
    hard_samples = {item['sample_id']: item for item in hard['samples']}
    if set(hard_samples) != {'level-5', 'level-5-hardened'}:
        raise ValueError('Expected original and hardened Level 5 static fixtures')
    keys = {'nx', 'pie', 'relro', 'canary', 'fortify'}
    checks = {}
    for label, sample_id in [('baseline', 'level-5'), ('hardened', 'level-5-hardened')]:
        source = hard_samples[sample_id]['hardening']
        if source['format'] != 'ELF' or set(source['checks']) != keys:
            raise ValueError('Unexpected Level 5 ELF hardening evidence')
        checks[label] = {key: source['checks'][key]['state'] for key in keys}
    samples = qemu['samples']
    if {row['sample_id'] for row in samples} != {f'level-{i}' for i in range(1, 6)} or len(samples) != 5:
        raise ValueError('QEMU comparison must cover exactly five original samples')
    if any(row['matched'] is not True or row['exit_codes'] != {'original': 0, 'protected': 0}
           or row['qemu_return_code'] != 0 for row in samples):
        raise ValueError('QEMU comparison is not fully matched in the evidence')
    if qemu.get('scope') != 'separate_deterministic_drivers' or qemu.get('artifact_behavior_verified') is not False:
        raise ValueError('QEMU evidence scope does not distinguish separate drivers from the downloadable artifact')
    if any(row.get('scope') != 'separate_deterministic_drivers'
           or row.get('artifact_behavior_verified') is not False for row in samples):
        raise ValueError('QEMU sample rows must state the separate-driver scope')
    return {'baseline': checks['baseline'], 'hardened': checks['hardened'],
            'qemu_count': len(samples)}


def make_scenes(facts: dict, screenshot: bool, sample_screenshot: bool = False) -> list[Scene]:
    """Timings and on-frame claims; separate QEMU from static hardening."""
    names = {'nx': 'NX / DEP', 'pie': 'PIE / ASLR', 'relro': 'RELRO',
             'canary': 'Stack canary', 'fortify': 'FORTIFY'}
    def rows(which: str) -> tuple[str, ...]:
        return tuple(f'{names[k]}  |  {facts[which][k].upper()}' for k in names)

    return [
        Scene(13, 'D4 / LOCAL DRAFT', 'ReverseShield',
              ('What can static analysis reveal?', 'Evidence-based storyboard, not a live screen recording.'), 'hero'),
        Scene(17, 'LOCAL WORKBENCH', 'Start with the interface',
              ('Captured local UI: static analysis by default.',
               'A host target is read as data, not executed.'), 'screenshot' if screenshot else 'text'),
        Scene(17, 'BUNDLED SAMPLE', 'A bounded example',
              ('Self-authored Level 5 policy engine.',
               'Inspect the original file, then a separate hardened fixture.'),
              'sample_screenshot' if sample_screenshot else 'text'),
        Scene(20, 'STATIC ELF CHECKS / ORIGINAL', 'Baseline properties', rows('baseline'), 'checks'),
        Scene(20, 'STATIC ELF CHECKS / HARDENED', 'Hardened fixture', rows('hardened'), 'checks'),
        Scene(18, 'INTERPRETATION', 'These are not security scores',
              ('Static properties do not establish exploitability.',
               'A present mitigation is not a security guarantee.'), 'text'),
        Scene(20, 'SEPARATE QEMU EVIDENCE', 'Five original sample drivers',
              (f'{facts["qemu_count"]} separate deterministic driver vectors matched.',
               'QEMU micro-VM: no disk and no network.',
               'Not the downloadable protected ELF.'), 'text'),
        Scene(15, 'SCOPE BOUNDARY', 'Do not conflate the checks',
              ('The hardened sixth fixture is analysis-only.',
               'QEMU did not test it or arbitrary target behavior.'), 'text'),
        Scene(16, 'NEXT / OWNER RECORDING', 'Evidence, with limits',
              ('Inspect  →  compare  →  qualify the result.',
               'Silent draft; narration is a separate recording script.'), 'outro'),
    ]


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    path = FONT_BOLD if bold else FONT_REGULAR
    if not path.exists():
        path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf' if bold
                    else '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
    return ImageFont.truetype(str(path), size)


def render_slide(scene: Scene, index: int, count: int, screenshot: Path | None) -> Image.Image:
    """Render a captioned frame, with an actual screenshot only when supplied."""
    image = Image.new('RGB', SIZE, BACKGROUND)
    draw = ImageDraw.Draw(image)
    # A repeatable technical texture; no synthetic fake UI elements.
    for x in range(0, 1280, 36):
        for y in range(0, 720, 36):
            draw.ellipse((x + 8, y + 8, x + 10, y + 10), fill='#202b37')
    draw.rounded_rectangle((30, 25, 1250, 686), radius=22, fill=PANEL, outline='#334253', width=2)
    draw.rectangle((30, 25, 1250, 31), fill=BLUE)
    draw.text((66, 55), scene.tag, font=_font(20, True), fill=BLUE)
    draw.text((1120, 56), f'{index + 1:02}/{count:02}', font=_font(18), fill=MUTED)

    if scene.kind in ('screenshot', 'sample_screenshot') and screenshot is not None:
        draw.text((66, 94), scene.title, font=_font(43, True), fill=WHITE)
        with Image.open(screenshot) as source:
            source = source.convert('RGB').crop((0, 0, 1440, 590 if scene.kind == 'screenshot' else 630))
            source.thumbnail((1136, 418), Image.Resampling.LANCZOS)
            x = (SIZE[0] - source.width) // 2
            image.paste(source, (x, 150))
        draw.rounded_rectangle((72, 575, 1208, 645), radius=9, fill='#10151c')
        draw.text((91, 582), scene.lines[0], font=_font(19, True), fill=WHITE)
        draw.text((91, 613), scene.lines[1], font=_font(18), fill=MUTED)
    elif scene.kind == 'checks':
        draw.text((66, 105), scene.title, font=_font(49, True), fill=WHITE)
        for row, label in enumerate(scene.lines):
            y = 201 + row * 75
            name, state = [item.strip() for item in label.split('|')]
            color = GREEN if state == 'PRESENT' else AMBER if state == 'PARTIAL' else '#ef9091'
            draw.rounded_rectangle((66, y, 1212, y + 62), radius=12, fill='#111b25')
            draw.text((92, y + 15), name, font=_font(25, True), fill=WHITE)
            w = draw.textbbox((0, 0), state, font=_font(23, True))[2]
            draw.text((1177 - w, y + 17), state, font=_font(23, True), fill=color)
    else:
        draw.text((66, 130), scene.title, font=_font(54, True), fill=WHITE)
        draw.rounded_rectangle((66, 262, 1212, 552), radius=20, fill='#111b25', outline='#344456', width=2)
        for i, line in enumerate(scene.lines):
            y = 324 + i * 95
            draw.ellipse((92, y + 10, 110, y + 28), fill=GREEN if i == 0 else BLUE)
            draw.text((138, y), line, font=_font(26 if len(line) > 55 else 30, i == 0), fill=WHITE)
        if scene.kind == 'hero':
            draw.text((75, 586), 'SELF-AUTHORED FIXTURES  /  BOUNDED EVIDENCE', font=_font(19, True), fill=MUTED)
        if scene.kind == 'outro':
            draw.text((75, 586), 'NO PUBLIC LINK  ·  NO EVENT UPLOAD', font=_font(19, True), fill=MUTED)

    draw.text((66, 657), 'EVIDENCE-BASED STORYBOARD  ·  SILENT LOCAL DRAFT', font=_font(15, True), fill=MUTED)
    draw.rectangle((30, 683, 30 + round(1220 * (index + 1) / count), 687), fill=BLUE)
    return image


def create_video(output: Path, evidence_dir: Path, screenshot: Path | None) -> int:
    """Encode still caption slides locally; return their exact sum in seconds."""
    facts = load_evidence(evidence_dir)
    if screenshot is not None and not screenshot.is_file():
        raise FileNotFoundError(screenshot)
    sample_screenshot = screenshot.parent / 'ui-level5-select.png' if screenshot is not None else None
    scenes = make_scenes(facts, screenshot is not None,
                         sample_screenshot is not None and sample_screenshot.is_file())
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='reverseshield-demo-') as temp:
        folder = Path(temp)
        manifest = folder / 'slides.ffconcat'
        entries = ['ffconcat version 1.0']
        for i, scene in enumerate(scenes):
            frame = folder / f'scene-{i:02}.png'
            reference = sample_screenshot if scene.kind == 'sample_screenshot' else screenshot
            render_slide(scene, i, len(scenes), reference).save(frame)
            entries.extend((f"file '{frame}'", f'duration {scene.seconds}'))
        last_frame = folder / f'scene-{len(scenes) - 1:02}.png'
        entries.append(f"file '{last_frame}'")  # ffconcat honors the final duration.
        manifest.write_text('\n'.join(entries) + '\n', encoding='utf-8')
        subprocess.run(['ffmpeg', '-hide_banner', '-loglevel', 'error', '-y',
                        '-f', 'concat', '-safe', '0', '-i', str(manifest),
                        '-t', str(sum(scene.seconds for scene in scenes)),
                        '-r', '24', '-c:v', 'libopenh264', '-b:v', '2500k',
                        '-pix_fmt', 'yuv420p', '-an',
                        '-movflags', '+faststart', str(output)], check=True)
    return sum(scene.seconds for scene in scenes)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'docs/demo/reverseshield-d4-silent-draft.mp4')
    parser.add_argument('--evidence-dir', type=Path, default=ROOT / 'docs/evidence')
    parser.add_argument('--screenshot', type=Path, default=ROOT / 'docs/demo/ui-operate.png')
    parser.add_argument('--no-screenshot', action='store_true')
    args = parser.parse_args()
    duration = create_video(args.output, args.evidence_dir,
                            None if args.no_screenshot else args.screenshot)
    print(f'Created {args.output} ({duration}s; silent storyboard)')


if __name__ == '__main__':
    main()
