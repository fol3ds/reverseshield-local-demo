"""The local-only demo must distinguish static and QEMU evidence."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/create_demo_video.py'


def load_module():
    if importlib.util.find_spec('PIL') is None:
        raise unittest.SkipTest(
            'optional Pillow is not installed; install requirements-docs.txt to run demo tests')
    spec = importlib.util.spec_from_file_location('create_demo_video', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DemoVideoTests(unittest.TestCase):
    def test_evidence_backed_scenes_have_bounded_duration_and_qemu_scope(self):
        module = load_module()
        facts = module.load_evidence(ROOT / 'docs/evidence')
        scenes = module.make_scenes(facts, screenshot=False)
        captions = ' '.join(' '.join(scene.lines) for scene in scenes)
        self.assertGreaterEqual(sum(scene.seconds for scene in scenes), 120)
        self.assertLessEqual(sum(scene.seconds for scene in scenes), 180)
        self.assertEqual(facts['baseline']['pie'], 'absent')
        self.assertEqual(facts['hardened']['pie'], 'present')
        self.assertEqual(facts['qemu_count'], 5)
        self.assertIn('analysis-only', captions)
        self.assertIn('original', captions.lower())
        self.assertNotIn('/home/', captions)
        self.assertNotIn('sha256', captions.lower())

    def test_slide_renders_at_video_size_without_input_screenshot(self):
        module = load_module()
        facts = module.load_evidence(ROOT / 'docs/evidence')
        scenes = module.make_scenes(facts, screenshot=False)
        image = module.render_slide(scenes[0], 0, len(scenes), screenshot=None)
        self.assertEqual(image.size, (1280, 720))
        self.assertEqual(image.mode, 'RGB')
        self.assertGreater(len(image.getcolors(maxcolors=1000000) or []), 10)

    def test_sample_scene_uses_real_selector_image_when_available(self):
        module = load_module()
        facts = module.load_evidence(ROOT / 'docs/evidence')
        scenes = module.make_scenes(facts, screenshot=True, sample_screenshot=True)
        self.assertEqual(scenes[1].kind, 'screenshot')
        self.assertEqual(scenes[2].kind, 'sample_screenshot')

    def test_unmatched_qemu_vector_rejected_not_advertised_as_match(self):
        module = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            for name in ('hardening-level5.json', 'ollvm-five-qemu.json'):
                (evidence / name).write_bytes((ROOT / 'docs/evidence' / name).read_bytes())
            qemu_path = evidence / 'ollvm-five-qemu.json'
            qemu = json.loads(qemu_path.read_text())
            qemu['samples'][0]['matched'] = False
            qemu_path.write_text(json.dumps(qemu))
            with self.assertRaisesRegex(ValueError, 'QEMU'):
                module.load_evidence(evidence)


if __name__ == '__main__':
    unittest.main()
