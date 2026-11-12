"""Packaging must include reviewed source, never incidental workspace data."""
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.package_lite_windows import main, source_files
import hashlib
import zipfile


class PackageSelectionTests(unittest.TestCase):
    def test_archive_keeps_run_script_executable_but_samples_non_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'source'
            root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'run.sh').write_text('#!/bin/sh\npython3 app.py\n', encoding='utf-8')
            (root / 'fixture.elf').write_bytes(b'ELF-data-not-executed')
            subprocess.run(['git', '-C', str(root), 'add', 'run.sh', 'fixture.elf'], check=True)
            subprocess.run(['git', '-C', str(root), 'update-index', '--chmod=+x', 'run.sh'], check=True)
            (root / 'run.sh').chmod(0o755)
            output = Path(temp) / 'release.zip'
            main(root=root, output=output, checksum_output=Path(temp) / 'SHA256SUMS.txt')
            with zipfile.ZipFile(output) as archive:
                launch = archive.getinfo('reverseshield-local-demo/run.sh')
                sample = archive.getinfo('reverseshield-local-demo/fixture.elf')
                self.assertEqual((launch.external_attr >> 16) & 0o111, 0o111)
                self.assertEqual((sample.external_attr >> 16) & 0o111, 0)

    def test_unstaged_change_to_indexed_source_refuses_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'source'
            root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'README.md').write_text('reviewed', encoding='utf-8')
            subprocess.run(['git', '-C', str(root), 'add', 'README.md'], check=True)
            (root / 'README.md').write_text('unreviewed edit', encoding='utf-8')
            output = Path(temp) / 'release.zip'
            with self.assertRaisesRegex(RuntimeError, 'unstaged'):
                main(root=root, output=output, checksum_output=Path(temp) / 'SHA256SUMS.txt')
            self.assertFalse(output.exists())

    def test_candidate_zip_and_detached_checksum_are_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'source'
            root.mkdir()
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'README.md').write_text('sample workbench', encoding='utf-8')
            subprocess.run(['git', '-C', str(root), 'add', 'README.md'], check=True)
            output = Path(temp) / 'dist' / 'ReverseShield_Lite_Windows_v0.5.0-team.zip'
            checksum = output.parent / 'SHA256SUMS.txt'
            main(root=root, output=output, checksum_output=checksum)
            self.assertTrue(output.is_file())
            self.assertEqual(checksum.read_text(encoding='ascii'),
                             f'{hashlib.sha256(output.read_bytes()).hexdigest()}  {output.name}\n')
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.namelist(), ['reverseshield-local-demo/README.md'])

    def test_only_git_index_files_are_packaged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'README.md').write_text('source', encoding='utf-8')
            (root / 'private.log').write_text('sensitive workspace data', encoding='utf-8')
            (root / 'samples/bin').mkdir(parents=True)
            (root / 'samples/bin/fixture.elf').write_bytes(b'ELF fixture')
            subprocess.run(['git', '-C', str(root), 'add', 'README.md', 'samples/bin/fixture.elf'], check=True)
            result = sorted(p.resolve().relative_to(root.resolve()).as_posix() for p in source_files(root))
            self.assertEqual(result, ['README.md', 'samples/bin/fixture.elf'])

    def test_raw_scan_assets_and_video_are_not_source_archive_entries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            files = {
                'README.md': b'source',
                'docs/security/raw.json': b'raw scanner path',
                'docs/assets/old-screen.png': b'old screenshot',
                'docs/handoff/private.md': b'internal handoff',
                'docs/event/draft.md': b'not for release',
                'docs/evidence/hardening-level5.json': b'{"sanitized":true}',
                'docs/demo/storyboard.md': b'local narration script',
                'docs/performance-day3.json': b'historical machine notes',
                'docs/demo/draft.mp4': b'video draft',
            }
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            subprocess.run(['git', '-C', str(root), 'add', '-f', *files], check=True)
            result = sorted(p.resolve().relative_to(root.resolve()).as_posix() for p in source_files(root))
            self.assertEqual(result, ['README.md',
                                      'docs/evidence/hardening-level5.json'])

    def test_retired_team_notes_are_excluded_but_retained_guides_are_packaged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            files = {
                'README.md': b'public setup',
                'docs/AI_CONTEXT.md': b'retained architecture and safety guidance',
                'docs/RELEASE_CHECKLIST.md': b'preserved privacy and acceptance gates',
                'docs/GITHUB_WORKFLOW.md': b'retired team handoff',
                'docs/IS_CYBERNEXT_REQUIREMENTS.md': b'retired event planning',
                'docs/NASER_AGENT_PROMPT.md': b'retired agent prompt',
                'docs/TEAM_TASKS_DAY1-4.md': b'retired team assignments',
            }
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            subprocess.run(['git', '-C', str(root), 'add', *files], check=True)
            selected = sorted(path.resolve().relative_to(root.resolve()).as_posix()
                              for path in source_files(root))
            self.assertEqual(selected, ['README.md', 'docs/AI_CONTEXT.md',
                                        'docs/RELEASE_CHECKLIST.md'])

    def test_tracked_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / 'README.md').write_text('source', encoding='utf-8')
            (root / 'escape').symlink_to('/etc/passwd')
            subprocess.run(['git', '-C', str(root), 'add', 'README.md', 'escape'], check=True)
            self.assertEqual([p.name for p in source_files(root)], ['README.md'])


if __name__ == '__main__':
    unittest.main()
