"""Tests for local path discovery and mocked Linux package metadata.

Inputs are temporary directory trees and inert executable headers; outputs are
target records and scan diagnostics. No discovered file is launched. Extend
with platform-specific walkers and explicit capability-based skips.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import discovery


@unittest.skipIf(os.name == "nt", "Flatpak discovery is Linux-only")
class FlatpakDiscoveryTests(unittest.TestCase):
    def test_parse_flatpak_list_preserves_application_metadata(self):
        raw = "com.example.Editor\tExample Editor\t2.4.1\tstable\tsystem\n"
        apps = discovery.parse_flatpak_list(raw)
        self.assertEqual(apps, [{
            "app_id": "com.example.Editor",
            "name": "Example Editor",
            "version": "2.4.1",
            "branch": "stable",
            "installation": "system",
        }])

    def test_list_flatpak_apps_uses_read_only_flatpak_list(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            return discovery.CommandResult(0, "com.example.App\tExample\t1.0\tstable\tsystem\n", "")

        apps = discovery.list_flatpak_apps(runner=runner)
        self.assertEqual(apps[0]["app_id"], "com.example.App")
        self.assertEqual(calls, [["flatpak", "list", "--app", "--columns=application,name,version,branch,installation"]])

    def test_find_elf_targets_scans_regular_files_and_ignores_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "app"
            (root / "files/bin").mkdir(parents=True)
            (root / "files/lib").mkdir(parents=True)
            (root / "files/bin/easyeffects").write_bytes(b"\x7fELF" + b"\0" * 8)
            (root / "files/lib/libfx.so").write_bytes(b"\x7fELF" + b"\1" * 8)
            (root / "files/share/readme.txt").parent.mkdir(parents=True)
            (root / "files/share/readme.txt").write_text("not an executable")
            outside = Path(temporary) / "outside.elf"
            outside.write_bytes(b"\x7fELF" + b"\2" * 8)
            (root / "files/bin/outside-link").symlink_to(outside)

            targets = discovery.find_elf_targets(root / "files")

            self.assertEqual({target["relative_path"] for target in targets}, {"bin/easyeffects", "lib/libfx.so"})
            self.assertTrue(all(target["size_bytes"] == 12 for target in targets))

    def test_discover_flatpak_targets_resolves_only_installed_application(self):
        calls = []

        def runner(args, **kwargs):
            calls.append(args)
            if args[:3] == ["flatpak", "list", "--app"]:
                return discovery.CommandResult(0, "com.example.App\tExample\t1.0\tstable\tsystem\n", "")
            return discovery.CommandResult(0, "/var/lib/flatpak/app/com.example.App/x86_64/stable/deploy\n", "")

        with tempfile.TemporaryDirectory() as temporary:
            deploy = Path(temporary) / "deploy"
            (deploy / "files/bin").mkdir(parents=True)
            (deploy / "files/bin/example").write_bytes(b"\x7fELF" + b"\0" * 4)

            def installed_runner(args, **kwargs):
                if args[:3] == ["flatpak", "list", "--app"]:
                    calls.append(args)
                    return discovery.CommandResult(0, "com.example.App\tExample\t1.0\tstable\tsystem\n", "")
                calls.append(args)
                if "--show-runtime" in args:
                    return discovery.CommandResult(0, "org.example.Platform/x86_64/24.08\n", "")
                return discovery.CommandResult(0, str(deploy) + "\n", "")

            result = discovery.discover_flatpak_targets("com.example.App", runner=installed_runner)
            self.assertEqual(result["app"]["app_id"], "com.example.App")
            self.assertEqual([item["relative_path"] for item in result["targets"]], ["bin/example"])
            self.assertEqual(result["runtime"]["dependencies"], ["org.example.Platform/x86_64/24.08"])
            self.assertFalse(result["runtime"]["scanned"])
            self.assertIn(["flatpak", "info", "--show-runtime", "com.example.App"], calls)
            self.assertEqual(calls[-1], ["flatpak", "info", "--show-location", "com.example.App"])

    def test_discover_flatpak_targets_rejects_uninstalled_application(self):
        def runner(args, **kwargs):
            return discovery.CommandResult(0, "com.example.Other\tOther\t1\tstable\tsystem\n", "")

        with self.assertRaises(ValueError):
            discovery.discover_flatpak_targets("com.example.Missing", runner=runner)


class ToolLaunchErrorTests(unittest.TestCase):
    def test_unlaunchable_tool_is_reported_as_unavailable(self):
        def runner(*_args, **_kwargs):
            raise PermissionError(13, "Permission denied", "flatpak")
        with self.assertRaisesRegex(RuntimeError, "cannot be started: flatpak"):
            discovery._command(["flatpak", "list"], runner)


class PathDiscoveryTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative symlink race is not a Windows path")
    def test_file_replaced_by_symlink_at_open_is_never_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            candidate = root / "candidate"
            candidate.write_bytes(b"\x7fELFinitial")
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"\x7fELFoutside")
            real_path_open, real_os_open = Path.open, os.open
            swapped = []

            def swap():
                if not swapped:
                    candidate.unlink()
                    candidate.symlink_to(outside)
                    swapped.append(True)

            def path_open(path, *args, **kwargs):
                if path == candidate:
                    swap()
                return real_path_open(path, *args, **kwargs)

            def fd_open(path, flags, *args, **kwargs):
                if str(path) in (str(candidate), candidate.name):
                    swap()
                return real_os_open(path, flags, *args, **kwargs)

            with patch.object(Path, "open", path_open), patch.object(os, "open", fd_open):
                result = discovery.discover_path(root, workspace=root / "work")
            self.assertTrue(swapped)
            self.assertEqual(result["targets"], [])
            self.assertFalse(result["scan"]["complete"])

    def test_directory_limit_counts_empty_directories_too(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(5):
                (root / str(index)).mkdir()
            with patch.object(discovery, "MAX_SCAN_FILES", 3):
                with self.assertRaisesRegex(ValueError, "safety limit"):
                    discovery.discover_path(root, workspace=root / "work")

    @unittest.skipIf(os.name == "nt", "Windows ACL permissions are not changed by chmod(0)")
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root bypasses chmod(0); run as a normal user")
    def test_unreadable_directory_is_reported_as_partial(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            blocked = root / "blocked"
            blocked.mkdir()
            blocked.chmod(0)
            try:
                result = discovery.discover_path(root, workspace=root / "work")
                self.assertIn("scan", result)
                self.assertFalse(result["scan"]["complete"])
                self.assertTrue(result["scan"]["errors"])
            finally:
                blocked.chmod(0o700)

    def test_folder_excludes_tooling_hidden_venvs_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for folder in ("tools", "runs", "backups", ".git", ".hidden", ".venv", "venv", "node_modules", "bin"):
                (root / folder).mkdir()
                (root / folder / "sample").write_bytes(b"\x7fELF")
            try:
                (root / "bin/alias").symlink_to(root / "bin/sample")
            except OSError:
                # Windows needs Developer Mode or admin rights to create symlinks
                # (WinError 1314); the folder and venv exclusions are still checked.
                pass
            (root / "custom-environment").mkdir()
            (root / "custom-environment/pyvenv.cfg").write_text("home = unused")
            (root / "custom-environment/sample").write_bytes(b"\x7fELF")
            result = discovery.discover_path(root, workspace=root / "runs")
            self.assertEqual([item["relative_path"] for item in result["targets"]], ["bin/sample"])

    def test_selected_elf_accepts_inventory_magic_with_64_mib_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "sample.elf"
            with source.open("wb") as stream:
                stream.write(b"\x7fELF")
                stream.truncate(64 * 1024 * 1024)
            result = discovery.discover_path(source, workspace=Path(temporary) / "work")
            target = result["targets"][0]
            self.assertEqual(target["relative_path"], source.name)
            self.assertEqual(os.path.normcase(os.path.realpath(target["absolute_path"])),
                             os.path.normcase(os.path.realpath(source)))
            self.assertTrue(target["analyzable"])
            with source.open("ab") as stream:
                stream.write(b"x")
            self.assertFalse(discovery.discover_path(source, workspace=Path(temporary))["targets"][0]["analyzable"])

    def test_selected_folder_inventory_uses_same_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "selected"
            (root / "bin").mkdir(parents=True)
            (root / "bin/app").write_bytes(b"\x7fELFminimal")
            (root / "readme.txt").write_text("data only")
            self.assertTrue(callable(getattr(discovery, "discover_path", None)))
            result = discovery.discover_path(root, workspace=Path(temporary) / "work")
            self.assertEqual(result["app"]["name"], "selected")
            self.assertEqual([item["relative_path"] for item in result["targets"]], ["bin/app"])
            self.assertFalse(result["runtime"]["scanned"])
            self.assertEqual(result["runtime"]["dependencies"], [])


if __name__ == "__main__":
    unittest.main()
