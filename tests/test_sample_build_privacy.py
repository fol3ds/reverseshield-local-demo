"""Compile-only privacy checks; ELF fixtures are read, never executed."""
from contextlib import chdir
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
BASELINE_SAMPLES = tuple(f"level-{level}" for level in range(1, 6))
ALL_SAMPLES = (*BASELINE_SAMPLES, "level-5-hardened")
CAN_BUILD_ELF = sys.platform.startswith("linux") and bool(shutil.which("gcc") or shutil.which("clang"))
READELF = shutil.which("readelf")


@unittest.skipUnless(CAN_BUILD_ELF, "compile-only ELF checks require Linux and gcc or clang")
class SampleBuildPrivacyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rs-private-dwarf-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temporary_root = Path(cls.temporary.name)
        cls.checkout = cls.temporary_root / "private-source-checkout"
        cls.build_cwd = cls.temporary_root / "private-build-directory"
        cls.checkout.mkdir()
        cls.build_cwd.mkdir()
        for name in ("build_samples.py", "platform_support.py", "hardening.py"):
            shutil.copyfile(ROOT / name, cls.checkout / name)
        shutil.copytree(ROOT / "samples/src", cls.checkout / "samples/src")
        # Expose __FILE__ in data as well as DWARF, including the -g0 variant.
        # These are temporary test copies of the self-authored sources only.
        for slug in ALL_SAMPLES:
            source = cls.checkout / "samples/src" / slug / "main.c"
            with source.open("a", encoding="utf-8") as stream:
                stream.write("\nconst char *sample_build_source_path = __FILE__;\n")
        cls.build = subprocess.run(
            [sys.executable, "-B", str(cls.checkout / "build_samples.py")],
            cwd=cls.build_cwd, capture_output=True, text=True, timeout=180,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"},
            check=True,
        )

    def test_builds_do_not_embed_private_source_or_working_directories(self):
        private_prefixes = {
            str(self.checkout), str(self.build_cwd), str(self.temporary_root),
            str(ROOT), str(Path.home()), "/home/", "/Users/",
        }
        for slug in ALL_SAMPLES:
            with self.subTest(sample=slug):
                data = (self.checkout / "samples/bin" / f"{slug}.elf").read_bytes()
                leaked = sorted(prefix for prefix in private_prefixes if os.fsencode(prefix) in data)
                self.assertEqual(leaked, [], f"{slug} embeds private paths")
                self.assertIn(f"./samples/src/{slug}/main.c".encode(), data)

    def test_builds_write_private_nonexecutable_artifacts(self):
        for slug in ALL_SAMPLES:
            with self.subTest(sample=slug):
                sample = self.checkout / "samples/bin" / f"{slug}.elf"
                self.assertEqual(stat.S_IMODE(sample.stat().st_mode), 0o600)

    def test_hardened_build_rejects_observed_missing_mitigations(self):
        import build_samples
        from hardening import analyze_hardening

        overrides = {
            "nx": ["-Wl,-z,execstack"],
            "pie": ["-fno-pie", "-no-pie"],
            "relro": ["-Wl,-z,norelro"],
            "canary": ["-fno-stack-protector"],
            "fortify": ["-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0"],
        }
        with tempfile.TemporaryDirectory(prefix="rs-missing-mitigation-") as temporary:
            output_dir = Path(temporary)
            for property_name, flags in overrides.items():
                with self.subTest(property=property_name):
                    with mock.patch.object(build_samples, "HARDENED_FLAGS", [*build_samples.HARDENED_FLAGS, *flags]):
                        with self.assertRaisesRegex(RuntimeError, "Hardened Level 5.*" + property_name):
                            build_samples.build_hardened_sample(output_dir)
                    observed = analyze_hardening(output_dir / "level-5-hardened.elf")
                    self.assertNotEqual(observed["checks"][property_name]["state"], "present")

    def test_hardened_build_keeps_relative_output_in_callers_directory(self):
        import build_samples

        with tempfile.TemporaryDirectory(prefix="rs-relative-build-") as temporary, chdir(temporary):
            output_dir = Path(Path(temporary).name + "-output")
            self.assertFalse((ROOT / output_dir).exists())
            try:
                output = build_samples.build_hardened_sample(output_dir)
            except subprocess.CalledProcessError as exc:
                self.fail(f"Compiler did not resolve the caller's relative output: {exc.stderr}")
            self.assertEqual(output, output_dir / "level-5-hardened.elf")
            self.assertTrue(output.is_file())
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)


class BundledSamplePrivacyTests(unittest.TestCase):
    def test_all_six_bundled_samples_do_not_embed_private_paths(self):
        expected = {f"{slug}.elf" for slug in ALL_SAMPLES}
        self.assertEqual({path.name for path in (ROOT / "samples/bin").glob("*.elf")}, expected)
        private_prefixes = {"/home/", "/Users/", str(Path.home()), str(ROOT)}
        for slug in ALL_SAMPLES:
            with self.subTest(sample=slug):
                data = (ROOT / "samples/bin" / f"{slug}.elf").read_bytes()
                self.assertTrue(data.startswith(b"\x7fELF"))
                leaked = sorted(prefix for prefix in private_prefixes if os.fsencode(prefix) in data)
                self.assertEqual(leaked, [], f"{slug} embeds private paths")

    @unittest.skipUnless(os.name != "nt", "POSIX file modes are not Windows ACLs")
    def test_all_six_bundled_samples_are_private_nonexecutable_files(self):
        # Builds create 0600 files, but Git only tracks the executable bit, so a
        # fresh checkout can normalise the mode. The safety property is that the
        # bundled samples are never executable and remain owner-readable.
        for slug in ALL_SAMPLES:
            with self.subTest(sample=slug):
                sample = ROOT / "samples/bin" / f"{slug}.elf"
                mode = stat.S_IMODE(sample.stat().st_mode)
                self.assertFalse(mode & 0o111, f"{slug} must not be executable")
                self.assertTrue(mode & 0o400, f"{slug} must remain owner-readable")

    @unittest.skipUnless(READELF, "DWARF inspection requires readelf")
    def test_baselines_keep_dwarf_with_stable_project_relative_source_paths(self):
        assert READELF is not None
        for slug in BASELINE_SAMPLES:
            with self.subTest(sample=slug):
                sample = ROOT / "samples/bin" / f"{slug}.elf"
                sections = subprocess.run(
                    [READELF, "--sections", "--wide", "--", str(sample)],
                    capture_output=True, text=True, timeout=30, check=True,
                    env={**os.environ, "LC_ALL": "C"},
                ).stdout
                for name in (".debug_info", ".debug_line", ".symtab"):
                    self.assertIn(name, sections)
                info = subprocess.run(
                    [READELF, "--debug-dump=info", "--wide", "--", str(sample)],
                    capture_output=True, text=True, timeout=30, check=True,
                    env={**os.environ, "LC_ALL": "C"},
                ).stdout
                self.assertTrue(f"./samples/src/{slug}/main.c" in info, f"{slug} lacks a project-relative DW_AT_name")
                directories = [line.rsplit(":", 1)[-1].strip() for line in info.splitlines()
                               if "DW_AT_comp_dir" in line]
                self.assertEqual(directories, ["."] * (2 if slug == "level-5" else 1))
                if slug == "level-5":
                    self.assertIn("./samples/src/level-5/rules.c", info)

    def test_level5_baseline_and_hardened_properties_remain_distinct(self):
        from hardening import analyze_hardening

        expected = {
            "level-5": {"nx": "present", "pie": "absent", "relro": "partial",
                        "canary": "absent", "fortify": "absent"},
            "level-5-hardened": dict.fromkeys(("nx", "pie", "relro", "canary", "fortify"), "present"),
        }
        for slug, states in expected.items():
            with self.subTest(sample=slug):
                sample = ROOT / "samples/bin" / f"{slug}.elf"
                observed = analyze_hardening(sample)
                self.assertEqual(observed["format"], "ELF")
                self.assertEqual(observed["errors"], [])
                self.assertFalse(observed["input_truncated"])
                self.assertEqual({key: check["state"] for key, check in observed["checks"].items()}, states)
                if slug == "level-5-hardened":
                    self.assertNotIn(b".debug_", sample.read_bytes())

    def test_hardening_evidence_matches_actual_bytes_and_static_observations(self):
        from hardening import analyze_hardening

        record = json.loads((ROOT / "docs/evidence/hardening-level5.json").read_text(encoding="utf-8"))
        self.assertEqual(set(record), {"observed_at", "method", "samples", "interpretation"})
        self.assertEqual(record["method"], "Read ELF bytes with hardening.analyze_hardening; binaries were not executed")
        self.assertEqual(record["interpretation"], "Static property evidence only, not a security score or behavior-equivalence proof.")
        self.assertEqual([item["sample_id"] for item in record["samples"]], ["level-5", "level-5-hardened"])
        for item in record["samples"]:
            with self.subTest(sample=item["sample_id"]):
                self.assertEqual(set(item), {"sample_id", "sha256", "bytes", "mode", "hardening"})
                sample = ROOT / "samples/bin" / f"{item['sample_id']}.elf"
                data = sample.read_bytes()
                self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(item["bytes"], len(data))
                if os.name != "nt":
                    actual = stat.S_IMODE(sample.stat().st_mode)
                    recorded = int(item["mode"], 8)
                    # Git does not preserve 0600; both modes must stay non-executable.
                    self.assertFalse(actual & 0o111)
                    self.assertFalse(recorded & 0o111)
                self.assertEqual(item["hardening"], analyze_hardening(sample))


if __name__ == "__main__":
    unittest.main()
