"""Static-only RPM and archive safety tests.

Inputs are synthetic headers and optional locally built RPM fixtures; outputs
are extraction-boundary assertions. Embedded executables are package data and
are never launched. Extend with adversarial archive metadata, not execution.
"""
import io
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import discovery
import rpm_ingest


def newc(members):
    """Build inert byte fixtures: (name, data, mode, nlink)."""
    result = bytearray()
    for name, data, mode, links in [*members, ("TRAILER!!!", b"", 0, 1)]:
        encoded = name.encode("utf-8") + b"\0"
        fields = [1, mode, 0, 0, links, 0, len(data), 0, 0, 0, 0, len(encoded), 0]
        result.extend(b"070701" + b"".join(f"{field:08x}".encode() for field in fields))
        result.extend(encoded)
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(data)
        result.extend(b"\0" * (-len(result) % 4))
    return io.BytesIO(result)


class RpmSafetyTests(unittest.TestCase):
    def test_non_hex_header_fields_are_rejected_before_payload_write(self):
        data = bytearray(newc([("file", b"data", stat.S_IFREG | 0o644, 1)]).getvalue())
        data[22:30] = b"-0000001"  # A signed uid is not valid newc hex.
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            with self.assertRaisesRegex(ValueError, "header"):
                rpm_ingest._extract_newc(io.BytesIO(data), payload)
            self.assertFalse(payload.exists())

    def test_implicit_parent_directories_count_toward_member_cap(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            archive = newc([("a/b/c/file", b"data", stat.S_IFREG | 0o644, 1)])
            with patch.object(rpm_ingest, "MAX_MEMBERS", 3):
                with self.assertRaisesRegex(ValueError, "member-count"):
                    rpm_ingest._extract_newc(archive, payload)
            self.assertFalse(payload.exists())

    def test_forward_file_parent_conflict_is_rejected_before_any_payload_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / "payload"
            archive = newc([("parent/child", b"\x7fELF", stat.S_IFREG | 0o644, 1),
                            ("parent", b"data", stat.S_IFREG | 0o644, 1)])
            with self.assertRaisesRegex(ValueError, "conflict"):
                rpm_ingest._extract_newc(archive, payload)
            self.assertFalse(payload.exists())


def build_fixture(top: Path) -> Path:
    for name in ("SOURCES", "SPECS", "BUILD", "BUILDROOT", "RPMS", "SRPMS", "TMP"):
        (top / name).mkdir(parents=True, exist_ok=True)
    source = top / "SOURCES/sample.c"
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run(["cc", str(source), "-o", str(top / "SOURCES/sample.elf")],
                   check=True, capture_output=True, timeout=30)
    spec = top / "SPECS/fixture.spec"
    spec.write_text("""Name: reverseshield-static-fixture
Version: 1.0
Release: 1
Summary: Self-authored inert static-analysis fixture
License: MIT
Source0: sample.elf
AutoReqProv: no
Requires: reverseshield-fixture-runtime
%description
An ELF stored as non-executable package data. Never launch this sample.
%install
mkdir -p %{buildroot}/usr/share/reverseshield-fixture
install -m 0644 %{SOURCE0} %{buildroot}/usr/share/reverseshield-fixture/sample.elf
%files
/usr/share/reverseshield-fixture/sample.elf
""")
    subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {top}",
                    "--define", f"_tmppath {top / 'TMP'}", "--define", "_build_id_links none",
                    "--define", "__os_install_post %{nil}", str(spec)],
                   check=True, capture_output=True, timeout=60,
                   env={**os.environ, "TMPDIR": str(top / "TMP")})
    packages = list((top / "RPMS").rglob("*.rpm"))
    if len(packages) != 1:
        raise AssertionError(f"Expected one fixture RPM, got {packages}")
    return packages[0]


@unittest.skipUnless(shutil.which("rpmbuild") and shutil.which("cc") and shutil.which("rpm2cpio"),
                     "local RPM fixture build tools unavailable")
class RealRpmDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="rpm-fixture-")
        cls.top = Path(cls.temporary.name)
        cls.rpm = build_fixture(cls.top)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_rpm_payload_is_data_only_in_unique_workspace(self):
        work = self.top / "ingested"
        result = discovery.discover_path(self.rpm, workspace=work)
        self.assertEqual(result["app"]["source_type"], "rpm")
        self.assertEqual([t["relative_path"] for t in result["targets"]],
                         ["usr/share/reverseshield-fixture/sample.elf"])
        target = Path(result["targets"][0]["absolute_path"])
        self.assertTrue(target.is_relative_to(work))
        self.assertEqual(target.read_bytes(), (self.top / "SOURCES/sample.elf").read_bytes())
        self.assertFalse(target.stat().st_mode & 0o111)
        self.assertIn("reverseshield-fixture-runtime", result["runtime"]["dependencies"])
        self.assertFalse(result["runtime"]["scanned"])
        again = discovery.discover_path(self.rpm, workspace=work)
        self.assertNotEqual(result["payload_root"], again["payload_root"])
        converted = subprocess.run(["rpm2cpio", "-n", "-f", "pax", str(self.rpm)],
                                   check=True, capture_output=True, timeout=20)
        with tarfile.open(fileobj=io.BytesIO(converted.stdout), mode="r:") as archive:
            self.assertTrue(any(member.name.endswith("sample.elf") for member in archive))


if __name__ == "__main__":
    unittest.main()
