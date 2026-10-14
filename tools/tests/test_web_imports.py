import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import import_audit
import nid_names
import web_imports
from test_import_audit import build_elf, build_pe, GLOBAL_FUNCTION, STUB_SOURCE, write_source


class WebImportsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.archive = self.root / "libraries.zip"
        self.source = self.root / "prx"
        self.source.mkdir()

    def write_archive(self, entries):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, data in entries:
                    entry = zipfile.ZipInfo(name)
                    entry.filename = name
                    archive.writestr(entry, data)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def catalog(self, entries, platform="linux", source=None):
        checksum = self.write_archive(entries)
        return web_imports.library_catalog(self.archive, platform, checksum, source=source)

    def test_binary_exports_preserve_multiple_providers_and_ignore_undefined_symbols(self):
        catalog = self.catalog([
            ("libs/libSceZ.prx", build_elf([("AAAAAAAAAAA", 1, GLOBAL_FUNCTION), ("BBBBBBBBBBB", 0, GLOBAL_FUNCTION)])),
            ("libs/libSceA.prx", build_elf([("AAAAAAAAAAA", 1, GLOBAL_FUNCTION), ("CCCCCCCCCCC", 1, GLOBAL_FUNCTION)])),
        ])
        self.assertEqual(catalog["libraries"], ["libSceA.prx", "libSceZ.prx"])
        self.assertEqual(catalog["exports"], {"AAAAAAAAAAA": ["libSceA.prx", "libSceZ.prx"], "CCCCCCCCCCC": ["libSceA.prx"]})
        self.assertEqual(catalog["schema"], 1)
        self.assertEqual(catalog["platform"], "linux")
        self.assertEqual(catalog["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())

    def test_windows_catalog_uses_pe_exports_and_allows_runtime_dlls(self):
        catalog = self.catalog([
            ("libs/libSceA.prx", build_pe(["AAAAAAAAAAA", "BBBBBBBBBBB"])),
            ("libs/libstdc++-6.dll", b"runtime"),
        ], "windows")
        self.assertEqual(catalog["exports"], {"AAAAAAAAAAA": ["libSceA.prx"], "BBBBBBBBBBB": ["libSceA.prx"]})
        self.assertEqual(catalog["libraries"], ["libSceA.prx"])

    def test_source_stubs_cannot_add_binary_exports_or_establish_library_commit(self):
        name = "sceExampleMissing"
        nid = nid_names.compute_nid(name)
        write_source(self.source, "libSceA", STUB_SOURCE.format(name=name))
        with patch.object(import_audit, "git_stamp", return_value=("a" * 40, False)):
            catalog = self.catalog([("libs/libSceA.prx", build_elf([("AAAAAAAAAAA", 1, GLOBAL_FUNCTION)]))], source=self.source)
        self.assertEqual(catalog["exports"], {"AAAAAAAAAAA": ["libSceA.prx"]})
        self.assertEqual(catalog["source_stubs"], [{"library": "libSceA.prx", "nid": nid, "name": name}])
        self.assertEqual(catalog["source_commit"], "a" * 40)
        self.assertFalse(catalog["source_dirty"])
        self.assertIsNone(catalog["library_commit"])

    def test_source_unavailable_or_dirty_is_explicit(self):
        entry = [("libs/libSceA.prx", build_elf([("AAAAAAAAAAA", 1, GLOBAL_FUNCTION)]))]
        unavailable = self.catalog(entry)
        self.assertEqual(unavailable["source_stubs"], [])
        self.assertIsNone(unavailable["source_commit"])
        self.assertIsNone(unavailable["source_dirty"])
        self.assertIn("unavailable", " ".join(unavailable["source_warnings"]))
        with patch.object(import_audit, "git_stamp", return_value=(None, None)):
            missing = self.catalog(entry, source=self.root / "missing")
        self.assertIn("unavailable", " ".join(missing["source_warnings"]))
        self.assertIn("unknown", " ".join(missing["source_warnings"]))
        with patch.object(import_audit, "git_stamp", return_value=("b" * 40, True)):
            dirty = self.catalog(entry, source=self.source)
        self.assertTrue(dirty["source_dirty"])
        self.assertIn("uncommitted", " ".join(dirty["source_warnings"]))

    def test_source_scanner_failure_keeps_binary_findings_and_warns(self):
        with patch.object(import_audit, "source_stubs", side_effect=import_audit.AuditError("shared source cycle")), patch.object(import_audit, "git_stamp", return_value=("c" * 40, False)):
            catalog = self.catalog([("libs/libSceA.prx", build_elf([("AAAAAAAAAAA", 1, GLOBAL_FUNCTION)]))], source=self.source)
        self.assertEqual(catalog["exports"], {"AAAAAAAAAAA": ["libSceA.prx"]})
        self.assertEqual(catalog["source_stubs"], [])
        self.assertIn("shared source cycle", " ".join(catalog["source_warnings"]))

    def test_platform_mismatch_rejects_both_directions(self):
        for platform, data, message in (
            ("windows", build_elf([]), "PE32+"),
            ("linux", build_pe([]), "ELF64"),
        ):
            with self.subTest(platform=platform), self.assertRaisesRegex(import_audit.AuditError, message.replace("+", r"\+")):
                self.catalog([("libs/libSceA.prx", data)], platform)

    def test_wrong_architecture_or_binary_class_is_rejected(self):
        elf = build_elf([])
        pe = build_pe([])
        for platform, image, offset, value in (
            ("linux", elf, 18, struct.pack("<H", 0xb7)),
            ("linux", elf, 4, b"\x01"),
            ("linux", elf, 5, b"\x02"),
            ("windows", pe, 0x44, struct.pack("<H", 0xaa64)),
            ("windows", pe, 0x58, struct.pack("<H", 0x10b)),
        ):
            data = bytearray(image)
            data[offset:offset + len(value)] = value
            with self.subTest(platform=platform, offset=offset, value=value), self.assertRaises(import_audit.AuditError):
                self.catalog([("libs/libSceA.prx", data)], platform)

    def test_malformed_library_is_rejected_with_its_path(self):
        pe = bytearray(build_pe([]))
        struct.pack_into("<I", pe, 0x3c, len(pe) + 1)
        elf = bytearray(build_elf([]))
        struct.pack_into("<Q", elf, 40, len(elf) + 1)
        for platform, data in (("linux", b"\x7fELF"), ("windows", b"MZ"), ("windows", pe), ("linux", elf)):
            with self.subTest(platform=platform, length=len(data)), self.assertRaisesRegex(import_audit.AuditError, "libSceA.prx"):
                self.catalog([("libs/libSceA.prx", data)], platform)

    def test_duplicates_and_unsafe_layouts_are_rejected(self):
        library = build_elf([])
        for entries in (
            [("libs/libSceA.prx", library), ("libs/libSceA.prx", library)],
            [("libs/libSceA.prx", library), ("libs/LIBSCEA.PRX", library)],
            [("libSceA.prx", library)],
            [("libs/../libSceA.prx", library)],
            [("libs\\libSceA.prx", library)],
            [("libs/nested/libSceA.prx", library)],
            [("libs///", b""), ("libs/libSceA.prx", library)],
            [("libs/libSceA.prx ", library)],
            [("libs/con.prx", library)],
        ):
            with self.subTest(paths=[name for name, _ in entries]), self.assertRaises(import_audit.AuditError):
                self.catalog(entries)

    def test_links_are_rejected_before_reading_libraries(self):
        link = zipfile.ZipInfo("libs/libSceA.prx")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(link, "target")
        checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(import_audit.AuditError, "invalid library archive layout"):
            web_imports.library_catalog(self.archive, "linux", checksum, source=None)

    def test_empty_archive_or_missing_libraries_are_rejected(self):
        for entries in ([], [("libs/", b"")], [("libs/libstdc++-6.dll", b"runtime")]):
            with self.subTest(entries=entries), self.assertRaises(import_audit.AuditError):
                self.catalog(entries)

    def test_corrupt_library_archive_is_rejected(self):
        self.write_archive([("libs/libSceA.prx", build_elf([]))])
        data = bytearray(self.archive.read_bytes())
        filename_size, extra_size = struct.unpack_from("<HH", data, 26)
        data[30 + filename_size + extra_size] ^= 1
        self.archive.write_bytes(data)
        checksum = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(import_audit.AuditError, "corrupt"):
            web_imports.library_catalog(self.archive, "linux", checksum, source=None)

    def test_archive_digest_must_match_and_invalid_zip_is_rejected(self):
        checksum = self.write_archive([("libs/libSceA.prx", build_elf([]))])
        with self.assertRaisesRegex(import_audit.AuditError, "SHA-256 mismatch"):
            web_imports.library_catalog(self.archive, "linux", "0" * 64)
        with self.assertRaisesRegex(import_audit.AuditError, "Invalid library archive SHA-256"):
            web_imports.library_catalog(self.archive, "linux", "invalid")
        with self.assertRaisesRegex(import_audit.AuditError, "Unsupported library platform"):
            web_imports.library_catalog(self.archive, "macos", checksum)
        self.archive.write_bytes(b"not a ZIP")
        checksum = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        with self.assertRaisesRegex(import_audit.AuditError, "cannot read library archive"):
            web_imports.library_catalog(self.archive, "linux", checksum)


if __name__ == "__main__":
    unittest.main()
