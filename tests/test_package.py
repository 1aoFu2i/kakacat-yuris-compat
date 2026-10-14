import hashlib
import tempfile
import unittest
from pathlib import Path
import zipfile
from kakacat_yuris.common import inventory, package, verify_zip, Utf8ZipInfo
from kakacat_yuris.cli import build

class ResourcePackageTests(unittest.TestCase):
    def test_utf8_readback_and_changed_member_are_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            game = root / "testgame"
            game.mkdir()
            (game / "标题.dat").write_bytes(b"test resource\x00")
            (game / "ascii.dat").write_bytes(b"unchanged")
            records = inventory(game)
            zipped = root / "game.zip"
            package(game, zipped, records)
            self.assertEqual(verify_zip(zipped, game.name, records)["members"], 2)
            with zipfile.ZipFile(zipped) as archive:
                self.assertTrue(all(i.flag_bits & 0x800 for i in archive.infolist()))
            altered = [dict(row) for row in records]
            altered[0]["sha256"] = hashlib.sha256(b"wrong").hexdigest()
            with self.assertRaisesRegex(ValueError, "SHA256"):
                verify_zip(zipped, game.name, altered)

    def test_input_output_overlap_and_existing_output_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source"
            source.mkdir()
            with self.assertRaisesRegex(ValueError, "separate"):
                build("euphoria-r1", source, source / "child")
            existing = Path(temp) / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(ValueError, "overwrite"):
                build("euphoria-r1", source, existing)

    def test_executable_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            game = Path(temp) / "testgame"
            game.mkdir()
            (game / "x.exe").write_bytes(b"synthetic")
            with self.assertRaisesRegex(ValueError, "Executable"):
                inventory(game)

    def test_missing_zip64_local_header_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            game = Path(temp) / "testgame"
            game.mkdir()
            (game / "test.dat").write_bytes(b"synthetic")
            rows = inventory(game)
            zipped = Path(temp) / "plain.zip"
            with zipfile.ZipFile(zipped, "x") as archive:
                info = Utf8ZipInfo.from_file(game / "test.dat", arcname="testgame/test.dat")
                archive.writestr(info, b"synthetic")
            with self.assertRaisesRegex(ValueError, "ZIP64"):
                verify_zip(zipped, game.name, rows)

if __name__ == "__main__":
    unittest.main()
