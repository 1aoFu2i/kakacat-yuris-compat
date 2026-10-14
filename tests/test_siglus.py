"""Independent neutral fixtures for the G24 Siglus R2 profile.

No real game, save, image, audio, or executable is read by these tests.
Temporary data lives beside this file and cleanup is limited to its own root.
"""
from __future__ import annotations

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import builtins
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from kakacat_yuris import cli, siglus


PROFILE = "seishojyo-r2"
GAME_NAME = "G24_Kaka_R2_20261014"
KEY = bytes(range(16))
PUBLIC_HEAD = bytes.fromhex("d829b9163d1a76d0879b2d0c7bd1a919")
DIRECTORIES = ("bgm", "dat", "g00", "gan", "koe", "mov", "wav")
SUFFIXES = ("ogg", "tcr", "g00", "gan", "ovk", "wmv", "nwa")
MARKER = (
    b"Game 24 Siglus compatibility R2 20261014\r\n"
    b"Extra XOR removed; common compression and all translated scenes retained.\r\n"
    b"Use this unique folder for iOS testing.\r\n"
)
TEST_HOME = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def independent_xor(data, key=KEY):
    # This oracle deliberately does not call any production transformation.
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def scene_fixture():
    """190 blocks with unequal lengths, gaps, and per-block XOR restarts."""
    count, table = 190, 92
    data_start = table + count * 8 + 11
    header = [0] * 23
    header[0] = 92
    header[17:22] = [table, count, data_start, count, 1]
    source = bytearray(struct.pack("<23I", *header))
    source.extend(b"\x00" * (data_start - len(source)))
    source[table + count * 8:data_start] = b"\xa5" * 11
    expected = bytearray(source)
    struct.pack_into("<I", expected, 84, 0)
    spans = []
    for index in range(count):
        gap = bytes([0xC0 + index % 16]) * (index % 4)
        source.extend(gap)
        expected.extend(gap)
        start = len(source)
        block = bytes((index * 7 + offset * 13 + 19) % 256
                      for offset in range(8 + index % 23))
        record = struct.pack("<II", start - data_start, len(block))
        source[table + index * 8:table + (index + 1) * 8] = record
        expected[table + index * 8:table + (index + 1) * 8] = record
        source.extend(independent_xor(block))
        expected.extend(block)
        spans.append((start, start + len(block)))
    source.extend(b"\x7f\x7e\x7d")
    expected.extend(b"\x7f\x7e\x7d")
    return bytes(source), bytes(expected), spans


def game_fixture():
    """Neutral public-header/extra-XOR fixture for unique key recovery."""
    tail = bytes((index * 31 + 17) % 256 for index in range(69))
    payload_len = 16 + len(tail)
    prefix = struct.pack("<II", payload_len, 69544) + bytes([251, 10, 0, 37, 0, 35, 0, 68])
    common_prefix = bytes(a ^ b for a, b in zip(prefix, PUBLIC_HEAD))
    r2_payload = common_prefix + tail
    source = struct.pack("<II", 0, 1) + independent_xor(r2_payload)
    expected = struct.pack("<II", 0, 0) + r2_payload
    return source, expected


def core_overrides():
    source_scene, r2_scene, _ = scene_fixture()
    source_game, r2_game = game_fixture()
    return {
        "SCENE_SIZE": len(source_scene), "SCENE_SHA256": digest(source_scene),
        "SCENE_R2_SHA256": digest(r2_scene),
        "GAMEEXE_SIZE": len(source_game), "GAMEEXE_SHA256": digest(source_game),
        "GAMEEXE_R2_SHA256": digest(r2_game),
    }


def snapshot(root):
    """Content/mtime snapshot of our own regular fixture tree."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_file():
            info = path.stat()
            result[path.relative_to(root).as_posix()] = (
                info.st_size, info.st_mtime_ns, digest(path.read_bytes()))
    return result


@contextmanager
def fixture_profile(rows):
    values = core_overrides()
    values.update(MEDIA_COUNT=len(rows), MEDIA_BYTES=sum(row["size"] for row in rows),
                  MEDIA_INVENTORY_SHA256=siglus.media_digest(rows))
    with mock.patch.multiple(siglus, **values):
        yield


@contextmanager
def reject_ignored_reads(source):
    """Opening fixture root EXE/DLL/savedata is an actual test failure."""
    source = source.resolve()
    forbidden = {source / "unused.exe", source / "unused.dll"}
    save = source / "savedata"
    real_open, real_io_open = builtins.open, io.open

    def guarded(original, file, *args, **kwargs):
        if isinstance(file, (str, bytes, os.PathLike)):
            path = Path(os.fsdecode(file)).absolute()
            if path in forbidden or path == save or path.is_relative_to(save):
                raise AssertionError("Profile opened an excluded fixture input")
        return original(file, *args, **kwargs)

    with mock.patch("builtins.open", side_effect=lambda *a, **k: guarded(real_open, *a, **k)):
        with mock.patch("io.open", side_effect=lambda *a, **k: guarded(real_io_open, *a, **k)):
            yield


class LowLevelTests(unittest.TestCase):
    def setUp(self):
        self.scene, self.scene_r2, self.spans = scene_fixture()
        self.game, self.game_r2 = game_fixture()
        patcher = mock.patch.multiple(siglus, **core_overrides())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_scene_matches_independent_190_block_oracle(self):
        actual = siglus.transform_scene(self.scene, KEY)
        self.assertEqual(actual, self.scene_r2)
        self.assertEqual(struct.unpack_from("<I", actual, 84)[0], 0)
        self.assertEqual(len(self.spans), 190)
        changed = {index for index, pair in enumerate(zip(self.scene, actual)) if pair[0] != pair[1]}
        allowed = {84}
        for start, end in self.spans:
            allowed.update(range(start, end))
        self.assertTrue(changed <= allowed)

    def test_game_matches_independent_payload_oracle(self):
        self.assertEqual(siglus.transform_gameexe(self.game, KEY), self.game_r2)

    def test_reverse_xor_restores_every_fixture_byte(self):
        self.assertEqual(siglus._xor_scene(self.scene_r2, KEY, 0, 1), self.scene)
        self.assertEqual(siglus._xor_gameexe(self.game_r2, KEY, 0, 1), self.game)

    def test_key_is_derived_from_neutral_cipher_and_target_hash(self):
        self.assertEqual(siglus.derive_extra_key(self.game), KEY)

    def test_key_derivation_rejects_nonmatching_payload(self):
        bad = bytearray(self.game)
        bad[-1] ^= 1
        # Accept only the synthetic input identity; the unchanged target hash
        # must reject all 256 recovered-parameter candidates.
        with mock.patch.object(siglus, "GAMEEXE_SHA256", digest(bad)):
            with self.assertRaisesRegex(ValueError, "unique"):
                siglus.derive_extra_key(bytes(bad))

    def test_key_derivation_rejects_truncated_header(self):
        with self.assertRaises(ValueError):
            siglus.derive_extra_key(self.game[:20])

    def test_xor_key_length_is_exactly_16(self):
        for key in (b"", b"x" * 15, b"x" * 17):
            with self.subTest(length=len(key)):
                with self.assertRaises(ValueError):
                    siglus.transform_scene(self.scene, key)
                with self.assertRaises(ValueError):
                    siglus.transform_gameexe(self.game, key)

    def test_already_transformed_flags_are_rejected(self):
        with self.assertRaises(ValueError):
            siglus.transform_scene(self.scene_r2, KEY)
        with self.assertRaises(ValueError):
            siglus.transform_gameexe(self.game_r2, KEY)

    def test_game_header_is_not_truncated(self):
        with self.assertRaises(ValueError):
            siglus.transform_gameexe(self.game[:7], KEY)

    def test_scene_header_and_index_boundaries(self):
        malformed = {"short_header": self.scene[:91],
                     "last_block_truncated": self.scene[:self.spans[-1][1] - 1]}
        changes = {
            "wrong_header_size": (0, 88), "index_count": (18 * 4, 189),
            "data_count": (20 * 4, 189), "wrong_flag": (84, 2),
            "index_inside_header": (17 * 4, 4),
            "index_outside_file": (17 * 4, len(self.scene) - 1),
            "data_overlaps_index": (19 * 4, 92),
            "data_outside_file": (19 * 4, len(self.scene) + 1),
            "block_offset_outside_file": (92, 0xFFFFFFF0),
            "short_block": (96, 7), "long_block": (96, 0xFFFFFFFF),
        }
        for label, (offset, value) in changes.items():
            bad = bytearray(self.scene)
            struct.pack_into("<I", bad, offset, value)
            malformed[label] = bytes(bad)
        overlap = bytearray(self.scene)
        first_offset, first_length = struct.unpack_from("<II", self.scene, 92)
        struct.pack_into("<I", overlap, 100, first_offset + first_length - 1)
        malformed["overlapping_blocks"] = bytes(overlap)
        duplicate = bytearray(self.scene)
        duplicate[100:108] = duplicate[92:100]
        malformed["duplicate_blocks"] = bytes(duplicate)
        for label, data in malformed.items():
            with self.subTest(case=label):
                # Version checks may be present in the low-level function.
                # Match only this input identity so the shape is still rejected.
                with mock.patch.multiple(siglus, SCENE_SIZE=len(data), SCENE_SHA256=digest(data)):
                    with self.assertRaises(ValueError):
                        siglus.transform_scene(data, KEY)

    def test_media_digest_is_canonical_and_content_sensitive(self):
        rows = [{"path": "wav/b.nwa", "size": 3, "sha256": digest(b"two")},
                {"path": "bgm/a.ogg", "size": 3, "sha256": digest(b"one")}]
        result = siglus.media_digest(rows)
        self.assertRegex(result, r"^[0-9a-f]{64}$")
        self.assertEqual(result, siglus.media_digest(list(reversed(rows))))
        for field, value in (("path", "wav/c.nwa"), ("size", 4), ("sha256", digest(b"new"))):
            with self.subTest(field=field):
                changed = [dict(row) for row in rows]
                changed[0][field] = value
                self.assertNotEqual(result, siglus.media_digest(changed))


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix=".g24-test-", dir=TEST_HOME))
        self.addCleanup(self.cleanup_owned_root)
        self.source = self.root / "source"
        self.source.mkdir()
        self.scene, self.scene_r2, _ = scene_fixture()
        self.game, self.game_r2 = game_fixture()
        (self.source / "Scene.pck").write_bytes(self.scene)
        (self.source / "Gameexe.dat").write_bytes(self.game)
        self.rows = []
        for index, (directory, suffix) in enumerate(zip(DIRECTORIES, SUFFIXES)):
            folder = self.source / directory
            folder.mkdir()
            data = bytes([index + 1]) * (17 + index)
            relative = directory + "/neutral." + suffix
            (self.source / relative).write_bytes(data)
            self.rows.append({"path": relative, "size": len(data), "sha256": digest(data)})
        (self.source / "unused.exe").write_bytes(b"NEUTRAL-DO-NOT-OPEN-EXE")
        (self.source / "unused.dll").write_bytes(b"NEUTRAL-DO-NOT-OPEN-DLL")
        (self.source / "savedata").mkdir()
        (self.source / "savedata" / "slot.dat").write_bytes(b"NEUTRAL-SAVE-SENTINEL")
        self.profile_patch = fixture_profile(self.rows)
        self.profile_patch.__enter__()
        self.addCleanup(self.profile_patch.__exit__, None, None, None)

    def cleanup_owned_root(self):
        # Python 3.12 rmtree unlinks directory junctions without traversing them.
        # Verify the absolute resolved target before any recursive cleanup.
        root = self.root.resolve()
        if root.parent != TEST_HOME or not root.name.startswith(".g24-test-"):
            raise RuntimeError("Refusing cleanup outside this test's owned root")
        if self.root.is_symlink() or getattr(self.root.lstat(), "st_file_attributes", 0) & 0x400:
            raise RuntimeError("Refusing cleanup of a replaced temporary root")
        shutil.rmtree(self.root)

    def quiet_build(self, output=None):
        output = output or self.root / "output"
        with redirect_stdout(io.StringIO()):
            report = cli.build(PROFILE, self.source, output)
        return output, report

    def test_profile_routes_to_siglus(self):
        self.assertIn(PROFILE, cli.PROFILES)
        self.assertIs(cli.module_for(PROFILE), siglus)

    def test_inspect_is_readonly_and_ignores_excluded_root_inputs(self):
        before = snapshot(self.source)
        with reject_ignored_reads(self.source):
            result = siglus.inspect(self.source, PROFILE)
        self.assertIsInstance(result, dict)
        self.assertEqual(snapshot(self.source), before)
        self.assertEqual(set(self.root.iterdir()), {self.source})

    def test_inspect_rejects_wrong_profile(self):
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, "euphoria-r1")

    def test_inspect_rejects_changed_core_same_size_and_mtime(self):
        for filename in ("Scene.pck", "Gameexe.dat"):
            with self.subTest(file=filename):
                path = self.source / filename
                original, info = path.read_bytes(), path.stat()
                altered = bytearray(original)
                altered[-1] ^= 1
                path.write_bytes(altered)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                with self.assertRaises(ValueError):
                    siglus.inspect(self.source, PROFILE)
                path.write_bytes(original)
                os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))

    def test_inspect_rejects_changed_media_same_size_and_mtime(self):
        path = self.source / self.rows[0]["path"]
        info = path.stat()
        altered = bytearray(path.read_bytes())
        altered[0] ^= 1
        path.write_bytes(altered)
        os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, PROFILE)

    def test_inspect_rejects_added_or_deleted_media(self):
        extra = self.source / "bgm" / "extra.ogg"
        extra.write_bytes(b"NEUTRAL-EXTRA")
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, PROFILE)
        extra.unlink()
        (self.source / self.rows[0]["path"]).unlink()
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, PROFILE)

    def test_inspect_rejects_missing_runtime_directory(self):
        folder = self.source / "gan"
        (folder / "neutral.gan").unlink()
        folder.rmdir()
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, PROFILE)

    def test_prepare_outputs_only_the_seven_directories_and_three_root_files(self):
        stage = self.root / "stage"
        stage.mkdir()
        before = snapshot(self.source)
        with reject_ignored_reads(self.source):
            result = siglus.prepare(self.source, stage, PROFILE)
        game = Path(result["game_dir"])
        self.assertEqual(game, stage / GAME_NAME)
        self.assertEqual((game / "Scene.pck").read_bytes(), self.scene_r2)
        self.assertEqual((game / "Gameexe.dat").read_bytes(), self.game_r2)
        self.assertEqual((game / "PACKAGE_VERSION_R2.txt").read_bytes(), MARKER)
        self.assertEqual(len(MARKER), 158)
        expected = {row["path"] for row in self.rows} | {
            "Scene.pck", "Gameexe.dat", "PACKAGE_VERSION_R2.txt"}
        self.assertEqual(set(snapshot(game)), expected)
        for row in self.rows:
            self.assertEqual((game / row["path"]).read_bytes(),
                             (self.source / row["path"]).read_bytes())
        self.assertEqual(snapshot(self.source), before)

    def test_wav_accepts_mixed_nwa_and_ogg_without_relaxing_fingerprints(self):
        relative, data = "wav/neutral-extra.ogg", b"NEUTRAL-WAV-OGG"
        extra = self.source / relative
        extra.write_bytes(data)
        rows = self.rows + [{"path": relative, "size": len(data), "sha256": digest(data)}]
        before = snapshot(self.source)
        with fixture_profile(rows), reject_ignored_reads(self.source):
            inspected = siglus.inspect(self.source, PROFILE)
            self.assertEqual(inspected["media_count"], 8)
            output, _ = self.quiet_build()
            game = output / "stage" / GAME_NAME
            self.assertEqual((game / relative).read_bytes(), data)
            self.assertEqual((game / "wav/neutral.nwa").read_bytes(),
                             (self.source / "wav/neutral.nwa").read_bytes())
            output_rows = cli.inventory(game)
            siglus.validate_output_inventory(output_rows)
            self.assertEqual(len(output_rows), 11)
            with zipfile.ZipFile(output / (PROFILE + ".zip")) as archive:
                self.assertEqual(archive.read(GAME_NAME + "/" + relative), data)
                self.assertIn(GAME_NAME + "/wav/neutral.nwa", archive.namelist())
            for extension in ("exe", "dll"):
                with self.subTest(extension=extension):
                    invalid = [dict(row) for row in output_rows]
                    next(row for row in invalid if row["path"] == relative)["path"] = "wav/neutral." + extension
                    with self.assertRaises(ValueError):
                        siglus.validate_output_inventory(invalid)
        self.assertEqual(snapshot(self.source), before)
        info = extra.stat()
        changed = bytearray(data)
        changed[0] ^= 1
        extra.write_bytes(changed)
        os.utime(extra, ns=(info.st_atime_ns, info.st_mtime_ns))
        with fixture_profile(rows):
            with self.assertRaises(ValueError):
                siglus.inspect(self.source, PROFILE)

    def test_prepare_refuses_preexisting_game_root(self):
        stage = self.root / "stage"
        game = stage / GAME_NAME
        game.mkdir(parents=True)
        sentinel = game / "keep.txt"
        sentinel.write_bytes(b"KEEP-EXISTING-OUTPUT")
        before = snapshot(self.source)
        with self.assertRaises(ValueError):
            siglus.prepare(self.source, stage, PROFILE)
        self.assertEqual(sentinel.read_bytes(), b"KEEP-EXISTING-OUTPUT")
        self.assertEqual(set(snapshot(game)), {"keep.txt"})
        self.assertEqual(snapshot(self.source), before)

    def test_prepare_refuses_stage_inside_source(self):
        stage = self.source / "new-stage"
        stage.mkdir()
        before = snapshot(self.source)
        with self.assertRaises(ValueError):
            siglus.prepare(self.source, stage, PROFILE)
        self.assertEqual(snapshot(self.source), before)
        self.assertEqual(list(stage.iterdir()), [])

    def test_build_and_verify_use_real_profile_and_report_unmeasured_ios(self):
        before = snapshot(self.source)
        with reject_ignored_reads(self.source):
            output, report = self.quiet_build()
        self.assertEqual(report["status"], "FILE_VALIDATED")
        self.assertEqual(report["ios_status"], "NOT_TESTED_BY_THIS_BUILD")
        self.assertTrue(report["source_unchanged"])
        manifest = json.loads((output / "manifest.json").read_text("utf-8"))
        self.assertEqual(manifest["profile"], PROFILE)
        self.assertEqual(manifest["game_directory"], GAME_NAME)
        expected = {row["path"] for row in self.rows} | {
            "Scene.pck", "Gameexe.dat", "PACKAGE_VERSION_R2.txt"}
        self.assertEqual({row["path"] for row in manifest["files"]}, expected)
        with zipfile.ZipFile(output / (PROFILE + ".zip")) as archive:
            self.assertEqual(set(archive.namelist()), {GAME_NAME + "/" + item for item in expected})
            self.assertEqual(archive.read(GAME_NAME + "/Scene.pck"), self.scene_r2)
            self.assertEqual(archive.read(GAME_NAME + "/Gameexe.dat"), self.game_r2)
            for row in self.rows:
                self.assertEqual(digest(archive.read(GAME_NAME + "/" + row["path"])), row["sha256"])
        with redirect_stdout(io.StringIO()):
            checked = cli.verify(output)
        self.assertEqual(checked["status"], "PASS")
        self.assertEqual(checked["ios_status"], "NOT_TESTED_BY_THIS_VERIFICATION")
        self.assertEqual(snapshot(self.source), before)

    def test_build_bad_version_does_not_create_output(self):
        (self.source / "Scene.pck").write_bytes(b"NOT-A-SUPPORTED-SOURCE")
        output = self.root / "output"
        before = snapshot(self.source)
        with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
            cli.build(PROFILE, self.source, output)
        self.assertFalse(output.exists())
        self.assertEqual(snapshot(self.source), before)

    def test_build_refuses_existing_file_or_directory(self):
        for kind in ("file", "directory"):
            with self.subTest(kind=kind):
                output = self.root / ("existing-" + kind)
                if kind == "file":
                    output.write_bytes(b"KEEP-EXISTING")
                else:
                    output.mkdir()
                    (output / "keep.txt").write_bytes(b"KEEP-EXISTING")
                before = snapshot(self.source)
                with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                    cli.build(PROFILE, self.source, output)
                if kind == "file":
                    self.assertEqual(output.read_bytes(), b"KEEP-EXISTING")
                else:
                    self.assertEqual(set(snapshot(output)), {"keep.txt"})
                self.assertEqual(snapshot(self.source), before)

    def test_build_refuses_equal_nested_and_ancestor_output(self):
        before = snapshot(self.source)
        for output in (self.source, self.source / "nested-output", self.root):
            with self.subTest(path=output.name):
                with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                    cli.build(PROFILE, self.source, output)
        self.assertEqual(snapshot(self.source), before)
        self.assertFalse((self.source / "nested-output").exists())

    def test_mid_build_corruption_leaves_failure_and_preserves_source(self):
        before = snapshot(self.source)
        real_package = cli.package

        def corrupt_after_package(game, destination, records):
            real_package(game, destination, records)
            # Corrupt only this test's newly created partial ZIP.
            with open(destination, "r+b") as stream:
                stream.seek(0)
                stream.write(b"BROKEN")

        output = self.root / "output"
        with mock.patch.object(cli, "package", side_effect=corrupt_after_package):
            with self.assertRaises((ValueError, zipfile.BadZipFile)), redirect_stdout(io.StringIO()):
                cli.build(PROFILE, self.source, output)
        self.assertTrue((output / "failure.json").is_file())
        self.assertFalse((output / (PROFILE + ".zip")).exists())
        self.assertFalse((output / "validation.json").exists())
        self.assertFalse((output / "manifest.json").exists())
        self.assertEqual(snapshot(self.source), before)

    def test_media_change_during_build_blocks_final_publication(self):
        real_package = cli.package
        altered_snapshot = []

        def modify_test_source_then_package(game, destination, records):
            path = self.source / self.rows[0]["path"]
            info = path.stat()
            data = bytearray(path.read_bytes())
            data[0] ^= 1
            path.write_bytes(data)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
            altered_snapshot.append(snapshot(self.source))
            real_package(game, destination, records)

        output = self.root / "output"
        with mock.patch.object(cli, "package", side_effect=modify_test_source_then_package):
            with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                cli.build(PROFILE, self.source, output)
        self.assertTrue((output / "failure.json").is_file())
        self.assertFalse((output / (PROFILE + ".zip")).exists())
        self.assertFalse((output / "validation.json").exists())
        self.assertEqual(snapshot(self.source), altered_snapshot[0])

    def test_verify_refuses_stage_tampering(self):
        output, _ = self.quiet_build()
        path = output / "stage" / GAME_NAME / "Scene.pck"
        data = bytearray(path.read_bytes())
        data[-1] ^= 1
        path.write_bytes(data)
        with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
            cli.verify(output)

    def test_verify_refuses_zip_tampering(self):
        output, _ = self.quiet_build()
        path = output / (PROFILE + ".zip")
        with open(path, "r+b") as stream:
            stream.seek(20)
            first = stream.read(1)
            stream.seek(20)
            stream.write(bytes([first[0] ^ 1]))
        with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
            cli.verify(output)

    def test_output_inventory_rejects_core_marker_and_media_changes(self):
        stage = self.root / "stage"
        stage.mkdir()
        game = Path(siglus.prepare(self.source, stage, PROFILE)["game_dir"])
        rows = cli.inventory(game)
        siglus.validate_output_inventory(rows)
        for path in ("Scene.pck", "Gameexe.dat", "PACKAGE_VERSION_R2.txt", self.rows[0]["path"]):
            with self.subTest(path=path):
                altered = [dict(row) for row in rows]
                next(row for row in altered if row["path"] == path)["sha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    siglus.validate_output_inventory(altered)

    def test_output_inventory_rejects_unsafe_and_wrong_resource_paths(self):
        stage = self.root / "stage"
        stage.mkdir()
        game = Path(siglus.prepare(self.source, stage, PROFILE)["game_dir"])
        rows = cli.inventory(game)
        for path in ("savedata/neutral.ogg", "bgm/../neutral.ogg", "bgm/CON.ogg",
                     "bgm/neutral.dll", "bgm/neutral.exe", "bgm/trailing. /neutral.ogg"):
            with self.subTest(path=path):
                altered = [dict(row) for row in rows]
                next(row for row in altered if row["path"] == self.rows[0]["path"])["path"] = path
                with self.assertRaises(ValueError):
                    siglus.validate_output_inventory(altered)

    def test_verify_rejects_modified_stage_even_when_manifest_hashes_are_updated(self):
        output, _ = self.quiet_build()
        game = output / "stage" / GAME_NAME
        path = game / self.rows[0]["path"]
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        manifest_path = output / "manifest.json"
        manifest = json.loads(manifest_path.read_text("utf-8"))
        manifest["files"] = cli.inventory(game)
        zipped = output / (PROFILE + ".zip")
        zipped.unlink()
        cli.package(game, zipped, manifest["files"])
        manifest["zip_size"] = zipped.stat().st_size
        manifest["zip_sha256"] = digest(zipped.read_bytes())
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "R2 media"), redirect_stdout(io.StringIO()):
            cli.verify(output)

    def make_symlink_or_skip(self, target, link, directory=False):
        try:
            os.symlink(target, link, target_is_directory=directory)
        except (NotImplementedError, OSError) as exc:
            self.skipTest("Local symbolic links unavailable: " + type(exc).__name__)

    def test_build_refuses_dangling_output_symlink(self):
        target, link = self.root / "missing-target", self.root / "output-link"
        self.make_symlink_or_skip(target, link, directory=True)
        with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
            cli.build(PROFILE, self.source, link)
        self.assertTrue(link.is_symlink())
        self.assertFalse(target.exists())

    def test_inspect_refuses_runtime_file_symlink(self):
        target, link = self.root / "external-neutral.bin", self.source / "bgm" / "linked.ogg"
        target.write_bytes(b"NEUTRAL-EXTERNAL")
        self.make_symlink_or_skip(target, link)
        with self.assertRaises(ValueError):
            siglus.inspect(self.source, PROFILE)

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_inspect_refuses_windows_directory_junction(self):
        target, link = self.root / "junction-target", self.source / "bgm" / "junction"
        target.mkdir()
        (target / "neutral.ogg").write_bytes(b"NEUTRAL-JUNCTION-TARGET")
        self.assertTrue(target.resolve().is_relative_to(self.root.resolve()))
        self.assertTrue(link.parent.resolve().is_relative_to(self.root.resolve()))
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
                                capture_output=True, check=False)
        if result.returncode:
            self.skipTest("Local junction creation unavailable")
        try:
            with self.assertRaises(ValueError):
                siglus.inspect(self.source, PROFILE)
            self.assertEqual((target / "neutral.ogg").read_bytes(), b"NEUTRAL-JUNCTION-TARGET")
        finally:
            # Remove only the known junction itself; never recurse its target.
            os.rmdir(link)

    def test_inspect_refuses_reparse_attribute_even_when_not_a_symlink(self):
        target = self.source / self.rows[0]["path"]
        real_lstat = Path.lstat

        class ReparseStat:
            def __init__(self, original):
                self.original = original
                self.st_file_attributes = getattr(original, "st_file_attributes", 0) | 0x400

            def __getattr__(self, name):
                return getattr(self.original, name)

        def injected_lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if Path(path).absolute() == target.absolute():
                return ReparseStat(info)
            return info

        # Path.lstat uses os.stat(follow_symlinks=False) on Python 3.12;
        # intercept its actual public entry point rather than os.lstat.
        with mock.patch.object(Path, "lstat", injected_lstat):
            with self.assertRaises(ValueError):
                siglus.inspect(self.source, PROFILE)

    def test_cli_inspect_does_not_resolve_away_source_root_reparse_check(self):
        alias = self.root / "simulated-source-link"
        real_lstat, real_resolve = Path.lstat, Path.resolve

        class LinkStat:
            def __init__(self, original):
                self.original = original
                self.st_mode = stat.S_IFLNK | 0o777
                self.st_file_attributes = getattr(original, "st_file_attributes", 0) | 0x400

            def __getattr__(self, name):
                return getattr(self.original, name)

        def alias_lstat(path, *args, **kwargs):
            if Path(path).absolute() == alias:
                return LinkStat(real_lstat(self.source))
            return real_lstat(path, *args, **kwargs)

        def alias_resolve(path, *args, **kwargs):
            if Path(path).absolute() == alias:
                return self.source
            return real_resolve(path, *args, **kwargs)

        with mock.patch.object(Path, "lstat", alias_lstat), mock.patch.object(Path, "resolve", alias_resolve):
            with self.assertRaises(ValueError):
                siglus.inspect(alias, PROFILE)
            with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                cli.build(PROFILE, alias, self.root / "alias-build-output")
            self.assertFalse((self.root / "alias-build-output").exists())
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = cli.main(["inspect", "--profile", PROFILE, "--source", str(alias)])
            self.assertEqual(code, 1, "CLI must preserve the raw source root for the profile's link check")


if __name__ == "__main__":
    unittest.main()
