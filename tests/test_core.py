"""Synthetic archives/expressions only; no game or translation assets."""
import hashlib
import mmap
import struct
import tempfile
import unittest
import zlib

from kakacat_yuris import ybn, ypf


def archive_fixture(version=474, members=None):
    members = members or [("res/a.bin", b"alpha" * 17, True), ("res/b.bin", b"other-data", False)]
    tailsize = 22 if version >= 481 else 18
    directory_end = 32 + sum(5 + len(name.encode("cp932")) + tailsize for name, _, _ in members)
    header = struct.pack("<8I", int.from_bytes(b"YPF\0", "little"), version, len(members),
                         directory_end - 32 if version == 292 else directory_end, 0, 0, 0, 0)
    directory, payloads, offset = bytearray(), bytearray(), directory_end
    for name, payload, packed in members:
        raw_name = name.encode("cp932")
        name_hash = ypf.murmur2(raw_name) if version >= 481 else zlib.crc32(raw_name) & 0xFFFFFFFF
        stored = zlib.compress(payload, 6) if packed else payload
        checksum = ypf.murmur2(stored) if version >= 481 else zlib.adler32(stored) & 0xFFFFFFFF
        directory.extend(struct.pack("<IB", name_hash, len(raw_name) ^ 255))
        directory.extend(bytes(x ^ 255 for x in raw_name))
        directory.extend(struct.pack("<BBIIQI" if version >= 481 else "<BBIIII", 1, int(packed),
                                     len(payload), len(stored), offset, checksum))
        payloads.extend(stored)
        offset += len(stored)
    return header + directory + payloads


def script_fixture(version=474):
    # These fabricated variables stand for slot, selected FD, transition
    # progress, target alpha and BASE width; none contains game expressions.
    condition = ybn.eq(ybn.var(20), 0)
    center = ybn.operation(ybn.var(30), ybn.num(2), "/")
    center += ybn.token("D", struct.pack("<d", 1.28)) + ybn.token("/")
    multiply = ybn.operation(ybn.var(40), ybn.var(12), "*")
    expressions = condition + center + multiply
    descriptors = [(0, 1, len(condition), 0), (0, 0, 0, 0), (0, 0, 2, len(condition)),
                   (12, 2, len(center), len(condition)),
                   (0, 1, len(multiply), len(condition) + len(center))]
    sections = [struct.pack("<BBHBBHBBHBBH", 30, 3, 0, 33, 1, 0, 39, 1, 0, 12, 0, 0),
                b"".join(struct.pack("<HHII", *item) for item in descriptors), expressions,
                struct.pack("<4I", 1, 2, 3, 4)]
    return ybn.rebuild((int.from_bytes(b"YSTB", "little"), version, 4, 0, 0, 0, 0, 0), sections)


def evaluate(expression, variables):
    # An independent, deliberately small stack evaluator for fabricated RPN
    # cases. It does not claim to be a YU-RIS interpreter or renderer.
    stack = []
    for op, body in ybn.tokens(expression):
        if op == "H":
            stack.append(variables[struct.unpack("<H", body[1:])[0]])
        elif op == "B":
            stack.append(struct.unpack("<b", body)[0])
        elif op == "D":
            stack.append(struct.unpack("<d", body)[0])
        else:
            right, left = stack.pop(), stack.pop()
            if op == "=":
                stack.append(int(left == right))
            elif op == "&":
                stack.append(int(bool(left) and bool(right)))
            elif op == "|":
                stack.append(int(bool(left) or bool(right)))
            elif op == "/":
                stack.append(left / right)
            elif op == "*":
                stack.append(left * right)
            else:
                raise AssertionError("unsupported synthetic token")
    assert len(stack) == 1
    return stack[0]


class ArchiveTests(unittest.TestCase):
    def test_versions_and_hashes(self):
        self.assertEqual(ypf.murmur2(b"hello"), 0xE56129CB)
        for version in ypf.SUPPORTED_VERSIONS:
            with self.subTest(version=version):
                blob = archive_fixture(version)
                parsed = ypf.parse(blob)
                self.assertEqual(parsed.version, version)
                self.assertEqual(parsed.entries[0]["payload"], b"alpha" * 17)
                self.assertEqual(ypf.validate(blob)["entry_count"], 2)

    def test_append_only_order_and_flags(self):
        for version in (292, 474, 481, 490):
            blob = archive_fixture(version)
            old = ypf.parse(blob)
            # Deliberately reverse dict order. The original directory order
            # must control the order of new payloads, not dict insertion.
            output = ypf.replace(blob, {"res/b.bin": b"new-b", "res/a.bin": b"new-a"})
            new = ypf.parse(output)
            self.assertEqual(new.entries[0]["offset"], len(blob))
            self.assertEqual(output[old.directory_end:len(blob)], blob[old.directory_end:])
            self.assertEqual([r["name"] for r in old.entries], [r["name"] for r in new.entries])
            self.assertEqual([r["packed"] for r in old.entries], [r["packed"] for r in new.entries])
            self.assertEqual(new.entries[1]["payload"], b"new-b")
            for row in old.entries:
                self.assertEqual(blob[row["record_offset"]:row["field_offset"] + 2],
                                 output[row["record_offset"]:row["field_offset"] + 2])

    def test_unselected_resource_and_force_plain(self):
        blob = archive_fixture()
        before = ypf.parse(blob)
        output = ypf.replace(blob, {"res/a.bin": b"new-a"}, compression_level=0)
        after = ypf.parse(output)
        self.assertFalse(after.entries[0]["packed"])
        self.assertEqual(after.entries[1], before.entries[1])
        self.assertEqual(output[len(blob):], b"new-a")

    def test_missing_identical_and_repeat_rejected(self):
        blob = archive_fixture()
        for replacement in ({"missing": b"x"}, {}, {"res/a.bin": b"alpha" * 17}):
            with self.assertRaises(ValueError):
                ypf.replace(blob, replacement)
        output = ypf.replace(blob, {"res/a.bin": b"new"})
        with self.assertRaisesRegex(ValueError, "already applied"):
            ypf.replace(output, {"res/a.bin": b"new"})

    def test_historical_merge_appends_identical_payload(self):
        for packed in (False, True):
            with self.subTest(packed=packed):
                blob = archive_fixture(490, [("res/a.bin", b"unchanged", packed),
                                             ("res/b.bin", b"peer", False)])
                before = ypf.parse(blob)
                output = ypf.replace(blob, {"res/a.bin": b"unchanged"}, allow_identical=True)
                after = ypf.parse(output)
                self.assertGreater(len(output), len(blob))
                self.assertEqual(after.entries[0]["offset"], len(blob))
                self.assertEqual(after.entries[0]["payload"], before.entries[0]["payload"])
                self.assertEqual(after.entries[0]["packed"], before.entries[0]["packed"])
                self.assertEqual(after.entries[1], before.entries[1])
                self.assertEqual(output[before.directory_end:len(blob)], blob[before.directory_end:])
                target = before.entries[0]
                self.assertEqual(output[target["record_offset"]:target["field_offset"] + 2],
                                 blob[target["record_offset"]:target["field_offset"] + 2])
                with self.assertRaisesRegex(ValueError, "already applied"):
                    ypf.replace(output, {"res/a.bin": b"unchanged"})

    def test_bad_header_directory_name_and_bounds(self):
        blob = archive_fixture()
        row = ypf.parse(blob).entries[0]
        mutations = []
        for offset, value in ((4, 999), (8, 0xFFFFFFFF), (12, 33), (32, 1), (row["field_offset"] + 10, len(blob) + 1)):
            damaged = bytearray(blob)
            struct.pack_into("<I", damaged, offset, value)
            mutations.append(damaged)
        mutations.extend((blob[:31], blob[:-1]))
        for damaged in mutations:
            with self.assertRaises(ValueError):
                ypf.parse(damaged)

    def test_checksum_compression_and_unsafe_paths(self):
        damaged = bytearray(archive_fixture())
        damaged[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "checksum"):
            ypf.parse(damaged)
        for members in ([("../evil", b"x", False)], [("res/A", b"x", False), ("res/a", b"y", False)]):
            with self.assertRaises(ValueError):
                ypf.parse(archive_fixture(members=members))
        blob = bytearray(archive_fixture())
        row = ypf.parse(blob).entries[0]
        stored = row["stored"] + b"garbage"
        offset = len(blob)
        struct.pack_into("<BBIIII", blob, row["field_offset"], row["type"], 1, row["size"], len(stored),
                         offset, zlib.adler32(stored) & 0xFFFFFFFF)
        blob.extend(stored)
        with self.assertRaisesRegex(ValueError, "trailing"):
            ypf.parse(blob)

    def test_streaming_mmap_summary(self):
        blob = archive_fixture()
        with tempfile.TemporaryFile() as stream:
            stream.write(blob)
            stream.flush()
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                report = ypf.validate(mapped)
                self.assertEqual(report["archive_sha256"], hashlib.sha256(blob).hexdigest())
                self.assertNotIn("payload", report["entries"][0])
                self.assertNotIn("name_bytes", report["entries"][0])


class ScriptTests(unittest.TestCase):
    def test_both_xor_keys_and_roundtrip(self):
        for version in (474, 481):
            script = script_fixture(version)
            parsed = ybn.parse_script(script)
            self.assertEqual(parsed["header"][1], version)
            self.assertEqual(ybn.rebuild(parsed["header"], parsed["sections"]), script)

    def test_endpoint_semantics_and_unchanged_linked_branch(self):
        script = script_fixture()
        extra = ybn.operation(ybn.operation(ybn.var(10), ybn.var(11), "="), ybn.eq(ybn.var(12), 0), "&")
        result = ybn.extend_condition(script, 0, extra)
        old, new = ybn.parse_script(script), ybn.parse_script(result)
        self.assertEqual(new["commands"][0]["rows"][1:], old["commands"][0]["rows"][1:])
        self.assertEqual(new["commands"][2:], old["commands"][2:])
        self.assertEqual(new["sections"][2][:len(old["sections"][2])], old["sections"][2])
        self.assertEqual(new["sections"][0], old["sections"][0])
        self.assertEqual(new["sections"][3], old["sections"][3])
        _, _, size, offset = new["commands"][0]["rows"][0]
        condition = new["sections"][2][offset:offset + size]
        cases = [(256, 0, 9, 9, 1), (256, 128, 9, 9, 0), (256, 0, 8, 9, 0),
                 (0, 128, 8, 9, 1), (256, 1, 9, 9, 0)]
        for alpha, progress, slot, fd_slot, expected in cases:
            with self.subTest(alpha=alpha, progress=progress, slot=slot):
                self.assertEqual(evaluate(condition, {20: alpha, 12: progress, 10: slot, 11: fd_slot}), expected)
        with self.assertRaisesRegex(ValueError, "already applied"):
            ybn.extend_condition(result, 0, extra)

    def test_geometry_prefix_and_endpoint_preservation(self):
        script = script_fixture()
        r1 = ybn.extend_condition(script, 0, ybn.eq(ybn.var(12), 0))
        before = ybn.parse_script(r1)
        descriptor = before["commands"][1]["rows"][0]
        r2 = ybn.shorten_parameter(r1, 1, 0, descriptor, 13)
        after = ybn.parse_script(r2)
        self.assertEqual(after["commands"][0], before["commands"][0])
        self.assertEqual(after["sections"][2], before["sections"][2])
        self.assertEqual(after["sections"][0], before["sections"][0])
        self.assertEqual(after["sections"][3], before["sections"][3])
        _, _, old_length, offset = descriptor
        self.assertEqual(evaluate(before["sections"][2][offset:offset + old_length], {30: 1024}), 400)
        self.assertEqual(evaluate(after["sections"][2][offset:offset + 13], {30: 1024}), 512)
        with self.assertRaises(ValueError):
            ybn.shorten_parameter(r2, 1, 0, descriptor, 13)

    def test_bad_section_descriptor_and_token_rejected(self):
        script = script_fixture()
        with self.assertRaises(ValueError):
            ybn.parse_script(script[:-1])
        parsed = ybn.parse_script(script)
        parameters = bytearray(parsed["sections"][1])
        struct.pack_into("<I", parameters, 8, len(parsed["sections"][2]) + 1)
        raw = struct.pack("<8I", *parsed["header"]) + b"".join(
            ybn.xor(section, key=ybn.VERSION_KEYS[474]) for section in
            (parsed["sections"][0], parameters, parsed["sections"][2], parsed["sections"][3]))
        with self.assertRaisesRegex(ValueError, "bounds"):
            ybn.parse_script(raw)
        for token in (b"B", b"B\x04\0\x01"):
            with self.assertRaises(ValueError):
                ybn.tokens(token)
        with self.assertRaises(ValueError):
            ybn.extend_condition(script, 4, ybn.num(0))

    def test_profile_rejects_synthetic_unknown_input(self):
        with self.assertRaisesRegex(ValueError, "identity"):
            ybn.patch_euphoria(script_fixture(), "r1")
        with self.assertRaisesRegex(ValueError, "unknown"):
            ybn.patch_euphoria(script_fixture(), "r3")


if __name__ == "__main__":
    unittest.main()
