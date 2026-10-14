"""Static, sample-specific MoleBox extraction for the euphoriaHD CHS patch.

No sample code is loaded, executed, emulated, or reconstructed as an executable.
The caller receives ordinary resource bytes and is responsible for writing them.
Requires cryptography==50.0.2. All executable inputs are read as data only.

NewDES and the package layout are adapted from Alexey Sudachen's MoleBox source,
commit f526e8a41bcb7884231154e8e5ccb74c789f188d, distributed under GPL-3.0.
The NewDES rotor is included with upstream attribution; no vendor source is executed.
SPDX-License-Identifier: GPL-3.0-only
Adapted for kakacat-yuris-compat; see licenses/molebox-gpl-3.0.txt.
"""

from __future__ import annotations

import array
import hashlib
import struct
import zlib



MOLEBOX_COMMIT = "f526e8a41bcb7884231154e8e5ccb74c789f188d"
XTERNAL_COMMIT = "1cfcaacbdeca03cacc8f8d6ed8a51c8942ca277d"
_CATALOG_KEY = hashlib.md5(b"7233DA04FCF24B388408701CB1F874F3").digest()
_UNKNOWN_SIGN = "06751d87b27887494d2366e3be1654a5"
_UNKNOWN_SHA = "3c3b6bd716c6117ef59ececbda1c55be6aeff4d02c54e05b5ea4489742e94985"

# Case is taken from the actual logprint.dll references; SVFS hashes alone
# cannot distinguish OP.ass from op.ass.
_EXPECTED = {
    "dummy012345678901234/dummy1.png": (1381518, "3c4ec9c1a9b9d807f1141bf6934c78cd6b263954f648f757ba8035646e3896fb"),
    "dummy012345678901234/dummy2.png": (745797, "0a823893e263064881a238865e13880d67e7608a4db8bf0ecaafd7fcfb706725"),
    "dummy012345678901234/dummy3.png": (919178, "0e70d2b77a09ac07204095dd6e05b33440ddcbd97e0532cd73a426baf4201d62"),
    "pac/update2.ypf": (48205403, "9578b355a520dad1a9898050fca59db4d12b38ccc2093f3aaab734409317488d"),
    "pac/update3.ypf": (10482218, "7f554277553af819e92cde5fc8f39d71dfb161dfad12470e87833a37f0787fcb"),
    "1.ttf": (10004408, "10819a4f4c8a8318edb87920690a8837d4aa4cf5518a81370cb96770f889a17a"),
    "2.ttf": (12128500, "0d0e8ba436f803236fa10c27903327284c39186a6e7d859e0fae423d11c44583"),
    "autosub.dll": (19456, "a36e527c98360c6c2b363f80655913755614051912e0b21011899155b236a820"),
    "logprint.dll": (6144, "43b60defb987c626d5792b880207231f43397d6688e1a257d63ef65f04e48e83"),
    "kan_coment.ass": (2211, "5ac15bc31b02b10ddff189a0d8a9fc607708115e5ef5dcc8c5012325b0b9e159"),
    "rin_comment.ass": (1854, "b0193472c52bca7f266cb034937ae59f2f012877d2285681142a8bd88dca7f91"),
    "rik_comment.ass": (3037, "abffa4be54de2ab268ed85a41852a30101cc97e89ac7f710005b0b9866fa74de"),
    "nem_comment.ass": (2761, "25273db8ef036343c5c5647e3f9be6b97d84700bdbd19e095333eaec2b9fe63a"),
    "nat_commente.ass": (3483, "fa5130ec251e84b8b9cbff8e4e2fd8270ad43e38e35922d090fe99d6c3aea7c9"),
    "miy_comment.ass": (2774, "8f4088c554c1430f5edfc14ca449ca02fb23bb9c2ae8d2010ba3d555f1dcded0"),
    "OP.ass": (99402, "a9cdbe7b6ae5b6acd4906ef55ae04846fd01fedba9c8fd16a1fe47b1b96ae9d2"),
}


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _slice(data: bytes, offset: int, length: int, label: str) -> bytes:
    _check(0 <= offset <= len(data) and 0 <= length <= len(data) - offset,
           f"{label}: out-of-bounds range {offset}+{length}")
    return data[offset:offset + length]


def _unpack(fmt: str, data: bytes, offset: int, label: str):
    return struct.unpack(fmt, _slice(data, offset, struct.calcsize(fmt), label))


# Rotor literal from MoleBox MxbPack/stub/ndes.py at MOLEBOX_COMMIT (GPL-3.0).
# xternal C sources were consulted during the original audit, but are neither
# imported, compiled nor needed by this implementation.
_NEWDES_ROTOR = (
    32, 137, 239, 188, 102, 125, 221, 72, 212, 68, 81, 37, 86, 237, 147, 149,
    70, 229, 17, 124, 115, 207, 33, 20, 122, 143, 25, 215, 51, 183, 138, 142,
    146, 211, 110, 173, 1, 228, 189, 14, 103, 78, 162, 36, 253, 167, 116, 255,
    158, 45, 185, 50, 98, 168, 250, 235, 54, 141, 195, 247, 240, 63, 148, 2,
    224, 169, 214, 180, 62, 22, 117, 108, 19, 172, 161, 159, 160, 47, 43, 171,
    194, 175, 178, 56, 196, 112, 23, 220, 89, 21, 164, 130, 157, 8, 85, 251,
    216, 44, 94, 179, 226, 38, 90, 119, 40, 202, 34, 206, 35, 69, 231, 246,
    29, 109, 74, 71, 176, 6, 60, 145, 65, 13, 77, 151, 12, 127, 95, 199,
    57, 101, 5, 232, 150, 210, 129, 24, 181, 10, 121, 187, 48, 193, 139, 252,
    219, 64, 88, 233, 96, 128, 80, 53, 191, 144, 218, 11, 106, 132, 155, 104,
    91, 136, 31, 42, 243, 66, 126, 135, 30, 26, 87, 186, 182, 154, 242, 123,
    82, 166, 208, 39, 152, 190, 113, 205, 114, 105, 225, 84, 73, 163, 99, 111,
    204, 61, 200, 217, 170, 15, 198, 28, 192, 254, 134, 234, 222, 7, 236, 248,
    201, 41, 177, 156, 92, 131, 67, 249, 245, 184, 203, 9, 241, 0, 27, 46,
    133, 174, 75, 18, 93, 209, 100, 120, 76, 213, 16, 83, 4, 107, 140, 52,
    58, 55, 3, 244, 97, 197, 238, 227, 118, 49, 79, 230, 223, 165, 153, 59,
)
_ROTOR_SHA256 = "37954cf0c3c2bf8d753a6514c4a427011155618f7fc0a5db173f7df4d6320859"
_EXE_SHA256 = "1bfb8eedf517c61d933bdb49a760a651a178bf203fe13628577e026fe53e2f18"
_UPSTREAM_SOURCES = [{
    "repository": "sudachen/Molebox", "commit": MOLEBOX_COMMIT,
    "license": "GPL-3.0", "source_path": "MxbPack/stub/ndes.py",
    "url": "https://github.com/sudachen/Molebox/blob/" + MOLEBOX_COMMIT + "/MxbPack/stub/ndes.py",
}]


def _fixed_rotor() -> tuple[list[dict], list[int]]:
    _check(len(_NEWDES_ROTOR) == 256 and sorted(_NEWDES_ROTOR) == list(range(256)),
           "Invalid fixed NewDES rotor")
    _check(hashlib.sha256(bytes(_NEWDES_ROTOR)).hexdigest() == _ROTOR_SHA256,
           "Fixed NewDES rotor changed")
    return [dict(item) for item in _UPSTREAM_SOURCES], list(_NEWDES_ROTOR)


def _newdes_key(key: bytes) -> list[int]:
    _check(len(key) >= 15, "Short NewDES key")
    result = []
    index = 11
    while True:
        for _ in range(3):
            result.append(key[index])
            index = (index + 1) % 15
        result.append(key[index])
        index = (index + 9) % 15
        if index == 12:
            break
        result.append(key[index])
        index += 1
        result.append(key[index])
        index += 1
        result.append(key[index])
        index = (index + 9) % 15
    _check(len(result) == 60, "Unexpected NewDES decipher schedule")
    return result


def _newdes_cbc(key: bytes, data: bytes, rotor: list[int]) -> bytes:
    _check(len(data) % 8 == 0, "Unaligned NewDES metadata")
    schedule = _newdes_key(key)
    result = bytearray()
    previous = bytes(8)
    for offset in range(0, len(data), 8):
        ciphertext = data[offset:offset + 8]
        block = list(ciphertext)
        cursor = 0
        for _ in range(8):
            for j in range(4):
                block[j + 4] ^= rotor[block[j] ^ schedule[cursor]]
                cursor += 1
            block[1] ^= rotor[block[4] ^ schedule[cursor]]
            cursor += 1
            block[2] ^= rotor[block[4] ^ block[5]]
            block[3] ^= rotor[block[6] ^ schedule[cursor]]
            cursor += 1
            block[0] ^= rotor[block[7] ^ schedule[cursor]]
            cursor += 1
        for j in range(4):
            block[j + 4] ^= rotor[block[j] ^ schedule[cursor]]
            cursor += 1
        result.extend(a ^ b for a, b in zip(block, previous))
        previous = ciphertext
    return bytes(result)


def _swap_words(data: bytes) -> bytes:
    words = array.array("I")
    _check(words.itemsize == 4, "Blowfish requires four-byte words")
    words.frombytes(data)
    words.byteswap()
    return words.tobytes()


def _blowfish(key: bytes, data: bytes, cbc: bool = False) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
    except ImportError as exc:
        raise ValueError("MoleBox extraction requires cryptography==50.0.2; install the project requirements") from exc
    # The official wrapper's default key length is 15, despite a 16-byte MD5.
    aligned = len(data) // 8 * 8
    context = Cipher(Blowfish(key[:15]), modes.ECB()).decryptor()
    plain = _swap_words(context.update(_swap_words(data[:aligned])) + context.finalize())
    if cbc:
        previous = bytes(8) + data[:max(0, aligned - 8)]
        plain = bytes(a ^ b for a, b in zip(plain, previous))
    return plain + data[aligned:]


def _crc_table() -> list[int]:
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ (0xA001 if value & 1 else 0)
        table.append(value)
    return table


_CRC16_TABLE = _crc_table()


def _crc16(data: bytes) -> int:
    value = 0
    for byte in data:
        value = (value >> 8) ^ _CRC16_TABLE[(value ^ byte) & 255]
    return value


def _cstring(data: bytes, offset: int) -> str:
    _check(0 <= offset < len(data), "Invalid catalog string offset")
    end = data.find(b"\0", offset)
    _check(end >= offset, "Unterminated catalog string")
    return data[offset:end].decode("ascii")


def _overlay_offset(exe: bytes) -> int:
    _check(exe[:2] == b"MZ", "Input has no PE DOS signature")
    pe_offset, = _unpack("<I", exe, 60, "e_lfanew")
    _check(_slice(exe, pe_offset, 4, "PE signature") == b"PE\0\0", "Invalid PE signature")
    machine, sections = _unpack("<HH", exe, pe_offset + 4, "PE machine/sections")
    optional_size, = _unpack("<H", exe, pe_offset + 20, "PE optional size")
    _check(machine == 0x14C and 0 < sections <= 96, "Expected x86 PE")
    table = pe_offset + 24 + optional_size
    ends = []
    for index in range(sections):
        raw_size, raw_offset = _unpack("<II", exe, table + index * 40 + 16, "PE section")
        _slice(exe, raw_offset, raw_size, "PE raw section")
        ends.append(raw_offset + raw_size)
    return max(ends)


def extract_resources(exe_bytes: bytes) -> tuple[dict[str, bytes], list[dict], dict]:
    """Return 16 exact resource paths, one archived unknown, and JSON-safe audit.

    Unknown records include a ``bytes`` field for the caller's work archive.
    No filesystem mutation or executable reconstruction occurs in this function.
    Deviations from the reviewed sample's resources fail closed with ValueError.
    """
    _check(isinstance(exe_bytes, bytes), "exe_bytes must be immutable bytes")
    _check(hashlib.sha256(exe_bytes).hexdigest() == _EXE_SHA256,
           "Unsupported MoleBox input: SHA256 does not match the reviewed euphoria CHS 1.01 sample")
    sources, rotor = _fixed_rotor()
    overlay = _overlay_offset(exe_bytes)
    sign_a, sign_b = _unpack("<II", exe_bytes, overlay, "MoleBox signature")
    _check(sign_a ^ sign_b == 0x554A4F58 ^ 0x4A4E414D, "MoleBox masked signature mismatch")
    info_offset = overlay + 8
    key = _slice(exe_bytes, info_offset + 368, 16, "STB_INFO key")
    info = _newdes_cbc(key, _slice(exe_bytes, info_offset, 368, "STB_INFO"), rotor)
    extension = _newdes_cbc(key, _slice(exe_bytes, info_offset + 384, 112, "STB_INFO2"), rotor)
    catalog_offset, = _unpack("<I", extension, 60, "catalog pointer")
    catalog_size, catalog_crc = struct.unpack("<II", _blowfish(
        _CATALOG_KEY, _slice(exe_bytes, catalog_offset, 8, "catalog footer")))
    _check(0 < catalog_size <= 65536 and catalog_size % 8 == 0, "Invalid catalog size")
    catalog = _blowfish(_CATALOG_KEY, _slice(
        exe_bytes, catalog_offset - catalog_size, catalog_size, "catalog"), True)
    _check(zlib.crc32(catalog) == catalog_crc, "Catalog CRC32 mismatch")
    package_offset, package_count, mount_offset, mount_count = _unpack("<4I", catalog, 0, "catalog lists")
    _check(package_count == 1 and mount_count == 1, "Unexpected package/mount count")
    header_offset, package_name_offset = _unpack("<II", catalog, package_offset, "package record")
    mount_flags, mount_name_offset, package_key = _unpack("<II16s", catalog, mount_offset, "mount record")
    package_name = _cstring(catalog, package_name_offset)
    _check(package_name == "default" and _cstring(catalog, mount_name_offset) == "default"
           and mount_flags == 1, "Unexpected mount configuration")
    header = _blowfish(package_key, _slice(exe_bytes, header_offset, 48, "package header"), True)
    _check(header[-8:] == b"STELPACK", "Package STELPACK signature mismatch")
    tree_offset, tree_size, root_offset, base_back, tree_crc, map_offset, map_count, _, stream_offset, stream_size = struct.unpack("<10I", header[:40])
    _check(tree_offset == header_offset - tree_size and tree_size % 8 == 0
           and stream_offset == 0 and stream_size == 0 and map_count == 19,
           "Unexpected package tree layout")
    tree = _blowfish(package_key, _slice(exe_bytes, tree_offset, tree_size, "file tree"), True)
    _check(zlib.crc32(tree) == tree_crc, "File tree CRC32 mismatch")
    base = header_offset - base_back
    _check(0 <= base < tree_offset, "Invalid package base")
    name_lookup = {hashlib.md5(path.replace("/", "\\").upper().encode("utf-16le")).digest(): path
                   for path in _EXPECTED}
    resources: dict[str, bytes] = {}
    unknowns: list[dict] = []
    records: list[dict] = []
    seen: set[int] = set()
    directory_count = block_count = path_crc_count = 0

    def walk(node_offset: int, parent: str, depth: int) -> None:
        nonlocal directory_count, block_count, path_crc_count
        _check(depth <= 32 and node_offset not in seen, "Cycle or excessive tree depth")
        seen.add(node_offset)
        node = _slice(tree, node_offset, 52, "file node")
        name_offset, name_length = struct.unpack_from("<II", node, 8)
        name_crc, = struct.unpack_from("<I", node, 16)
        path_sign = node[20:36]
        flags, real_size, count = struct.unpack_from("<III", node, 40)
        _check(count <= 4096, "Excessive file block/child count")
        if flags & 0x80000000:
            directory_count += 1
            public_name = _slice(tree, name_offset, name_length * 2, "directory name").decode("utf-16le") if name_offset else ""
            _check(not any(char in public_name for char in "\\/:\0") and public_name not in (".", ".."),
                   "Unsafe public directory name")
            path = "/".join(part for part in (parent, public_name) if part)
            for index in range(count):
                child, = _unpack("<I", tree, node_offset + 52 + index * 4, "child reference")
                walk(child, path, depth + 1)
            return
        _check(flags == 7 and real_size <= 64 * 1024 * 1024, "Unexpected hidden file flags/size")
        output = bytearray()
        for index in range(count):
            packed_size, block_size, block_flags, expected_crc, block_offset = _unpack(
                "<4HI", tree, node_offset + 52 + index * 12, "file block")
            _check(0 < block_size <= 48 * 1024 and 0 < packed_size <= 48 * 1024
                   and block_flags & ~6 == 0, "Invalid block descriptor")
            _check(base + block_offset + packed_size <= tree_offset, "Block overlaps directory")
            packed = _slice(exe_bytes, base + block_offset, packed_size, "resource block")
            if block_flags & 4:
                packed = _blowfish(package_key, packed, True)
            if block_flags & 2:
                decoder = zlib.decompressobj()
                decoded = decoder.decompress(packed, block_size + 1)
                _check(decoder.eof and not decoder.unconsumed_tail, "Incomplete/oversized zlib block")
                decoded += decoder.flush()
            else:
                _check(len(packed) >= block_size, "Short uncompressed block")
                decoded = packed[:block_size]
            _check(len(decoded) == block_size, "Block decompression length mismatch")
            _check(_crc16(decoded) == expected_crc, "Block CRC16 mismatch")
            output.extend(decoded)
            block_count += 1
        _check(len(output) == real_size, "Complete file length mismatch")
        payload = bytes(output)
        sha256 = hashlib.sha256(payload).hexdigest()
        path = name_lookup.get(path_sign)
        record = {"path": path, "parent": parent, "sign": path_sign.hex(),
                  "size": real_size, "sha256": sha256, "flags": flags, "blocks": count}
        if path is not None:
            _check(path not in resources and path.rpartition("/")[0] == parent, "Duplicate or misplaced resource")
            encoded_path = path.replace("/", "\\").upper().encode("utf-16le")
            _check(zlib.crc32(encoded_path) == name_crc, "Recovered path CRC32 mismatch")
            _check((real_size, sha256) == _EXPECTED[path], "Resource differs from reviewed baseline")
            path_crc_count += 1
            resources[path] = payload
        else:
            _check(path_sign.hex() == _UNKNOWN_SIGN and real_size == 10 and sha256 == _UNKNOWN_SHA
                   and parent == "", "Unexpected unresolved resource")
            unknowns.append({**record, "bytes": payload,
                             "archive_filename": f"unknown_{path_sign.hex()}.bin"})
        records.append(record)

    walk(root_offset, "", 0)
    mapped_nodes = set(_unpack("<I", tree, map_offset + index * 4, "map reference")[0]
                       for index in range(map_count))
    _check(mapped_nodes == seen - {root_offset}, "SVFS map differs from traversed tree")
    _check(set(resources) == set(_EXPECTED) and len(unknowns) == 1 and len(records) == 17
           and directory_count == 3 and block_count == 1722
           and sum(item["size"] for item in records) == 84008154,
           "Reviewed resource inventory differs")
    audit = {
        "format": "MoleBox", "status": "PASS", "static_only": True,
        "molebox_commit": MOLEBOX_COMMIT, "xternal_commit": XTERNAL_COMMIT,
        "fixed_sources": sources, "exe_sha256": hashlib.sha256(exe_bytes).hexdigest(),
        "exe_size": len(exe_bytes), "overlay_offset": overlay, "stb_info_offset": info_offset,
        "catalog_offset": catalog_offset, "catalog_size": catalog_size,
        "catalog_crc32": f"{catalog_crc:08x}", "package_name": package_name,
        "package_header_offset": header_offset, "package_base": base,
        "tree_offset": tree_offset, "tree_size": tree_size, "tree_crc32": f"{tree_crc:08x}",
        "virtual_files": len(records), "known_paths": len(resources),
        "unknown_files": len(unknowns), "directories_including_root": directory_count,
        "blocks": block_count, "expanded_bytes": 84008154,
        "checks": {"catalog_crc32_pass": 1, "tree_crc32_pass": 1,
                   "block_crc16_pass": block_count, "block_length_pass": block_count,
                   "file_length_pass": len(records), "recovered_path_md5_pass": len(resources),
                   "recovered_path_crc32_pass": path_crc_count,
                   "resource_sha256_baseline_pass": len(records), "tree_map_pass": True},
        "resources": records,
    }
    return resources, unknowns, audit
