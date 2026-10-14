"""Version-locked G24 Siglus R2 reconstruction. Never executes game code."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import stat
import struct
from pathlib import Path
from .common import CHUNK, require, file_hash, is_reparse

PROFILE = "seishojyo-r2"
GAME_DIR_NAME = "G24_Kaka_R2_20261014"
SCENE_SIZE = 13607939
SCENE_SHA256 = "60affba5f824237947fdf4cbba2521f5c969095ad1b13908926f086539d196d0"
SCENE_R2_SHA256 = "4e75f803a231db9be66e7b084dbd779946afdd2193399e7f2526138ac7e36cd2"
GAMEEXE_SIZE = 13492
GAMEEXE_SHA256 = "6f980594e8beb8c3f1ee489ca62ff1c00b7f86bc9149382d0989c61248de3460"
GAMEEXE_R2_SHA256 = "8fd6b1cff8b3309ce4c8c983c514602b1ed41443f2d513d8bc8ea638d7635513"
MEDIA_COUNT = 2298
MEDIA_BYTES = 3379290100
MEDIA_INVENTORY_SHA256 = "0e38ecac9573f07c0aca5f8c283be9b70faf407176c6b7e3bcfbca8ae5f6353f"
MEDIA_SUFFIXES = {"bgm": ".ogg", "dat": ".tcr", "g00": ".g00", "gan": ".gan",
                  "koe": ".ovk", "mov": ".wmv", "wav": ".nwa"}
MARKER_NAME = "PACKAGE_VERSION_R2.txt"
MARKER = (b"Game 24 Siglus compatibility R2 20261014\r\n"
          b"Extra XOR removed; common compression and all translated scenes retained.\r\n"
          b"Use this unique folder for iOS testing.\r\n")
MARKER_SHA256 = "c2402c2d284935cbc5525e6e964ddf8d8350b6f3b6bd24a3eba302e1669b602e"
# Public format constant, not this title's extra16 parameter.
PUBLIC_GAME_HEAD = bytes.fromhex("d829b9163d1a76d0879b2d0c7bd1a919")


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _key(key):
    require(isinstance(key, (bytes, bytearray)) and len(key) == 16, "Expected a 16-byte XOR parameter")


def _scene_blocks(data, flag=1):
    require(isinstance(data, (bytes, bytearray)) and len(data) >= 92, "Truncated Scene header")
    head = struct.unpack_from("<23I", data)
    require(head[0] == 92 and head[18] == head[20] == 190, "Unsupported Scene header/count")
    require(head[21] == flag, "Scene extra XOR flag differs; do not apply R2 twice")
    table, payload = head[17], head[19]
    require(92 <= table and table + 190 * 8 <= payload <= len(data), "Scene index table out of bounds")
    blocks, last_end = [], payload
    for index in range(190):
        offset, length = struct.unpack_from("<II", data, table + index * 8)
        start, end = payload + offset, payload + offset + length
        require(length >= 8 and start >= last_end and end <= len(data), "Scene block overlap/order/bounds")
        blocks.append((start, end))
        last_end = end
    return blocks


def _xor_scene(data, key, old_flag, new_flag):
    _key(key)
    blocks = _scene_blocks(data, old_flag)
    result = bytearray(data)
    for start, end in blocks:
        for offset in range(end - start):
            result[start + offset] ^= key[offset % 16]
    struct.pack_into("<I", result, 84, new_flag)
    return bytes(result)


def transform_scene(data, key):
    return _xor_scene(data, key, 1, 0)


def _xor_gameexe(data, key, old_flag, new_flag):
    _key(key)
    require(isinstance(data, (bytes, bytearray)) and len(data) >= 8, "Truncated Gameexe header")
    require(struct.unpack_from("<I", data, 4)[0] == old_flag,
            "Gameexe extra XOR flag differs; do not apply R2 twice")
    result = bytearray(data)
    for offset in range(len(data) - 8):
        result[offset + 8] ^= key[offset % 16]
    struct.pack_into("<I", result, 4, new_flag)
    return bytes(result)


def transform_gameexe(data, key):
    return _xor_gameexe(data, key, 1, 0)


def derive_extra_key(data):
    """Recover only from the matched config; validate the unique result by R2 hash.

    The reviewed configuration's compressed prefix has one back-reference token
    byte to resolve. Candidates never leave memory or appear in reports.
    """
    require(len(data) == GAMEEXE_SIZE and _sha(data) == GAMEEXE_SHA256,
            "Unsupported original Gameexe fingerprint")
    require(len(data) >= 24 and struct.unpack_from("<I", data, 4)[0] == 1,
            "Unsupported Gameexe key-recovery header")
    header = struct.pack("<II", len(data) - 8, 69544)
    matches = []
    for token in range(256):
        plain = header + bytes((0xFB, 10, 0, token, 0, 35, 0, 68))
        candidate = bytes(a ^ b ^ c for a, b, c in zip(data[8:24], PUBLIC_GAME_HEAD, plain))
        if _sha(transform_gameexe(data, candidate)) == GAMEEXE_R2_SHA256:
            matches.append(candidate)
    require(len(matches) == 1, "Config parameter recovery did not produce a unique reviewed R2")
    return matches[0]


def _regular(path, directory=False):
    item = Path(path).lstat()
    require(not is_reparse(path), "Source/stage contains a link or reparse entry")
    require(stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode),
            "Expected a regular directory" if directory else "Expected a regular file")


def _component(name):
    require(name not in ("", ".", "..") and not name.endswith((".", " "))
            and not any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name), "Unsafe resource name")
    reserved = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
    require(name.split(".", 1)[0].upper() not in reserved, "Reserved resource name")


def _snapshot(path, root):
    _regular(path)
    before = path.stat()
    hashed = file_hash(path)
    _regular(path)
    after = path.stat()
    require((before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) ==
            (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev), "Source changed while hashing")
    return {"path": path.relative_to(root).as_posix(), "size": after.st_size,
            "sha256": hashed, "mtime_ns": after.st_mtime_ns}


def media_digest(rows):
    ordered = sorted(({field: row[field] for field in ("path", "size", "sha256")}
                      for row in rows), key=lambda row: row["path"])
    return _sha(json.dumps(ordered, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii"))


def _media_suffix(folder, suffix):
    # The reviewed wav directory contains 305 NWA and 12 Ogg resources.
    return suffix == MEDIA_SUFFIXES[folder] or (folder == "wav" and suffix == ".ogg")


def _media_rows(source):
    rows, seen = [], set()
    for folder, suffix in MEDIA_SUFFIXES.items():
        top = source / folder
        _regular(top, True)
        queue, count = [top], 0
        while queue:
            parent = queue.pop()
            _regular(parent, True)
            for child in sorted(parent.iterdir(), key=lambda path: path.name):
                _component(child.name)
                require(not is_reparse(child), "Source media contains a link or reparse entry")
                relative = child.relative_to(source).as_posix()
                require(relative.casefold() not in seen, "Case-insensitive resource name collision")
                seen.add(relative.casefold())
                if child.is_dir():
                    _regular(child, True)
                    queue.append(child)
                else:
                    _regular(child)
                    require(_media_suffix(folder, child.suffix.lower()), "Unexpected runtime resource type: " + relative)
                    rows.append(_snapshot(child, source))
                    count += 1
        require(count > 0, "Required media directory is empty")
    require(len(rows) == MEDIA_COUNT and sum(row["size"] for row in rows) == MEDIA_BYTES,
            "Runtime media count/size does not match reviewed original version")
    require(media_digest(rows) == MEDIA_INVENTORY_SHA256, "Runtime media fingerprint differs from reviewed original version")
    return sorted(rows, key=lambda row: row["path"])


def inspect(source, profile):
    require(profile == PROFILE, "Unsupported Siglus profile")
    source = Path(source)
    _regular(source, True)
    source = source.resolve()
    # Inspect only required entries; root saves, backups and executables are not read.
    names = [child.name.casefold() for child in source.iterdir()]
    for required in ("Scene.pck", "Gameexe.dat", *MEDIA_SUFFIXES):
        require(names.count(required.casefold()) == 1, "Missing or duplicate required source entry")
    core = [_snapshot(source / name, source) for name in ("Scene.pck", "Gameexe.dat")]
    for row, size, expected in ((core[0], SCENE_SIZE, SCENE_SHA256), (core[1], GAMEEXE_SIZE, GAMEEXE_SHA256)):
        require(row["size"] == size and row["sha256"] == expected, "Unsupported or already patched source fingerprint")
    _scene_blocks((source / "Scene.pck").read_bytes())
    game = (source / "Gameexe.dat").read_bytes()
    require(len(game) >= 8 and struct.unpack_from("<I", game, 4)[0] == 1, "Gameexe extra XOR flag differs")
    media = _media_rows(source)
    return {"game": "G24 Siglus", "profile": profile, "status": "SOURCE_FINGERPRINTS_VALIDATED",
            "ios_status": "NOT_TESTED", "source_files": sorted(core + media, key=lambda row: row["path"]),
            "media_count": len(media), "media_inventory_sha256": media_digest(media),
            "expected_output_file_count": MEDIA_COUNT + 3}


def _write_new(path, data):
    with path.open("xb") as stream:
        stream.write(data)
    require(file_hash(path) == _sha(data), "Generated file readback mismatch")


def prepare(source, stage, profile):
    source, stage = Path(source), Path(stage)
    _regular(source, True)
    if os.path.lexists(stage):
        _regular(stage, True)
        require(not any(stage.iterdir()), "Staging directory must be empty")
    source, stage = source.resolve(), stage.resolve()
    require(not stage.is_relative_to(source) and not source.is_relative_to(stage), "Source and stage trees must be separate")
    game_dir = stage / GAME_DIR_NAME
    require(not os.path.lexists(game_dir), "Refusing to overwrite staged game")
    baseline = inspect(source, profile)
    scene = (source / "Scene.pck").read_bytes()
    game = (source / "Gameexe.dat").read_bytes()
    require(_sha(scene) == SCENE_SHA256 and len(scene) == SCENE_SIZE, "Scene changed before transformation")
    key = derive_extra_key(game)
    scene_r2, game_r2 = transform_scene(scene, key), transform_gameexe(game, key)
    require(_sha(scene_r2) == SCENE_R2_SHA256 and _sha(game_r2) == GAMEEXE_R2_SHA256, "R2 output fingerprints differ")
    require(_xor_scene(scene_r2, key, 0, 1) == scene and _xor_gameexe(game_r2, key, 0, 1) == game,
            "XOR reversal failed to restore original bytes")
    require(_sha(MARKER) == MARKER_SHA256, "Version marker differs from accepted R2")
    ancestor = stage
    while not ancestor.exists():
        ancestor = ancestor.parent
    needed = 2 * (MEDIA_BYTES + SCENE_SIZE + GAMEEXE_SIZE + len(MARKER)) + 256 * 1024 * 1024
    require(shutil.disk_usage(ancestor).free >= needed, "Insufficient space for independent stage and ZIP")
    stage.mkdir(parents=True, exist_ok=True)
    game_dir.mkdir(exist_ok=False)
    for row in baseline["source_files"]:
        if row["path"] in ("Scene.pck", "Gameexe.dat"):
            continue
        original, target = source / row["path"], game_dir / row["path"]
        _regular(original)
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        with original.open("rb") as src, target.open("xb") as dst:
            for chunk in iter(lambda: src.read(CHUNK), b""):
                digest.update(chunk)
                dst.write(chunk)
        require(digest.hexdigest() == row["sha256"] and file_hash(target) == row["sha256"],
                "Media changed during copy or target readback")
    for name, data in (("Scene.pck", scene_r2), ("Gameexe.dat", game_r2), (MARKER_NAME, MARKER)):
        _write_new(game_dir / name, data)
    require(inspect(source, profile) == baseline, "Source files changed during preparation")
    return {"game_dir": game_dir, "summary": {
        "game": "G24 Siglus", "profile": profile, "repair": "R2", "status": "FILE_VALIDATED",
        "ios_status": "NOT_TESTED_BY_THIS_BUILD", "game_executed": False, "source_preserved": True,
        "file_count": MEDIA_COUNT + 3, "scene_count": 190, "media_count": MEDIA_COUNT,
        "media_inventory_sha256": MEDIA_INVENTORY_SHA256, "xor_reversal_exact": True,
        "original_scene_sha256": SCENE_SHA256, "output_scene_sha256": SCENE_R2_SHA256,
        "original_gameexe_sha256": GAMEEXE_SHA256, "output_gameexe_sha256": GAMEEXE_R2_SHA256,
        "extra_parameter_recovered_locally": True, "common_xor_and_lzss_preserved": True,
        "excluded": ["executables", "DLLs", "savedata", "patch_directories", "backups", "key_files"]}}


def validate_output_inventory(rows):
    """Verify supported R2 contents independently of editable manifest claims."""
    require(len(rows) == MEDIA_COUNT + 3 and len({r["path"].casefold() for r in rows}) == len(rows),
            "Unexpected R2 output member count or collision")
    indexed = {row["path"]: row for row in rows}
    for name, size, expected in (("Scene.pck", SCENE_SIZE, SCENE_R2_SHA256),
                                 ("Gameexe.dat", GAMEEXE_SIZE, GAMEEXE_R2_SHA256),
                                 (MARKER_NAME, len(MARKER), MARKER_SHA256)):
        require(name in indexed and indexed[name]["size"] == size and indexed[name]["sha256"] == expected,
                "R2 output fingerprint/marker mismatch")
    media = [row for row in rows if row["path"] not in ("Scene.pck", "Gameexe.dat", MARKER_NAME)]
    for row in media:
        parts = row["path"].split("/")
        require(len(parts) >= 2 and parts[0] in MEDIA_SUFFIXES, "Unexpected R2 resource path")
        for part in parts:
            _component(part)
        require(_media_suffix(parts[0], Path(row["path"]).suffix.lower()), "Unexpected R2 resource type")
    require(sum(row["size"] for row in media) == MEDIA_BYTES and media_digest(media) == MEDIA_INVENTORY_SHA256,
            "R2 media differs from reviewed original version")
