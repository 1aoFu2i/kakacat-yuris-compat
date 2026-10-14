# SPDX-License-Identifier: GPL-3.0-only AND Apache-2.0
"""Version-locked, read-only EVB preparation for Maggot Baits."""

from __future__ import annotations

from collections import Counter
import hashlib
import io
import struct
import zlib

CN_EXE_SHA256 = "a9532cea19f4f5d6e8c4dd19acbc385db2e99cf3bc6fc393ec14b6716fd226dd"
CN_EXE_SIZE = 19549184
EVB_OFFSET = 3628282
KEY = bytes.fromhex("76033b26")

# The following bounded structure reader is adapted from evbunpack 0.2.6,
# mos9527 and contributors, Apache-2.0, commit
# ee7b647acf2a46617b0c448dfa83d63132ea917b. Source: __main__.py / const.py.
# Modifications 2026-10-14: no PE restoration, no decompression or file writes,
# no third-party imports, explicit truncation and bounded-tree checks.
# Full license and source notices are retained in licenses/ and third_party/.
EVB_MAGIC = b"EVB\0"
NODE_TYPE_FILE = 2
NODE_TYPE_FOLDER = 3
_HEADER = struct.Struct("<I8sI")
_FILE = struct.Struct("<2sI4s8s8s8s15sI")


def _read(stream: io.BytesIO, size: int) -> bytes:
    result = stream.read(size)
    if len(result) != size:
        raise ValueError("Truncated EVB structure")
    return result


def _header(stream: io.BytesIO) -> dict:
    size, _padding, children = _HEADER.unpack(_read(stream, _HEADER.size))
    return {"size": size, "objects_count": children}


def _named(stream: io.BytesIO) -> dict:
    raw = bytearray()
    for _ in range(32768):
        pair = _read(stream, 2)
        if pair == b"\0\0":
            break
        raw.extend(pair)
    else:
        raise ValueError("EVB filename exceeds limit")
    kind = _read(stream, 1)[0]
    try:
        name = raw.decode("utf-16-le", errors="strict")
    except UnicodeDecodeError as error:
        raise ValueError("Invalid EVB UTF-16 filename") from error
    return {"name": name, "type": kind}


def external_tree(data: bytes, offset: int, *, max_nodes: int = 4096):
    if not 0 <= offset <= len(data) - 80:
        raise ValueError("EVB marker offset is outside the input")
    stream = io.BytesIO(data)
    stream.seek(offset)
    if _read(stream, 4) != EVB_MAGIC:
        raise ValueError("Invalid EVB signature")
    _read(stream, 60)
    main = _header(stream)
    payload_offset = stream.tell() + main["size"] - 12
    if not stream.tell() <= payload_offset <= len(data):
        raise ValueError("EVB payload origin is outside the input")
    stream.seek(-1, 1)
    yield main
    maximum = current = 0
    for _ in range(max_nodes):
        node = {**_header(stream), **_named(stream)}
        if node["type"] == NODE_TYPE_FILE:
            (_pad, original_size, _pad2, _time1, _time2, _time3,
             _pad3, stored_size) = _FILE.unpack(_read(stream, _FILE.size))
            if original_size != stored_size:
                raise ValueError("Compressed EVB resources are not supported by this profile")
            if payload_offset < 0 or stored_size > len(data) - payload_offset:
                raise ValueError("EVB payload extends beyond the input")
            node.update(original_size=original_size, stored_size=stored_size,
                        offset=payload_offset)
            payload_offset += stored_size
            current += 1
        elif node["type"] == NODE_TYPE_FOLDER:
            _read(stream, 25)
            maximum += node["objects_count"]
            current += 1
        else:
            raise ValueError("Unexpected EVB node type")
        if stream.tell() > payload_offset:
            raise ValueError("EVB tree overlaps its payloads")
        yield node
        if current > maximum and maximum > 0:
            return
    raise ValueError("EVB node count exceeds limit")

# End of the Apache-2.0-derived structure reader. The version-locking,
# resource safety and integrity validation below is original GPL-3.0 code.


def _need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _png(data: bytes) -> None:
    """Validate PNG container, IDAT stream and scanline layout using stdlib."""
    _need(data.startswith(b"\x89PNG\r\n\x1a\n"), "PNG signature mismatch")
    pos, state, header, palette = 8, "before", None, None
    idat: list[bytes] = []
    ended = False
    while pos < len(data):
        _need(pos + 12 <= len(data), "PNG chunk header truncated")
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4:pos + 8]
        end = pos + 12 + length
        _need(end <= len(data), "PNG chunk exceeds payload")
        _need(all(65 <= value <= 90 or 97 <= value <= 122 for value in kind)
              and 65 <= kind[2] <= 90, "Invalid PNG chunk type")
        body = data[pos + 8:end - 4]
        checksum = struct.unpack_from(">I", data, end - 4)[0]
        _need(zlib.crc32(body, zlib.crc32(kind)) & 0xffffffff == checksum,
              "PNG chunk CRC mismatch")
        if header is None:
            _need(kind == b"IHDR" and length == 13, "PNG first chunk must be IHDR")
            header = struct.unpack(">IIBBBBB", body)
            width, height, depth, color, compression, filtering, interlace = header
            depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8},
                      4: {8, 16}, 6: {8, 16}}
            _need(0 < width <= 0x7fffffff and 0 < height <= 0x7fffffff
                  and color in depths and depth in depths[color],
                  "PNG dimensions or color/depth invalid")
            _need(compression == filtering == 0 and interlace in (0, 1),
                  "PNG IHDR method invalid")
        elif kind == b"IHDR":
            raise ValueError("Duplicate PNG IHDR")
        elif kind == b"PLTE":
            _need(palette is None and state == "before" and color not in (0, 4)
                  and 0 < length <= 768 and length % 3 == 0, "Invalid PNG palette")
            palette = length // 3
            _need(color != 3 or palette <= 1 << depth, "PNG palette exceeds depth")
        elif kind == b"IDAT":
            _need(state != "after" and (color != 3 or palette is not None),
                  "Invalid PNG IDAT order")
            state = "during"
            idat.append(body)
        elif kind == b"IEND":
            _need(length == 0 and idat and end == len(data), "Invalid PNG IEND")
            ended = True
            break
        else:
            _need(bool(kind[0] & 0x20), "Unknown critical PNG chunk")
            if state == "during":
                state = "after"
        pos = end
    _need(ended and header is not None, "PNG missing IEND or IHDR")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    passes = [(0, 0, 1, 1)] if interlace == 0 else [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]
    rows = []
    for x0, y0, dx, dy in passes:
        w = max(0, (width - x0 + dx - 1) // dx)
        h = max(0, (height - y0 + dy - 1) // dy)
        if w and h:
            rows.append(((w * channels * depth + 7) // 8, h))
    expanded = sum((row_bytes + 1) * count for row_bytes, count in rows)
    _need(expanded <= 512 * 1024 * 1024, "PNG expansion exceeds limit")
    decoder = zlib.decompressobj()
    raw = decoder.decompress(b"".join(idat), expanded + 1)
    _need(len(raw) == expanded and decoder.eof and not decoder.unused_data
          and not decoder.unconsumed_tail, "Incomplete or trailing PNG IDAT stream")
    pos = 0
    for row_bytes, count in rows:
        for _ in range(count):
            _need(raw[pos] <= 4, "Invalid PNG scanline filter")
            pos += row_bytes + 1
    _need(pos == len(raw), "PNG scanline layout mismatch")


def resources(executable: bytes) -> tuple[dict[str, bytes], dict]:
    """Return resource bytes in memory; never launch or reconstruct the EXE."""
    _need(len(executable) == CN_EXE_SIZE and sha256(executable) == CN_EXE_SHA256,
          "Unsupported Maggot Baits Chinese executable fingerprint")
    _need(executable.find(EVB_MAGIC) == EVB_OFFSET, "EVB package marker changed")
    nodes = iter(external_tree(executable, EVB_OFFSET))
    main = next(nodes)
    _need(main["objects_count"] == 1, "Unexpected EVB virtual root count")
    files: dict[str, bytes] = {}
    directories, seen, offsets = [], set(), []

    def visit(prefix: str = "", depth: int = 0) -> None:
        _need(depth <= 32, "EVB nesting exceeds limit")
        try:
            node = next(nodes)
        except StopIteration as error:
            raise ValueError("EVB tree ended before declared node counts") from error
        name = node["name"]
        if name == "%DEFAULT FOLDER%":
            _need(depth == 0 and node["type"] == NODE_TYPE_FOLDER,
                  "EVB default folder appears outside the root")
            name = ""
        else:
            _need(bool(name) and name not in (".", "..") and name[-1] not in (".", " ")
                  and not any(value in name for value in '\\/:*?"<>|\0')
                  and "\ufffd" not in name, "Unsafe EVB resource filename")
        path = "/".join(value for value in (prefix, name) if value)
        _need(path.casefold() not in seen, "Duplicate or case-colliding EVB path")
        seen.add(path.casefold())
        if node["type"] == NODE_TYPE_FOLDER:
            directories.append(path)
            for _ in range(node["objects_count"]):
                visit(path, depth + 1)
            return
        _need(node["type"] == NODE_TYPE_FILE, "Unexpected EVB resource type")
        offset, size = node["offset"], node["original_size"]
        _need(size == node["stored_size"] and 0 <= offset <= len(executable)
              and size <= len(executable) - offset, "Invalid EVB payload range")
        _need(not offsets or offsets[-1][1] == offset, "EVB payloads are not contiguous")
        offsets.append((offset, offset + size))
        files[path] = executable[offset:offset + size]

    visit()
    _need(next(nodes, None) is None, "Unconsumed EVB tree nodes")
    _need(len(files) == 696 and len(directories) == 34
          and sum(map(len, files.values())) == 15431146, "EVB resource inventory changed")
    _need(offsets[0][0] == 3700905 and offsets[-1][1] == 19132051,
          "EVB payload region changed")
    counts = Counter(path.split("/")[0] for path in files)
    _need(counts == {"cgsys": 489, "ysbin": 198, "cg": 9},
          "EVB resource path inventory changed")
    magic_counts: Counter = Counter()
    complete_scripts = 0
    for path, payload in files.items():
        if path.endswith(".png"):
            _png(payload)
            continue
        _need(path.endswith(".ybn") and len(payload) >= 8, "Unexpected EVB extension")
        magic, version = struct.unpack_from("<4sI", payload)
        _need(version == 481 and magic in (b"YSTB", b"YSCF"), "Unexpected translated YBN format")
        magic_counts[magic] += 1
        if magic == b"YSCF":
            _need(path == "ysbin/yscfg.ybn" and len(payload) == 98,
                  "Unexpected translated YSCF resource")
        elif path == "ysbin/yst00028.ybn":
            _need(len(payload) == 7883 and struct.unpack_from("<8I", payload) ==
                  (int.from_bytes(b"YSTB", "little"), 481, 184, 736, 3552, 2748, 736, 0),
                  "Unsupported legacy caption-script layout")
        else:
            from .maggot_patches import parse_script
            parse_script(payload)
            complete_scripts += 1
    _need(magic_counts == {b"YSTB": 197, b"YSCF": 1} and complete_scripts == 196,
          "EVB script inventory changed")
    return files, {"resources": 696, "directories": 34, "expanded_bytes": 15431146,
                   "png_integrity_pass": 498, "ordinary_ystb_structure_pass": 196,
                   "compressed_resources": 0, "aplib_used": False, "pefile_used": False,
                   "executable_executed_or_reconstructed": False,
                   "upstream_version": "0.2.6",
                   "upstream_commit": "ee7b647acf2a46617b0c448dfa83d63132ea917b"}
