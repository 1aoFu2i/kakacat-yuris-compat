"""Strict, read-only YPF parsing and append-only resource replacement.

No engine executable is loaded. Filename lengths are recovered from their
hashes, without redistributing a filename substitution table. This is a
purpose-built implementation for the archive versions in the documented
KrkrCat compatibility cases, not a general game archive converter.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import zlib

SUPPORTED_VERSIONS = frozenset((290, 292, 474, 481, 490))
MAX_RESOURCE_BYTES = 512 * 1024 * 1024


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("YPF: " + message)


def murmur2(data) -> int:
    """MurmurHash2, little endian, seed zero (YPF 481/490)."""
    mult = 0x5BD1E995
    h = len(data) & 0xFFFFFFFF
    end = len(data) & ~3
    for (k,) in struct.iter_unpack("<I", memoryview(data)[:end]):
        k = k * mult & 0xFFFFFFFF
        k ^= k >> 24
        k = k * mult & 0xFFFFFFFF
        h = (h * mult & 0xFFFFFFFF) ^ k
    if len(data) != end:
        h ^= int.from_bytes(memoryview(data)[end:], "little")
        h = h * mult & 0xFFFFFFFF
    h ^= h >> 13
    h = h * mult & 0xFFFFFFFF
    return (h ^ (h >> 15)) & 0xFFFFFFFF


def _name_hash(raw: bytes, version: int) -> int:
    return murmur2(raw) if version >= 481 else zlib.crc32(raw) & 0xFFFFFFFF


def _stored_hash(raw, version: int) -> int:
    return murmur2(raw) if version >= 481 else zlib.adler32(raw) & 0xFFFFFFFF


def _safe_name(raw: bytes) -> str:
    try:
        name = raw.decode("cp932", errors="strict").replace("\\", "/")
    except UnicodeDecodeError as exc:
        raise ValueError("YPF: filename is not CP932") from exc
    _need(not name.startswith("/") and ":" not in name and all(ord(c) >= 32 for c in name), "unsafe filename")
    _need(all(part not in ("", ".", "..") for part in name.split("/")), "unsafe filename component")
    return name


def _index(data) -> tuple[int, int, list[dict]]:
    view = memoryview(data)
    _need(len(view) >= 32, "truncated header")
    signature, version, count, field = struct.unpack_from("<4sIII", view)
    _need(signature == b"YPF\0", "invalid signature")
    _need(version in SUPPORTED_VERSIONS, f"unsupported version {version}")
    # The Chinese 292 updates use a directory size. The original 290 and
    # 474/481/490 archives use an absolute end, verified against source files.
    directory_end = field + 32 if version == 292 else field
    tail_format = "<BBIIQI" if version >= 481 else "<BBIIII"
    tail_size = struct.calcsize(tail_format)
    _need(32 <= directory_end <= len(view), "invalid directory boundary")
    _need(count <= (directory_end - 32) // (6 + tail_size), "impossible entry count")
    pos, rows, names = 32, [], set()
    length_mapping = {}
    for index in range(count):
        _need(pos + 6 + tail_size <= directory_end, f"truncated directory record {index}")
        name_hash, encoded_length = struct.unpack_from("<IB", view, pos)
        start = pos + 5
        matches = []
        # At most 255 bytes can be encoded. A matching checksum is required
        # and ambiguous matches are rejected; no guessed length is accepted.
        maximum = min(255, directory_end - start - tail_size)
        decoded_names = bytes(byte ^ 255 for byte in view[start:start + maximum])
        for length in range(1, maximum + 1):
            raw = decoded_names[:length]
            if _name_hash(raw, version) == name_hash:
                matches.append((length, raw))
        _need(len(matches) == 1, f"filename hash has {len(matches)} matches at record {index}")
        length, raw_name = matches[0]
        key = encoded_length ^ 255
        _need(key not in length_mapping or length_mapping[key] == length, "inconsistent filename length encoding")
        length_mapping[key] = length
        name = _safe_name(raw_name)
        _need(name.casefold() not in names, f"duplicate filename {name!r}")
        names.add(name.casefold())
        field_offset = start + length
        kind, packed, size, stored_size, offset, checksum = struct.unpack_from(tail_format, view, field_offset)
        _need(packed in (0, 1), f"invalid compression flag for {name}")
        _need(size <= MAX_RESOURCE_BYTES, f"resource exceeds expansion limit: {name}")
        _need(directory_end <= offset <= len(view) and stored_size <= len(view) - offset, f"payload out of bounds: {name}")
        _need(packed or size == stored_size, f"uncompressed size differs: {name}")
        rows.append({"index": index, "name": name, "name_bytes": raw_name, "name_hash": name_hash,
                     "flags": packed, "type": kind, "packed": bool(packed), "size": size,
                     "packed_size": stored_size, "stored_size": stored_size, "offset": offset,
                     "checksum": checksum, "record_offset": pos, "field_offset": field_offset,
                     "record_end": field_offset + tail_size})
        pos = field_offset + tail_size
    _need(pos == directory_end, "directory does not end at declared boundary")
    ranges = {}
    for row in rows:
        if row["packed_size"]:
            extent = (row["offset"], row["offset"] + row["packed_size"])
            signature = (row["type"], row["packed"], row["size"], row["checksum"])
            _need(extent not in ranges or ranges[extent] == signature, "shared payload has different metadata")
            ranges[extent] = signature
    ordered = sorted(ranges)
    _need(all(a[1] <= b[0] for a, b in zip(ordered, ordered[1:])), "partially overlapping payloads")
    return version, directory_end, rows


def _read_payload(view, row: dict, version: int):
    stored = view[row["offset"]:row["offset"] + row["packed_size"]]
    _need(_stored_hash(stored, version) == row["checksum"], f"stored checksum mismatch: {row['name']}")
    if row["packed"]:
        inflater = zlib.decompressobj()
        try:
            payload = inflater.decompress(stored, row["size"] + 1)
        except zlib.error as exc:
            raise ValueError(f"YPF: invalid zlib stream: {row['name']}") from exc
        _need(len(payload) == row["size"] and inflater.eof and not inflater.unused_data
              and not inflater.unconsumed_tail, f"incomplete/trailing zlib data: {row['name']}")
    else:
        payload = stored
    _need(len(payload) == row["size"], f"payload length differs: {row['name']}")
    return stored, payload


@dataclass
class Archive:
    version: int
    directory_end: int
    entries: list[dict]


def parse(data) -> Archive:
    """Fully validate and return decoded resource bytes for smaller archives.

    For large CG archives use :func:`validate` with a read-only mmap instead;
    that function does not retain resource bytes in its returned report.
    """
    version, directory_end, rows = _index(data)
    view = memoryview(data)
    for row in rows:
        stored, payload = _read_payload(view, row, version)
        row["stored"], row["payload"] = bytes(stored), bytes(payload)
    return Archive(version, directory_end, rows)


def validate(data) -> dict:
    """Return JSON metadata after full checksum/length/zlib validation.

    Accepts bytes or a read-only mmap; only one expanded resource is retained
    while scanning. The returned metadata contains no game resource bytes.
    """
    version, directory_end, rows = _index(data)
    view, result = memoryview(data), []
    for row in rows:
        stored, payload = _read_payload(view, row, version)
        result.append({key: row[key] for key in ("name", "type", "packed", "size", "packed_size", "offset", "checksum")}
                      | {"sha256": hashlib.sha256(payload).hexdigest(),
                         "stored_sha256": hashlib.sha256(stored).hexdigest()})
    return {"status": "PASS", "version": version, "entry_count": len(rows),
            "directory_end": directory_end, "archive_sha256": hashlib.sha256(view).hexdigest(),
            "directory_end_mode": "size_plus_32" if version == 292 else "absolute",
            "name_hash_verified": True, "stored_checksum_verified": True,
            "payload_lengths_verified": True, "payload_ranges_verified": True,
            "zlib_eof_verified": True, "entries": result}


def replace(data: bytes, replacements: dict[str, bytes], compression_level: int = 6,
            *, allow_identical: bool = False) -> bytes:
    """Replace existing members in directory order, preserving old data.

    Level 1..9 retains each member's original compression flag. Level 0
    explicitly stores replacements uncompressed, as required by the
    historical euphoria R1/R2 archives. Identical targets are rejected by
    default. A version-locked resource merge can set ``allow_identical=True``
    to append every requested resource, including unchanged payloads, as
    required to reproduce historical Maggot V2 archive layouts.
    """
    _need(isinstance(compression_level, int) and 0 <= compression_level <= 9, "invalid compression level")
    archive = parse(data)
    by_name = {row["name"]: row for row in archive.entries}
    _need(bool(replacements), "no replacements specified")
    _need(set(replacements) <= by_name.keys(), "replacement filename missing from archive")
    result = bytearray(data)
    for row in archive.entries:
        if row["name"] not in replacements:
            continue
        payload = replacements[row["name"]]
        _need(isinstance(payload, bytes), "replacement payload must be bytes")
        _need(len(payload) <= MAX_RESOURCE_BYTES, "replacement exceeds expansion limit")
        _need(allow_identical or payload != row["payload"],
              f"identical/already applied replacement: {row['name']}")
        packed = int(row["packed"] and compression_level != 0)
        stored = zlib.compress(payload, compression_level) if packed else payload
        offset = len(result)
        _need(archive.version >= 481 or offset <= 0xFFFFFFFF, "32-bit archive offset overflow")
        if archive.version >= 481:
            struct.pack_into("<BBIIQI", result, row["field_offset"], row["type"], packed,
                             len(payload), len(stored), offset, _stored_hash(stored, archive.version))
        else:
            struct.pack_into("<BBIIII", result, row["field_offset"], row["type"], packed,
                             len(payload), len(stored), offset, _stored_hash(stored, archive.version))
        result.extend(stored)
    output = bytes(result)
    after = parse(output)
    for old, new in zip(archive.entries, after.entries):
        _need(new["payload"] == replacements.get(old["name"], old["payload"]), "replacement readback differs")
        if old["name"] not in replacements:
            _need(old == new, "unselected directory entry changed")
    _need(output[archive.directory_end:len(data)] == data[archive.directory_end:], "old resource region changed")
    return output
