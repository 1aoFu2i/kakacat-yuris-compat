# SPDX-License-Identifier: Apache-2.0
# Adapted 2026-10-14 from mos9527/evbunpack 0.2.6, commit
# ee7b647acf2a46617b0c448dfa83d63132ea917b, evbunpack/__main__.py and const.py.
# Original project copyright: mos9527 and its contributors.
# Modifications: bounded reads, explicit ValueError checks, no compressed
# resources, no executable restoration, no third-party imports, no file writes.
"""Read the modern uncompressed Enigma Virtual Box virtual-file tree."""

from __future__ import annotations

import io
import struct
from collections.abc import Iterator

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


def external_tree(data: bytes, offset: int, *, max_nodes: int = 4096) -> Iterator[dict]:
    """Yield a main node and flattened tree without extracting resources.

    The field order and payload-origin formula follow upstream pe_external_tree.
    The supported compatibility profile validates exact input fingerprints,
    node counts and payload bounds separately.
    """
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
