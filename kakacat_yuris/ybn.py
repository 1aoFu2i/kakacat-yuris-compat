"""YSTB structure and expressions used by the KrkrCat compatibility fixes.

The parser inspects bytecode; it does not interpret story text or execute the
game. Public profile patches accept only the documented original identity.
"""
from __future__ import annotations

import hashlib
import struct

KEY = bytes.fromhex("76033b26")
VERSION_KEYS = {474: bytes.fromhex("781b7330"), 481: KEY}
EUPHORIA_SOURCE_SHA256 = "9152a25a0009fb666240a66e66d4dbc28a16a32fd8bfb4b2c0be4724fae9304c"
EUPHORIA_R1_SHA256 = "60fde261810dbee0b92d19249d4c4d62b573d2b12794a53f3ff68c057ce1f0cb"
EUPHORIA_R2_SHA256 = "bb122e98cded9799f23618a8095750be4bbb9e12ec9e7bda79c9904e50154161"


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("YBN: " + message)


def xor(data: bytes, phase: int = 0, key: bytes = KEY) -> bytes:
    _need(len(key) == 4, "invalid section XOR key")
    return bytes(value ^ key[(index + phase) % 4] for index, value in enumerate(data))


def token(op: str, payload: bytes = b"") -> bytes:
    _need(len(op) == 1 and ord(op) < 128, "invalid token opcode")
    _need(len(payload) <= 65535, "token payload exceeds 16-bit length")
    return op.encode("ascii") + struct.pack("<H", len(payload)) + payload


tok = token


def tokens(data: bytes) -> list[tuple[str, bytes]]:
    pos, result = 0, []
    while pos < len(data):
        _need(pos + 3 <= len(data), "truncated expression token header")
        length = struct.unpack_from("<H", data, pos + 1)[0]
        _need(pos + 3 + length <= len(data), "expression token out of bounds")
        result.append((chr(data[pos]), data[pos + 3:pos + 3 + length]))
        pos += 3 + length
    return result


def var(index: int, sig: str = "@") -> bytes:
    _need(sig in ("@", "$") and 0 <= index <= 65535, "invalid variable reference")
    return token("H", sig.encode("ascii") + struct.pack("<H", index))


def local(index: int) -> bytes:
    return var(index)


def num(value: int) -> bytes:
    if -128 <= value <= 127:
        return token("B", struct.pack("<b", value))
    if -32768 <= value <= 32767:
        return token("W", struct.pack("<h", value))
    return token("I", struct.pack("<i", value))


def operation(left: bytes, right: bytes, op: str) -> bytes:
    return left + right + token(op)


def eq(left: bytes, number: int) -> bytes:
    return operation(left, num(number), "=")


def parse_script(data: bytes) -> dict:
    _need(len(data) >= 32, "truncated YSTB header")
    header = struct.unpack_from("<8I", data)
    _need(header[0] == int.from_bytes(b"YSTB", "little") and header[1] in (474, 481)
          and header[7] == 0, "unsupported YSTB magic/version/header")
    _need(header[3] == header[6] == header[2] * 4 and header[4] % 12 == 0,
          "invalid section dimensions")
    _need(32 + sum(header[3:7]) == len(data), "truncated/trailing YSTB sections")
    offset, sections, cipher = 32, [], []
    for length in header[3:7]:
        raw = data[offset:offset + length]
        cipher.append(raw)
        sections.append(xor(raw, key=VERSION_KEYS[header[1]]))
        offset += length
    descriptors = list(struct.iter_unpack("<HHII", sections[1]))
    commands, row = [], 0
    for pc, (opcode, argc, flags) in enumerate(struct.iter_unpack("<BBH", sections[0])):
        _need(row + argc <= len(descriptors), "command parameter range out of bounds")
        ordered = descriptors[row:row + argc]
        for _, kind, size, location in ordered:
            if kind:
                _need(location + size <= len(sections[2]), "expression range out of bounds")
                tokens(sections[2][location:location + size])
        commands.append({"opcode": opcode, "argc": argc, "flags": flags, "npar": flags,
                         "first_row": row, "rows": ordered, "parameters": ordered,
                         "line": struct.unpack_from("<I", sections[3], pc * 4)[0]})
        row += argc
    _need(row == len(descriptors), "unreferenced parameter descriptors")
    return {"header": header, "sections": sections, "cipher": cipher,
            "descriptors": descriptors, "commands": commands}


def rebuild(header, sections) -> bytes:
    _need(len(header) == 8 and len(sections) == 4, "invalid rebuild dimensions")
    new_header = list(header)
    new_header[3:7] = [len(section) for section in sections]
    _need(new_header[1] in VERSION_KEYS, "unsupported rebuild version")
    result = struct.pack("<8I", *new_header) + b"".join(xor(section, key=VERSION_KEYS[new_header[1]]) for section in sections)
    parse_script(result)
    return result


def extend_condition(data: bytes, pc: int, extra: bytes) -> bytes:
    """Append ``old OR extra`` to an IF, preserving all existing bytecode.

    The generic helper is exercised with synthetic expressions. Production
    callers must additionally require the profile's source/output identities.
    """
    parsed = parse_script(data)
    _need(0 <= pc < len(parsed["commands"]), "condition PC out of bounds")
    command = parsed["commands"][pc]
    _need(command["opcode"] == 30 and command["rows"] and command["rows"][0][1] == 1,
          "selected command is not a numeric IF")
    property_id, kind, size, location = command["rows"][0]
    sections = list(parsed["sections"])
    old = sections[2][location:location + size]
    suffix = extra + token("|")
    tokens(extra)
    _need(bool(extra) and not old.endswith(suffix), "condition patch already applied")
    condition = old + suffix
    tokens(condition)
    parameters = bytearray(sections[1])
    struct.pack_into("<HHII", parameters, command["first_row"] * 12,
                     property_id, kind, len(condition), len(sections[2]))
    sections[1] = bytes(parameters)
    sections[2] += condition
    return rebuild(parsed["header"], sections)


def shorten_parameter(data: bytes, pc: int, argument: int, expected: tuple, length: int) -> bytes:
    """Select an existing expression prefix without changing its bytes."""
    parsed = parse_script(data)
    _need(0 <= pc < len(parsed["commands"]), "parameter PC out of bounds")
    command = parsed["commands"][pc]
    _need(0 <= argument < len(command["rows"]), "argument index out of bounds")
    _need(command["rows"][argument] == expected and expected[1] != 0,
          "original parameter descriptor differs")
    prop, kind, old_length, location = expected
    _need(0 < length < old_length, "new length is not a strict expression prefix")
    tokens(parsed["sections"][2][location:location + length])
    sections = list(parsed["sections"])
    parameters = bytearray(sections[1])
    struct.pack_into("<HHII", parameters, (command["first_row"] + argument) * 12, prop, kind, length, location)
    sections[1] = bytes(parameters)
    return rebuild(parsed["header"], sections)


def patch_euphoria(data: bytes, repair: str = "r1") -> bytes:
    """Build one R1 or R1+R2 script from the exact original 26 script."""
    _need(repair in ("r1", "r2"), "unknown euphoria repair")
    identity = hashlib.sha256(data).hexdigest()
    _need(identity not in (EUPHORIA_R1_SHA256, EUPHORIA_R2_SHA256), "compatibility patch already applied")
    _need(len(data) == 332424 and identity == EUPHORIA_SOURCE_SHA256,
          "unsupported original euphoria script identity")
    before = parse_script(data)
    _need(before["commands"][5211]["rows"] == [(0, 1, 23, 110498), (0, 0, 0, 0), (0, 0, 5213, 110550)]
          and before["commands"][5211]["first_row"] == 10186, "original IF signature differs")
    extra = operation(operation(var(3428), var(2956), "="), eq(var(3451), 0), "&")
    result = extend_condition(data, 5211, extra)
    after_r1 = parse_script(result)
    _need(len(result) == 332481 and hashlib.sha256(result).hexdigest() == EUPHORIA_R1_SHA256,
          "R1 output identity differs")
    _need(after_r1["commands"][5212] == before["commands"][5212], "PC5212 changed")
    if repair == "r1":
        return result
    for pc, location in ((2398, 52370), (2399, 52431)):
        result = shorten_parameter(result, pc, 2, (12, 2, 27, location), 13)
    _need(hashlib.sha256(result).hexdigest() == EUPHORIA_R2_SHA256, "R2 output identity differs")
    _need([i for i, (old, new) in enumerate(zip(result, rebuild(after_r1["header"], after_r1["sections"])))
           if old != new] == [79288, 79360], "unexpected R2 byte changes")
    return result
