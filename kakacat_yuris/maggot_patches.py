# SPDX-License-Identifier: GPL-3.0-only
"""Exact caption, SYSBLACK and endpoint changes for one supported YU-RIS sample."""

from __future__ import annotations

import hashlib
import struct

KEY = bytes.fromhex("76033b26")
PINS = {
    "caption_before": "a5814ef10fa7e5eb5478dfc06057fd1705985664c094ab52bf1c6a57729bcd96",
    "caption_after": "04477201ec4f0f41325b4bc54cafadbc853be371eb0ee2f1e611e687aa3fd49c",
    "black_before": "a7acb5dff21b9987a7c430515cdd6e09746e41c81b6628b81ab7173dcaed3d74",
    "black_after": "19735013c919ea3d643c3b2d3d534e378fd479c584e6ef1ca318fb3e83bd087b",
    "endpoint_before": "efd221dcab9ca12e392ad74848237dba9c42b73087182f8a87c8d35c56e3e5a5",
    "endpoint_after": "c48556fe811b8ad64699f199db7db1f3ad7fa5acbe14e59387f86d58cd4f15ec",
    "condition": "06048c42eaecd1bb2587cf463a403f83fd71c19076e4179dd3b37fe9080b1a11",
}


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def xor(data: bytes, phase: int = 0) -> bytes:
    return bytes(value ^ KEY[(index + phase) % 4] for index, value in enumerate(data))


def parse_script(data: bytes) -> dict:
    need(len(data) >= 32, "Truncated YSTB header")
    header = struct.unpack_from("<8I", data)
    need(header[:2] == (int.from_bytes(b"YSTB", "little"), 481) and header[7] == 0,
         "Unsupported YSTB header")
    need(header[3] == header[6] == header[2] * 4 and header[4] % 12 == 0
         and 32 + sum(header[3:7]) == len(data), "Invalid YSTB section dimensions")
    pos, cipher, sections = 32, [], []
    for size in header[3:7]:
        cipher.append(data[pos:pos + size])
        sections.append(xor(cipher[-1]))
        pos += size
    parameters = list(struct.iter_unpack("<HHII", sections[1]))
    row, commands = 0, []
    for opcode, argc, flags in struct.iter_unpack("<BBH", sections[0]):
        need(row + argc <= len(parameters), "YSTB ordered-parameter range exceeds section")
        selected = parameters[row:row + argc]
        for _property, kind, size, location in selected:
            if kind:
                need(location <= len(sections[2]) and size <= len(sections[2]) - location,
                     "YSTB expression exceeds section")
                expression = sections[2][location:location + size]
                token_pos = 0
                while token_pos < len(expression):
                    need(token_pos + 3 <= len(expression), "Truncated expression token")
                    length = struct.unpack_from("<H", expression, token_pos + 1)[0]
                    token_pos += 3
                    need(length <= len(expression) - token_pos, "Expression token exceeds boundary")
                    token_pos += length
        commands.append({"opcode": opcode, "argc": argc, "flags": flags,
                         "first_row": row, "parameters": selected})
        row += argc
    need(row == len(parameters), "Unreferenced YSTB parameter rows")
    return {"header": header, "cipher": cipher, "sections": sections,
            "parameters": parameters, "commands": commands}


def normalize_caption(data: bytes) -> bytes:
    need(len(data) == 7883 and sha(data) == PINS["caption_before"],
         "Unsupported caption-script fingerprint")
    header = list(struct.unpack_from("<8I", data))
    need(header == [int.from_bytes(b"YSTB", "little"), 481, 184, 736, 3552, 2748, 736, 0],
         "Unsupported legacy caption layout")
    command_end = 32 + header[3]
    parameter_end = command_end + header[4]
    expression_end = parameter_end + header[5]
    line_end = expression_end + header[6]
    parameters = bytearray(xor(data[command_end:parameter_end]))
    tail = data[line_end:]
    need(len(tail) == 79 and tail[:3] == b"M\x4c\0" and tail[3] == tail[-1] == 34,
         "Unexpected legacy caption expression")
    need(struct.unpack_from("<HHII", parameters, 93 * 12)[1:] == (3, 79, 3484),
         "Caption parameter changed")
    struct.pack_into("<I", parameters, 93 * 12 + 8, 2748)
    header[5] = 2827
    result = (struct.pack("<8I", *header) + data[32:command_end] + xor(parameters)
              + data[parameter_end:expression_end] + xor(tail, 2748 % 4)
              + data[expression_end:line_end])
    need(len(result) == len(data) and sha(result) == PINS["caption_after"],
         "Normalized caption fingerprint differs")
    after = parse_script(result)
    need(after["commands"][61]["opcode"] == data[32 + 61 * 4] ^ KEY[0]
         and after["cipher"][3] == data[expression_end:line_end],
         "Caption commands or line table changed")
    return result


def _check_cg_table(data: bytes) -> None:
    need(data[:4] == b"YSCM" and len(data) >= 16, "Invalid command metadata table")
    count = struct.unpack_from("<I", data, 8)[0]
    pos, commands = 16, []
    for _ in range(count):
        end = data.find(b"\0", pos)
        need(end >= pos, "Unterminated command name")
        name = data[pos:end]
        pos = end + 1
        need(pos < len(data), "Truncated command metadata")
        argc = data[pos]
        pos += 1
        arguments = []
        for _ in range(argc):
            end = data.find(b"\0", pos)
            need(end >= pos and end + 3 <= len(data), "Truncated command argument metadata")
            arguments.append(data[pos:end])
            pos = end + 3
        commands.append((name, arguments))
    need(len(commands) > 1 and commands[1][0] == b"CG"
         and len(commands[1][1]) > 2 and commands[1][1][2] == b"E",
         "Command metadata does not identify the expected CG E property")


def add_sysblack_e0(data: bytes, command_table: bytes) -> bytes:
    need(len(data) == 68009 and sha(data) == PINS["black_before"],
         "Unsupported SYSBLACK-script fingerprint")
    _check_cg_table(command_table)
    before = parse_script(data)
    header = list(before["header"])
    need(header == [int.from_bytes(b"YSTB", "little"), 481, 1295, 5180, 31608, 26009, 5180, 0],
         "Unsupported SYSBLACK script layout")
    target = before["commands"][453]
    need((target["opcode"], target["argc"], target["flags"], target["first_row"]) == (1, 7, 0, 849)
         and before["parameters"][855] == (33, 3, 5, 8614),
         "SYSBLACK command differs")
    descriptor = before["parameters"][849]
    need(before["sections"][2][descriptor[3]:descriptor[3] + descriptor[2]] ==
         b'M\x0a\0"SYSBLACK"', "Target CG does not reference SYSBLACK")
    sample = before["commands"][889]
    need(sample["opcode"] == 1 and sample["first_row"] == 1839
         and before["parameters"][1841] == (2, 1, 4, 18368)
         and before["sections"][2][18368:18372] == b"B\x01\0\0",
         "Existing same-script CG E=0 pattern differs")
    commands = bytearray(before["cipher"][0])
    commands[453 * 4 + 1] = 8 ^ KEY[1]
    new_descriptor = struct.pack("<HHII", 2, 1, 4, 26009)
    parameter_offset = 856 * 12
    parameters = (before["cipher"][1][:parameter_offset]
                  + xor(new_descriptor, parameter_offset % 4)
                  + before["cipher"][1][parameter_offset:])
    literal = b"B\x01\0\0"
    header[4] += 12
    header[5] += 4
    result = (struct.pack("<8I", *header) + bytes(commands) + parameters
              + before["cipher"][2] + xor(literal, 26009 % 4) + before["cipher"][3])
    need(len(result) == 68025 and sha(result) == PINS["black_after"],
         "SYSBLACK E=0 output fingerprint differs")
    after = parse_script(result)
    need(after["parameters"][:856] == before["parameters"][:856]
         and after["parameters"][857:] == before["parameters"][856:]
         and after["parameters"][856] == (2, 1, 4, 26009)
         and after["cipher"][3] == before["cipher"][3]
         and after["sections"][2][:-4] == before["sections"][2],
         "SYSBLACK E=0 changed unrelated parameters or script sections")
    need([pc for pc, (old, new) in enumerate(zip(before["commands"], after["commands"]))
          if (old["opcode"], old["argc"], old["flags"]) != (new["opcode"], new["argc"], new["flags"])]
         == [453], "SYSBLACK E=0 changed another command")
    return result


def _token(opcode: str, payload: bytes = b"") -> bytes:
    return opcode.encode("ascii") + struct.pack("<H", len(payload)) + payload


def _local(index: int) -> bytes:
    return _token("H", b"@" + struct.pack("<H", index))


def fix_endpoint(data: bytes) -> bytes:
    need(len(data) == 341621 and sha(data) == PINS["endpoint_before"],
         "Unsupported endpoint-script fingerprint")
    before = parse_script(data)
    header = list(before["header"])
    need(header == [int.from_bytes(b"YSTB", "little"), 481, 6565, 26260, 151500, 137569, 26260, 0],
         "Unsupported endpoint-script layout")
    command = before["commands"][5312]
    need(command["first_row"] == 10494 and command["parameters"][0] == (0, 1, 23, 112706),
         "Endpoint IF parameter differs")
    condition = before["sections"][2][112706:112729]
    condition += _local(3525) + _local(3052) + _token("=")
    condition += _local(3548) + _token("B", b"\0") + _token("=") + _token("&") + _token("|")
    need(len(condition) == 57 and sha(condition) == PINS["condition"],
         "Endpoint condition bytecode differs")
    parameters = bytearray(before["cipher"][1])
    offset = 10494 * 12
    parameters[offset:offset + 12] = xor(struct.pack("<HHII", 0, 1, 57, 137569), offset % 4)
    header[5] += 57
    result = (struct.pack("<8I", *header) + before["cipher"][0] + bytes(parameters)
              + before["cipher"][2] + xor(condition, 137569 % 4) + before["cipher"][3])
    need(len(result) == 341678 and sha(result) == PINS["endpoint_after"],
         "Endpoint output fingerprint differs")
    after = parse_script(result)
    need([pc for pc, (old, new) in enumerate(zip(before["commands"], after["commands"])) if old != new]
         == [5312] and after["commands"][5313] == before["commands"][5313],
         "Endpoint fix changed another command or original alpha multiplication")
    need(after["parameters"][:10494] == before["parameters"][:10494]
         and after["parameters"][10495:] == before["parameters"][10495:]
         and after["cipher"][0] == before["cipher"][0]
         and after["cipher"][3] == before["cipher"][3]
         and after["cipher"][2][:-57] == before["cipher"][2],
         "Endpoint fix changed original script sections")
    need(sum(parameter[1] == 0 for parameter in before["parameters"]) == 1870
         and [parameter for parameter in after["parameters"] if parameter[1] == 0]
         == [parameter for parameter in before["parameters"] if parameter[1] == 0],
         "Endpoint control descriptors changed")
    need(after["commands"][6564]["opcode"] == before["commands"][6564]["opcode"] == 14,
         "Endpoint fix changed the original END")
    return result
