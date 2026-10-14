"""Local file and resource-only ZIP validation; no source files are modified."""
from __future__ import annotations
import hashlib
import json
import shutil
import struct
import zipfile
from pathlib import Path

CHUNK = 8 * 1024 * 1024

def require(ok, message):
    if not ok:
        raise ValueError(message)

def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def write_json(path, value):
    with open(path, "x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

def inventory(game_dir):
    records = []
    for path in sorted(Path(game_dir).rglob("*")):
        require(not path.is_symlink(), "Output contains a symbolic link")
        if path.is_file():
            relative = path.relative_to(game_dir).as_posix()
            require(path.suffix.lower() != ".exe", "Executable in resource package")
            records.append({"path": relative, "size": path.stat().st_size,
                            "sha256": file_hash(path)})
    require(bool(records), "Empty resource package")
    return records

class Utf8ZipInfo(zipfile.ZipInfo):
    def _encodeFilenameFlags(self):
        return self.filename.encode("utf-8"), self.flag_bits | 0x800

def package(game_dir, destination, records):
    game_dir, destination = Path(game_dir), Path(destination)
    require(not destination.exists(), "Refusing to overwrite ZIP")
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=3, allowZip64=True) as archive:
        for row in records:
            path = game_dir / row["path"]
            name = game_dir.name + "/" + row["path"]
            info = Utf8ZipInfo.from_file(path, arcname=name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info._compresslevel = 3
            with open(path, "rb") as src, archive.open(info, "w", force_zip64=True) as dst:
                shutil.copyfileobj(src, dst, CHUNK)

def verify_zip(path, game_name, records):
    expected = {game_name + "/" + row["path"]: row for row in records}
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        require(len(infos) == len(expected), "ZIP file count mismatch")
        require(len({i.filename for i in infos}) == len(infos), "Duplicate ZIP member")
        require({i.filename for i in infos} == set(expected), "ZIP member set mismatch")
        for info in infos:
            require(not info.flag_bits & 1, "Encrypted ZIP member")
            require(bool(info.flag_bits & 0x800), "ZIP filename not marked UTF-8")
            row = expected[info.filename]
            require(info.file_size == row["size"], "ZIP member size mismatch")
            # The writer explicitly uses ZIP64 for every local record. Check
            # actual local headers rather than inferring this from allowZip64.
            archive.fp.seek(info.header_offset)
            header = archive.fp.read(30)
            require(len(header) == 30, "Truncated ZIP local header")
            fields = struct.unpack("<4s5H3I2H", header)
            require(fields[0] == b"PK\x03\x04" and fields[7:9] == (0xFFFFFFFF, 0xFFFFFFFF),
                    "ZIP64 local size markers missing")
            archive.fp.read(fields[9])
            extra = archive.fp.read(fields[10])
            cursor, sizes = 0, None
            while cursor < len(extra):
                require(cursor + 4 <= len(extra), "Truncated ZIP extra field")
                kind, length = struct.unpack_from("<HH", extra, cursor)
                cursor += 4
                require(cursor + length <= len(extra), "ZIP extra field exceeds boundary")
                if kind == 1:
                    require(sizes is None and length >= 16, "Invalid ZIP64 size field")
                    sizes = struct.unpack_from("<QQ", extra, cursor)
                cursor += length
            require(sizes == (info.file_size, info.compress_size), "ZIP64 local sizes mismatch")
            digest = hashlib.sha256()
            with archive.open(info) as stream:
                for chunk in iter(lambda: stream.read(CHUNK), b""):
                    digest.update(chunk)
            require(digest.hexdigest() == row["sha256"], "ZIP member SHA256 mismatch")
    return {"status": "PASS", "members": len(expected), "crc_readback": "PASS",
            "sha256_readback": "PASS", "utf8": True, "zip64_enabled": True,
            "zip64_local_headers": "PASS",
            "password": False, "exe_files": 0}
