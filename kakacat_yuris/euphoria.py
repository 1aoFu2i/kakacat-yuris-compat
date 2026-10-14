"""Prepare known euphoria HD sources for Kakacat without modifying the source.

SPDX-License-Identifier: GPL-3.0-only
The resource bytes are supplied locally by the user and are never distributed
with this project. File validation is separate from iOS acceptance.
"""
from __future__ import annotations

import hashlib
import mmap
import os
from pathlib import Path
import shutil

from .molebox import extract_resources


PROFILES = {
    "euphoria-r1": {"repair": "r1", "alternate": False, "file_count": 39},
    "euphoria-r2": {"repair": "r2", "alternate": False, "file_count": 39},
    "euphoria-alt-r2": {"repair": "r2", "alternate": True, "file_count": 43},
}
BN_SHA256 = "5182ab95b5845ded3860678bfbd685b126efb02cc76857ff13477eabc0767008"
EXE_SHA256 = "1bfb8eedf517c61d933bdb49a760a651a178bf203fe13628577e026fe53e2f18"
CG_SHA256 = {
    False: "b534ae3fe072f56fceb74255365ff9bc49d12f72c188478ce992f87e80f29636",
    True: "1e173ef530a0e724493b8bf8dd514d94cfb6741d1c12f4d835c7e13028d04ed4",
}
OUTPUT_BN_SHA256 = {
    "r1": "afb9fc1ddd5fb2f678901590e8646a3c4a81af5db653348f0f607a1a836fb836",
    "r2": "0300edb2956e95c38ea99ae87e9905b9e72baaf33d5e3510e39749def99d4b96",
}
TARGET = "ysbin/yst00026.ybn"
_CHUNK = 8 * 1024**2
_ARCHIVES = (
    "bn", "cg", "cgsys", "fake", "normal_bad", "normal_good", "OP", "se",
    "sn", "special_bad", "true_end", "update1", "update2", "update3", "vo",
)
_BASE = tuple("pac/" + name + ".ypf" for name in _ARCHIVES) + (
    "yscfg.dat", "yssfs.dat", "sxs.dll", "VSFilter.dll",
    "save/gsd.sd", "save/kidoku.sd", "save/seld.sd",
    "緊急回避用ダミー画像/dummy1.png", "緊急回避用ダミー画像/dummy2.png",
    "緊急回避用ダミー画像/dummy3.png",
)
_ALT_EXTRA = ("yshpd.dat", "save/save00101.sd", "save/save30001.sd", "save/save30002.sd")


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _native(path: Path) -> str:
    """Use Windows extended paths without exposing them in public reports."""
    name = str(path.absolute())
    if os.name == "nt" and not name.startswith("\\\\?\\"):
        return "\\\\?\\UNC\\" + name[2:] if name.startswith("\\\\") else "\\\\?\\" + name
    return name


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(_native(path), "rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _read_file(path: Path) -> bytes:
    with open(_native(path), "rb") as stream:
        return stream.read()


def _profile(profile: str) -> dict:
    _need(profile in PROFILES, "Unsupported euphoria profile: " + profile)
    return PROFILES[profile]


def _root(source: Path) -> Path:
    source = Path(source).expanduser().absolute()
    _need(source.is_dir() and not source.is_symlink(),
          "euphoria source must be an unpacked game directory, not an archive or symlink")
    return source.resolve()


def _source_file(source: Path, relative: str) -> Path:
    path = source / relative
    current = source
    for part in Path(relative).parts:
        current /= part
        _need(not current.is_symlink(), "Source symlink is unsupported: " + relative)
    _need(path.is_file() and path.resolve().is_relative_to(source),
          "Missing or unsafe source resource: " + relative)
    return path


def _value(entry, name: str):
    return entry[name] if isinstance(entry, dict) else getattr(entry, name)


def _entry(archive, name: str):
    entries = [entry for entry in archive.entries if _value(entry, "name") == name]
    _need(len(entries) == 1, "Expected exactly one YPF resource: " + name)
    return entries[0]


def inspect(source: Path, profile: str) -> dict:
    """Read and fingerprint only the selected known-version source resources."""
    from . import ypf

    config = _profile(profile)
    source = _root(source)
    selected = _BASE + (_ALT_EXTRA if config["alternate"] else ())
    known_pac = {name + ".ypf" for name in _ARCHIVES}
    actual_pac = {path.name for path in (source / "pac").glob("*.ypf") if path.is_file()}
    _need(actual_pac == known_pac, "Source pac inventory differs from the reviewed version")
    allowed_saves = {Path(name).name for name in selected if name.startswith("save/")}
    actual_saves = {path.name for path in (source / "save").iterdir() if path.is_file()} if (source / "save").is_dir() else set()
    _need(actual_saves == allowed_saves,
          "Source save inventory differs; keep additional saves separately instead of silently dropping them")
    files = []
    for relative in selected:
        path = _source_file(source, relative)
        stat = path.stat()
        files.append({"path": relative, "size": stat.st_size, "sha256": _hash_file(path),
                      "mtime_ns": stat.st_mtime_ns})
    indexed = {item["path"]: item for item in files}
    _need(indexed["pac/bn.ypf"]["sha256"] == BN_SHA256,
          "Unsupported or already patched BN; this profile requires the reviewed original BN")
    _need(indexed["pac/cg.ypf"]["sha256"] == CG_SHA256[config["alternate"]],
          "CG fingerprint does not match the selected original/alternate profile")
    for name in ("update1", "update2", "update3"):
        _need(_read_file(_source_file(source, "pac/" + name + ".ypf")) == b"\x01",
              "Expected the reviewed one-byte source placeholder: " + name)
    exe = _source_file(source, "乐园_高清版.exe")
    exe_sha = _hash_file(exe)
    _need(exe_sha == EXE_SHA256, "Unsupported MoleBox CHS executable fingerprint")
    bn = ypf.parse(_read_file(source / "pac/bn.ypf"))
    _need(bn.version == 474 and len(bn.entries) == 595, "Unexpected original BN structure")
    _entry(bn, TARGET)
    if config["alternate"]:
        _need(indexed["yshpd.dat"]["size"] == 10 and indexed["yshpd.dat"]["sha256"] ==
              "3c3b6bd716c6117ef59ececbda1c55be6aeff4d02c54e05b5ea4489742e94985",
              "Alternate yshpd.dat differs from the reviewed embedded resource")
    return {
        "game": "euphoria HD", "profile": profile, "repair": config["repair"],
        "source_kind": "unpacked_game_directory", "wrapper": "MoleBox",
        "localized_exe": {"path": "乐园_高清版.exe", "size": exe.stat().st_size, "sha256": exe_sha},
        "base_file_count": len(files), "expected_output_file_count": config["file_count"],
        "source_files": files, "status": "SOURCE_FINGERPRINTS_VALIDATED",
        "ios_status": "NOT_TESTED",
    }


def prepare(source: Path, stage: Path, profile: str) -> dict:
    """Create stage/euphoriaHD with exact source resources and the chosen repair."""
    from . import ybn, ypf

    config = _profile(profile)
    source = _root(source)
    game = Path(stage).expanduser().absolute() / "euphoriaHD"
    _need(not game.exists(), "Refusing to overwrite an existing staged euphoriaHD directory")
    resolved_game = game.resolve()
    _need(not resolved_game.is_relative_to(source) and not source.is_relative_to(resolved_game),
          "Staged game must be outside the source game")
    baseline = inspect(source, profile)
    resources, unknowns, extraction = extract_resources(_read_file(source / "乐园_高清版.exe"))
    _need(len(resources) == 16 and len(unknowns) == 1 and extraction["blocks"] == 1722,
          "Unexpected MoleBox resource inventory")
    if config["alternate"]:
        marker = _read_file(source / "yshpd.dat")
        _need(marker == unknowns[0]["bytes"] and hashlib.md5("YSHPD.DAT".encode("utf-16le")).hexdigest() == unknowns[0]["sign"],
              "Alternate yshpd.dat does not resolve the embedded virtual path")
    translated = ypf.parse(resources["pac/update3.ypf"])
    _need(translated.version == 292 and len(translated.entries) == 464,
          "Unexpected translated update3 structure")
    _need(TARGET not in {_value(entry, "name") for entry in translated.entries},
          "Translated update3 overrides the script targeted by this repair")
    original_bn = _read_file(source / "pac/bn.ypf")
    archive = ypf.parse(original_bn)
    original_script = _value(_entry(archive, TARGET), "payload")
    script = ybn.patch_euphoria(original_script, repair=config["repair"])
    patched_bn = ypf.replace(original_bn, {TARGET: script}, compression_level=0)
    _need(hashlib.sha256(patched_bn).hexdigest() == OUTPUT_BN_SHA256[config["repair"]],
          "Reconstructed BN differs from the reviewed fixed output")

    game.mkdir(parents=True, exist_ok=False)
    origins = {}
    for item in baseline["source_files"]:
        relative = item["path"]
        path = _source_file(source, relative)
        destination = game / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_native(path), _native(destination))
        _need(_hash_file(destination) == item["sha256"], "Staged source copy differs: " + relative)
        origins[relative] = "source_version_unchanged"
    for relative, payload in resources.items():
        destination = game / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        with open(_native(destination), "wb") as stream:
            stream.write(payload)
        origins[relative] = "static_molebox_resource"
    with open(_native(game / "pac/bn.ypf"), "wb") as stream:
        stream.write(patched_bn)
    origins["pac/bn.ypf"] = "r1_endpoint" if config["repair"] == "r1" else "r1_endpoint_plus_r2_geometry"

    validation = {}
    for relative in ("pac/bn.ypf", "pac/update2.ypf", "pac/update3.ypf", "pac/cg.ypf", "pac/cgsys.ypf"):
        with open(_native(game / relative), "rb") as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
                validation[relative] = ypf.validate(data)
    files = []
    for path in sorted(game.rglob("*")):
        if path.is_file():
            relative = path.relative_to(game).as_posix()
            _need(relative in origins, "Untracked staged resource")
            files.append({"path": relative, "size": path.stat().st_size,
                          "sha256": _hash_file(path), "origin": origins[relative]})
    _need(len(files) == config["file_count"], "Unexpected final resource count")
    indexed = {item["path"]: item for item in files}
    _need(indexed["pac/cg.ypf"]["sha256"] == CG_SHA256[config["alternate"]], "Current version CG changed")
    for item in baseline["source_files"]:
        path = _source_file(source, item["path"])
        stat = path.stat()
        _need(stat.st_size == item["size"] and stat.st_mtime_ns == item["mtime_ns"] and
              _hash_file(path) == item["sha256"], "Source resource changed during preparation: " + item["path"])
    _need(_hash_file(source / "乐园_高清版.exe") == EXE_SHA256, "Source executable changed during preparation")
    marker_report = {key: value for key, value in unknowns[0].items() if key != "bytes"}
    marker_report.update({"identified_path": "yshpd.dat", "included_in_game": config["alternate"]})
    summary = {
        "game": "euphoria HD", "profile": profile, "repair": config["repair"],
        "status": "FILE_VALIDATED", "ios_status": "NOT_TESTED", "game_executed": False,
        "source_preserved": True, "file_count": len(files), "files": files,
        "molebox": extraction, "embedded_marker": marker_report, "archive_validation": validation,
        "repair_target": TARGET, "original_bn_sha256": BN_SHA256,
        "output_bn_sha256": OUTPUT_BN_SHA256[config["repair"]],
        "changed_pcs": [5211] if config["repair"] == "r1" else [2398, 2399, 5211],
        "resource_overlay_order": ["current_source_version", "original_molebox_translation", "bn_repair"],
        "ios_resource_priority_verified": False,
        "excluded": ["executables", "installers", "old_cg_backups", "alternate_translation_directories",
                     "unlock_save_backups", "nested_archives", "source_documentation", "diagnostic_resources"],
    }
    return {"game_dir": game, "summary": summary}
