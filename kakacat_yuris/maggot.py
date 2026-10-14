# SPDX-License-Identifier: GPL-3.0-only
"""Full local Maggot Baits Chinese-resource and Kakacat R1 compatibility recipe.

The supported source game remains read-only. No EXE is executed. Intermediate
archives are produced in memory; the only game output is an independently
created stage/maggotbaits tree. Game resources are never repository assets.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import os
from pathlib import Path
import shutil
import stat
import zlib

from . import evb, ypf
from .maggot_patches import add_sysblack_e0, fix_endpoint, normalize_caption, sha

SOURCE_PINS = {
    "maggotbaits_cn.exe": (19549184, evb.CN_EXE_SHA256),
    "maggotbaits.exe": (3628032, "520e655bb3999253757c4d5c653b3c7455dd34807ef5b196a582a0f34427cb81"),
    "pac/bn.ypf": (3499188, "0070aeea365361b7ea2bbca63a1fdde039b1effb68a3d8238690962e4f150ce8"),
    "pac/cg.ypf": (353493806, "309ae1de50256d5a677e591503afbba11edd9a6f30fae0d451fa71d7299a9dc7"),
    "pac/cgsys.ypf": (14442023, "ccafa07ad039f54ddbab991bbdc82c03a52d8e23e32751d175eea7da6550a446"),
    "pac/update1.ypf": (51319787, "a7266b252f917f6d1c8a7e4d8eff2f7eb54657dd9743a909a76b999d1372acfd"),
    "pac/update2.ypf": (55048393, "cfdefd1fdb7c2ffed2d7c3fa3414fda8a39f6237224e33bc2ace8dd64865df7b"),
    "pac/update3.ypf": (26887818, "a989a0cf7b169c6500de165a55e3a1a71288fa488515a26ed624c7207999a78c"),
}
ARCHIVE_RULES = {
    "bn.ypf": (481, 340, 198),
    "cg.ypf": (490, 979, 9),
    "cgsys.ypf": (490, 2077, 489),
    "update1.ypf": (490, 98, 1),
    "update2.ypf": (490, 78, 2),
}
V2_ARCHIVE_PINS = {
    "bn.ypf": (6979368, "0489766718cae3dfc916d49fe47f083d378c97c8022a897a72514ebcccfd3e0d"),
    "cg.ypf": (353581077, "ba4a4e632174d21f2958944a73917e03042c9e1de214cae494629bb17fbedeb9"),
    "cgsys.ypf": (21769234, "f82ba33b4252f381ac85edbe15df408c0bec2f4b1c6214c551ccdac296bcffb2"),
    "update1.ypf": (51501216, "ddf54ac4c7057808efc2fc35fd889f2f607fef467d9c56d6b7eb4e2096d20869"),
    "update2.ypf": (55165289, "7254fc8ec73b4d5dc5c146fc7469259a1489815811f8c44eb92736e313c96f72"),
}
BN_PINS = {
    "v3": (6982652, "2703c48f119d951c41e5513cf5e86c8bce55497bba05c04ba86a094cc8b89576"),
    "v4": (7003999, "e0cd912d2ee404670f6aee62590685306f5c846f688aa720fcee4c59a87ed28d"),
    "r1": (7093096, "4b8b4e4a45ff068fc45c498f9e9cceb02942ba6a0cc1fabbe27cc9585f4de5a3"),
}
SYSTEM_SAVES = frozenset("save/" + name + ".sd"
                         for name in ("config", "extra", "global", "kidoku", "seld", "voice"))
_FORBIDDEN = frozenset((".exe", ".msi", ".msp", ".bat", ".cmd", ".ps1", ".py",
                        ".zip", ".rar", ".7z", ".tar", ".gz", ".json", ".md", ".txt",
                        ".pdf", ".doc", ".docx"))
_CHUNK = 4 * 1024 * 1024


def _need(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _profile(value: str) -> str:
    _need(value in ("r1", "maggot-r1"), "Maggot Baits supports the r1 profile only")
    return "r1"


def _file_sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path) -> os.stat_result:
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and not path.is_symlink()
          and not getattr(info, "st_file_attributes", 0)
          & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
          "Source runtime contains a symlink, junction or nonregular file")
    return info


def _safe_relative(name: str) -> None:
    _need(bool(name) and "\\" not in name and ":" not in name and not name.startswith("/")
          and all(part not in ("", ".", "..") and not part.endswith((".", " "))
                  for part in name.split("/")), "Unsafe source-relative runtime path")


def _runtime_inventory(source: Path) -> tuple[list[dict], list[str]]:
    rows: list[dict] = []
    excluded_saves = []
    for root_name in ("pac", "cg"):
        directory = source / root_name
        _need(directory.is_dir() and not directory.is_symlink()
              and not directory.is_junction(), "Required runtime directory missing or linked")
        for current, directories, files in os.walk(directory, followlinks=False):
            for name in directories:
                child = Path(current) / name
                _need(not child.is_symlink() and not child.is_junction(),
                      "Runtime directory contains a symlink or junction")
            for name in files:
                path = Path(current) / name
                rel = path.relative_to(source).as_posix()
                _safe_relative(rel)
                _need(path.suffix.lower() not in _FORBIDDEN,
                      "Unexpected executable, archive or document in runtime directory")
                info = _regular(path)
                rows.append({"name": rel, "size": info.st_size, "mtime_ns": info.st_mtime_ns})
    save_directory = source / "save"
    _need(save_directory.is_dir() and not save_directory.is_symlink()
          and not save_directory.is_junction(), "Source system-save directory missing or linked")
    for path in save_directory.iterdir():
        rel = path.relative_to(source).as_posix()
        if rel not in SYSTEM_SAVES:
            excluded_saves.append(rel)
            continue
        info = _regular(path)
        rows.append({"name": rel, "size": info.st_size, "mtime_ns": info.st_mtime_ns})
    _need({row["name"] for row in rows if row["name"].startswith("save/")} == SYSTEM_SAVES,
          "The six source system-save files are required")
    for path in source.iterdir():
        if path.is_file() and path.suffix.lower() in (".dat", ".dll", ".png"):
            rel = path.name
            _safe_relative(rel)
            info = _regular(path)
            rows.append({"name": rel, "size": info.st_size, "mtime_ns": info.st_mtime_ns})
    rows.sort(key=lambda row: row["name"])
    _need(len(rows) == 1425 and len({row["name"].casefold() for row in rows}) == 1425,
          "Unsupported runtime inventory: the supported profile requires 1425 unique files")
    return rows, sorted(excluded_saves)


def _preflight(source: Path, profile: str) -> tuple[dict, list[dict], dict[str, bytes]]:
    profile = _profile(profile)
    source = source.resolve()
    _need(source.is_dir() and not source.is_junction(), "Source game directory does not exist")
    fingerprints = []
    for name, (size, expected) in SOURCE_PINS.items():
        path = source / name
        before = _regular(path)
        actual = _file_sha(path)
        after = _regular(path)
        _need((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
              "Source changed during compatibility preflight")
        _need(before.st_size == size and actual == expected,
              "Unsupported source-game fingerprint: " + name)
        fingerprints.append({"path": name, "size": size, "sha256": actual})
    rows, excluded = _runtime_inventory(source)
    resources, resource_summary = evb.resources((source / "maggotbaits_cn.exe").read_bytes())
    summary = {
        "game": "maggot", "profile": profile, "status": "SUPPORTED_SOURCE_CONFIRMED",
        "compatibility_target": "咔咔喵 / Kakacat", "engine_version": 481,
        "source_fingerprints": fingerprints, "source_runtime_files": len(rows),
        "source_runtime_bytes": sum(row["size"] for row in rows),
        "source_system_saves_preserved": sorted(SYSTEM_SAVES),
        "additional_save_files_excluded_count": len(excluded),
        "evb": resource_summary, "external_tools_required": [],
        "python_dependencies": "standard library only; bundled minimal Apache-2.0 EVB tree reader",
        "zlib_compile_version": zlib.ZLIB_VERSION,
        "zlib_runtime_version": zlib.ZLIB_RUNTIME_VERSION,
        "historical_byte_reproduction": zlib.ZLIB_VERSION == zlib.ZLIB_RUNTIME_VERSION == "1.3.1",
        "game_executable_executed_or_reconstructed": False,
    }
    return summary, rows, resources


def inspect(source: Path, profile: str = "r1") -> dict:
    """Check source fingerprints and the embedded resource tree without writing."""
    return _preflight(Path(source), profile)[0]


def _historical(name: str, data: bytes, pin: tuple[int, str]) -> dict:
    actual = sha(data)
    required = zlib.ZLIB_VERSION == zlib.ZLIB_RUNTIME_VERSION == "1.3.1"
    match = len(data) == pin[0] and actual == pin[1]
    _need(not required or match, "Historical zlib 1.3.1 output fingerprint differs: " + name)
    return {"stage": name, "size": len(data), "sha256": actual,
            "historical_pin_match": match, "historical_pin_required": required}


def _same_region(left: bytes, right: bytes, begin: int, end: int) -> bool:
    for offset in range(begin, end, _CHUNK):
        bound = min(end, offset + _CHUNK)
        if left[offset:bound] != right[offset:bound]:
            return False
    return True


def _verify_replacement(before: bytes, after: bytes, replacements: dict[str, bytes]) -> dict:
    old, new = ypf.parse(before), ypf.parse(after)
    _need(old.version == new.version and old.directory_end == new.directory_end
          and len(old.entries) == len(new.entries) and before[:32] == after[:32],
          "YPF replacement changed header, entry count or directory size")
    _need(_same_region(before, after, old.directory_end, len(before)),
          "YPF replacement changed the original data area")
    changed, preserved = [], 0
    for left, right in zip(old.entries, new.entries):
        _need(all(left[field] == right[field] for field in
                  ("name", "name_bytes", "type", "packed", "flags", "record_offset", "field_offset")),
              "YPF replacement changed entry identity or original flags")
        name = left["name"]
        if name in replacements:
            _need(right["payload"] == replacements[name] and right["offset"] >= len(before),
                  "YPF replacement payload differs from prepared Chinese resource")
            _need(before[left["record_offset"]:left["field_offset"] + 2]
                  == after[right["record_offset"]:right["field_offset"] + 2],
                  "YPF replacement changed original name/type/packed record bytes")
            changed.append({"path": name, "before_sha256": sha(left["payload"]),
                            "after_sha256": sha(right["payload"]),
                            "before_size": left["size"], "after_size": right["size"]})
        else:
            _need(left == right, "YPF replacement changed an unrelated entry")
            preserved += 1
    _need(set(replacements) == {row["path"] for row in changed},
          "YPF replacement target set differs")
    return {"changed": changed, "changed_entries": len(changed), "preserved_entries": preserved,
            "entries": len(new.entries), "new_entries": 0,
            "original_data_area_preserved": True, "entry_order_names_types_flags_preserved": True}


def _mapping(resources: dict[str, bytes], archive) -> tuple[dict[str, bytes], dict[str, str]]:
    lookup = {entry["name"].casefold(): entry for entry in archive.entries}
    replacements, original_paths = {}, {}
    for virtual, payload in resources.items():
        canonical = virtual
        entry = lookup.get(canonical.casefold())
        if entry is None and virtual.startswith("cg/tip/"):
            raw_name = virtual.encode("gbk", errors="strict")
            canonical = raw_name.decode("cp932", errors="strict")
            entry = lookup.get(canonical.casefold())
            if entry is not None:
                _need(entry["name_bytes"].replace(b"\\", b"/") == raw_name,
                      "EVB GBK / YPF CP932 filename byte alias differs")
        if entry is None:
            continue
        _need(entry["name"] == canonical and canonical not in replacements,
              "Case-only or duplicate resource mapping is not supported")
        replacements[canonical] = payload
        original_paths[canonical] = virtual
    return replacements, original_paths


def _patch_archive(data: bytes, name: str, payload: bytes, *, level: int) -> tuple[bytes, dict]:
    result = ypf.replace(data, {name: payload}, compression_level=level)
    return result, _verify_replacement(data, result, {name: payload})


def _build_archives(source: Path, resources: dict[str, bytes]) -> tuple[dict[str, bytes], dict]:
    output, phases, audits = {}, [], {}
    seen: Counter = Counter()
    aliases = set()
    for name, (version, count, replacements_count) in sorted(ARCHIVE_RULES.items()):
        original = (source / "pac" / name).read_bytes()
        size, expected = SOURCE_PINS["pac/" + name]
        _need(len(original) == size and sha(original) == expected,
              "Source archive changed after preflight: " + name)
        archive = ypf.parse(original)
        _need(archive.version == version and len(archive.entries) == count,
              "Unsupported archive structure: " + name)
        replacements, original_paths = _mapping(resources, archive)
        _need(len(replacements) == replacements_count, "Chinese replacement count changed: " + name)
        for canonical, virtual in original_paths.items():
            seen[virtual] += 1
            if canonical != virtual:
                aliases.add(virtual)
            if virtual.endswith(".ybn"):
                _need(name == "bn.ypf", "Translated script unexpectedly overrides another archive")
        # Historical V2 appends every planned occurrence, including resources
        # whose Chinese bytes already equal the original. Skipping these would
        # change the archive layout and supported historical fingerprint.
        merged = ypf.replace(original, replacements, compression_level=6, allow_identical=True)
        audits[name] = _verify_replacement(original, merged, replacements)
        phases.append(_historical("v2/" + name, merged, V2_ARCHIVE_PINS[name]))
        output[name] = merged
    _need(len(seen) == 696 and sum(seen.values()) == 699 and len(aliases) == 9,
          "Chinese resource occurrence/filename-alias inventory differs")
    _need({path for path, count in seen.items() if count == 2} ==
          {"cgsys/config/back_easy.png", "cgsys/config/back_playstyle.png", "cg/tip/奺榖斷_娬榖.png"}
          and all(count in (1, 2) for count in seen.values()),
          "Cross-archive Chinese resource overrides differ")
    bn = output["bn.ypf"]
    by_name = {entry["name"]: entry for entry in ypf.parse(bn).entries}
    caption = normalize_caption(by_name["ysbin/yst00028.ybn"]["payload"])
    bn, audits["v3"] = _patch_archive(bn, "ysbin/yst00028.ybn", caption, level=6)
    phases.append(_historical("v3/bn.ypf", bn, BN_PINS["v3"]))
    by_name = {entry["name"]: entry for entry in ypf.parse(bn).entries}
    black = add_sysblack_e0(by_name["ysbin/yst00018.ybn"]["payload"],
                           by_name["ysbin/ysc.ybn"]["payload"])
    bn, audits["v4"] = _patch_archive(bn, "ysbin/yst00018.ybn", black, level=6)
    phases.append(_historical("v4/bn.ypf", bn, BN_PINS["v4"]))
    by_name = {entry["name"]: entry for entry in ypf.parse(bn).entries}
    endpoint = fix_endpoint(by_name["ysbin/yst00027.ybn"]["payload"])
    bn, audits["r1"] = _patch_archive(bn, "ysbin/yst00027.ybn", endpoint, level=9)
    phases.append(_historical("r1/bn.ypf", bn, BN_PINS["r1"]))
    output["bn.ypf"] = bn
    _need(sha(next(entry["payload"] for entry in ypf.parse(bn).entries
                   if entry["name"] == "ysbin/yscfg.ybn")) ==
          "a2786c2b7a245dafd09dd3d26e7e1da9dd2eb4c4ea383923787f9d97447336ab",
          "Chinese configuration changed during compatibility patches")
    update3 = (source / "pac/update3.ypf").read_bytes()
    _need(sha(update3) == SOURCE_PINS["pac/update3.ypf"][1],
          "Source update3 changed after preflight")
    for name, data in [("update1.ypf", output["update1.ypf"]),
                       ("update2.ypf", output["update2.ypf"]), ("update3.ypf", update3)]:
        _need(not any(entry["name"].casefold().startswith("ysbin/")
                      for entry in ypf.parse(data).entries),
              "An update archive overrides patched system scripts: " + name)
    return output, {"phases": phases, "archive_audits": audits,
                    "chinese_resources": 696, "replacement_occurrences": 699,
                    "filename_byte_aliases": 9, "added_entries": 0,
                    "script_update_shadowing_check": "PASS"}


def prepare(source: Path, stage: Path, profile: str = "r1") -> dict:
    """Create one independent, version-locked full runtime tree."""
    source, stage = Path(source).resolve(), Path(stage).resolve()
    _need(stage != source and not stage.is_relative_to(source),
          "Output stage must be outside the source-game directory")
    game_dir = stage / "maggotbaits"
    _need(not game_dir.exists(), "Refusing to overwrite an existing Maggot Baits output")
    summary, rows, resources = _preflight(source, profile)
    stage.mkdir(parents=True, exist_ok=True)
    _need(shutil.disk_usage(stage).free >= summary["source_runtime_bytes"] + 512 * 1024 * 1024,
          "Insufficient free space for the independent runtime tree")
    archives, build_summary = _build_archives(source, resources)
    game_dir.mkdir()
    fingerprints = []
    changed_paths = {"pac/" + name for name in archives}
    for row in rows:
        name = row["name"]
        original, target = source / name, game_dir / name
        before = _regular(original)
        _need((before.st_size, before.st_mtime_ns) == (row["size"], row["mtime_ns"]),
              "Source runtime metadata changed after preflight")
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        if name in changed_paths:
            old_sha = _file_sha(original)
            _need(old_sha == SOURCE_PINS[name][1],
                  "Source archive changed between resource construction and staging")
            payload = archives[Path(name).name]
            with target.open("xb") as stream:
                stream.write(payload)
            _need(_file_sha(target) == sha(payload), "Patched archive disk readback differs")
            after_sha = sha(payload)
        else:
            count = 0
            with original.open("rb") as reader, target.open("xb") as writer:
                while chunk := reader.read(_CHUNK):
                    digest.update(chunk)
                    count += len(chunk)
                    writer.write(chunk)
            old_sha = after_sha = digest.hexdigest()
            _need(count == row["size"] and _file_sha(target) == old_sha,
                  "Preserved runtime file disk readback differs")
        after = _regular(original)
        _need((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
              "Source changed during runtime preparation")
        fingerprints.append({"path": name, "source_size": row["size"],
                             "source_sha256": old_sha, "output_size": target.stat().st_size,
                             "output_sha256": after_sha, "changed": name in changed_paths})
    # Rehash the required runtime source only, never backup archives or phone saves.
    for row in fingerprints:
        _need(_file_sha(source / row["path"]) == row["source_sha256"],
              "Source runtime changed before final preparation verification")
    for name in ("maggotbaits.exe", "maggotbaits_cn.exe"):
        _need(_file_sha(source / name) == SOURCE_PINS[name][1],
              "Read-only executable input changed before final verification")
    actual = sorted(path.relative_to(game_dir).as_posix()
                    for path in game_dir.rglob("*") if path.is_file())
    _need(actual == [row["name"] for row in rows]
          and {name for name in actual if name.startswith("save/")} == SYSTEM_SAVES,
          "Final runtime inventory or source-system-save set differs")
    summary.update(build_summary)
    summary.update(
        status="PREPARED_FILE_VALIDATED_AWAITING_PACKAGING_AND_DEVICE_ACCEPTANCE",
        game_directory_name="maggotbaits", output_files=1425,
        changed_runtime_files=5, preserved_runtime_files=1420,
        source_read_only_verified=True, runtime_fingerprints=fingerprints,
        phone_saves_embedded=False, extra_user_saves_embedded=False,
        historical_ios_acceptance={
            "evidence": "User confirmed the previous R1 package on Kakacat 1.5",
            "direct_and_exit_reopen_readload_slots": [1, 2, 6, 7],
            "background_and_required_characters_restored_without_advancing": True,
            "all_routes_all_transitions_new_save_flow": "NOT_FULLY_CONFIRMED",
            "this_new_build_device_tested": False,
        },
    )
    return {"game_dir": game_dir, "summary": summary}
