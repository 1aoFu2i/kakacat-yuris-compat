"""咔咔喵（KrkrCat）兼容适配的离线、版本限定命令行入口。"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import sys
import zlib
from . import __version__
from .common import require, write_json, file_hash, inventory, package, verify_zip

PROFILES = ("euphoria-r1", "euphoria-r2", "euphoria-alt-r2", "maggot-r1")

def module_for(profile):
    name = "maggot" if profile == "maggot-r1" else "euphoria"
    return importlib.import_module("." + name, __package__)

def emit(value):
    print(json.dumps(value, ensure_ascii=False, indent=2), flush=True)

def build(profile, source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    require(source.is_dir(), "Source must be an extracted game directory")
    require(not output.exists(), "Refusing to overwrite existing output")
    require(not output.is_relative_to(source) and not source.is_relative_to(output),
            "Source and output directory trees must be separate")
    engine = module_for(profile)
    emit({"phase": "inspect", "profile": profile})
    inspected = engine.inspect(source, profile)
    output.mkdir(parents=True, exist_ok=False)
    stage = output / "stage"
    stage.mkdir()
    try:
        emit({"phase": "prepare", "profile": profile})
        prepared = engine.prepare(source, stage, profile)
        game_dir = Path(prepared["game_dir"])
        require(game_dir.parent == stage and game_dir.is_dir(), "Invalid stage root")
        emit({"phase": "inventory", "profile": profile})
        rows = inventory(game_dir)
        partial = output / (profile + ".zip.partial")
        emit({"phase": "package", "profile": profile, "members": len(rows)})
        package(game_dir, partial, rows)
        emit({"phase": "readback", "profile": profile})
        zip_result = verify_zip(partial, game_dir.name, rows)
        after = engine.inspect(source, profile)
        require(after == inspected, "Source fingerprints changed during build")
        final = output / (profile + ".zip")
        partial.rename(final)
        manifest = {"schema_version": 1, "tool_version": __version__, "profile": profile,
                    "target_runtime": "咔咔喵（KrkrCat）", "game_directory": game_dir.name,
                    "zip_filename": final.name, "files": rows,
                    "zip_size": final.stat().st_size, "zip_sha256": file_hash(final)}
        report = {"status": "FILE_VALIDATED", "ios_status": "NOT_TESTED_BY_THIS_BUILD",
                  "created_at": datetime.now(timezone.utc).isoformat(), "profile": profile,
                  "target_runtime": "咔咔喵（KrkrCat）", "python_version": sys.version.split()[0],
                  "zlib_version": zlib.ZLIB_RUNTIME_VERSION, "source_unchanged": True,
                  "preparation": prepared["summary"], "zip_validation": zip_result,
                  "zip_sha256": manifest["zip_sha256"]}
        write_json(output / "manifest.json", manifest)
        write_json(output / "validation.json", report)
        emit({"phase": "complete", "profile": profile, "status": report["status"],
              "members": len(rows), "zip_sha256": manifest["zip_sha256"]})
        return report
    except Exception as exc:
        write_json(output / "failure.json", {"status": "FAILED", "profile": profile,
                                             "error_type": type(exc).__name__})
        raise

def verify(output):
    output = Path(output).resolve()
    manifest = json.loads((output / "manifest.json").read_text("utf-8"))
    profile = manifest["profile"]
    require(profile in PROFILES, "Unknown manifest profile")
    game_name = "maggotbaits" if profile == "maggot-r1" else "euphoriaHD"
    require(manifest["game_directory"] == game_name, "Unexpected game directory")
    require(manifest["zip_filename"] == profile + ".zip", "Unexpected ZIP filename")
    game_dir = output / "stage" / game_name
    require(inventory(game_dir) == manifest["files"], "Stage files changed")
    zipped = output / manifest["zip_filename"]
    require(zipped.stat().st_size == manifest["zip_size"], "ZIP size changed")
    require(file_hash(zipped) == manifest["zip_sha256"], "ZIP file hash changed")
    result = verify_zip(zipped, game_name, manifest["files"])
    result.update(profile=profile, target_runtime="咔咔喵（KrkrCat）",
                  ios_status="NOT_TESTED_BY_THIS_VERIFICATION")
    emit(result)
    return result

def main(argv=None):
    parser = argparse.ArgumentParser(description="咔咔喵（KrkrCat）YU-RIS 游戏兼容适配；离线、已知版本限定")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "build"):
        command = commands.add_parser(name)
        command.add_argument("--profile", choices=PROFILES, required=True)
        command.add_argument("--source", type=Path, required=True, help="已解压的源游戏根目录，只读")
        if name == "build":
            command.add_argument("--output", type=Path, required=True, help="尚不存在的独立输出目录")
    check = commands.add_parser("verify")
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            emit(module_for(args.profile).inspect(args.source.resolve(), args.profile))
        elif args.command == "build":
            build(args.profile, args.source, args.output)
        else:
            verify(args.output)
        return 0
    except (ValueError, OSError, KeyError, ImportError) as exc:
        print(f"咔咔喵兼容适配失败：{exc}", file=sys.stderr)
        return 1
