#!/usr/bin/env python3
"""Deterministic local/remote helpers for sslctlw release bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any, NoReturn


ASSET_NAME = "sslctlw-windows-amd64.exe"
MANIFEST_NAME = "manifest.json"
INSTALL_NAME = "install.ps1"
SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$"
)


def fail(message: str) -> NoReturn:
    raise SystemExit(message)


def parse_version(value: str) -> tuple[str, str]:
    version = value[1:] if value.startswith("v") else value
    match = SEMVER_RE.fullmatch(version)
    if not match:
        fail(f"无效 SemVer: {value}")
    return version, "dev" if match.group(4) else "main"


def stable_version_key(value: str) -> tuple[int, int, int]:
    version, channel = parse_version(value)
    if channel != "main":
        fail(f"main.latest 必须是稳定 SemVer: {value}")
    major, minor, patch = version.split(".")
    return int(major), int(minor), int(patch)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"无法读取 JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON 顶层必须是对象: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def validate_manifest(bundle: Path) -> dict[str, Any]:
    manifest = load_json(bundle / MANIFEST_NAME)
    required = {
        "schema_version",
        "product",
        "channel",
        "version",
        "source_commit",
        "dirty",
        "created_at",
        "assets",
        "install_script",
        "signature",
    }
    if set(manifest) != required:
        fail("manifest 字段集合不符合约定")
    version, channel = parse_version(str(manifest["version"]))
    if manifest["product"] != "sslctlw" or manifest["channel"] != channel:
        fail("manifest 产品或通道不匹配")
    if manifest["schema_version"] != 1:
        fail("不支持的 manifest schema_version")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest["source_commit"])):
        fail("manifest source_commit 无效")
    if not isinstance(manifest["dirty"], bool):
        fail("manifest dirty 必须是布尔值")
    if channel == "main" and manifest["dirty"]:
        fail("main bundle 不得来自脏工作区")
    assets = manifest["assets"]
    if not isinstance(assets, list) or len(assets) != 1:
        fail("规范资产集合必须且只能包含一个文件")
    asset = assets[0]
    if not isinstance(asset, dict) or set(asset) != {"name", "size", "sha256"}:
        fail("manifest 资产字段无效")
    if asset["name"] != ASSET_NAME:
        fail(f"规范资产名称必须是 {ASSET_NAME}")
    asset_path = bundle / ASSET_NAME
    if not asset_path.is_file():
        fail(f"bundle 缺少资产: {ASSET_NAME}")
    if asset["size"] != asset_path.stat().st_size or asset["sha256"] != sha256(asset_path):
        fail("bundle 资产大小或 SHA256 与 manifest 不一致")
    install = manifest["install_script"]
    install_path = bundle / INSTALL_NAME
    if not isinstance(install, dict) or set(install) != {"name", "sha256"}:
        fail("manifest install_script 字段无效")
    if install["name"] != INSTALL_NAME or not install_path.is_file():
        fail("bundle 缺少 install.ps1")
    if install["sha256"] != sha256(install_path):
        fail("install.ps1 SHA256 与 manifest 不一致")
    if manifest["signature"] != {"type": "authenticode", "verified": True}:
        fail("bundle 缺少已验证的 Authenticode 声明")
    manifest["version"] = version
    return manifest


def command_validate(args: argparse.Namespace) -> None:
    version, channel = parse_version(args.version)
    print(f"{version}\t{channel}")


def command_sha256(args: argparse.Namespace) -> None:
    path = Path(args.path).resolve()
    if not path.is_file():
        fail(f"文件不存在: {path}")
    print(sha256(path))


def command_create(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle).resolve()
    version, channel = parse_version(args.version)
    source_commit = args.source_commit.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        fail("source_commit 必须是 40 位 Git SHA")
    dirty = args.dirty == "true"
    if channel == "main" and dirty:
        fail("main bundle 不得来自脏工作区")
    asset_path = bundle / ASSET_NAME
    install_path = bundle / INSTALL_NAME
    if not asset_path.is_file() or not install_path.is_file():
        fail("创建 manifest 前 bundle 文件不完整")
    manifest = {
        "schema_version": 1,
        "product": "sslctlw",
        "channel": channel,
        "version": version,
        "source_commit": source_commit,
        "dirty": dirty,
        "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "assets": [
            {
                "name": ASSET_NAME,
                "size": asset_path.stat().st_size,
                "sha256": sha256(asset_path),
            }
        ],
        "install_script": {"name": INSTALL_NAME, "sha256": sha256(install_path)},
        "signature": {"type": "authenticode", "verified": True},
    }
    write_json(bundle / MANIFEST_NAME, manifest)
    validate_manifest(bundle)


def command_verify_bundle(args: argparse.Namespace) -> None:
    manifest = validate_manifest(Path(args.bundle).resolve())
    asset = manifest["assets"][0]
    print(
        "\t".join(
            [
                manifest["version"],
                manifest["channel"],
                manifest["source_commit"],
                "true" if manifest["dirty"] else "false",
                asset["sha256"],
                manifest["install_script"]["sha256"],
            ]
        )
    )


def command_next_index(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    output = Path(args.output).resolve()
    manifest = validate_manifest(bundle)
    version = manifest["version"]
    channel = manifest["channel"]
    index_path = root / "releases.json"
    data: dict[str, Any] = load_json(index_path) if index_path.exists() else {}
    channel_data = data.setdefault(channel, {"latest": "", "versions": []})
    if not isinstance(channel_data, dict) or not isinstance(channel_data.get("versions"), list):
        fail(f"releases.json.{channel} 结构无效")
    versions = channel_data["versions"]
    existing = [item for item in versions if isinstance(item, dict) and item.get("version") == version]
    final_dir = root / channel / f"v{version}"
    if channel == "main" and (existing or final_dir.exists()):
        fail(f"正式版本已存在，禁止覆盖: {version}")
    latest = channel_data.get("latest")
    if channel == "main" and latest and stable_version_key(version) <= stable_version_key(str(latest)):
        fail(f"正式版本必须高于当前 main.latest: {latest}")
    asset = manifest["assets"][0]
    entry: dict[str, Any] = {
        "version": version,
        "released_at": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "checksums": {asset["name"]: asset["sha256"]},
        "source_commit": manifest["source_commit"],
        "dirty": manifest["dirty"],
    }
    retained = [item for item in versions if not isinstance(item, dict) or item.get("version") != version]
    channel_data["versions"] = [entry, *retained][:5]
    channel_data["latest"] = version
    write_json(output, data)


def validate_index_for_manifest(path: Path, manifest: dict[str, Any]) -> None:
    index = load_json(path)
    channel_data = index.get(manifest["channel"])
    if not isinstance(channel_data, dict) or channel_data.get("latest") != manifest["version"]:
        fail("待发布索引 latest 与 manifest 不一致")
    versions = channel_data.get("versions")
    matches = [
        item
        for item in versions or []
        if isinstance(item, dict) and item.get("version") == manifest["version"]
    ]
    if len(matches) != 1:
        fail("待发布索引缺少唯一版本条目")
    asset = manifest["assets"][0]
    expected = {
        "version": manifest["version"],
        "checksums": {asset["name"]: asset["sha256"]},
        "source_commit": manifest["source_commit"],
        "dirty": manifest["dirty"],
    }
    for key, value in expected.items():
        if matches[0].get(key) != value:
            fail(f"待发布索引字段与 manifest 不一致: {key}")


def command_verify_release(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    manifest = validate_manifest(bundle)
    version = manifest["version"]
    channel = manifest["channel"]
    index = load_json(root / "releases.json")
    channel_data = index.get(channel)
    if not isinstance(channel_data, dict) or channel_data.get("latest") != version:
        fail(f"{channel}.latest 未指向 {version}")
    versions = channel_data.get("versions")
    matches = [item for item in versions or [] if isinstance(item, dict) and item.get("version") == version]
    if len(matches) != 1:
        fail("索引中版本条目不是唯一一条")
    asset = manifest["assets"][0]
    expected_checksums = {asset["name"]: asset["sha256"]}
    if matches[0].get("checksums") != expected_checksums:
        fail("索引 checksums 与 manifest 不一致")
    if matches[0].get("source_commit") != manifest["source_commit"]:
        fail("索引 source_commit 与 manifest 不一致")
    if matches[0].get("dirty") is not manifest["dirty"]:
        fail("索引 dirty 与 manifest 不一致")
    release_dir = root / channel / f"v{version}"
    files = sorted(path.name for path in release_dir.iterdir() if path.is_file()) if release_dir.is_dir() else []
    if files != [ASSET_NAME]:
        fail(f"远端正式资产集合不完整或含额外文件: {files}")
    if sha256(release_dir / ASSET_NAME) != asset["sha256"]:
        fail("远端资产 SHA256 与 manifest 不一致")
    if sha256(root / INSTALL_NAME) != manifest["install_script"]["sha256"]:
        fail("远端 install.ps1 与 bundle 不一致")


def command_prune(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    channel = args.channel
    if channel not in {"main", "dev"}:
        fail("无效通道")
    index = load_json(root / "releases.json")
    channel_data = index.get(channel, {})
    keep = {
        f"v{item['version']}"
        for item in channel_data.get("versions", [])
        if isinstance(item, dict) and isinstance(item.get("version"), str)
    }
    channel_dir = root / channel
    if not channel_dir.is_dir():
        return
    for path in channel_dir.iterdir():
        if path.is_dir() and path.name.startswith("v") and path.name not in keep:
            if not SEMVER_RE.fullmatch(path.name[1:]):
                fail(f"拒绝清理非 SemVer 目录: {path}")
            shutil.rmtree(path)


def release_paths(root_value: str, bundle_value: str, release_id: str) -> tuple[Path, Path, Path]:
    root = Path(root_value).resolve()
    bundle = Path(bundle_value).resolve()
    stage = bundle.parent
    expected_stage = (root / ".staging" / release_id).resolve()
    if stage != expected_stage or bundle != stage / "bundle":
        fail("暂存目录不在预期发布根目录内")
    if not re.fullmatch(r"[0-9A-Za-z._-]+", release_id):
        fail("release_id 含非法字符")
    rollback = (root / ".rollback" / release_id).resolve()
    return root, stage, rollback


def save_state(path: Path, state: dict[str, Any]) -> None:
    write_json(path, state)


def command_commit(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    bundle = stage / "bundle"
    manifest = validate_manifest(bundle)
    next_index = Path(args.next_index).resolve()
    if next_index != stage / "releases.json.next" or not next_index.is_file():
        fail("待发布索引位置无效")
    validate_index_for_manifest(next_index, manifest)
    version = manifest["version"]
    channel = manifest["channel"]
    final_dir = root / channel / f"v{version}"
    staged_release = stage / "release"
    if sorted(path.name for path in staged_release.iterdir()) != [ASSET_NAME]:
        fail("暂存资产集合不完整")
    if sha256(staged_release / ASSET_NAME) != manifest["assets"][0]["sha256"]:
        fail("待提升资产 SHA256 与 manifest 不一致")
    if rollback.exists():
        fail("检测到未清理的回滚状态，请先恢复或核查")
    rollback.mkdir(parents=True)
    state: dict[str, Any] = {
        "release_started": False,
        "old_release_moved": False,
        "index_backed_up": False,
        "install_backed_up": False,
        "committed": False,
    }
    state_path = rollback / "state.json"
    save_state(state_path, state)
    if final_dir.exists():
        if channel == "main":
            fail(f"正式版本目录已存在: {final_dir}")
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(final_dir, rollback / "release.old")
        state["old_release_moved"] = True
        save_state(state_path, state)
    index_path = root / "releases.json"
    if index_path.exists():
        shutil.copy2(index_path, rollback / "releases.json.old")
        state["index_backed_up"] = True
        save_state(state_path, state)
    install_path = root / INSTALL_NAME
    if install_path.exists():
        shutil.copy2(install_path, rollback / "install.ps1.old")
        state["install_backed_up"] = True
        save_state(state_path, state)
    state["release_started"] = True
    save_state(state_path, state)
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staged_release, final_dir)
    install_tmp = root / f".{INSTALL_NAME}.{args.release_id}.tmp"
    shutil.copy2(bundle / INSTALL_NAME, install_tmp)
    os.replace(install_tmp, install_path)
    os.replace(next_index, index_path)
    state["committed"] = True
    save_state(state_path, state)


def command_rollback(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    state_path = rollback / "state.json"
    if not state_path.exists():
        return
    state = load_json(state_path)
    manifest = validate_manifest(stage / "bundle")
    final_dir = root / manifest["channel"] / f"v{manifest['version']}"
    old_release = rollback / "release.old"
    if (state.get("release_started") or old_release.exists()) and final_dir.exists():
        shutil.rmtree(final_dir)
    if old_release.exists():
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(old_release, final_dir)
    index_path = root / "releases.json"
    old_index = rollback / "releases.json.old"
    if old_index.exists():
        os.replace(old_index, index_path)
    elif state.get("release_started") and index_path.exists():
        index_path.unlink()
    install_path = root / INSTALL_NAME
    old_install = rollback / "install.ps1.old"
    if old_install.exists():
        os.replace(old_install, install_path)
    elif state.get("release_started") and install_path.exists():
        install_path.unlink()
    shutil.rmtree(rollback, ignore_errors=True)


def command_cleanup(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    manifest = validate_manifest(stage / "bundle")
    command_prune(argparse.Namespace(root=str(root), channel=manifest["channel"]))
    shutil.rmtree(rollback, ignore_errors=True)
    shutil.rmtree(stage, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-version")
    validate.add_argument("version")
    validate.set_defaults(func=command_validate)
    hash_file = sub.add_parser("sha256-file")
    hash_file.add_argument("--path", required=True)
    hash_file.set_defaults(func=command_sha256)
    create = sub.add_parser("create-manifest")
    create.add_argument("--bundle", required=True)
    create.add_argument("--version", required=True)
    create.add_argument("--source-commit", required=True)
    create.add_argument("--dirty", choices=["true", "false"], required=True)
    create.set_defaults(func=command_create)
    verify_bundle = sub.add_parser("verify-bundle")
    verify_bundle.add_argument("--bundle", required=True)
    verify_bundle.set_defaults(func=command_verify_bundle)
    next_index = sub.add_parser("next-index")
    next_index.add_argument("--root", required=True)
    next_index.add_argument("--bundle", required=True)
    next_index.add_argument("--output", required=True)
    next_index.set_defaults(func=command_next_index)
    verify_release = sub.add_parser("verify-release")
    verify_release.add_argument("--root", required=True)
    verify_release.add_argument("--bundle", required=True)
    verify_release.set_defaults(func=command_verify_release)
    prune = sub.add_parser("prune")
    prune.add_argument("--root", required=True)
    prune.add_argument("--channel", required=True)
    prune.set_defaults(func=command_prune)
    commit = sub.add_parser("commit-release")
    commit.add_argument("--root", required=True)
    commit.add_argument("--bundle", required=True)
    commit.add_argument("--next-index", required=True)
    commit.add_argument("--release-id", required=True)
    commit.set_defaults(func=command_commit)
    rollback = sub.add_parser("rollback-release")
    rollback.add_argument("--root", required=True)
    rollback.add_argument("--bundle", required=True)
    rollback.add_argument("--release-id", required=True)
    rollback.set_defaults(func=command_rollback)
    cleanup = sub.add_parser("cleanup-release")
    cleanup.add_argument("--root", required=True)
    cleanup.add_argument("--bundle", required=True)
    cleanup.add_argument("--release-id", required=True)
    cleanup.set_defaults(func=command_cleanup)
    return result


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
