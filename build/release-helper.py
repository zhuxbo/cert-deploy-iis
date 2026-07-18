#!/usr/bin/env python3
"""Deterministic local/remote helpers for sslctlw release bundles."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
from functools import wraps
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any, NoReturn


ASSET_NAME = "sslctlw-windows-amd64.exe"
MANIFEST_NAME = "manifest.json"
INSTALL_NAME = "install.ps1"
OWNER_NAME = ".release-owner.json"
MUTEX_NAME = ".release.mutex"
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


def write_json(path: Path, value: dict[str, Any], file_mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    target_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else file_mode
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, target_mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


@contextmanager
def file_mutex(mutex_path: Path):
    mutex_path.parent.mkdir(parents=True, exist_ok=True)
    with mutex_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def root_mutex(root: Path):
    with file_mutex(root / MUTEX_NAME):
        yield


def locked_root_command(func):
    @wraps(func)
    def wrapped(args: argparse.Namespace) -> None:
        root = Path(args.root).resolve()
        with root_mutex(root):
            func(args)

    return wrapped


def command_run_locked(args: argparse.Namespace) -> None:
    lock_path = Path(args.lock_path).resolve()
    if not args.command:
        fail("run-locked 缺少待执行命令")
    with file_mutex(lock_path):
        environment = dict(os.environ)
        environment["SSLCTLW_COORDINATOR_LOCKED"] = "1"
        completed = subprocess.run(args.command, env=environment, check=False)
    raise SystemExit(completed.returncode)


def validate_release_id(release_id: str) -> None:
    if not re.fullmatch(r"[0-9A-Za-z._-]+", release_id):
        fail("release_id 含非法字符")


def manifest_identity(bundle: Path) -> str:
    validate_manifest(bundle)
    return sha256(bundle / MANIFEST_NAME)


def owner_path(root: Path) -> Path:
    return root / OWNER_NAME


def expected_owner(bundle: Path, release_id: str) -> dict[str, Any]:
    validate_release_id(release_id)
    manifest = validate_manifest(bundle)
    return {
        "schema_version": 1,
        "release_id": release_id,
        "manifest_sha256": manifest_identity(bundle),
        "channel": manifest["channel"],
        "version": manifest["version"],
        "source_commit": manifest["source_commit"],
        "phase": "staging",
    }


def require_release_owner(root: Path, bundle: Path, release_id: str) -> dict[str, Any]:
    path = owner_path(root)
    if not path.is_file() or path.is_symlink():
        fail("发布根未由当前 bundle 锁定；请重新 stage")
    owner = load_json(path)
    expected = expected_owner(bundle, release_id)
    identity_keys = set(expected) - {"phase"}
    if {key: owner.get(key) for key in identity_keys} != {
        key: expected[key] for key in identity_keys
    }:
        current = owner.get("release_id", "未知")
        fail(f"发布根正由其他发布占用: {current}")
    return owner


def set_owner_phase(root: Path, owner: dict[str, Any], phase: str) -> None:
    updated = dict(owner)
    updated["phase"] = phase
    write_json(owner_path(root), updated)


def require_publish_token(owner: dict[str, Any], publish_token: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{32}", publish_token):
        fail("publish token 无效")
    if owner.get("publish_token") != publish_token:
        fail("publish token 不匹配，拒绝其他协调器操作")


def current_index_generation(root: Path) -> str:
    path = root / "releases.json"
    return sha256(path) if path.is_file() else "absent"


def file_generation(path: Path) -> str:
    return sha256(path) if path.is_file() else "absent"


def baseline_path(next_index: Path) -> Path:
    return next_index.with_name(f"{next_index.name}.base")


def cleanup_tombstone(root: Path, release_id: str) -> Path:
    validate_release_id(release_id)
    return root / f".cleanup-complete.{release_id}.json"


def rollback_tombstone(root: Path, release_id: str) -> Path:
    validate_release_id(release_id)
    return root / f".rollback-complete.{release_id}.json"


def completion_record(bundle: Path, release_id: str, publish_token: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "release_id": release_id,
        "manifest_sha256": manifest_identity(bundle),
        "publish_token": publish_token,
    }


def validate_completion_record(
    path: Path, bundle: Path, release_id: str, publish_token: str
) -> None:
    if load_json(path) != completion_record(bundle, release_id, publish_token):
        fail("完成标记与当前 bundle 或 token 不匹配")


def validate_completion_values(
    path: Path,
    release_id: str,
    manifest_sha256: str,
    publish_token: str,
) -> None:
    expected = {
        "schema_version": 1,
        "release_id": release_id,
        "manifest_sha256": manifest_sha256,
        "publish_token": publish_token,
    }
    if load_json(path) != expected:
        fail("完成标记与当前 manifest 或 token 不匹配")


def copy_file_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        shutil.copy2(source, temporary)
        with temporary.open("rb+") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


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
    write_json(bundle / MANIFEST_NAME, manifest, 0o644)
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


@locked_root_command
def command_acquire_lock(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    expected = expected_owner(bundle, args.release_id)
    path = owner_path(root)
    if path.exists():
        if path.is_symlink() or not path.is_file():
            fail("发布根锁状态无效，需要人工核查")
        owner = load_json(path)
        identity_keys = set(expected) - {"phase"}
        if {key: owner.get(key) for key in identity_keys} != {
            key: expected[key] for key in identity_keys
        }:
            current = owner.get("release_id", "未知")
            fail(f"发布根正由其他发布占用: {current}")
        if owner.get("phase") not in {"staging", "staged"}:
            fail("发布已进入公开阶段；请先 verify 或 rollback")
        return
    for completed in (
        rollback_tombstone(root, args.release_id),
        cleanup_tombstone(root, args.release_id),
    ):
        if completed.exists():
            record = load_json(completed)
            if (
                record.get("release_id") != args.release_id
                or record.get("manifest_sha256") != expected["manifest_sha256"]
            ):
                fail("既有完成标记与待暂存 bundle 不一致，需要人工核查")
            completed.unlink()
    write_json(path, expected)


@locked_root_command
def command_assert_lock(args: argparse.Namespace) -> None:
    owner = require_release_owner(
        Path(args.root).resolve(), Path(args.bundle).resolve(), args.release_id
    )
    if owner.get("phase") in {"publishing", "committed", "verified"}:
        require_publish_token(owner, args.publish_token)


@locked_root_command
def command_release_lock(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    path = owner_path(root)
    if not path.exists():
        return
    owner = require_release_owner(root, Path(args.bundle).resolve(), args.release_id)
    if owner.get("phase") not in {"staging", "staged"}:
        fail("发布已进入公开阶段，禁止直接释放锁")
    path.unlink()


@locked_root_command
def command_next_index(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    output = Path(args.output).resolve()
    owner = require_release_owner(root, bundle, args.release_id)
    if owner.get("phase") not in {"staging", "staged"}:
        fail("当前发布阶段不允许重新生成索引")
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
    if channel == "dev" and final_dir.exists():
        if len(existing) != 1:
            fail("dev 既有版本目录与索引条目不一致")
        expected_checksums = existing[0].get("checksums")
        files = sorted(path.name for path in final_dir.iterdir() if path.is_file())
        if files != [ASSET_NAME] or not isinstance(expected_checksums, dict):
            fail("dev 既有版本资产集合与索引不一致")
        if expected_checksums.get(ASSET_NAME) != sha256(final_dir / ASSET_NAME):
            fail("dev 既有版本资产哈希与索引不一致")
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
    write_json(output, data, 0o644)
    write_text(baseline_path(output), current_index_generation(root))
    set_owner_phase(root, owner, "staged")


@locked_root_command
def command_begin_publish(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    owner = require_release_owner(root, bundle, args.release_id)
    if owner.get("phase") == "staged":
        if not re.fullmatch(r"[0-9a-f]{32}", args.publish_token):
            fail("publish token 无效")
        updated = dict(owner)
        updated["phase"] = "publishing"
        updated["publish_token"] = args.publish_token
        write_json(owner_path(root), updated)
        return
    if owner.get("phase") in {"publishing", "committed", "verified"}:
        require_publish_token(owner, args.publish_token)
        return
    fail("当前发布阶段不允许开始公开")


@locked_root_command
def command_promote_stage(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    validate_release_id(args.release_id)
    incoming_bundle = Path(args.incoming_bundle).resolve()
    stage = (root / ".staging" / args.release_id).resolve()
    if incoming_bundle != stage / "incoming" / "bundle":
        fail("incoming bundle 不在预期暂存目录")
    require_release_owner(root, incoming_bundle, args.release_id)
    canonical = stage / "bundle"
    previous = stage / "bundle.previous"
    if previous.exists() and canonical.exists():
        shutil.rmtree(previous)
    if canonical.exists():
        os.replace(canonical, previous)
    try:
        os.replace(incoming_bundle, canonical)
    except BaseException:
        if previous.exists() and not canonical.exists():
            os.replace(previous, canonical)
        raise
    require_release_owner(root, canonical, args.release_id)
    shutil.rmtree(previous, ignore_errors=True)


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


def index_asset_checksum(path: Path, channel: str, version: str) -> str:
    index = load_json(path)
    channel_data = index.get(channel)
    versions = channel_data.get("versions") if isinstance(channel_data, dict) else None
    matches = [
        item
        for item in versions or []
        if isinstance(item, dict) and item.get("version") == version
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("checksums"), dict):
        fail("回滚索引缺少旧版本唯一条目")
    checksum = matches[0]["checksums"].get(ASSET_NAME)
    if not isinstance(checksum, str):
        fail("回滚索引缺少旧版本资产哈希")
    return checksum


def validate_release_directory(path: Path, expected_checksum: str) -> None:
    files = sorted(item.name for item in path.iterdir() if item.is_file()) if path.is_dir() else []
    if files != [ASSET_NAME] or sha256(path / ASSET_NAME) != expected_checksum:
        fail("旧版本回滚资产缺失或哈希不一致")


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


@locked_root_command
def command_prune_cli(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    if owner_path(root).exists():
        fail("发布根存在活动事务，禁止独立 prune")
    command_prune(args)


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


@locked_root_command
def command_commit(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    bundle = stage / "bundle"
    owner = require_release_owner(root, bundle, args.release_id)
    require_publish_token(owner, args.publish_token)
    if owner.get("phase") in {"committed", "verified"}:
        command_verify_release(argparse.Namespace(root=str(root), bundle=str(bundle)))
        return
    if owner.get("phase") != "publishing":
        fail("当前发布阶段不允许提交")
    manifest = validate_manifest(bundle)
    next_index = Path(args.next_index).resolve()
    if next_index != stage / "releases.json.next" or not next_index.is_file():
        fail("待发布索引位置无效")
    base_index = baseline_path(next_index)
    if not base_index.is_file():
        fail("待发布索引缺少基线代际")
    expected_generation = base_index.read_text(encoding="utf-8").strip()
    if expected_generation not in {"absent", current_index_generation(root)}:
        fail("发布根索引代际已变化，拒绝提交陈旧索引")
    if current_index_generation(root) != expected_generation:
        fail("发布根索引代际已变化，拒绝提交陈旧索引")
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
    set_owner_phase(root, owner, "publishing")
    rollback.mkdir(parents=True)
    state: dict[str, Any] = {
        "schema_version": 1,
        "base_index_generation": expected_generation,
        "target_index_generation": sha256(next_index),
        "base_install_generation": file_generation(root / INSTALL_NAME),
        "target_install_generation": manifest["install_script"]["sha256"],
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
        copy_file_atomic(index_path, rollback / "releases.json.old")
        state["index_backed_up"] = True
        save_state(state_path, state)
    install_path = root / INSTALL_NAME
    if install_path.exists():
        copy_file_atomic(install_path, rollback / "install.ps1.old")
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
    set_owner_phase(root, owner, "committed")


@locked_root_command
def command_mark_verified(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    bundle = Path(args.bundle).resolve()
    owner = require_release_owner(root, bundle, args.release_id)
    require_publish_token(owner, args.publish_token)
    if owner.get("phase") not in {"committed", "verified"}:
        fail("只有已提交发布可以标记验收完成")
    set_owner_phase(root, owner, "verified")


def rollback_phase(owner: dict[str, Any]) -> str:
    phase = str(owner.get("phase", ""))
    if phase == "rolling-back":
        return str(owner.get("rollback_from_phase", ""))
    return phase


def validate_rollback_preconditions(
    root: Path,
    stage: Path,
    rollback: Path,
    release_id: str,
    publish_token: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    bundle = stage / "bundle"
    owner = require_release_owner(root, bundle, release_id)
    phase = rollback_phase(owner)
    if phase == "verified":
        fail("发布已完成节点验收，禁止回滚")
    if phase in {"publishing", "committed"}:
        require_publish_token(owner, publish_token)
    state_path = rollback / "state.json"
    if not state_path.exists():
        rollback_entries = list(rollback.iterdir()) if rollback.is_dir() else []
        if phase == "publishing" and not rollback_entries:
            return owner, None
        if phase not in {"staging", "staged"}:
            fail("公开阶段缺少回滚状态，拒绝假成功；需要人工核查")
        return owner, None

    state = load_json(state_path)
    manifest = validate_manifest(bundle)
    current_generation = current_index_generation(root)
    if current_generation not in {
        state.get("base_index_generation"),
        state.get("target_index_generation"),
    }:
        fail("公开索引已进入其他代际，拒绝旧事务回滚")
    install_path = root / INSTALL_NAME
    current_install_generation = file_generation(install_path)
    if current_install_generation not in {
        state.get("base_install_generation"),
        state.get("target_install_generation"),
    }:
        fail("安装入口已进入其他代际，拒绝旧事务回滚")

    old_index = rollback / "releases.json.old"
    base_index = state.get("base_index_generation")
    if base_index != "absent" and not (
        (old_index.is_file() and sha256(old_index) == base_index)
        or current_generation == base_index
    ):
        fail("索引回滚备份缺失或不完整，拒绝恢复")
    old_install = rollback / "install.ps1.old"
    base_install = state.get("base_install_generation")
    if base_install != "absent" and not (
        (old_install.is_file() and sha256(old_install) == base_install)
        or current_install_generation == base_install
    ):
        fail("安装入口回滚备份缺失或不完整，拒绝恢复")

    if state.get("old_release_moved"):
        index_source = old_index if old_index.is_file() else root / "releases.json"
        old_checksum = index_asset_checksum(
            index_source, manifest["channel"], manifest["version"]
        )
        old_release = rollback / "release.old"
        final_dir = root / manifest["channel"] / f"v{manifest['version']}"
        if old_release.exists():
            validate_release_directory(old_release, old_checksum)
        elif final_dir.exists():
            validate_release_directory(final_dir, old_checksum)
        else:
            fail("旧版本资产备份缺失，拒绝恢复")
    return owner, state


@locked_root_command
def command_can_rollback(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    bundle = stage / "bundle"
    tombstone = rollback_tombstone(root, args.release_id)
    if tombstone.is_file():
        validate_completion_record(
            tombstone, bundle, args.release_id, args.publish_token
        )
        return
    validate_rollback_preconditions(
        root, stage, rollback, args.release_id, args.publish_token
    )


@locked_root_command
def command_begin_rollback(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    bundle = stage / "bundle"
    tombstone = rollback_tombstone(root, args.release_id)
    if tombstone.is_file():
        validate_completion_record(
            tombstone, bundle, args.release_id, args.publish_token
        )
        return
    owner, _state = validate_rollback_preconditions(
        root, stage, rollback, args.release_id, args.publish_token
    )
    if owner.get("phase") != "rolling-back":
        updated = dict(owner)
        updated["rollback_from_phase"] = owner.get("phase")
        updated["phase"] = "rolling-back"
        write_json(owner_path(root), updated)


@locked_root_command
def command_rollback(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    bundle = stage / "bundle"
    tombstone = rollback_tombstone(root, args.release_id)
    if tombstone.is_file():
        validate_completion_record(
            tombstone, bundle, args.release_id, args.publish_token
        )
        shutil.rmtree(rollback, ignore_errors=True)
        if owner_path(root).exists():
            owner = require_release_owner(root, bundle, args.release_id)
            if rollback_phase(owner) in {"publishing", "committed"}:
                require_publish_token(owner, args.publish_token)
            owner_path(root).unlink()
        return
    owner, state = validate_rollback_preconditions(
        root, stage, rollback, args.release_id, args.publish_token
    )
    state_path = rollback / "state.json"
    if state is None:
        write_json(
            tombstone,
            completion_record(bundle, args.release_id, args.publish_token),
        )
        shutil.rmtree(rollback, ignore_errors=True)
        owner_path(root).unlink()
        return
    manifest = validate_manifest(stage / "bundle")
    current_generation = current_index_generation(root)
    allowed_generations = {
        state.get("base_index_generation"),
        state.get("target_index_generation"),
    }
    if current_generation not in allowed_generations:
        fail("公开索引已进入其他代际，拒绝旧事务回滚")
    install_path = root / INSTALL_NAME
    current_install_generation = file_generation(install_path)
    allowed_install_generations = {
        state.get("base_install_generation"),
        state.get("target_install_generation"),
    }
    if current_install_generation not in allowed_install_generations:
        fail("安装入口已进入其他代际，拒绝旧事务回滚")
    old_index = rollback / "releases.json.old"
    if state.get("base_index_generation") != "absent":
        if not old_index.is_file() and current_generation == state.get("base_index_generation"):
            copy_file_atomic(root / "releases.json", old_index)
        if not old_index.is_file() or sha256(old_index) != state.get("base_index_generation"):
            fail("索引回滚备份缺失或不完整，拒绝恢复")
    old_install = rollback / "install.ps1.old"
    if state.get("base_install_generation") != "absent":
        if (
            not old_install.is_file()
            and current_install_generation == state.get("base_install_generation")
        ):
            copy_file_atomic(install_path, old_install)
        if (
            not old_install.is_file()
            or sha256(old_install) != state.get("base_install_generation")
        ):
            fail("安装入口回滚备份缺失或不完整，拒绝恢复")
    final_dir = root / manifest["channel"] / f"v{manifest['version']}"
    old_release = rollback / "release.old"
    old_release_checksum = ""
    if state.get("old_release_moved"):
        old_release_checksum = index_asset_checksum(
            old_index, manifest["channel"], manifest["version"]
        )
        if not old_release.exists() and final_dir.exists():
            validate_release_directory(final_dir, old_release_checksum)
            shutil.copytree(final_dir, old_release)
        validate_release_directory(old_release, old_release_checksum)
        restore_tmp = rollback / "release.restore.tmp"
        shutil.rmtree(restore_tmp, ignore_errors=True)
        shutil.copytree(old_release, restore_tmp)
        validate_release_directory(restore_tmp, old_release_checksum)
        if final_dir.exists():
            shutil.rmtree(final_dir)
        final_dir.parent.mkdir(parents=True, exist_ok=True)
        os.replace(restore_tmp, final_dir)
    elif state.get("release_started") and final_dir.exists():
        shutil.rmtree(final_dir)
    index_path = root / "releases.json"
    if old_index.exists():
        copy_file_atomic(old_index, index_path)
    elif state.get("base_index_generation") == "absent" and state.get("release_started") and index_path.exists():
        index_path.unlink()
    if old_install.exists():
        copy_file_atomic(old_install, install_path)
    elif state.get("base_install_generation") == "absent" and state.get("release_started") and install_path.exists():
        install_path.unlink()
    if current_index_generation(root) != state.get("base_index_generation"):
        fail("回滚后索引代际未恢复")
    if file_generation(install_path) != state.get("base_install_generation"):
        fail("回滚后安装入口代际未恢复")
    if state.get("old_release_moved"):
        validate_release_directory(final_dir, old_release_checksum)
    write_json(
        tombstone,
        completion_record(bundle, args.release_id, args.publish_token),
    )
    shutil.rmtree(rollback, ignore_errors=True)
    owner_path(root).unlink()


@locked_root_command
def command_cleanup(args: argparse.Namespace) -> None:
    root, stage, rollback = release_paths(args.root, args.bundle, args.release_id)
    owner = require_release_owner(root, stage / "bundle", args.release_id)
    if owner.get("phase") != "verified":
        fail("发布尚未完成全节点验收，禁止 cleanup")
    require_publish_token(owner, args.publish_token)
    manifest = validate_manifest(stage / "bundle")
    command_prune(argparse.Namespace(root=str(root), channel=manifest["channel"]))
    shutil.rmtree(rollback, ignore_errors=True)
    tombstone = cleanup_tombstone(root, args.release_id)
    write_json(
        tombstone,
        completion_record(stage / "bundle", args.release_id, args.publish_token),
    )
    owner_path(root).unlink()


@locked_root_command
def command_complete_cleanup(args: argparse.Namespace) -> None:
    root, stage, _rollback = release_paths(args.root, args.bundle, args.release_id)
    tombstone = cleanup_tombstone(root, args.release_id)
    if owner_path(root).exists():
        fail("cleanup owner 尚未释放")
    if not tombstone.is_file():
        fail("cleanup 完成标记缺失")
    validate_completion_values(
        tombstone,
        args.release_id,
        args.manifest_sha256,
        args.publish_token,
    )
    shutil.rmtree(stage, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    run_locked = sub.add_parser("run-locked")
    run_locked.add_argument("--lock-path", required=True)
    run_locked.add_argument("command", nargs=argparse.REMAINDER)
    run_locked.set_defaults(func=command_run_locked)
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
    acquire_lock = sub.add_parser("acquire-lock")
    acquire_lock.add_argument("--root", required=True)
    acquire_lock.add_argument("--bundle", required=True)
    acquire_lock.add_argument("--release-id", required=True)
    acquire_lock.set_defaults(func=command_acquire_lock)
    assert_lock = sub.add_parser("assert-lock")
    assert_lock.add_argument("--root", required=True)
    assert_lock.add_argument("--bundle", required=True)
    assert_lock.add_argument("--release-id", required=True)
    assert_lock.add_argument("--publish-token", default="")
    assert_lock.set_defaults(func=command_assert_lock)
    release_lock = sub.add_parser("release-lock")
    release_lock.add_argument("--root", required=True)
    release_lock.add_argument("--bundle", required=True)
    release_lock.add_argument("--release-id", required=True)
    release_lock.set_defaults(func=command_release_lock)
    next_index = sub.add_parser("next-index")
    next_index.add_argument("--root", required=True)
    next_index.add_argument("--bundle", required=True)
    next_index.add_argument("--output", required=True)
    next_index.add_argument("--release-id", required=True)
    next_index.set_defaults(func=command_next_index)
    begin_publish = sub.add_parser("begin-publish")
    begin_publish.add_argument("--root", required=True)
    begin_publish.add_argument("--bundle", required=True)
    begin_publish.add_argument("--release-id", required=True)
    begin_publish.add_argument("--publish-token", required=True)
    begin_publish.set_defaults(func=command_begin_publish)
    promote_stage = sub.add_parser("promote-stage")
    promote_stage.add_argument("--root", required=True)
    promote_stage.add_argument("--incoming-bundle", required=True)
    promote_stage.add_argument("--release-id", required=True)
    promote_stage.set_defaults(func=command_promote_stage)
    verify_release = sub.add_parser("verify-release")
    verify_release.add_argument("--root", required=True)
    verify_release.add_argument("--bundle", required=True)
    verify_release.set_defaults(func=command_verify_release)
    mark_verified = sub.add_parser("mark-verified")
    mark_verified.add_argument("--root", required=True)
    mark_verified.add_argument("--bundle", required=True)
    mark_verified.add_argument("--release-id", required=True)
    mark_verified.add_argument("--publish-token", required=True)
    mark_verified.set_defaults(func=command_mark_verified)
    prune = sub.add_parser("prune")
    prune.add_argument("--root", required=True)
    prune.add_argument("--channel", required=True)
    prune.set_defaults(func=command_prune_cli)
    commit = sub.add_parser("commit-release")
    commit.add_argument("--root", required=True)
    commit.add_argument("--bundle", required=True)
    commit.add_argument("--next-index", required=True)
    commit.add_argument("--release-id", required=True)
    commit.add_argument("--publish-token", required=True)
    commit.set_defaults(func=command_commit)
    rollback = sub.add_parser("rollback-release")
    rollback.add_argument("--root", required=True)
    rollback.add_argument("--bundle", required=True)
    rollback.add_argument("--release-id", required=True)
    rollback.add_argument("--publish-token", default="")
    rollback.set_defaults(func=command_rollback)
    can_rollback = sub.add_parser("can-rollback")
    can_rollback.add_argument("--root", required=True)
    can_rollback.add_argument("--bundle", required=True)
    can_rollback.add_argument("--release-id", required=True)
    can_rollback.add_argument("--publish-token", default="")
    can_rollback.set_defaults(func=command_can_rollback)
    begin_rollback = sub.add_parser("begin-rollback")
    begin_rollback.add_argument("--root", required=True)
    begin_rollback.add_argument("--bundle", required=True)
    begin_rollback.add_argument("--release-id", required=True)
    begin_rollback.add_argument("--publish-token", default="")
    begin_rollback.set_defaults(func=command_begin_rollback)
    cleanup = sub.add_parser("cleanup-release")
    cleanup.add_argument("--root", required=True)
    cleanup.add_argument("--bundle", required=True)
    cleanup.add_argument("--release-id", required=True)
    cleanup.add_argument("--publish-token", required=True)
    cleanup.set_defaults(func=command_cleanup)
    complete_cleanup = sub.add_parser("complete-cleanup")
    complete_cleanup.add_argument("--root", required=True)
    complete_cleanup.add_argument("--bundle", required=True)
    complete_cleanup.add_argument("--release-id", required=True)
    complete_cleanup.add_argument("--publish-token", required=True)
    complete_cleanup.add_argument("--manifest-sha256", required=True)
    complete_cleanup.set_defaults(func=command_complete_cleanup)
    return result


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
