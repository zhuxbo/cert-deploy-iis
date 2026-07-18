#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HELPER="$SCRIPT_DIR/release-helper.py"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN=python
else
    echo "缺少 Python 3" >&2
    exit 1
fi

make_bundle() {
    local path="$1" version="$2" commit="$3" dirty="$4" content="$5"
    mkdir -p "$path"
    printf '%s' "$content" >"$path/sslctlw-windows-amd64.exe"
    printf 'install-%s' "$content" >"$path/install.ps1"
    "$PYTHON_BIN" "$HELPER" create-manifest --bundle "$path" --version "$version" --source-commit "$commit" --dirty "$dirty"
}

stage_bundle() {
    local root="$1" bundle="$2" release_id="$3"
    local stage="$root/.staging/$release_id"
    mkdir -p "$stage/bundle" "$stage/release"
    cp "$bundle/manifest.json" "$bundle/install.ps1" "$bundle/sslctlw-windows-amd64.exe" "$stage/bundle/"
    cp "$bundle/sslctlw-windows-amd64.exe" "$stage/release/"
    cp "$HELPER" "$stage/release-helper.py"
    "$PYTHON_BIN" "$HELPER" next-index --root "$root" --bundle "$stage/bundle" --output "$stage/releases.json.next"
}

REMOTE_ROOT="$TEST_ROOT/remote"
mkdir -p "$REMOTE_ROOT"

MAIN_BUNDLE="$TEST_ROOT/main-bundle"
make_bundle "$MAIN_BUNDLE" 1.2.3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa false main-v1
stage_bundle "$REMOTE_ROOT" "$MAIN_BUNDLE" main-release
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --next-index "$REMOTE_ROOT/.staging/main-release/releases.json.next" --release-id main-release
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle"
"$PYTHON_BIN" "$HELPER" cleanup-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release
if "$PYTHON_BIN" "$HELPER" next-index --root "$REMOTE_ROOT" --bundle "$MAIN_BUNDLE" --output "$TEST_ROOT/forbidden.json" 2>/dev/null; then
    echo "main 同版本覆盖未被拒绝" >&2
    exit 1
fi
LOWER_MAIN="$TEST_ROOT/lower-main"
make_bundle "$LOWER_MAIN" 1.2.2 dddddddddddddddddddddddddddddddddddddddd false lower-main
if "$PYTHON_BIN" "$HELPER" next-index --root "$REMOTE_ROOT" --bundle "$LOWER_MAIN" --output "$TEST_ROOT/lower-forbidden.json" 2>/dev/null; then
    echo "低于 main.latest 的正式版本未被拒绝" >&2
    exit 1
fi
if "$PYTHON_BIN" "$HELPER" validate-version 1.2.3+build.1 >/dev/null 2>&1; then
    echo "带 build metadata 的版本未被拒绝" >&2
    exit 1
fi

DEV_OLD="$TEST_ROOT/dev-old"
make_bundle "$DEV_OLD" 1.3.0-rc.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb true dev-old
stage_bundle "$REMOTE_ROOT" "$DEV_OLD" dev-old-release
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --next-index "$REMOTE_ROOT/.staging/dev-old-release/releases.json.next" --release-id dev-old-release
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle"
"$PYTHON_BIN" "$HELPER" cleanup-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --release-id dev-old-release

DEV_NEW="$TEST_ROOT/dev-new"
make_bundle "$DEV_NEW" 1.3.0-rc.1 cccccccccccccccccccccccccccccccccccccccc true dev-new
stage_bundle "$REMOTE_ROOT" "$DEV_NEW" dev-new-release
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --next-index "$REMOTE_ROOT/.staging/dev-new-release/releases.json.next" --release-id dev-new-release
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle"
"$PYTHON_BIN" "$HELPER" rollback-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --release-id dev-new-release
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$DEV_OLD"

echo "release helper tests passed"
