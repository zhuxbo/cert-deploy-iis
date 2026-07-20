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
    "$PYTHON_BIN" "$HELPER" acquire-lock --root "$root" --bundle "$stage/bundle" --release-id "$release_id"
    "$PYTHON_BIN" "$HELPER" next-index --root "$root" --bundle "$stage/bundle" --output "$stage/releases.json.next" --release-id "$release_id"
}

restrict_config_permissions() {
    local path="$1" powershell_path win_path
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            command -v cygpath >/dev/null 2>&1 || { echo "Windows 测试缺少 cygpath" >&2; exit 1; }
            if command -v powershell.exe >/dev/null 2>&1; then
                powershell_path="powershell.exe"
            elif command -v powershell >/dev/null 2>&1; then
                powershell_path="powershell"
            else
                echo "Windows 测试缺少 PowerShell" >&2
                exit 1
            fi
            win_path="$(cygpath -w "$path")"
            SSLCTLW_CONFIG_FILE="$win_path" MSYS_NO_PATHCONV=1 "$powershell_path" \
                -NoProfile -NonInteractive -Command \
                '$file = Get-Item -LiteralPath $env:SSLCTLW_CONFIG_FILE -ErrorAction Stop; $acl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); $acl.SetAccessRuleProtection($true, $false); foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }; $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent(); $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow); [void]$acl.AddAccessRule($rule); $file.SetAccessControl($acl)'
            ;;
        *) chmod 600 "$path" ;;
    esac
}

weaken_config_permissions() {
    local path="$1" powershell_path win_path
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)
            if command -v powershell.exe >/dev/null 2>&1; then
                powershell_path="powershell.exe"
            else
                powershell_path="powershell"
            fi
            win_path="$(cygpath -w "$path")"
            SSLCTLW_CONFIG_FILE="$win_path" MSYS_NO_PATHCONV=1 "$powershell_path" \
                -NoProfile -NonInteractive -Command \
                '$file = Get-Item -LiteralPath $env:SSLCTLW_CONFIG_FILE -ErrorAction Stop; $acl = $file.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access); $everyone = [System.Security.Principal.SecurityIdentifier]::new("S-1-1-0"); $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($everyone, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow); [void]$acl.AddAccessRule($rule); $file.SetAccessControl($acl)'
            ;;
        *) chmod 644 "$path" ;;
    esac
}

REMOTE_ROOT="$TEST_ROOT/remote"
mkdir -p "$REMOTE_ROOT"

MAIN_BUNDLE="$TEST_ROOT/main-bundle"
make_bundle "$MAIN_BUNDLE" 1.2.3 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa false main-v1
stage_bundle "$REMOTE_ROOT" "$MAIN_BUNDLE" main-release
"$PYTHON_BIN" "$HELPER" begin-publish --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --next-index "$REMOTE_ROOT/.staging/main-release/releases.json.next" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
INDEX_MODE="$(stat -c '%a' "$REMOTE_ROOT/releases.json" 2>/dev/null || stat -f '%Lp' "$REMOTE_ROOT/releases.json")"
[ "$INDEX_MODE" = "644" ] || { echo "公开 releases.json 权限不是 644: $INDEX_MODE" >&2; exit 1; }
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle"
"$PYTHON_BIN" "$HELPER" mark-verified --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
if "$PYTHON_BIN" "$HELPER" rollback-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>/dev/null; then
    echo "已验收发布仍可被其他协调器回滚" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle"
"$PYTHON_BIN" "$HELPER" cleanup-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MAIN_MANIFEST_SHA="$("$PYTHON_BIN" "$HELPER" sha256-file --path "$MAIN_BUNDLE/manifest.json")"
"$PYTHON_BIN" "$HELPER" complete-cleanup --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/main-release/bundle" --release-id main-release --publish-token aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --manifest-sha256 "$MAIN_MANIFEST_SHA"
"$PYTHON_BIN" "$HELPER" acquire-lock --root "$REMOTE_ROOT" --bundle "$MAIN_BUNDLE" --release-id main-check
if "$PYTHON_BIN" "$HELPER" next-index --root "$REMOTE_ROOT" --bundle "$MAIN_BUNDLE" --output "$TEST_ROOT/forbidden.json" --release-id main-check 2>/dev/null; then
    echo "main 同版本覆盖未被拒绝" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" release-lock --root "$REMOTE_ROOT" --bundle "$MAIN_BUNDLE" --release-id main-check
LOWER_MAIN="$TEST_ROOT/lower-main"
make_bundle "$LOWER_MAIN" 1.2.2 dddddddddddddddddddddddddddddddddddddddd false lower-main
"$PYTHON_BIN" "$HELPER" acquire-lock --root "$REMOTE_ROOT" --bundle "$LOWER_MAIN" --release-id lower-check
if "$PYTHON_BIN" "$HELPER" next-index --root "$REMOTE_ROOT" --bundle "$LOWER_MAIN" --output "$TEST_ROOT/lower-forbidden.json" --release-id lower-check 2>/dev/null; then
    echo "低于 main.latest 的正式版本未被拒绝" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" release-lock --root "$REMOTE_ROOT" --bundle "$LOWER_MAIN" --release-id lower-check
if "$PYTHON_BIN" "$HELPER" validate-version 1.2.3+build.1 >/dev/null 2>&1; then
    echo "带 build metadata 的版本未被拒绝" >&2
    exit 1
fi

DEV_OLD="$TEST_ROOT/dev-old"
make_bundle "$DEV_OLD" 1.3.0-rc.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb true dev-old
stage_bundle "$REMOTE_ROOT" "$DEV_OLD" dev-old-release
"$PYTHON_BIN" "$HELPER" begin-publish --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --release-id dev-old-release --publish-token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --next-index "$REMOTE_ROOT/.staging/dev-old-release/releases.json.next" --release-id dev-old-release --publish-token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle"
"$PYTHON_BIN" "$HELPER" mark-verified --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --release-id dev-old-release --publish-token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"$PYTHON_BIN" "$HELPER" cleanup-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --release-id dev-old-release --publish-token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
DEV_OLD_MANIFEST_SHA="$("$PYTHON_BIN" "$HELPER" sha256-file --path "$DEV_OLD/manifest.json")"
"$PYTHON_BIN" "$HELPER" complete-cleanup --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-old-release/bundle" --release-id dev-old-release --publish-token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --manifest-sha256 "$DEV_OLD_MANIFEST_SHA"

DEV_NEW="$TEST_ROOT/dev-new"
make_bundle "$DEV_NEW" 1.3.0-rc.1 cccccccccccccccccccccccccccccccccccccccc true dev-new
stage_bundle "$REMOTE_ROOT" "$DEV_NEW" dev-new-release
if "$PYTHON_BIN" "$HELPER" acquire-lock --root "$REMOTE_ROOT" --bundle "$DEV_NEW" --release-id conflicting-release 2>/dev/null; then
    echo "并发发布未被发布根锁拒绝" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" begin-publish --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --release-id dev-new-release --publish-token cccccccccccccccccccccccccccccccc
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --next-index "$REMOTE_ROOT/.staging/dev-new-release/releases.json.next" --release-id dev-new-release --publish-token cccccccccccccccccccccccccccccccc
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle"
if "$PYTHON_BIN" "$HELPER" begin-publish --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --release-id dev-new-release --publish-token 22222222222222222222222222222222 2>/dev/null; then
    echo "第二协调器 publish token 未被拒绝" >&2
    exit 1
fi
if "$PYTHON_BIN" "$HELPER" rollback-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --release-id dev-new-release --publish-token 22222222222222222222222222222222 2>/dev/null; then
    echo "第二协调器可以回滚其他 publish attempt" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle"
rm -rf "$REMOTE_ROOT/dev/v1.3.0-rc.1"
mv "$REMOTE_ROOT/.rollback/dev-new-release/release.old" "$REMOTE_ROOT/dev/v1.3.0-rc.1"
"$PYTHON_BIN" "$HELPER" rollback-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-release/bundle" --release-id dev-new-release --publish-token cccccccccccccccccccccccccccccccc
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$DEV_OLD"

stage_bundle "$REMOTE_ROOT" "$DEV_NEW" dev-new-final-release
"$PYTHON_BIN" "$HELPER" begin-publish --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-final-release/bundle" --release-id dev-new-final-release --publish-token 33333333333333333333333333333333
"$PYTHON_BIN" "$HELPER" commit-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-final-release/bundle" --next-index "$REMOTE_ROOT/.staging/dev-new-final-release/releases.json.next" --release-id dev-new-final-release --publish-token 33333333333333333333333333333333
rm -rf "$REMOTE_ROOT/dev/v1.3.0-rc.1"
mv "$REMOTE_ROOT/.rollback/dev-new-final-release/release.old" "$REMOTE_ROOT/dev/v1.3.0-rc.1"
cp "$REMOTE_ROOT/.rollback/dev-new-final-release/releases.json.old" "$REMOTE_ROOT/releases.json"
cp "$REMOTE_ROOT/.rollback/dev-new-final-release/install.ps1.old" "$REMOTE_ROOT/install.ps1"
ROLLBACK_MANIFEST_SHA="$("$PYTHON_BIN" "$HELPER" sha256-file --path "$REMOTE_ROOT/.staging/dev-new-final-release/bundle/manifest.json")"
printf '{"schema_version":1,"release_id":"dev-new-final-release","manifest_sha256":"%s","publish_token":"33333333333333333333333333333333"}\n' "$ROLLBACK_MANIFEST_SHA" >"$REMOTE_ROOT/.rollback-complete.dev-new-final-release.json"
rm -rf "$REMOTE_ROOT/.rollback/dev-new-final-release"
"$PYTHON_BIN" "$HELPER" rollback-release --root "$REMOTE_ROOT" --bundle "$REMOTE_ROOT/.staging/dev-new-final-release/bundle" --release-id dev-new-final-release --publish-token 33333333333333333333333333333333
[ ! -e "$REMOTE_ROOT/.release-owner.json" ] && [ -e "$REMOTE_ROOT/.rollback-complete.dev-new-final-release.json" ] || {
    echo "rollback 完成窗口重试未保留完成标记" >&2
    exit 1
}
"$PYTHON_BIN" "$HELPER" verify-release --root "$REMOTE_ROOT" --bundle "$DEV_OLD"

CAS_ROOT="$TEST_ROOT/cas-remote"
mkdir -p "$CAS_ROOT"
CAS_BUNDLE="$TEST_ROOT/cas-bundle"
make_bundle "$CAS_BUNDLE" 2.0.0-rc.1 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee true cas
stage_bundle "$CAS_ROOT" "$CAS_BUNDLE" cas-release
printf '{"dev":{"latest":"external","versions":[]}}\n' >"$CAS_ROOT/releases.json"
"$PYTHON_BIN" "$HELPER" begin-publish --root "$CAS_ROOT" --bundle "$CAS_ROOT/.staging/cas-release/bundle" --release-id cas-release --publish-token dddddddddddddddddddddddddddddddd
if "$PYTHON_BIN" "$HELPER" commit-release --root "$CAS_ROOT" --bundle "$CAS_ROOT/.staging/cas-release/bundle" --next-index "$CAS_ROOT/.staging/cas-release/releases.json.next" --release-id cas-release --publish-token dddddddddddddddddddddddddddddddd 2>/dev/null; then
    echo "索引基线漂移未被拒绝" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" rollback-release --root "$CAS_ROOT" --bundle "$CAS_ROOT/.staging/cas-release/bundle" --release-id cas-release --publish-token dddddddddddddddddddddddddddddddd

STALE_ROOT="$TEST_ROOT/stale-rollback-remote"
mkdir -p "$STALE_ROOT"
STALE_BUNDLE="$TEST_ROOT/stale-rollback-bundle"
make_bundle "$STALE_BUNDLE" 2.1.0-rc.1 3333333333333333333333333333333333333333 true stale
stage_bundle "$STALE_ROOT" "$STALE_BUNDLE" stale-release
"$PYTHON_BIN" "$HELPER" begin-publish --root "$STALE_ROOT" --bundle "$STALE_ROOT/.staging/stale-release/bundle" --release-id stale-release --publish-token eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
"$PYTHON_BIN" "$HELPER" commit-release --root "$STALE_ROOT" --bundle "$STALE_ROOT/.staging/stale-release/bundle" --next-index "$STALE_ROOT/.staging/stale-release/releases.json.next" --release-id stale-release --publish-token eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
printf '{"dev":{"latest":"third-generation","versions":[]}}\n' >"$STALE_ROOT/releases.json"
cp "$STALE_ROOT/releases.json" "$TEST_ROOT/third-generation.json"
if "$PYTHON_BIN" "$HELPER" can-rollback --root "$STALE_ROOT" --bundle "$STALE_ROOT/.staging/stale-release/bundle" --release-id stale-release --publish-token eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 2>/dev/null; then
    echo "回滚预检未拒绝第三代索引" >&2
    exit 1
fi
if "$PYTHON_BIN" "$HELPER" rollback-release --root "$STALE_ROOT" --bundle "$STALE_ROOT/.staging/stale-release/bundle" --release-id stale-release --publish-token eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee 2>/dev/null; then
    echo "旧事务回滚覆盖了第三代索引" >&2
    exit 1
fi
cmp -s "$STALE_ROOT/releases.json" "$TEST_ROOT/third-generation.json" || {
    echo "拒绝旧回滚后第三代索引仍被修改" >&2
    exit 1
}

PHASE_ROOT="$TEST_ROOT/phase-remote"
mkdir -p "$PHASE_ROOT"
printf '{}\n' >"$PHASE_ROOT/releases.json"
PHASE_BUNDLE="$TEST_ROOT/phase-bundle"
make_bundle "$PHASE_BUNDLE" 2.2.0-rc.1 4444444444444444444444444444444444444444 true phase
stage_bundle "$PHASE_ROOT" "$PHASE_BUNDLE" phase-release
if "$PYTHON_BIN" "$HELPER" cleanup-release --root "$PHASE_ROOT" --bundle "$PHASE_ROOT/.staging/phase-release/bundle" --release-id phase-release --publish-token ffffffffffffffffffffffffffffffff 2>/dev/null; then
    echo "未验收发布允许 cleanup" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" rollback-release --root "$PHASE_ROOT" --bundle "$PHASE_ROOT/.staging/phase-release/bundle" --release-id phase-release

MISSING_STATE_ROOT="$TEST_ROOT/missing-state-remote"
mkdir -p "$MISSING_STATE_ROOT"
MISSING_STATE_BUNDLE="$TEST_ROOT/missing-state-bundle"
make_bundle "$MISSING_STATE_BUNDLE" 2.3.0-rc.1 7777777777777777777777777777777777777777 true missing-state
stage_bundle "$MISSING_STATE_ROOT" "$MISSING_STATE_BUNDLE" missing-state-release
"$PYTHON_BIN" "$HELPER" begin-publish --root "$MISSING_STATE_ROOT" --bundle "$MISSING_STATE_ROOT/.staging/missing-state-release/bundle" --release-id missing-state-release --publish-token 11111111111111111111111111111111
"$PYTHON_BIN" "$HELPER" commit-release --root "$MISSING_STATE_ROOT" --bundle "$MISSING_STATE_ROOT/.staging/missing-state-release/bundle" --next-index "$MISSING_STATE_ROOT/.staging/missing-state-release/releases.json.next" --release-id missing-state-release --publish-token 11111111111111111111111111111111
mv "$MISSING_STATE_ROOT/.rollback/missing-state-release/state.json" "$TEST_ROOT/missing-state.json"
if "$PYTHON_BIN" "$HELPER" rollback-release --root "$MISSING_STATE_ROOT" --bundle "$MISSING_STATE_ROOT/.staging/missing-state-release/bundle" --release-id missing-state-release --publish-token 11111111111111111111111111111111 2>/dev/null; then
    echo "公开阶段缺失 state.json 时 rollback 假成功" >&2
    exit 1
fi
[ -f "$MISSING_STATE_ROOT/.release-owner.json" ] && [ -d "$MISSING_STATE_ROOT/dev/v2.3.0-rc.1" ] || {
    echo "拒绝缺失状态回滚后仍破坏了 owner 或公开资产" >&2
    exit 1
}

COORDINATOR_ROOT="$TEST_ROOT/coordinator"
mkdir -p "$COORDINATOR_ROOT/build" "$COORDINATOR_ROOT/mock-bin" "$COORDINATOR_ROOT/node1" "$COORDINATOR_ROOT/node2"
cp "$SCRIPT_DIR/release.sh" "$SCRIPT_DIR/release-helper.py" "$SCRIPT_DIR/install.ps1" "$COORDINATOR_ROOT/build/"
printf 'key\n' >"$COORDINATOR_ROOT/key"

cat >"$COORDINATOR_ROOT/build/sign.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "--verify" ] || { echo "测试中禁止真实签名" >&2; exit 1; }
[ -f "${2:-}" ]
EOF

cat >"$COORDINATOR_ROOT/mock-bin/ssh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
command_arg="${!#}"
host=""
for arg in "$@"; do
    case "$arg" in
        *@*) host="${arg#*@}" ;;
    esac
done
if [ -n "${MOCK_FAIL_HOST:-}" ] && [ "$host" = "$MOCK_FAIL_HOST" ] && [[ "$command_arg" == *"${MOCK_FAIL_PATTERN:-__never__}"* ]]; then
    exit 55
fi
if [ -n "${MOCK_FAIL_HOST_2:-}" ] && [ "$host" = "$MOCK_FAIL_HOST_2" ] && [[ "$command_arg" == *"${MOCK_FAIL_PATTERN_2:-__never__}"* ]]; then
    exit 56
fi
if [ -n "${MOCK_PROMOTE_FAIL_HOST:-}" ] && [ "$host" = "$MOCK_PROMOTE_FAIL_HOST" ] && [[ "$command_arg" == *"promote-stage"* ]]; then
    promote_only="${command_arg%% && rmdir*}"
    bash -c "$promote_only"
    exit 56
fi
bash -c "$command_arg"
EOF

cat >"$COORDINATOR_ROOT/mock-bin/scp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
source_path="${args[${#args[@]}-2]}"
remote_path="${args[${#args[@]}-1]}"
destination="${remote_path#*:}"
cp "$source_path" "$destination"
EOF
chmod +x "$COORDINATOR_ROOT/build/sign.sh" "$COORDINATOR_ROOT/mock-bin/ssh" "$COORDINATOR_ROOT/mock-bin/scp"

cat >"$COORDINATOR_ROOT/build/release.conf" <<EOF
SSH_USER="test"
SSH_KEY="$COORDINATOR_ROOT/key"
SERVERS=(
  "node1,node1,22,$COORDINATOR_ROOT/node1,https://node1.invalid"
  "node2,node2,22,$COORDINATOR_ROOT/node2,https://node2.invalid"
)
EOF
restrict_config_permissions "$COORDINATOR_ROOT/build/release.conf"

coordinator_bundle() {
    local name="$1" version="$2" commit="$3" content="$4"
    local bundle="$COORDINATOR_ROOT/$name"
    make_bundle "$bundle" "$version" "$commit" true "$content"
    printf '%s\n' "$bundle"
}

STAGE_FAIL_BUNDLE="$(coordinator_bundle stage-fail 2.7.0-rc.1 8888888888888888888888888888888888888888 stage-fail)"
if MOCK_FAIL_HOST=node2 MOCK_FAIL_PATTERN=acquire-lock PATH="$COORDINATOR_ROOT/mock-bin:$PATH" \
    bash "$COORDINATOR_ROOT/build/release.sh" stage "$STAGE_FAIL_BUNDLE"; then
    echo "第二节点 stage 失败未返回非零" >&2
    exit 1
fi
[ ! -e "$COORDINATOR_ROOT/node1/.release-owner.json" ] && [ ! -e "$COORDINATOR_ROOT/node2/.release-owner.json" ] || {
    echo "stage 部分失败后未释放已取得的发布根锁" >&2
    exit 1
}

PROMOTE_FAIL_BUNDLE="$(coordinator_bundle promote-fail 2.7.1-rc.1 abababababababababababababababababababab promote-fail)"
if MOCK_PROMOTE_FAIL_HOST=node1 PATH="$COORDINATOR_ROOT/mock-bin:$PATH" \
    bash "$COORDINATOR_ROOT/build/release.sh" stage "$PROMOTE_FAIL_BUNDLE"; then
    echo "promote 后故障未使 stage 返回非零" >&2
    exit 1
fi
[ ! -e "$COORDINATOR_ROOT/node1/.release-owner.json" ] || {
    echo "promote 后故障遗留发布根锁" >&2
    exit 1
}

printf '{"dev":{"latest":"2.6.0-rc.1","versions":[{"version":"2.6.0-rc.1"}]}}\n' >"$COORDINATOR_ROOT/node1/releases.json"
DRIFT_BUNDLE="$(coordinator_bundle drift 2.8.0-rc.1 9999999999999999999999999999999999999999 drift)"
if PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$DRIFT_BUNDLE"; then
    echo "节点初始索引漂移未被 stage 拒绝" >&2
    exit 1
fi
[ ! -e "$COORDINATOR_ROOT/node1/.release-owner.json" ] && [ ! -e "$COORDINATOR_ROOT/node2/.release-owner.json" ] || {
    echo "索引漂移失败后未释放发布根锁" >&2
    exit 1
}
rm -f "$COORDINATOR_ROOT/node1/releases.json"

CONFLICT_A="$COORDINATOR_ROOT/conflict-a/shared-release"
CONFLICT_B="$COORDINATOR_ROOT/conflict-b/shared-release"
make_bundle "$CONFLICT_A" 2.9.0-rc.1 5555555555555555555555555555555555555555 true conflict-a
make_bundle "$CONFLICT_B" 2.9.0-rc.1 6666666666666666666666666666666666666666 true conflict-b
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$CONFLICT_A"
cp "$COORDINATOR_ROOT/node1/.staging/shared-release/bundle/manifest.json" "$TEST_ROOT/original-staged-manifest.json"
if PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$CONFLICT_B"; then
    echo "同 release ID 的不同 bundle 未被拒绝" >&2
    exit 1
fi
cmp -s "$COORDINATOR_ROOT/node1/.staging/shared-release/bundle/manifest.json" "$TEST_ROOT/original-staged-manifest.json" || {
    echo "冲突 stage 破坏了原暂存 bundle" >&2
    exit 1
}
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" rollback "$CONFLICT_A"

OLD_COORDINATOR_BUNDLE="$(coordinator_bundle old 3.0.0-rc.1 ffffffffffffffffffffffffffffffffffffffff old)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$OLD_COORDINATOR_BUNDLE"
[ ! -e "$COORDINATOR_ROOT/node1/releases.json" ] && [ ! -e "$COORDINATOR_ROOT/node2/releases.json" ] || {
    echo "stage 提前修改了公开索引" >&2
    exit 1
}
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" publish "$OLD_COORDINATOR_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" verify "$OLD_COORDINATOR_BUNDLE"
cmp -s "$COORDINATOR_ROOT/node1/releases.json" "$COORDINATOR_ROOT/node2/releases.json" || {
    echo "成功发布后节点索引不一致" >&2
    exit 1
}
[ -d "$OLD_COORDINATOR_BUNDLE" ] || { echo "发布后本地 bundle 被删除" >&2; exit 1; }
OLD_PUBLISH_TOKEN="$(tr -d '\r\n' <"$OLD_COORDINATOR_BUNDLE/.publish-token")"
"$PYTHON_BIN" "$COORDINATOR_ROOT/node1/.staging/old/release-helper.py" cleanup-release \
    --root "$COORDINATOR_ROOT/node1" --bundle "$COORDINATOR_ROOT/node1/.staging/old/bundle" \
    --release-id old --publish-token "$OLD_PUBLISH_TOKEN"
if MOCK_FAIL_HOST=node2 MOCK_FAIL_PATTERN=cleanup-release PATH="$COORDINATOR_ROOT/mock-bin:$PATH" \
    bash "$COORDINATOR_ROOT/build/release.sh" cleanup "$OLD_COORDINATOR_BUNDLE"; then
    echo "部分节点 cleanup 失败未返回非零" >&2
    exit 1
fi
[ ! -e "$COORDINATOR_ROOT/node1/.staging/old" ] && [ -f "$COORDINATOR_ROOT/node1/.cleanup-complete.old.json" ] || {
    echo "cleanup 最终窗口未保留独立于 stage 的完成标记" >&2
    exit 1
}
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" cleanup "$OLD_COORDINATOR_BUNDLE"
[ ! -e "$COORDINATOR_ROOT/node1/.release-owner.json" ] && [ ! -e "$COORDINATOR_ROOT/node2/.release-owner.json" ] || {
    echo "cleanup 未释放发布根锁" >&2
    exit 1
}

NEW_COORDINATOR_BUNDLE="$(coordinator_bundle new 3.0.0-rc.1 1111111111111111111111111111111111111111 new)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$NEW_COORDINATOR_BUNDLE"
if MOCK_FAIL_HOST=node2 MOCK_FAIL_PATTERN=commit-release PATH="$COORDINATOR_ROOT/mock-bin:$PATH" \
    bash "$COORDINATOR_ROOT/build/release.sh" publish "$NEW_COORDINATOR_BUNDLE"; then
    echo "第二节点提升失败未使 publish 返回非零" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node1" --bundle "$OLD_COORDINATOR_BUNDLE"
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node2" --bundle "$OLD_COORDINATOR_BUNDLE"
[ -d "$NEW_COORDINATOR_BUNDLE" ] || { echo "失败后本地 bundle 被删除" >&2; exit 1; }

RETRY_ROLLBACK_BUNDLE="$(coordinator_bundle retry-rollback 3.0.0-rc.2 1212121212121212121212121212121212121212 retry-rollback)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$RETRY_ROLLBACK_BUNDLE"
if MOCK_FAIL_HOST=node2 MOCK_FAIL_PATTERN=commit-release \
    MOCK_FAIL_HOST_2=node2 MOCK_FAIL_PATTERN_2=rollback-release \
    PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" publish "$RETRY_ROLLBACK_BUNDLE"; then
    echo "部分回滚失败未返回非零" >&2
    exit 1
fi
[ -f "$COORDINATOR_ROOT/node1/.rollback-complete.retry-rollback.json" ] || {
    echo "已回滚节点未保留完成标记" >&2
    exit 1
}
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" rollback "$RETRY_ROLLBACK_BUNDLE"
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node1" --bundle "$OLD_COORDINATOR_BUNDLE"
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node2" --bundle "$OLD_COORDINATOR_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$RETRY_ROLLBACK_BUNDLE"
if MOCK_FAIL_HOST=node2 MOCK_FAIL_PATTERN=commit-release \
    PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" publish "$RETRY_ROLLBACK_BUNDLE"; then
    echo "同 bundle 新 attempt 的第二次失败未返回非零" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node1" --bundle "$OLD_COORDINATOR_BUNDLE"
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node2" --bundle "$OLD_COORDINATOR_BUNDLE"

HASH_FAIL_BUNDLE="$(coordinator_bundle hash-fail 3.0.1-rc.1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa hash-fail)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$HASH_FAIL_BUNDLE"
if MOCK_FAIL_HOST=node1 MOCK_FAIL_PATTERN="/node1/releases.json'" PATH="$COORDINATOR_ROOT/mock-bin:$PATH" \
    bash "$COORDINATOR_ROOT/build/release.sh" publish "$HASH_FAIL_BUNDLE"; then
    echo "节点索引哈希读取失败被误报成功" >&2
    exit 1
fi
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node1" --bundle "$OLD_COORDINATOR_BUNDLE"
"$PYTHON_BIN" "$HELPER" verify-release --root "$COORDINATOR_ROOT/node2" --bundle "$OLD_COORDINATOR_BUNDLE"

RESUME_BUNDLE="$(coordinator_bundle resume 3.0.2-rc.1 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb resume)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$RESUME_BUNDLE"
RESUME_TOKEN=cccccccccccccccccccccccccccccccc
printf '%s\n' "$RESUME_TOKEN" >"$RESUME_BUNDLE/.publish-token"
restrict_config_permissions "$RESUME_BUNDLE/.publish-token"
for root in "$COORDINATOR_ROOT/node1" "$COORDINATOR_ROOT/node2"; do
    "$PYTHON_BIN" "$HELPER" begin-publish \
        --root "$root" --bundle "$root/.staging/resume/bundle" \
        --release-id resume --publish-token "$RESUME_TOKEN"
done
"$PYTHON_BIN" "$HELPER" commit-release \
    --root "$COORDINATOR_ROOT/node1" --bundle "$COORDINATOR_ROOT/node1/.staging/resume/bundle" \
    --next-index "$COORDINATOR_ROOT/node1/.staging/resume/releases.json.next" \
    --release-id resume --publish-token "$RESUME_TOKEN"
weaken_config_permissions "$RESUME_BUNDLE/.publish-token"
if PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" resume-publish "$RESUME_BUNDLE"; then
    echo "弱权限 publish token 未被拒绝" >&2
    exit 1
fi
restrict_config_permissions "$RESUME_BUNDLE/.publish-token"
if PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" publish "$RESUME_BUNDLE"; then
    echo "中断后普通 publish 绕过了显式恢复入口" >&2
    exit 1
fi
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" resume-publish "$RESUME_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" verify "$RESUME_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" cleanup "$RESUME_BUNDLE"

git -C "$COORDINATOR_ROOT" init -q -b main
git -C "$COORDINATOR_ROOT" config user.name release-test
git -C "$COORDINATOR_ROOT" config user.email release-test@example.invalid
printf 'release test\n' >"$COORDINATOR_ROOT/release-test.txt"
git -C "$COORDINATOR_ROOT" add release-test.txt
git -C "$COORDINATOR_ROOT" commit -q -m test
MAIN_COORDINATOR_COMMIT="$(git -C "$COORDINATOR_ROOT" rev-parse HEAD)"
git init -q --bare "$COORDINATOR_ROOT/origin.git"
git -C "$COORDINATOR_ROOT" remote add origin "$COORDINATOR_ROOT/origin.git"
git -C "$COORDINATOR_ROOT" push -q origin main
git -C "$COORDINATOR_ROOT" tag -a v4.0.0 -m v4.0.0
git -C "$COORDINATOR_ROOT" push -q origin v4.0.0
MAIN_COORDINATOR_BUNDLE="$COORDINATOR_ROOT/main-4.0.0"
make_bundle "$MAIN_COORDINATOR_BUNDLE" 4.0.0 "$MAIN_COORDINATOR_COMMIT" false main
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$MAIN_COORDINATOR_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" publish "$MAIN_COORDINATOR_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" verify "$MAIN_COORDINATOR_BUNDLE"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" cleanup "$MAIN_COORDINATOR_BUNDLE"

MISSING_HELPER_BUNDLE="$(coordinator_bundle missing-helper 3.1.0-rc.1 2222222222222222222222222222222222222222 missing)"
PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" stage "$MISSING_HELPER_BUNDLE"
rm -f "$COORDINATOR_ROOT/node2/.staging/$(basename "$MISSING_HELPER_BUNDLE")/release-helper.py"
if PATH="$COORDINATOR_ROOT/mock-bin:$PATH" bash "$COORDINATOR_ROOT/build/release.sh" rollback "$MISSING_HELPER_BUNDLE"; then
    echo "helper 缺失时 rollback 被误报成功" >&2
    exit 1
fi

echo "release helper tests passed"
