#!/usr/bin/env bash

# sslctlw release data-plane coordinator.
# Git/PR/tag/GitHub Release orchestration belongs to skills/remote-release.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="$SCRIPT_DIR/release.conf"
HELPER="$SCRIPT_DIR/release-helper.py"
DIST_EXE="$PROJECT_ROOT/dist/sslctlw.exe"
RECOVERY_DIR="$SCRIPT_DIR/recovery"
ASSET_NAME="sslctlw-windows-amd64.exe"

SSH_TIMEOUT=10
SSH_USER=""
SSH_KEY=""
SERVERS=()

VERSION=""
CHANNEL=""
SOURCE_COMMIT=""
DIRTY=""
ASSET_SHA=""
INSTALL_SHA=""
BUNDLE=""
RELEASE_ID=""
PREPARED_BUNDLE=""
PYTHON_BIN=""
LOCKED_SERVERS=("__none__")
PUBLISH_TOKEN=""
MANIFEST_SHA=""

info() { printf '[INFO] %s\n' "$*"; }
ok() { printf '[OK] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
sslctlw 发布数据面

用法:
  build/release.sh --dry-run <version>
  build/release.sh prepare <version>
  build/release.sh stage <bundle-dir>
  build/release.sh publish <bundle-dir>
  build/release.sh resume-publish <bundle-dir>
  build/release.sh verify <bundle-dir>
  build/release.sh rollback <bundle-dir>
  build/release.sh cleanup <bundle-dir>
  build/release.sh dev <prerelease-version>
  build/release.sh test

正式版 Git、PR、tag、GitHub Release 和恢复顺序见 skills/remote-release.md。
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

find_python() {
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_BIN=python3
    elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info < (3, 9))' 2>/dev/null; then
        PYTHON_BIN=python
    else
        die "缺少 Python 3.9+"
    fi
}

validate_version() {
    local output
    output="$("$PYTHON_BIN" "$HELPER" validate-version "$1")" || exit 1
    IFS=$'\t' read -r VERSION CHANNEL <<EOF
$output
EOF
    [ -n "$VERSION" ] && [ -n "$CHANNEL" ] || die "无法解析版本: $1"
}

validate_bundle() {
    BUNDLE="$(cd "$1" 2>/dev/null && pwd)" || die "bundle 不存在: $1"
    local output
    output="$("$PYTHON_BIN" "$HELPER" verify-bundle --bundle "$BUNDLE")" || exit 1
    IFS=$'\t' read -r VERSION CHANNEL SOURCE_COMMIT DIRTY ASSET_SHA INSTALL_SHA <<EOF
$output
EOF
    RELEASE_ID="$(basename "$BUNDLE")"
    [[ "$RELEASE_ID" =~ ^[0-9A-Za-z._-]+$ ]] || die "bundle 目录名不安全: $RELEASE_ID"
    MANIFEST_SHA="$("$PYTHON_BIN" "$HELPER" sha256-file --path "$BUNDLE/manifest.json")"
}

publish_token_path() {
    printf '%s/.publish-token' "$BUNDLE"
}

load_publish_token() {
    local token_file
    token_file="$(publish_token_path)"
    [ -f "$token_file" ] || die "bundle 缺少 publish token；首次公开请使用 publish"
    PUBLISH_TOKEN="$(tr -d '\r\n' <"$token_file")"
    [[ "$PUBLISH_TOKEN" =~ ^[0-9a-f]{32}$ ]] || die "bundle publish token 损坏，需要人工核查"
}

load_publish_token_optional() {
    local token_file
    token_file="$(publish_token_path)"
    PUBLISH_TOKEN=""
    [ ! -e "$token_file" ] || load_publish_token
}

create_publish_token() {
    local token_file token
    token_file="$(publish_token_path)"
    token="$($PYTHON_BIN -c 'import secrets; print(secrets.token_hex(16))')"
    if ! (umask 077; set -o noclobber; printf '%s\n' "$token" >"$token_file") 2>/dev/null; then
        die "bundle 已存在 publish attempt；中断恢复请使用 resume-publish"
    fi
    PUBLISH_TOKEN="$token"
}

clear_publish_token() {
    local token_file
    token_file="$(publish_token_path)"
    [ ! -e "$token_file" ] || rm -f "$token_file"
    PUBLISH_TOKEN=""
}

verify_bundle_signature() {
    info "核对 bundle Authenticode 与配置证书指纹"
    bash "$SCRIPT_DIR/sign.sh" --verify "$BUNDLE/$ASSET_NAME"
}

config_mode() {
    local mode
    mode="$(stat -f '%Lp' "$CONFIG_FILE" 2>/dev/null || stat -c '%a' "$CONFIG_FILE" 2>/dev/null || true)"
    printf '%s' "$mode"
}

load_config() {
    [ -f "$CONFIG_FILE" ] || die "缺少 $CONFIG_FILE；从 release.conf.example 创建并设为 600"
    local mode
    mode="$(config_mode)"
    [ "$mode" = "600" ] || die "$CONFIG_FILE 权限必须是 600，当前为 ${mode:-未知}"
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
    [ "${#SERVERS[@]}" -gt 0 ] || die "SERVERS 不能为空"
    [ -n "${SSH_USER:-}" ] || die "SSH_USER 不能为空"
    [ -n "${SSH_KEY:-}" ] || die "SSH_KEY 不能为空"
    SSH_KEY="${SSH_KEY/#\~/$HOME}"
    [ -f "$SSH_KEY" ] || die "SSH 密钥不存在: $SSH_KEY"
}

parse_server() {
    IFS=',' read -r SERVER_NAME SERVER_HOST SERVER_PORT SERVER_DIR SERVER_URL <<EOF
$1
EOF
    SERVER_PORT="${SERVER_PORT:-22}"
    [[ "$SERVER_NAME" =~ ^[0-9A-Za-z._-]+$ ]] || die "服务器名称不安全: $SERVER_NAME"
    [[ "$SERVER_HOST" =~ ^[0-9A-Za-z._:-]+$ ]] || die "服务器地址不安全: $SERVER_HOST"
    [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || die "服务器端口无效: $SERVER_PORT"
    [[ "$SERVER_DIR" =~ ^/[0-9A-Za-z._/-]+$ ]] || die "发布目录必须是安全的绝对路径: $SERVER_DIR"
}

ssh_cmd() {
    local host="$1" port="$2"
    shift 2
    ssh -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o "ConnectTimeout=$SSH_TIMEOUT" -p "$port" "$SSH_USER@$host" "$@"
}

scp_file() {
    local source="$1" host="$2" port="$3" destination="$4"
    scp -q -i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        -o "ConnectTimeout=$SSH_TIMEOUT" -P "$port" "$source" "$SSH_USER@$host:$destination"
}

test_connections() {
    local failed=0 server
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        info "检查节点 $SERVER_NAME ($SERVER_HOST:$SERVER_PORT)"
        if ! ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "command -v python3 >/dev/null && mkdir -p '$SERVER_DIR/.staging' '$SERVER_DIR/.rollback'"; then
            printf '[ERROR] 节点不可用: %s\n' "$SERVER_NAME" >&2
            failed=1
        fi
    done
    [ "$failed" -eq 0 ] || die "至少一个发布节点不可用"
}

prepare_bundle() {
    validate_version "$1"
    require_cmd git
    SOURCE_COMMIT="$(git -C "$PROJECT_ROOT" rev-parse HEAD)"
    [ -n "$(git -C "$PROJECT_ROOT" status --porcelain)" ] && DIRTY=true || DIRTY=false

    if [ "$CHANNEL" = "main" ]; then
        [ "$(git -C "$PROJECT_ROOT" branch --show-current)" = "main" ] || die "main 正式 bundle 只能从 main 分支构建"
        [ "$DIRTY" = false ] || die "main 正式 bundle 要求工作区干净"
        local origin_main
        origin_main="$(git -C "$PROJECT_ROOT" rev-parse refs/remotes/origin/main 2>/dev/null)" || die "缺少 origin/main，请先同步远端引用"
        [ "$SOURCE_COMMIT" = "$origin_main" ] || die "本地 main 与 origin/main 不一致"
        ! git -C "$PROJECT_ROOT" show-ref --verify --quiet "refs/tags/v$VERSION" || die "版本 tag 已存在；禁止重建正式 bundle"
        BUNDLE="$RECOVERY_DIR/v$VERSION-$SOURCE_COMMIT"
        [ ! -e "$BUNDLE" ] || die "正式 bundle 已存在，请直接复用: $BUNDLE"
    else
        BUNDLE="$RECOVERY_DIR/v$VERSION-$SOURCE_COMMIT-$(date -u +%Y%m%dT%H%M%SZ)-$$"
        [ ! -e "$BUNDLE" ] || die "bundle 路径已存在，请稍后重试"
    fi

    info "构建 Windows amd64 版本 $VERSION"
    bash "$SCRIPT_DIR/build.sh" "$VERSION"
    info "执行并验证 Authenticode 签名"
    bash "$SCRIPT_DIR/sign.sh" "$DIST_EXE"
    bash "$SCRIPT_DIR/sign.sh" --verify "$DIST_EXE"

    mkdir -p "$BUNDLE"
    cp "$DIST_EXE" "$BUNDLE/$ASSET_NAME"
    cp "$SCRIPT_DIR/install.ps1" "$BUNDLE/install.ps1"
    "$PYTHON_BIN" "$HELPER" create-manifest \
        --bundle "$BUNDLE" --version "$VERSION" --source-commit "$SOURCE_COMMIT" --dirty "$DIRTY"
    "$PYTHON_BIN" "$HELPER" verify-bundle --bundle "$BUNDLE" >/dev/null
    PREPARED_BUNDLE="$BUNDLE"
    ok "bundle 已持久化: $BUNDLE"
}

stage_bundle() {
    validate_bundle "$1"
    verify_bundle_signature
    load_config
    test_connections
    local server stage incoming bundle_remote node_index_sha expected_index_sha=""
    LOCKED_SERVERS=("__none__")
    trap 'release_locks || true' EXIT
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        incoming="$stage/incoming"
        bundle_remote="$incoming/bundle"
        info "暂存到 $SERVER_NAME"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "test ! -e '$SERVER_DIR/.rollback/$RELEASE_ID' && mkdir -p '$stage' && rm -rf '$incoming' && mkdir -p '$bundle_remote'" \
            || die "$SERVER_NAME 存在未处理的发布状态；先 verify 或 rollback"
        scp_file "$BUNDLE/manifest.json" "$SERVER_HOST" "$SERVER_PORT" "$bundle_remote/manifest.json"
        scp_file "$BUNDLE/install.ps1" "$SERVER_HOST" "$SERVER_PORT" "$bundle_remote/install.ps1"
        scp_file "$BUNDLE/$ASSET_NAME" "$SERVER_HOST" "$SERVER_PORT" "$bundle_remote/$ASSET_NAME"
        scp_file "$HELPER" "$SERVER_HOST" "$SERVER_PORT" "$stage/release-helper.incoming.py"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.incoming.py' verify-bundle --bundle '$bundle_remote' >/dev/null && python3 '$stage/release-helper.incoming.py' acquire-lock --root '$SERVER_DIR' --bundle '$bundle_remote' --release-id '$RELEASE_ID'"
        LOCKED_SERVERS+=("$server")
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.incoming.py' promote-stage --root '$SERVER_DIR' --incoming-bundle '$bundle_remote' --release-id '$RELEASE_ID' && rmdir '$incoming' && rm -rf '$stage/release' && mkdir -p '$stage/release' && cp '$stage/bundle/$ASSET_NAME' '$stage/release/$ASSET_NAME' && cp '$stage/release-helper.incoming.py' '$SERVER_DIR/.release-helper.py.tmp' && mv '$SERVER_DIR/.release-helper.py.tmp' '$SERVER_DIR/.release-helper.py' && mv '$stage/release-helper.incoming.py' '$stage/release-helper.py' && python3 '$stage/release-helper.py' next-index --root '$SERVER_DIR' --bundle '$stage/bundle' --output '$stage/releases.json.next' --release-id '$RELEASE_ID'"
        node_index_sha="$(ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "python3 '$stage/release-helper.py' sha256-file --path '$stage/releases.json.next'")"
        if [ -z "$expected_index_sha" ]; then
            expected_index_sha="$node_index_sha"
        elif [ "$node_index_sha" != "$expected_index_sha" ]; then
            die "各节点待发布 releases.json 不一致；先修复既有索引漂移"
        fi
        ok "$SERVER_NAME 暂存校验通过"
    done
    trap - EXIT
    ok "全部节点已暂存；公开索引尚未变更"
}

check_main_tag() {
    [ "$CHANNEL" = "main" ] || return 0
    local local_target remote_target
    local_target="$(git -C "$PROJECT_ROOT" rev-list -n 1 "v$VERSION" 2>/dev/null)" || die "main publish 要求本地 tag v$VERSION 已存在"
    [ "$local_target" = "$SOURCE_COMMIT" ] || die "tag v$VERSION 未指向 bundle commit"
    remote_target="$(git -C "$PROJECT_ROOT" ls-remote origin "refs/tags/v$VERSION^{}" | awk 'NR==1 {print $1}')"
    if [ -z "$remote_target" ]; then
        remote_target="$(git -C "$PROJECT_ROOT" ls-remote origin "refs/tags/v$VERSION" | awk 'NR==1 {print $1}')"
    fi
    [ "$remote_target" = "$SOURCE_COMMIT" ] || die "远端 tag v$VERSION 不存在或未指向 bundle commit"
}

release_locks() {
    local server stage failed=0
    for server in "${LOCKED_SERVERS[@]}"; do
        [ "$server" != "__none__" ] || continue
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "if test -f '$stage/release-helper.incoming.py'; then if test -d '$stage/incoming/bundle'; then lock_bundle='$stage/incoming/bundle'; else lock_bundle='$stage/bundle'; fi; python3 '$stage/release-helper.incoming.py' release-lock --root '$SERVER_DIR' --bundle \"\$lock_bundle\" --release-id '$RELEASE_ID'; else python3 '$stage/release-helper.py' release-lock --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID'; fi" \
            || failed=1
    done
    return "$failed"
}

rollback_all() {
    local server stage failed=0
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' can-rollback --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'" \
            || { printf '[ERROR] 节点不满足回滚前置条件: %s\n' "$SERVER_NAME" >&2; failed=1; }
    done
    [ "$failed" -eq 0 ] || return "$failed"
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' begin-rollback --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'" \
            || { printf '[ERROR] 节点无法绑定回滚事务: %s\n' "$SERVER_NAME" >&2; failed=1; }
    done
    [ "$failed" -eq 0 ] || return "$failed"
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' rollback-release --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'" \
            || { printf '[ERROR] 自动回滚失败，需人工处理节点: %s\n' "$SERVER_NAME" >&2; failed=1; }
    done
    return "$failed"
}

verify_remote_nodes() {
    local server stage failed=0 node_index_sha expected_index_sha=""
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        if ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' assert-lock --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN' && python3 '$stage/release-helper.py' verify-release --root '$SERVER_DIR' --bundle '$stage/bundle'"; then
            if ! node_index_sha="$(ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "python3 '$stage/release-helper.py' sha256-file --path '$SERVER_DIR/releases.json'")" || [ -z "$node_index_sha" ]; then
                printf '[ERROR] 节点索引哈希读取失败: %s\n' "$SERVER_NAME" >&2
                failed=1
                continue
            fi
            if [ -z "$expected_index_sha" ]; then
                expected_index_sha="$node_index_sha"
            elif [ "$node_index_sha" != "$expected_index_sha" ]; then
                printf '[ERROR] 节点 releases.json 字节不一致: %s\n' "$SERVER_NAME" >&2
                failed=1
                continue
            fi
            ok "$SERVER_NAME 资产与索引一致"
        else
            printf '[ERROR] 节点验收失败: %s\n' "$SERVER_NAME" >&2
            failed=1
        fi
    done
    return "$failed"
}

finalize_remote_nodes() {
    local server stage failed=0
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        if ! ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' mark-verified --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'"; then
            printf '[ERROR] 节点验收状态落盘失败: %s\n' "$SERVER_NAME" >&2
            failed=1
        fi
    done
    return "$failed"
}

publish_bundle() {
    local resume_mode="${2:-false}"
    validate_bundle "$1"
    verify_bundle_signature
    load_config
    test_connections
    check_main_tag
    local server stage node_index_sha expected_index_sha="" failed=0 begun=0

    if [ "$resume_mode" = true ]; then
        load_publish_token
    elif [ -e "$(publish_token_path)" ]; then
        die "bundle 已存在 publish attempt；中断恢复请使用 resume-publish"
    fi

    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        info "复核 $SERVER_NAME 的暂存内容与待发布索引"
        if [ "$resume_mode" = true ]; then
            ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
                "python3 '$stage/release-helper.py' assert-lock --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN' && python3 '$stage/release-helper.py' verify-bundle --bundle '$stage/bundle' >/dev/null" \
                || die "$SERVER_NAME 恢复预检失败；保留原 publish token"
        else
            ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
                "python3 '$stage/release-helper.py' assert-lock --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' && python3 '$stage/release-helper.py' verify-bundle --bundle '$stage/bundle' >/dev/null && python3 '$stage/release-helper.py' next-index --root '$SERVER_DIR' --bundle '$stage/bundle' --output '$stage/releases.json.next' --release-id '$RELEASE_ID'" \
                || die "$SERVER_NAME 暂存预检失败；公开状态未变更"
            node_index_sha="$(ssh_cmd "$SERVER_HOST" "$SERVER_PORT" "python3 '$stage/release-helper.py' sha256-file --path '$stage/releases.json.next'")"
            if [ -z "$expected_index_sha" ]; then
                expected_index_sha="$node_index_sha"
            elif [ "$node_index_sha" != "$expected_index_sha" ]; then
                die "各节点待发布 releases.json 不一致；公开状态未变更"
            fi
        fi
    done

    if [ "$resume_mode" != true ]; then
        create_publish_token
    fi

    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        if ! ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' begin-publish --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'"; then
            if [ "$begun" -ne 0 ]; then
                rollback_all || die "绑定 publish attempt 失败且部分节点无法恢复；保留 token 供人工恢复"
            fi
            clear_publish_token
            die "$SERVER_NAME 无法绑定 publish attempt；其他协调器可能正在操作"
        fi
        begun=$((begun + 1))
    done

    trap 'if rollback_all; then clear_publish_token; fi; exit 130' INT TERM HUP
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        info "提升 $SERVER_NAME 的版本目录与索引"
        if ! ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "python3 '$stage/release-helper.py' commit-release --root '$SERVER_DIR' --bundle '$stage/bundle' --next-index '$stage/releases.json.next' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'"; then
            failed=1
            break
        fi
    done

    if [ "$failed" -ne 0 ]; then
        trap - INT TERM HUP
        if rollback_all; then
            clear_publish_token
        fi
        die "节点提升失败，已尝试恢复全部节点的发布前状态"
    fi
    if ! verify_remote_nodes; then
        trap - INT TERM HUP
        if rollback_all; then
            clear_publish_token
        fi
        die "全节点验收失败，已尝试恢复全部节点的发布前状态"
    fi
    trap - INT TERM HUP
    finalize_remote_nodes || die "资产已全节点一致，但验收状态未全部落盘；保留 token 并执行 resume-publish"
    ok "全部节点已公开并对账；暂存与回滚数据保留到显式 verify"
}

verify_bundle_remote() {
    validate_bundle "$1"
    load_publish_token
    verify_bundle_signature
    load_config
    test_connections
    verify_remote_nodes || die "至少一个节点验收失败"
    finalize_remote_nodes || die "节点资产一致，但验收状态未全部落盘；请重试 verify"
    ok "全部节点验收通过"
}

cleanup_bundle_remote() {
    validate_bundle "$1"
    load_publish_token
    load_config
    test_connections
    local server stage failed=0
    for server in "${SERVERS[@]}"; do
        parse_server "$server"
        stage="$SERVER_DIR/.staging/$RELEASE_ID"
        if ! ssh_cmd "$SERVER_HOST" "$SERVER_PORT" \
            "tombstone='$SERVER_DIR/.cleanup-complete.$RELEASE_ID.json'; if test -e '$SERVER_DIR/.release-owner.json'; then python3 '$stage/release-helper.py' cleanup-release --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN'; fi; if test -f \"\$tombstone\"; then python3 '$SERVER_DIR/.release-helper.py' complete-cleanup --root '$SERVER_DIR' --bundle '$stage/bundle' --release-id '$RELEASE_ID' --publish-token '$PUBLISH_TOKEN' --manifest-sha256 '$MANIFEST_SHA'; elif test ! -e '$stage' && test ! -e '$SERVER_DIR/.release-owner.json'; then true; else exit 1; fi"; then
            printf '[ERROR] 节点清理失败: %s\n' "$SERVER_NAME" >&2
            failed=1
        fi
    done
    [ "$failed" -eq 0 ] || die "至少一个节点清理失败；修复后可用同一 bundle 重试 cleanup"
    clear_publish_token
    ok "全部节点的暂存、回滚数据和超额历史目录已清理"
}

rollback_bundle_remote() {
    validate_bundle "$1"
    load_publish_token_optional
    load_config
    test_connections
    rollback_all || die "至少一个节点自动回滚失败，需要人工恢复"
    clear_publish_token
    ok "已请求全部节点恢复发布前状态；请重新 stage 后继续"
}

dry_run() {
    validate_version "$1"
    printf 'dry-run: true\nversion: %s\nchannel: %s\n' "$VERSION" "$CHANNEL"
    if [ "$CHANNEL" = "dev" ]; then
        printf 'plan: prepare -> stage-all -> publish-all -> verify-all\n'
        printf 'git-writes: none\ngithub-writes: none\nnetwork-writes: none\n'
    else
        printf 'plan: remote-release main orchestration + persisted bundle\n'
        printf 'script-git-writes: none\nscript-github-writes: none\nnetwork-writes: none\n'
    fi
}

main() {
    find_python
    [ -f "$HELPER" ] || die "缺少 release-helper.py"
    case "${1:-}" in
        stage|publish|resume-publish|verify|rollback|cleanup)
            if [ "${SSLCTLW_COORDINATOR_LOCKED:-}" != "1" ] && [ "$#" -eq 2 ]; then
                local lock_name
                lock_name="$(basename "$2")"
                [[ "$lock_name" =~ ^[0-9A-Za-z._-]+$ ]] || die "bundle 目录名不安全: $lock_name"
                exec "$PYTHON_BIN" "$HELPER" run-locked \
                    --lock-path "$RECOVERY_DIR/.locks/$lock_name.lock" \
                    bash "$0" "$@"
            fi
            ;;
    esac
    case "${1:-}" in
        --dry-run)
            [ "$#" -eq 2 ] || die "--dry-run 需要一个版本参数"
            dry_run "$2"
            ;;
        prepare)
            [ "$#" -eq 2 ] || die "prepare 需要一个版本参数"
            prepare_bundle "$2"
            printf '%s\n' "$PREPARED_BUNDLE"
            ;;
        stage)
            [ "$#" -eq 2 ] || die "stage 需要一个 bundle 路径"
            stage_bundle "$2"
            ;;
        publish)
            [ "$#" -eq 2 ] || die "publish 需要一个 bundle 路径"
            publish_bundle "$2" false
            ;;
        resume-publish)
            [ "$#" -eq 2 ] || die "resume-publish 需要一个 bundle 路径"
            publish_bundle "$2" true
            ;;
        verify)
            [ "$#" -eq 2 ] || die "verify 需要一个 bundle 路径"
            verify_bundle_remote "$2"
            ;;
        cleanup)
            [ "$#" -eq 2 ] || die "cleanup 需要一个 bundle 路径"
            cleanup_bundle_remote "$2"
            ;;
        rollback)
            [ "$#" -eq 2 ] || die "rollback 需要一个 bundle 路径"
            rollback_bundle_remote "$2"
            ;;
        dev)
            [ "$#" -eq 2 ] || die "dev 需要一个预发布版本"
            validate_version "$2"
            [ "$CHANNEL" = "dev" ] || die "dev 命令只接受带预发布段的 SemVer"
            prepare_bundle "$2"
            stage_bundle "$PREPARED_BUNDLE"
            publish_bundle "$PREPARED_BUNDLE"
            verify_bundle_remote "$PREPARED_BUNDLE"
            cleanup_bundle_remote "$PREPARED_BUNDLE"
            ;;
        test)
            [ "$#" -eq 1 ] || die "test 不接受参数"
            load_config
            test_connections
            ok "全部节点连接与 Python3 检查通过"
            ;;
        -h|--help|help|"")
            usage
            ;;
        *)
            usage >&2
            die "未知命令: $1"
            ;;
    esac
}

main "$@"
