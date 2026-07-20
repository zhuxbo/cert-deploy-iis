#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$PROJECT_ROOT"

require_regular_file() {
    local path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "$path 必须是普通文件" >&2
        exit 1
    }
}

require_literal() {
    local path="$1" value="$2"
    grep -Fq -- "$value" "$path" || {
        echo "$path 缺少必需契约: $value" >&2
        exit 1
    }
}

cat >"$TMP_DIR/CLAUDE.md" <<'EOF'
# 项目智能体规则

@AGENTS.md

本文件仅为 Claude 兼容入口。禁止在此追加项目规则；需要调整时修改 `AGENTS.md` 或其引用的权威资料。
EOF

cat >"$TMP_DIR/finish-check.md" <<'EOF'
读取并严格遵循 `skills/finish-check.md`。
EOF

cat >"$TMP_DIR/remote-release.md" <<'EOF'
读取并严格遵循 `skills/remote-release.md`。

将用户参数 `$ARGUMENTS` 原样作为版本参数传入该流程。
EOF

mkdir -p "$TMP_DIR/codex/remote-release" "$TMP_DIR/codex/finish-check"
cat >"$TMP_DIR/codex/remote-release/SKILL.md" <<'EOF'
---
name: remote-release
description: 执行 sslctlw 正式发布、测试版发布、发布恢复或版本验收。用户要求发布、remote-release、恢复中断发布或验收版本时使用。
---

读取并严格遵循项目根目录的 `skills/remote-release.md`。

将用户提供的版本参数原样传入该流程。
EOF

cat >"$TMP_DIR/codex/finish-check/SKILL.md" <<'EOF'
---
name: finish-check
description: 执行 sslctlw 完成检查、提交前验证或 finish-check。用户要求完成检查、跑 finish-check 或判断是否可以提交时使用。
---

读取并严格遵循项目根目录的 `skills/finish-check.md`。
EOF

require_regular_file AGENTS.md
require_regular_file .gitattributes
require_regular_file CLAUDE.md
require_regular_file .claude/commands/finish-check.md
require_regular_file .claude/commands/remote-release.md
require_regular_file .agents/skills/finish-check/SKILL.md
require_regular_file .agents/skills/remote-release/SKILL.md

require_literal .gitattributes '*.sh text eol=lf'
require_literal .gitattributes 'CLAUDE.md text eol=lf'
require_literal .gitattributes '.claude/commands/*.md text eol=lf'
require_literal .gitattributes '.agents/skills/*/SKILL.md text eol=lf'

cmp -s CLAUDE.md "$TMP_DIR/CLAUDE.md" || { echo "CLAUDE.md 不符合固定模板" >&2; exit 1; }
cmp -s .claude/commands/finish-check.md "$TMP_DIR/finish-check.md" || { echo "finish-check 工具入口发生漂移" >&2; exit 1; }
cmp -s .claude/commands/remote-release.md "$TMP_DIR/remote-release.md" || { echo "remote-release 工具入口发生漂移" >&2; exit 1; }
cmp -s .agents/skills/finish-check/SKILL.md "$TMP_DIR/codex/finish-check/SKILL.md" || { echo "Codex finish-check 原生入口发生漂移" >&2; exit 1; }
cmp -s .agents/skills/remote-release/SKILL.md "$TMP_DIR/codex/remote-release/SKILL.md" || { echo "Codex remote-release 原生入口发生漂移" >&2; exit 1; }

find .agents/skills -mindepth 1 -maxdepth 1 -print | sort >"$TMP_DIR/codex-skill-dirs"
printf '%s\n' \
    '.agents/skills/finish-check' \
    '.agents/skills/remote-release' >"$TMP_DIR/expected-codex-skill-dirs"
cmp -s "$TMP_DIR/codex-skill-dirs" "$TMP_DIR/expected-codex-skill-dirs" || {
    echo "Codex 原生 skill 必须且只能包含 finish-check 与 remote-release" >&2
    exit 1
}
if find .agents/skills -mindepth 2 ! -path '*/SKILL.md' -print -quit | grep -q .; then
    echo "Codex 原生 skill 只能包含薄层 SKILL.md" >&2
    exit 1
fi

while IFS= read -r path; do
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "skills/ 一级项必须是普通文件: $path" >&2
        exit 1
    }
    name="$(basename "$path")"
    if [ "$name" != "SKILL.md" ] && ! printf '%s' "$name" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*\.md$'; then
        echo "skill 叶子文件名不符合 kebab-case: $path" >&2
        exit 1
    fi
done < <(find skills -mindepth 1 -maxdepth 1 -print | sort)

require_regular_file skills/SKILL.md
[ "$(sed -n '1p' skills/SKILL.md)" = "---" ] || { echo "skills/SKILL.md frontmatter 起始无效" >&2; exit 1; }
[ "$(sed -n '2p' skills/SKILL.md)" = "name: sslctlw" ] || { echo "skills/SKILL.md name 无效" >&2; exit 1; }
[ "$(sed -n '3p' skills/SKILL.md)" = "description: 路由 sslctlw 的 Go、IIS、Deploy API、windigo、构建发布和完成检查工作流。" ] || { echo "skills/SKILL.md description 无效" >&2; exit 1; }
[ "$(sed -n '4p' skills/SKILL.md)" = "---" ] || { echo "skills/SKILL.md frontmatter 未闭合" >&2; exit 1; }

find skills -mindepth 1 -maxdepth 1 -type f ! -name SKILL.md | sort >"$TMP_DIR/actual-leaves"
awk -F'|' '
    /^\|/ {
        trigger = $2
        resource = $3
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", trigger)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", resource)
        if (trigger != "" && resource ~ /^`skills\/[a-z0-9]+(-[a-z0-9]+)*\.md`$/) {
            gsub(/`/, "", resource)
            print resource
        }
    }
' skills/SKILL.md | sort -u >"$TMP_DIR/routed-leaves"
if ! cmp -s "$TMP_DIR/actual-leaves" "$TMP_DIR/routed-leaves"; then
    echo "Skill 路由与实际叶子不一致" >&2
    diff -u "$TMP_DIR/routed-leaves" "$TMP_DIR/actual-leaves" >&2 || true
    exit 1
fi

if grep -R -n -E 'skills/[^/[:space:]`<>]+/(SKILL\.md)?' \
    --include='*.md' --exclude-dir=.git --exclude-dir=.agents --exclude-dir=.superpowers --exclude-dir=recovery . \
    | grep -v -E '\.agents/skills/(finish-check|remote-release)/SKILL\.md'; then
    echo "文档仍引用旧的二级 skill 路径" >&2
    exit 1
fi

for leaf in skills/finish-check.md skills/remote-release.md; do
    [ -f "$leaf" ] || { echo "工具入口引用不存在: $leaf" >&2; exit 1; }
done

for contract in \
    '跨仓公共行为以 `deploy-spec.md` 为准' \
    '由 `skills/SKILL.md` 路由到对应叶子资源' \
    '任务命中某领域时，必须先读根路由及选中的叶子资源' \
    'Windows 运行期行为以 GitHub Actions 的 `windows-latest` 结果为准' \
    '不得削弱 Authenticode、DPAPI、数据目录 ACL、证书私钥配对或 IIS 绑定恢复校验' \
    '未经明确发布指令，不创建或移动 tag、GitHub Release，不上传发布节点' \
    'Codex 原生入口只保留 `.agents/skills/remote-release/SKILL.md` 与 `.agents/skills/finish-check/SKILL.md`' \
    'GOOS=windows GOARCH=amd64 go build -o /dev/null .' \
    'GOOS=windows GOARCH=amd64 go vet ./...' \
    'go test ./...' \
    'bash build/check-governance.sh' \
    '只记录长期有效、项目级、会影响智能体行为的规则' \
    '跨仓公共行为写入 `deploy-spec.md`' \
    '只直接维护 `AGENTS.md`' \
    '新增、删除或重命名领域 skill 时，同步更新 `skills/SKILL.md`' \
    '修改后删除失效或重复内容'; do
    require_literal AGENTS.md "$contract"
done

require_literal README.md 'GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=1.0.0" -o dist/sslctlw.exe .'

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

printf 'CLAUDE template sha256: %s\n' "$(hash_file CLAUDE.md)"
printf 'finish-check entry sha256: %s\n' "$(hash_file .claude/commands/finish-check.md)"
printf 'remote-release entry sha256: %s\n' "$(hash_file .claude/commands/remote-release.md)"
printf 'Codex finish-check skill sha256: %s\n' "$(hash_file .agents/skills/finish-check/SKILL.md)"
printf 'Codex remote-release skill sha256: %s\n' "$(hash_file .agents/skills/remote-release/SKILL.md)"
echo "governance drift check passed"
