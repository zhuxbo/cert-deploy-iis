#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cd "$PROJECT_ROOT"

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

cmp -s CLAUDE.md "$TMP_DIR/CLAUDE.md" || { echo "CLAUDE.md 不符合固定模板" >&2; exit 1; }
cmp -s .claude/commands/finish-check.md "$TMP_DIR/finish-check.md" || { echo "finish-check 工具入口发生漂移" >&2; exit 1; }
cmp -s .claude/commands/remote-release.md "$TMP_DIR/remote-release.md" || { echo "remote-release 工具入口发生漂移" >&2; exit 1; }

if find skills -mindepth 1 -type d -print -quit | grep -q .; then
    echo "skills/ 下不得存在二级目录" >&2
    exit 1
fi

while IFS= read -r path; do
    name="$(basename "$path")"
    if [ "$name" != "SKILL.md" ] && ! printf '%s' "$name" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*\.md$'; then
        echo "skill 叶子文件名不符合 kebab-case: $path" >&2
        exit 1
    fi
done < <(find skills -mindepth 1 -maxdepth 1 -type f | sort)

head -1 skills/SKILL.md | grep -qx -- '---' || { echo "skills/SKILL.md 缺少入口元数据" >&2; exit 1; }

while IFS= read -r leaf; do
    [ -f "$leaf" ] || { echo "Skill 路由引用不存在: $leaf" >&2; exit 1; }
done < <(grep -Eo 'skills/[a-z0-9]+(-[a-z0-9]+)*\.md' skills/SKILL.md | sort -u)

if grep -R -n -E 'skills/[a-z0-9-]+/(SKILL\.md)?' \
    --include='*.md' --exclude-dir=.git --exclude-dir=.superpowers --exclude-dir=recovery .; then
    echo "文档仍引用旧的二级 skill 路径" >&2
    exit 1
fi

for leaf in skills/finish-check.md skills/remote-release.md; do
    [ -f "$leaf" ] || { echo "工具入口引用不存在: $leaf" >&2; exit 1; }
done

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
echo "governance drift check passed"
