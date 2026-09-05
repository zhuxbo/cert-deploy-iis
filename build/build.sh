#!/bin/bash

# build.sh - sslctlw 构建脚本
# 仅构建，不签名不发布。
#
# 用法:
#   ./build.sh 1.0.0      # 发布构建
#   ./build.sh --debug     # 开发构建（保留调试符号）
#   ./build.sh             # 默认 dev 版本

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="$SCRIPT_DIR/build.conf"
DIST_DIR="$PROJECT_ROOT/dist"

VERSION="dev"
DEBUG=false

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ========================================
# 参数解析
# ========================================
while [ $# -gt 0 ]; do
    case "$1" in
        --debug) DEBUG=true; shift ;;
        -h|--help)
            echo "用法: $0 [--debug] [版本号]"
            echo "  --debug   保留调试符号"
            echo "  版本号    默认 dev"
            exit 0 ;;
        -*) echo "未知选项: $1"; exit 1 ;;
        *)  VERSION="$1"; shift ;;
    esac
done

# ========================================
# 读取 build.conf
# ========================================
TRUSTED_ORG=""
TRUSTED_COUNTRY="CN"

if [ -f "$CONF_FILE" ]; then
    echo -e "${CYAN}Loading build.conf...${NC}"
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" == \#* ]] && continue
        key=$(echo "$line" | cut -d'=' -f1 | sed 's/[[:space:]]*$//')
        val=$(echo "$line" | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/^["'"'"']//;s/["'"'"']$//')
        case "$key" in
            TRUSTED_ORG)     [ -z "$UPGRADE_TRUSTED_ORG" ]     && TRUSTED_ORG="$val" ;;
            TRUSTED_COUNTRY) [ -z "$UPGRADE_TRUSTED_COUNTRY" ] && TRUSTED_COUNTRY="$val" ;;
        esac
    done < "$CONF_FILE"
fi

[ -n "$UPGRADE_TRUSTED_ORG" ]     && TRUSTED_ORG="$UPGRADE_TRUSTED_ORG"
[ -n "$UPGRADE_TRUSTED_COUNTRY" ] && TRUSTED_COUNTRY="$UPGRADE_TRUSTED_COUNTRY"
[ -z "$TRUSTED_COUNTRY" ] && TRUSTED_COUNTRY="CN"

cd "$PROJECT_ROOT"

GO_TOOLCHAIN="$(awk '$1 == "toolchain" { print $2; exit }' go.mod)"
[ "$GO_TOOLCHAIN" = "go1.26.8" ] || {
    echo -e "${YELLOW}ERROR: go.mod 必须固定 toolchain go1.26.8${NC}"
    exit 1
}

# ========================================
# 发布构建必须配置 TRUSTED_ORG
# ========================================
if [ "$VERSION" != "dev" ] && [ -z "$TRUSTED_ORG" ]; then
    echo -e "${YELLOW}ERROR: 发布构建必须配置 TRUSTED_ORG（升级签名验证需要）${NC}"
    echo "  设置方式: build.conf 中添加 TRUSTED_ORG=xxx 或环境变量 UPGRADE_TRUSTED_ORG=xxx"
    exit 1
fi

# ========================================
# 构建
# ========================================
LDFLAGS="-X main.version=$VERSION"
[ -n "$TRUSTED_ORG" ]     && LDFLAGS="$LDFLAGS -X 'sslctlw/upgrade.buildTrustedOrg=$TRUSTED_ORG'"
[ -n "$TRUSTED_COUNTRY" ] && LDFLAGS="$LDFLAGS -X 'sslctlw/upgrade.buildTrustedCountry=$TRUSTED_COUNTRY'"
[ "$DEBUG" = false ]      && LDFLAGS="$LDFLAGS -s -w"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR"/*

echo "Building sslctlw.exe..."
echo "  Version: $VERSION"
echo "  Trusted Org: ${TRUSTED_ORG:-not set}"
echo "  Country: $TRUSTED_COUNTRY"
echo ""

GOTOOLCHAIN="$GO_TOOLCHAIN" GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$LDFLAGS" -o "$DIST_DIR/sslctlw.exe"

SIZE=$(du -h "$DIST_DIR/sslctlw.exe" | cut -f1)
echo -e "${GREEN}Build successful: dist/sslctlw.exe ($SIZE)${NC}"
