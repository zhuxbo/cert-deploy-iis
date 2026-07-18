#!/bin/bash

# sign.sh - Authenticode 代码签名
# 使用 SimplySign Desktop + signtool 进行云端 EV 签名
#
# 前提: SimplySign Desktop 已连接登录
#
# 用法:
#   ./sign.sh [exe路径]          # 签名（默认 dist/sslctlw.exe）
#   ./sign.sh --verify [exe路径] # 验证签名

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="$SCRIPT_DIR/build.conf"

# 默认值
SIGN_TSA="http://time.certum.pl"
SIGN_FD="sha256"
SIGN_TD="sha256"
SIGN_THUMBPRINT=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# ========================================
# 查找 signtool
# ========================================
find_signtool() {
    # PATH 中直接找
    if command -v signtool &>/dev/null; then
        echo "signtool"
        return
    fi

    # Windows SDK 常见路径
    local kits_dir="/c/Program Files (x86)/Windows Kits/10/bin"
    if [ -d "$kits_dir" ]; then
        local latest=$(ls -d "$kits_dir"/10.* 2>/dev/null | sort -V | tail -1)
        if [ -n "$latest" ] && [ -f "$latest/x64/signtool.exe" ]; then
            echo "$latest/x64/signtool.exe"
            return
        fi
    fi

    return 1
}

# ========================================
# 加载配置
# ========================================
load_config() {
    if [ ! -f "$CONF_FILE" ]; then
        log_error "配置文件不存在: $CONF_FILE"
        log_info "请复制 build.conf.example 并配置: cp build.conf.example build.conf"
        exit 1
    fi

    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" == \#* ]] && continue
        local key=$(echo "$line" | cut -d'=' -f1 | sed 's/[[:space:]]*$//')
        local val=$(echo "$line" | cut -d'=' -f2- | sed 's/^[[:space:]]*//;s/^["'"'"']//;s/["'"'"']$//')
        case "$key" in
            SIGN_THUMBPRINT) SIGN_THUMBPRINT="$val" ;;
            SIGN_TSA)        SIGN_TSA="$val" ;;
        esac
    done < "$CONF_FILE"

    if [ -z "$SIGN_THUMBPRINT" ]; then
        log_error "未配置 SIGN_THUMBPRINT（证书指纹）"
        exit 1
    fi
}

# ========================================
# 签名
# ========================================
sign_file() {
    local exe="$1"
    local signtool_path="$2"
    local win_exe=$(cygpath -w "$exe")

    log_info "签名: $exe"
    log_info "指纹: $SIGN_THUMBPRINT"
    log_info "时间戳: $SIGN_TSA"

    MSYS_NO_PATHCONV=1 "$signtool_path" sign \
        /sha1 "$SIGN_THUMBPRINT" \
        /tr "$SIGN_TSA" \
        /td "$SIGN_TD" \
        /fd "$SIGN_FD" \
        /v "$win_exe"

    log_success "签名完成: $exe"
}

# ========================================
# 验证签名
# ========================================
verify_file() {
    local exe="$1"
    local signtool_path="$2"
    local win_exe=$(cygpath -w "$exe")

    log_info "验证签名: $exe"
    MSYS_NO_PATHCONV=1 "$signtool_path" verify /pa /all "$win_exe"
    local powershell_path actual_thumbprint expected_thumbprint
    if command -v powershell.exe &>/dev/null; then
        powershell_path="powershell.exe"
    elif command -v powershell &>/dev/null; then
        powershell_path="powershell"
    else
        log_error "找不到 Windows PowerShell，无法核对签名证书指纹"
        exit 1
    fi
    actual_thumbprint=$(SSLCTLW_VERIFY_EXE="$win_exe" MSYS_NO_PATHCONV=1 "$powershell_path" \
        -NoProfile -NonInteractive -Command \
        '$s = Get-AuthenticodeSignature -LiteralPath $env:SSLCTLW_VERIFY_EXE; if ($s.Status -ne "Valid" -or $null -eq $s.SignerCertificate) { exit 1 }; $s.SignerCertificate.Thumbprint') || {
        log_error "PowerShell 无法确认 Authenticode 签名有效"
        exit 1
    }
    actual_thumbprint=$(printf '%s' "$actual_thumbprint" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    expected_thumbprint=$(printf '%s' "$SIGN_THUMBPRINT" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
    if [ "$actual_thumbprint" != "$expected_thumbprint" ]; then
        log_error "签名证书指纹与 build.conf 不一致"
        exit 1
    fi
    log_success "签名有效: $exe"
}

# ========================================
# 主流程
# ========================================
main() {
    # 环境检测：需要 MSYS2/Git Bash（cygpath）
    command -v cygpath &>/dev/null || { log_error "需要 MSYS2/Git Bash 环境（cygpath 不可用）"; exit 1; }

    local verify_only=false
    local exe=""

    while [ $# -gt 0 ]; do
        case "$1" in
            --verify) verify_only=true; shift ;;
            -h|--help)
                echo "用法: $0 [--verify] [exe路径]"
                echo "  默认签名 dist/sslctlw.exe"
                echo "  --verify  仅验证签名"
                exit 0 ;;
            -*) log_error "未知选项: $1"; exit 1 ;;
            *)  exe="$1"; shift ;;
        esac
    done

    [ -z "$exe" ] && exe="$PROJECT_ROOT/dist/sslctlw.exe"

    # 检查文件
    if [ ! -f "$exe" ]; then
        log_error "文件不存在: $exe"
        exit 1
    fi

    # 查找 signtool
    local signtool_path
    signtool_path=$(find_signtool) || {
        log_error "找不到 signtool，请安装 Windows SDK:"
        log_info "  winget install Microsoft.WindowsSDK.10.0.26100"
        log_info "  或从 https://developer.microsoft.com/windows/downloads/windows-sdk/ 下载"
        exit 1
    }
    log_info "signtool: $signtool_path"

    load_config

    if [ "$verify_only" = true ]; then
        verify_file "$exe" "$signtool_path"
    else
        sign_file "$exe" "$signtool_path"
        echo ""
        verify_file "$exe" "$signtool_path"
    fi
}

main "$@"
