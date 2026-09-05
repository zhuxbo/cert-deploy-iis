#!/bin/bash

# sign.sh - Authenticode 代码签名
# 通过 SimplySignAuto HTTP API 签名，并在构建机使用 signtool 独立验签
#
# 用法:
#   ./sign.sh [exe路径]          # 签名（默认 dist/sslctlw.exe）
#   ./sign.sh --verify [exe路径] # 验证签名

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="$SCRIPT_DIR/build.conf"

# 默认值
SIGN_THUMBPRINT=""
SIGN_API_BASE_URL="${SSLCTLW_SIGNING_BASE_URL:-}"
SIGN_CERTIFICATE_SERIAL=""
SIGN_TOKEN_FILE="${SSLCTLW_SIGNING_BEARER_TOKEN_FILE:-}"

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
            SIGN_THUMBPRINT)          SIGN_THUMBPRINT="$val" ;;
            SIGN_CERTIFICATE_SERIAL)  SIGN_CERTIFICATE_SERIAL="$val" ;;
        esac
    done < "$CONF_FILE"

    SIGN_CERTIFICATE_SERIAL="${SSLCTLW_SIGNING_CERTIFICATE_SERIAL:-$SIGN_CERTIFICATE_SERIAL}"

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
    local powershell_path
    powershell_path="$(resolve_windows_powershell)" || {
        log_error "找不到 Windows PowerShell，无法调用签名 API"
        return 1
    }

    if [ -z "$SIGN_API_BASE_URL" ]; then
        log_error "未配置 SSLCTLW_SIGNING_BASE_URL"
        return 1
    fi
    if [ -z "$SIGN_CERTIFICATE_SERIAL" ]; then
        log_error "未配置 SIGN_CERTIFICATE_SERIAL 或 SSLCTLW_SIGNING_CERTIFICATE_SERIAL"
        return 1
    fi
    if [ -z "$SIGN_TOKEN_FILE" ] || [ ! -f "$SIGN_TOKEN_FILE" ]; then
        log_error "SSLCTLW_SIGNING_BEARER_TOKEN_FILE 必须指向受保护的 Bearer Token 文件"
        return 1
    fi

    local signed_output="${exe}.signed.$$.$RANDOM"
    local win_exe win_signed_output win_token_file win_script
    win_exe=$(cygpath -w "$exe")
    win_signed_output=$(cygpath -w "$signed_output")
    win_token_file=$(cygpath -w "$SIGN_TOKEN_FILE")
    win_script=$(cygpath -w "$SCRIPT_DIR/sign-via-simplysign.ps1")

    log_info "通过 SimplySignAuto API 签名: $exe"
    log_info "API: $SIGN_API_BASE_URL"

    if ! MSYS_NO_PATHCONV=1 "$powershell_path" \
        -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -File "$win_script" \
        -InputPath "$win_exe" \
        -OutputPath "$win_signed_output" \
        -BaseUrl "$SIGN_API_BASE_URL" \
        -BearerTokenPath "$win_token_file" \
        -CertificateSerialNumber "$SIGN_CERTIFICATE_SERIAL" \
        -IdempotencyPrefix "sslctlw-release" \
        -TimeoutSeconds 300; then
        rm -f "$signed_output"
        log_error "签名 API 调用失败"
        return 1
    fi

    if ! verify_file "$signed_output" "$signtool_path"; then
        rm -f "$signed_output"
        return 1
    fi

    mv -f "$signed_output" "$exe"

    log_success "签名完成: $exe"
}

# resolve_windows_powershell 经 %WINDIR% 直接定位系统 Windows PowerShell。
# 与 release.sh 的 windows_powershell 同策略：不依赖 PATH，避开应用别名与 PowerShell 7 的行为差异。
# 仅在 %WINDIR% 下找不到时才回退 PATH 查找。
resolve_windows_powershell() {
    local win_path native_path candidate
    if command -v cygpath >/dev/null 2>&1; then
        win_path="${WINDIR:-C:\\Windows}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        native_path="$(cygpath -u "$win_path")"
        if [ -x "$native_path" ]; then
            printf '%s' "$native_path"
            return 0
        fi
    fi
    for candidate in powershell.exe powershell; do
        if command -v "$candidate" >/dev/null 2>&1; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
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
    powershell_path="$(resolve_windows_powershell)" || {
        log_error "找不到 Windows PowerShell，无法核对签名证书指纹"
        exit 1
    }
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
