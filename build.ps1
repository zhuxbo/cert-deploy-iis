# build.ps1 - Windows 构建脚本
# 从环境变量读取升级安全配置，编译到二进制中

param(
    [string]$Version = "dev",
    [switch]$Debug
)

# 读取环境变量
$fingerprints = $env:UPGRADE_FINGERPRINTS
$trustedOrg = $env:UPGRADE_TRUSTED_ORG
$trustedCountry = $env:UPGRADE_TRUSTED_COUNTRY
if (-not $trustedCountry) { $trustedCountry = "CN" }

# 构建 ldflags
$ldflags = "-X main.version=$Version"

if ($fingerprints) {
    $ldflags += " -X 'sslctlw/upgrade.buildFingerprints=$fingerprints'"
}
if ($trustedOrg) {
    $ldflags += " -X 'sslctlw/upgrade.buildTrustedOrg=$trustedOrg'"
}
if ($trustedCountry) {
    $ldflags += " -X 'sslctlw/upgrade.buildTrustedCountry=$trustedCountry'"
}

if (-not $Debug) {
    $ldflags += " -s -w -H windowsgui"
}

Write-Host "Building sslctlw.exe..."
Write-Host "  Version: $Version"
Write-Host "  Fingerprints: $(if ($fingerprints) { 'configured' } else { 'not set' })"
Write-Host "  Trusted Org: $(if ($trustedOrg) { $trustedOrg } else { 'not set' })"
Write-Host "  Country: $trustedCountry"

$cmd = "go build -ldflags=`"$ldflags`" -o sslctlw.exe"
Write-Host "`nExecuting: $cmd`n"

Invoke-Expression $cmd

if ($LASTEXITCODE -eq 0) {
    Write-Host "`nBuild successful: sslctlw.exe" -ForegroundColor Green
} else {
    Write-Host "`nBuild failed!" -ForegroundColor Red
    exit 1
}
