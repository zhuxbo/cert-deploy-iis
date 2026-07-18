# sslctlw Windows 安装脚本
# IIS SSL 证书部署工具
# 使用方法:
#   .\install.ps1 [-ReleaseHost <host>] [-Dev] [-Stable] [-Version <ver>] [-Force] [-Help]
#
# 注意: PowerShell 5.1 默认不启用 TLS 1.2，下载脚本前需先执行:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#
# 服务端要求:
#   管道模式依赖服务端返回 Content-Type: text/plain; charset=utf-8

param(
    [string]$ReleaseHost,
    [switch]$Dev,
    [switch]$Stable,
    [string]$Version,
    [switch]$Force,
    [switch]$Help
)

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
# 全局禁用 Invoke-WebRequest / Invoke-RestMethod 的进度条
# 在脚本级别设置，避免函数作用域导致 PowerShell 5.1 进度条仍然渲染覆盖控制台输出
$ProgressPreference = 'SilentlyContinue'

# 强制启用 TLS 1.2（PowerShell 5.1 默认仅 SSL3/TLS 1.0，无法连接现代 HTTPS 服务）
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {}

# 保存原始控制台编码（StreamWriter 降级时使用，避免 UTF-8 与 GBK 不匹配导致乱码）
$script:OrigConsoleEncoding = [Console]::OutputEncoding

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    [Console]::InputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# 兼容控制台缓冲区损坏的 Windows 终端（0x1F 错误）
# 创建底层输出流作为备用，覆盖 Write-Host：每次调用先尝试原生，失败自动降级
$script:RawOut = try {
    $w = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $script:OrigConsoleEncoding)
    $w.AutoFlush = $true; $w
} catch { $null }
$script:OrigWriteHost = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Utility\Write-Host', 'Cmdlet')
function Write-Host {
    param([Parameter(Position=0)]$Object = '', $ForegroundColor, $BackgroundColor, [switch]$NoNewline, $Separator)
    try {
        $p = @{ Object = $Object }
        if ($ForegroundColor) { $p.ForegroundColor = $ForegroundColor }
        if ($NoNewline) { $p.NoNewline = $true }
        & $script:OrigWriteHost @p
    } catch {
        if ($script:RawOut) {
            $t = if ($Object -ne $null) { $Object.ToString() } else { '' }
            if ($NoNewline) { $script:RawOut.Write($t) } else { $script:RawOut.WriteLine($t) }
        }
    }
}

function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Write-NetworkError {
    param([string]$ErrorMessage, [string]$Url)

    if ($ErrorMessage -match "SSL|TLS|SecureChannel|certificate") {
        Write-Err "TLS 连接失败: $Url"
        Write-Err "修复方法: 在 PowerShell 中先执行以下命令，然后重试:"
        Write-Host "  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" -ForegroundColor Yellow
    } elseif ($ErrorMessage -match "404|NotFound") {
        Write-Err "资源不存在: $Url"
        Write-Err "请检查版本号是否正确"
    } elseif ($ErrorMessage -match "timeout|timed out") {
        Write-Err "连接超时: $Url"
        Write-Err "请检查网络连接或稍后重试"
    } elseif ($ErrorMessage -match "resolve|DNS|NameResolution") {
        Write-Err "域名解析失败: $Url"
        Write-Err "请检查服务器地址是否正确"
    } else {
        Write-Err "网络请求失败: $Url"
        Write-Err "错误: $ErrorMessage"
    }
}

# 发布目录探测
# 先尝试根目录 https://{host}/sslctlw，失败回落到 https://{host}/release/sslctlw
function Resolve-ReleaseUrl {
    param([string]$Host_)
    $Host_ = $Host_.TrimEnd("/")
    if ($Host_ -match "^https?://") { return $Host_ }
    $candidates = @("https://$Host_/sslctlw", "https://$Host_/release/sslctlw")
    foreach ($base in $candidates) {
        try {
            $json = Invoke-RestMethod -Uri "$base/releases.json" -TimeoutSec 10 -ErrorAction Stop
            if ($json.main -or $json.dev) {
                return $base
            }
        } catch {}
    }
    return $null
}

if ($Help) {
    Write-Host "sslctlw 安装脚本 - IIS SSL 证书部署工具"
    Write-Host ""
    Write-Host "选项:"
    Write-Host "  -ReleaseHost HOST  指定服务器（默认 release.cnssl.com）"
    Write-Host "  -Dev               安装测试版（dev 通道）"
    Write-Host "  -Stable            安装稳定版（main 通道，默认）"
    Write-Host "  -Version VER       安装指定版本"
    Write-Host "  -Force             强制重新安装"
    Write-Host "  -Help              显示帮助"
    Write-Host ""
    Write-Host "示例:"
    Write-Host "  .\install.ps1                                   # 使用默认服务器安装"
    Write-Host "  .\install.ps1 -ReleaseHost release.cnssl.com    # 指定服务器安装"
    Write-Host "  .\install.ps1 -Dev                              # 安装最新测试版"
    Write-Host "  .\install.ps1 -Version 1.0.0                    # 安装指定版本"
    Write-Host "  .\install.ps1 -Force                            # 强制重新安装"
    exit 0
}

# 升级地址（参数优先，回落到内置默认域名；再探测根目录 / /release/ 两种布局）
$FallbackHost = "release.cnssl.com"
$TargetHost = if ($ReleaseHost) { $ReleaseHost } else { $FallbackHost }

Write-Info "探测发布目录..."
$ReleaseUrl = Resolve-ReleaseUrl $TargetHost
if (-not $ReleaseUrl) {
    $h = $TargetHost.TrimEnd("/")
    Write-Err "发布目录不可达: https://$h/sslctlw/releases.json 与 https://$h/release/sslctlw/releases.json 均无响应"
    exit 1
}
Write-Info "使用发布地址: $ReleaseUrl"

# --- 辅助函数 ---

function Normalize-Version {
    param([string]$Ver)
    if (-not $Ver.StartsWith("v")) { return "v$Ver" }
    return $Ver
}

function Get-InstalledVersion {
    $ExePath = "C:\sslctlw\sslctlw.exe"
    if (-not (Test-Path $ExePath)) { return "" }
    try {
        $output = & $ExePath version 2>&1
        if ($output -match '(v?\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?)') {
            return Normalize-Version $Matches[1]
        }
    } catch {}
    return ""
}

function Get-TargetVersion {
    param(
        [string]$BaseUrl,
        [string]$RequestedVersion,
        [switch]$UseDev,
        [switch]$UseStable
    )

    $releaseInfo = $null
    $releaseUrl = "$BaseUrl/releases.json"
    try {
        $releaseInfo = Invoke-RestMethod -Uri $releaseUrl -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-NetworkError -ErrorMessage $_.Exception.Message -Url $releaseUrl
        if (-not $RequestedVersion) { return $null }
    }

    $channel = ""
    $targetVersion = ""
    $checksum = ""

    if ($RequestedVersion) {
        $targetVersion = Normalize-Version $RequestedVersion
        if ($UseDev) { $channel = "dev" }
        elseif ($UseStable) { $channel = "main" }
        elseif ($targetVersion -match "-") { $channel = "dev" }
        else { $channel = "main" }
    } else {
        if (-not $releaseInfo) { return $null }
        # releases.json 结构: {channel: {latest, versions}} (spec 6.1)
        if ($UseDev) {
            $channel = "dev"
        } else {
            $channel = "main"
        }
        $chData = $releaseInfo.$channel
        if ($chData -and $chData.latest) {
            $targetVersion = Normalize-Version $chData.latest
        }
        # main 通道无版本时回退到 dev
        if (-not $targetVersion -and $channel -eq "main") {
            $channel = "dev"
            $chData = $releaseInfo.$channel
            if ($chData -and $chData.latest) {
                $targetVersion = Normalize-Version $chData.latest
            }
        }
    }

    if (-not $targetVersion) { return $null }

    # 从 checksums 获取 SHA256 哈希（spec 8.1: 按文件名查找）
    if ($releaseInfo -and $releaseInfo.$channel -and $releaseInfo.$channel.versions) {
        $stripped = $targetVersion.TrimStart("v")
        $artifactKey = "sslctlw-windows-amd64.exe"
        foreach ($v in $releaseInfo.$channel.versions) {
            if ($v.version -eq $stripped) {
                if ($v.checksums -and $v.checksums.$artifactKey) {
                    $checksum = $v.checksums.$artifactKey
                }
                break
            }
        }
    }

    return @{
        Version     = $targetVersion
        Channel     = $channel
        Checksum    = $checksum
        ReleaseInfo = $releaseInfo
    }
}

# 下载安装包，失败时提示输入新的升级域名重试
function Download-Package {
    param([string]$Url, [string]$OutFile)

    try {
        Invoke-WebRequest -Uri $Url -OutFile $OutFile -TimeoutSec 120 -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        Write-NetworkError -ErrorMessage $_.Exception.Message -Url $Url
        return $false
    }
}

# --- 主流程 ---

Write-Info "检测系统..."
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "x86" }
if ($Arch -ne "amd64") {
    Write-Err "不支持的架构: $Arch（仅支持 64 位）"
    exit 1
}

# 检测 IIS
try {
    $iisFeature = Get-WindowsOptionalFeature -Online -FeatureName IIS-WebServer -ErrorAction SilentlyContinue
    if (-not $iisFeature -or $iisFeature.State -ne 'Enabled') {
        Write-Err "未检测到 IIS，sslctlw 需要 IIS 环境"
        Write-Err "请先安装 IIS: Install-WindowsFeature -Name Web-Server"
        exit 1
    } else {
        Write-Info "检测到 IIS"
    }
} catch {
    Write-Warn "IIS 检测失败，继续安装"
}

# 安装目录
$InstallDir = "C:\sslctlw"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# 收紧安装/数据目录 ACL（在创建子目录前，使子目录继承受限 ACL）
# 机器作用域 DPAPI 密文的机密性完全依赖文件系统 ACL：C:\ 默认 DACL 含 BUILTIN\Users
# 读权限且被继承，普通用户可读 config.json（encrypted_token）与 orders\*\private.key 后自行解密。
# 用 SID 形式授权（SYSTEM=S-1-5-18, Administrators=S-1-5-32-544）保证非英文 locale 可用；
# /inheritance:r 断开继承，仅保留这两个主体的完全控制。失败必须中止安装。
Write-Info "收紧安装目录 ACL（仅 SYSTEM 与 Administrators）..."
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Err "收紧目录 ACL 失败（icacls 退出码 $LASTEXITCODE）"
    Write-Err "机器作用域加密要求数据目录仅限管理员访问；ACL 未收紧会使普通用户可读取并解密 Token 与私钥，已中止安装"
    exit 1
}
Write-Info "已收紧安装目录 ACL"

# 数据目录
$DataDir = Join-Path $InstallDir "sslctlw"
foreach ($dir in @("logs")) {
    $path = Join-Path $DataDir $dir
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
}

$LocalExeName = "sslctlw.exe"
$ExePath = Join-Path $InstallDir $LocalExeName

# 获取版本信息
Write-Info "获取版本信息..."
$targetInfo = Get-TargetVersion -BaseUrl $ReleaseUrl -RequestedVersion $Version -UseDev:$Dev -UseStable:$Stable
if (-not $targetInfo) {
    Write-Err "无法获取版本信息"
    exit 1
}

$TargetVersion = $targetInfo.Version
$Channel = $targetInfo.Channel

if ($Channel -eq "dev") {
    Write-Info "目标版本: $TargetVersion (测试版)"
} else {
    Write-Info "目标版本: $TargetVersion (稳定版)"
}

# 检测已安装版本
$CurrentVersion = Get-InstalledVersion
if ($CurrentVersion) {
    if ($CurrentVersion -eq $TargetVersion -and -not $Force) {
        Write-Info "当前版本 $CurrentVersion 已是目标版本，使用 -Force 强制重新安装"
        exit 0
    } elseif ($CurrentVersion -eq $TargetVersion) {
        Write-Info "当前版本: $CurrentVersion，强制重新安装"
    } else {
        Write-Info "安装: $CurrentVersion -> $TargetVersion"
    }
}

# 产物文件名: {product}-{os}-{arch}.{ext}（spec 8.1，版本在目录路径中体现）
$ArtifactName = "sslctlw-windows-amd64.exe"

# 下载到临时文件（避免覆盖正在运行的 exe 导致失败）
$TempExe = "$env:TEMP\$ArtifactName"
$DownloadUrl = "$ReleaseUrl/$Channel/$TargetVersion/$ArtifactName"
Write-Info "下载 $ArtifactName..."
$downloaded = Download-Package -Url $DownloadUrl -OutFile $TempExe

# 下载失败时提示输入新的升级域名
while (-not $downloaded) {
    Write-Host ""
    $newHost = Read-Host "请输入新的升级域名（直接回车退出）"
    if (-not $newHost) {
        Write-Err "下载失败，安装中止"
        exit 1
    }
    $resolved = Resolve-ReleaseUrl $newHost
    if (-not $resolved) {
        $h = $newHost.TrimEnd("/")
        Write-Warn "发布目录不可达: https://$h/sslctlw/releases.json 与 https://$h/release/sslctlw/releases.json 均无响应"
        continue
    }
    $ReleaseUrl = $resolved
    $DownloadUrl = "$ReleaseUrl/$Channel/$TargetVersion/$ArtifactName"
    Write-Info "重试下载: $DownloadUrl"
    $downloaded = Download-Package -Url $DownloadUrl -OutFile $TempExe
}

# SHA256 校验（spec 6.4）
$ExpectedChecksum = $targetInfo.Checksum
if ($ExpectedChecksum -and $ExpectedChecksum.StartsWith("sha256:")) {
    Write-Info "SHA256 校验..."
    $expectedHash = $ExpectedChecksum.Substring(7)
    $actualHash = (Get-FileHash -Path $TempExe -Algorithm SHA256).Hash
    if ($actualHash -ine $expectedHash) {
        Write-Err "SHA256 校验失败"
        Write-Err "  期望: $expectedHash"
        Write-Err "  实际: $actualHash"
        Remove-Item $TempExe -Force -ErrorAction SilentlyContinue
        exit 1
    }
    Write-Info "SHA256 校验通过"
} else {
    Write-Warn "未获取到校验值，跳过 SHA256 校验"
}

# 替换 exe（Windows 上运行中的 exe 无法覆盖，先重命名旧文件）
if (Test-Path $ExePath) {
    # 停止可能运行的 sslctlw 进程
    Get-Process -Name "sslctlw" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    $oldExe = "$ExePath.old"
    Remove-Item $oldExe -Force -ErrorAction SilentlyContinue
    try {
        Rename-Item $ExePath $oldExe -Force -ErrorAction Stop
    } catch {
        Write-Err "无法替换 sslctlw.exe，可能仍在运行"
        Remove-Item $TempExe -Force -ErrorAction SilentlyContinue
        exit 1
    }
}
Move-Item $TempExe $ExePath -Force
Remove-Item "$ExePath.old" -Force -ErrorAction SilentlyContinue

# 写入配置
$ConfigFile = Join-Path $DataDir "config.json"
if (Test-Path $ConfigFile) {
    try {
        $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
    } catch {
        Write-Warn "配置解析失败，创建新配置"
        $cfg = @{}
    }
} else {
    $cfg = @{}
}
$cfg | Add-Member -NotePropertyName "release_url" -NotePropertyValue $ReleaseUrl -Force
$cfg | Add-Member -NotePropertyName "upgrade_channel" -NotePropertyValue $Channel -Force
$tmpCfg = "$ConfigFile.tmp"
# PowerShell 5.1 的 -Encoding UTF8 会写 BOM，Go JSON 解析器不支持 BOM
# 使用 .NET 直接写入 UTF-8 无 BOM
$json = $cfg | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($tmpCfg, $json, (New-Object System.Text.UTF8Encoding $false))
Move-Item -Path $tmpCfg -Destination $ConfigFile -Force

# 添加到 PATH
$Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($Path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$Path;$InstallDir", "Machine")
    Write-Info "已添加 $InstallDir 到系统 PATH"
}
if ($env:Path -notlike "*$InstallDir*") {
    $env:Path = "$env:Path;$InstallDir"
}

# 桌面快捷方式
try {
    $desktopPath = [Environment]::GetFolderPath("CommonDesktopDirectory")
    $shortcutPath = Join-Path $desktopPath "sslctlw.lnk"
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($shortcutPath)
    $shortcut.TargetPath = $ExePath
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.Description = "IIS SSL 证书部署工具"
    $shortcut.Save()
    Write-Info "已创建桌面快捷方式"
} catch {
    Write-Warn "创建桌面快捷方式失败"
}

# 平台差异：spec §7.2 要求安装脚本注册计划任务，
# sslctlw 的计划任务由 setup 命令统一注册（需要证书配置后才能创建），安装脚本不提前注册。

Write-Host ""
Write-Info "安装完成！"
Write-Host ""
Write-Host "使用方法:"
Write-Host "  sslctlw                             # 打开 GUI"
Write-Host "  sslctlw setup --url <url> --token <token>  # 一键部署"
Write-Host "  sslctlw scan                         # 扫描 IIS 站点"
Write-Host "  sslctlw status                       # 查看状态"
Write-Host "  sslctlw help                         # 查看帮助"
Write-Host ""
Write-Host "配置目录: $DataDir"
Write-Host ""
