# 构建发布

## 构建命令

```bash
# 开发
go build -o sslctlw.exe

# 发布（隐藏控制台 + 优化体积）
go build -ldflags="-s -w -H windowsgui" -o sslctlw.exe
```

| 参数 | 作用 |
|------|------|
| `-s` | 去除符号表 |
| `-w` | 去除调试信息 |
| `-H windowsgui` | 隐藏控制台 |

## Manifest 嵌入

```bash
# 安装工具
go install github.com/akavel/rsrc@latest

# 生成资源
rsrc -manifest main.manifest -o rsrc.syso

# 构建（自动包含 rsrc.syso）
go build
```

manifest 提供：管理员权限、高 DPI 支持、现代控件样式

## 版本注入

```go
var Version = "dev"
```

```bash
go build -ldflags="-X main.version=1.0.0"
```

## 升级安全配置注入

升级功能需要在编译时注入安全配置（防止运行时被篡改）。

### 环境变量

设置环境变量后，`build.ps1` 会自动注入：

| 环境变量 | 说明 | 示例 |
|----------|------|------|
| `UPGRADE_FINGERPRINTS` | EV 证书 SHA256 指纹（逗号分隔） | `ABC123...,DEF456...` |
| `UPGRADE_TRUSTED_ORG` | 可信组织名称（精确匹配） | `My Company Ltd` |
| `UPGRADE_TRUSTED_COUNTRY` | 国家代码（默认 CN） | `CN` |

```powershell
# 设置环境变量后构建
$env:UPGRADE_FINGERPRINTS = "ABC123..."
$env:UPGRADE_TRUSTED_ORG = "My Company Ltd"
.\build.ps1 -Version "1.0.0"
```

### ldflags 变量对照

| 环境变量 | ldflags 变量 |
|----------|--------------|
| `UPGRADE_FINGERPRINTS` | `sslctlw/upgrade.buildFingerprints` |
| `UPGRADE_TRUSTED_ORG` | `sslctlw/upgrade.buildTrustedOrg` |
| `UPGRADE_TRUSTED_COUNTRY` | `sslctlw/upgrade.buildTrustedCountry` |

### 获取 EV 证书指纹

```powershell
# 对已签名的 EXE 获取证书 SHA256 指纹
$cert = (Get-AuthenticodeSignature .\sslctlw.exe).SignerCertificate
[System.BitConverter]::ToString($cert.GetCertHash('SHA256')).Replace('-','')
```

## 发布清单

1. 获取 EV 证书 SHA256 指纹
2. 构建：`go build -ldflags="-s -w -H windowsgui -X main.version=X.Y.Z -X 'sslctlw/upgrade.buildFingerprints=...' -X 'sslctlw/upgrade.buildTrustedOrg=...'"`
3. 代码签名
4. 验证管理员权限提示
5. 测试 IIS 扫描/证书绑定
6. 测试升级功能
7. `git tag vX.Y.Z && git push --tags`
