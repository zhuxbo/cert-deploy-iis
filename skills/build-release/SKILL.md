# 构建发布

## 构建命令

```bash
# 开发
go build -o sslctlw.exe

# 发布（优化体积；实际由 build/build.sh 注入版本号与升级安全配置）
go build -trimpath -ldflags="-X main.version=1.0.0 -s -w" -o sslctlw.exe
```

| 参数 | 作用 |
|------|------|
| `-trimpath` | 去除构建路径信息 |
| `-s` | 去除符号表 |
| `-w` | 去除调试信息 |
| `-X main.version=` | 注入版本号 |

> **不使用 `-H windowsgui`**：程序构建为 **Console 子系统**应用，GUI 模式在运行时由
> `util.HideConsole()`（`ShowWindow(SW_HIDE)` + `FreeConsole()`）隐藏控制台，使同一个 exe
> 兼作 CLI（子命令，控制台可见）与 GUI（无参数，隐藏控制台）。详见 `skills/windigo-ui/`。

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

升级功能在编译时注入安全配置（防止运行时被篡改）。仅校验 EV 签名的组织名、国家代码和 CA。

### 配置文件

复制 `build/build.conf.example` 为 `build/build.conf` 并填写：

```bash
cp build/build.conf.example build/build.conf
```

| 配置项 | 说明 | 示例 |
|--------|------|------|
| `TRUSTED_ORG` | 可信组织名称（精确匹配） | `My Company Ltd` |
| `TRUSTED_COUNTRY` | 国家代码（默认 CN） | `CN` |

### 环境变量覆盖

环境变量优先级高于 `build.conf`：

| 环境变量 | 对应配置项 |
|----------|------------|
| `UPGRADE_TRUSTED_ORG` | `TRUSTED_ORG` |
| `UPGRADE_TRUSTED_COUNTRY` | `TRUSTED_COUNTRY` |

### ldflags 变量对照

| 配置项 | ldflags 变量 |
|--------|--------------|
| `TRUSTED_ORG` | `sslctlw/upgrade.buildTrustedOrg` |
| `TRUSTED_COUNTRY` | `sslctlw/upgrade.buildTrustedCountry` |

## 升级验证机制

升级下载的 EXE 会经过以下验证：

1. **Authenticode 签名** — WinVerifyTrust 验证签名有效性
2. **组织名称** — 精确匹配编译时预埋的 `TrustedOrg`
3. **国家代码** — 精确匹配 `TrustedCountry`（默认 CN）
4. **CA 颁发者** — 匹配可信 CA 列表（DigiCert/Sectigo/GlobalSign）
5. 全部通过 → 直接升级（无需用户确认）

## 一键发布

```bash
./build/release.sh 1.0.0              # 构建 → 签名 → 发布
./build/release.sh --skip-build 1.0.0 # 跳过构建
./build/release.sh --skip-sign 1.0.0  # 跳过 Authenticode 签名
./build/release.sh --upload-only 1.0.0 # 仅上传
./build/release.sh 1.0.0-dev          # 发布到 dev 通道
```

流程：build.sh 构建 → sign.sh Authenticode 签名 → Ed25519 校验签名 → SSH 上传

### 发布脚本

| 脚本 | 说明 |
|------|------|
| `build/release.sh` | 一键发布（构建 → 签名 → 上传） |
| `build/build.sh` | 构建脚本（测试 → 编译 → 输出到 dist/） |
| `build/sign.sh` | Authenticode 签名（SimplySign + signtool） |
| `build/release-common.sh` | 公共函数库 |

### 配置

| 文件 | 说明 |
|------|------|
| `build/build.conf` | 构建 + 签名配置（TRUSTED_ORG、SIGN_THUMBPRINT 等） |
| `build/release.conf` | 发布服务器配置（SSH、Ed25519 签名密钥） |

### Authenticode 签名

使用 Certum SimplySign Desktop 云端 EV 证书，build.conf 中配置：

| 配置项 | 说明 |
|--------|------|
| `SIGN_THUMBPRINT` | 证书 SHA1 指纹（从 SimplySign Desktop 查看） |
| `SIGN_TSA` | 时间戳服务器（默认 `http://time.certum.pl`） |

前提：SimplySign Desktop 已连接登录。pinless 卡全自动，pin 卡签名时弹出 PIN 输入。

### releases.json 格式

升级检测使用 `releases.json` 数组格式：

```json
{
  "releases": [
    {
      "tag_name": "v1.0.0",
      "name": "v1.0.0",
      "prerelease": false,
      "published_at": "2026-03-14T...",
      "assets": [
        {
          "name": "sslctlw.exe",
          "size": 12345678,
          "browser_download_url": "https://release.example.com/sslctlw/main/v1.0.0/sslctlw.exe"
        }
      ]
    }
  ]
}
```

## 发布清单

1. 确认 SimplySign Desktop 已连接
2. `./build/release.sh X.Y.Z`
3. 验证：`curl <release-url>/releases.json | jq .`
