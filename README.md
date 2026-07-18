# IIS 证书部署工具

一个轻量级的 IIS SSL 证书管理工具，支持 CLI 和 GUI 双模式。

## 功能

- 一键部署：`sslctlw setup --url <url> --token <token> [--order <ids>]`
- 扫描 IIS 站点和绑定信息
- 自动部署和续签证书
- 查看已安装的 SSL 证书
- 管理本机证书（导入/删除/清理过期/补齐中级证书）
- 为站点绑定 SSL 证书 (SNI 模式)
- 从证书管理 API 自动获取并安装证书
- 在线升级（签名验证）

## 系统要求

- Windows Server 2012+ / Windows 8+
- IIS 8.0+ 已安装
- 管理员权限

## 安装

```powershell
# PowerShell 一键安装（管理员权限）
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
irm https://release.example.com/sslctlw/install.ps1 -OutFile install.ps1
.\install.ps1 -ReleaseHost release.example.com
```

或手动下载 `sslctlw.exe` 到 `C:\sslctlw\` 并添加到 PATH。

## 使用方法

### CLI 模式

```bash
sslctlw [--debug] <command> [options]

# 一键部署
sslctlw setup --url <url> --token <token>
sslctlw setup --url <url> --token <token> --order <id>
sslctlw setup --url <url> --token <token> --order "123,456"

# 扫描 IIS 站点
sslctlw scan
sslctlw scan --ssl-only

# 部署证书
sslctlw deploy --all
sslctlw deploy --cert <order_id>

# 查看状态
sslctlw status

# 诊断信息收集
sslctlw diagnose
sslctlw diagnose > diag.txt

# 升级
sslctlw upgrade
sslctlw upgrade --check

# 卸载
sslctlw uninstall
sslctlw uninstall --purge

# 版本/帮助
sslctlw version
sslctlw help
```

### GUI 模式

直接运行 `sslctlw.exe`（无参数）进入图形界面。

### 自动部署

计划任务调用 `sslctlw deploy --all` 实现自动续签。`setup` 命令会自动创建计划任务（XML 定义，启用错过补偿：关机错过计划时间后开机补跑）。`status` 命令显示任务上次运行时间与结果，停摆时告警。

## API 接口

工具支持以下 API 接口（Bearer Token 认证）：

**部署接口示例**: `https://manager.example.com/api/deploy`

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/deploy` | 获取证书列表 |
| GET | `/api/deploy?query=id1,id2` | 批量查询证书 |
| GET | `/api/deploy?order_id=123` | 按订单查询 |
| POST | `/api/deploy` | 提交 CSR（本机提交模式） |
| POST | `/api/deploy/callback` | 部署回调 |

API 配置在证书级别，每个证书可以有不同的 API 地址和 Token。

## 构建

### 依赖

- Go 1.24+
- Windows 环境 (使用 windigo GUI 库)

### 编译

```bash
# 发布构建（Windows amd64，注入版本）
./build/build.sh 1.0.0

# 仅签名
./build/sign.sh

# 或直接构建
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=1.0.0" -o dist/sslctlw.exe .
```

正式发布不是单个脚本命令：必须遵守 `skills/remote-release.md` 的 PR、CI、持久化 bundle、全节点暂存、不可变 tag/GitHub Release、恢复和最终验收顺序。平台资产与签名细节见 `skills/build-release.md`；`build/release.sh --dry-run <version>` 可无副作用检查版本分流与执行计划。

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Go |
| GUI | [windigo](https://github.com/rodrigocfd/windigo) |
| IIS 管理 | appcmd.exe |
| 证书绑定 | netsh http |
| 证书操作 | PowerShell |
| PEM/PFX 转换 | go-pkcs12 |
| Token 加密 | Windows DPAPI（机器作用域，SYSTEM 计划任务可解密；机密性依赖数据目录 ACL，数据目录应仅限管理员访问） |

## 项目结构

```
sslctlw/
├── main.go           # 入口：子命令路由 + 无参数开 GUI
├── setup/            # 一键部署核心逻辑（CLI/GUI 共用）
├── ui/               # windigo GUI 界面
├── iis/              # IIS 操作 (appcmd/netsh)
├── cert/             # 证书管理（存储/安装/转换/CSR）
├── api/              # Deploy API 客户端
├── config/           # JSON 配置（DPAPI 加密，证书级 API）
├── deploy/           # 自动部署逻辑（per-cert client）
├── upgrade/          # 在线升级（签名验证/链式升级）
├── util/             # 工具函数
├── build/            # 构建/发布/安装脚本
├── integration/      # 端到端集成测试
├── main.manifest     # Windows 清单
└── rsrc.syso         # 嵌入资源
```

## 许可证

MIT License
