# sslctlw 在线升级功能设计方案

## 一、功能概述

为 sslctlw 实现在线自动升级功能，支持：
- 自动/手动检查新版本
- 安全下载并验证 EXE
- 备份旧版本，支持回滚
- EV 代码签名验证

## 二、核心需求

| 项目 | 决定 |
|------|------|
| Release 服务 | GitHub Release 风格 API，配置文件可修改地址 |
| 分发形式 | 直接 EXE 文件 |
| 版本通道 | 稳定版 (stable) + 测试版 (beta) |
| 触发时机 | 启动时检查 + 定时检查 + 手动检查 |
| 升级方式 | 用户确认后升级 |
| 失败处理 | 备份旧版本 + 自动回滚 |
| 安全验证 | EV签名 + 预埋指纹（回退：双因素验证 + 用户确认） |
| 用户体验 | GUI 内嵌显示进度 |

## 三、架构设计

### 3.1 模块依赖图

```
┌─────────────────────────────────────────────────────────────────┐
│                           main.go                                │
│                        (新增升级入口)                             │
└─────────────────────────────────────────────────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
┌─────────────────┐   ┌─────────────────────┐   ┌─────────────────┐
│       ui/       │   │   upgrade/ (新增)    │   │     config/     │
│  (GUI 升级面板)  │──▶│   (升级核心逻辑)      │◀──│  (升级配置扩展)  │
└─────────────────┘   └─────────────────────┘   └─────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
┌─────────────────┐   ┌─────────────────────┐   ┌─────────────────┐
│ ReleaseChecker  │   │   FileDownloader    │   │   SelfUpdater   │
│ (版本检测接口)   │   │   (文件下载接口)      │   │  (自我更新接口)  │
└─────────────────┘   └─────────────────────┘   └─────────────────┘
                                │
                                ▼
                      ┌─────────────────────┐
                      │  SignatureVerifier  │
                      │    (签名验证接口)     │
                      └─────────────────────┘
```

### 3.2 upgrade/ 包结构

```
upgrade/
├── interfaces.go      # 接口定义（核心抽象）
├── types.go           # 数据结构定义
├── checker.go         # 版本检测实现
├── downloader.go      # 文件下载实现
├── verifier.go        # 签名验证实现
├── updater.go         # 自我更新实现
├── upgrade.go         # 升级流程编排
└── *_test.go          # 测试文件
```

## 四、核心接口定义

### 4.1 ReleaseChecker - 版本检测

```go
// ReleaseChecker 版本检测接口
type ReleaseChecker interface {
    // CheckUpdate 检查是否有可用更新
    CheckUpdate(ctx context.Context, channel string, currentVersion string) (*ReleaseInfo, error)
}
```

### 4.2 FileDownloader - 文件下载

```go
// FileDownloader 文件下载接口
type FileDownloader interface {
    // Download 下载文件到指定路径
    Download(ctx context.Context, url string, destPath string, onProgress ProgressCallback) error
}

// ProgressCallback 进度回调
type ProgressCallback func(downloaded, total int64, speed float64)
```

### 4.3 SignatureVerifier - 签名验证

```go
// SignatureVerifier 签名验证接口
type SignatureVerifier interface {
    // Verify 验证文件签名
    // fingerprints: 预埋的证书指纹白名单
    Verify(filePath string, fingerprints []string) (*VerifyResult, error)
}

type VerifyResult struct {
    Valid          bool   // 签名有效
    Fingerprint    string // 证书指纹
    Subject        string // 证书主题（组织名称等）
    Issuer         string // CA 名称
    FingerprintMatch bool  // 指纹是否匹配白名单
    NeedsConfirm   bool   // 是否需要用户确认（回退模式）
    Message        string // 验证消息
}
```

### 4.4 SelfUpdater - 自我更新

```go
// SelfUpdater 自我更新接口
type SelfUpdater interface {
    // PrepareUpdate 准备更新（备份当前版本）
    PrepareUpdate(ctx context.Context, newExePath string) (*UpdatePlan, error)

    // ApplyUpdate 应用更新
    ApplyUpdate(plan *UpdatePlan) error

    // Rollback 回滚到备份版本
    Rollback(plan *UpdatePlan) error
}

type UpdatePlan struct {
    CurrentExePath string // 当前 EXE 路径
    BackupExePath  string // 备份路径
    NewExePath     string // 新版本临时路径
}
```

## 五、数据结构

### 5.1 ReleaseInfo - 版本信息

```go
type ReleaseInfo struct {
    Version      string    `json:"version"`       // 版本号 "1.2.0"
    Channel      string    `json:"channel"`       // "stable" | "beta"
    ReleaseDate  time.Time `json:"release_date"`  // 发布日期
    DownloadURL  string    `json:"download_url"`  // EXE 下载地址
    FileSize     int64     `json:"file_size"`     // 文件大小
    ReleaseNotes string    `json:"release_notes"` // 更新说明
    MinVersion   string    `json:"min_version"`   // 最低要求版本（不可跳过版本）
    Fingerprints []string  `json:"fingerprints"`  // 允许的证书指纹
}
```

### 5.2 UpgradeConfig - 升级配置

```go
type UpgradeConfig struct {
    Enabled        bool     `json:"enabled"`          // 启用自动检查
    Channel        string   `json:"channel"`          // "stable" | "beta"
    CheckInterval  int      `json:"check_interval"`   // 检查间隔（小时）
    LastCheck      string   `json:"last_check"`       // 上次检查时间
    SkippedVersion string   `json:"skipped_version"`  // 用户跳过的版本
    ReleaseURL     string   `json:"release_url"`      // Release API 地址

    // 预埋安全配置（编译时写入）
    Fingerprints   []string // EV 证书指纹白名单
    TrustedOrg     string   // 可信组织名称
    TrustedCountry string   // 可信国家代码
    TrustedCAs     []string // 可信 CA 列表
}
```

## 六、安全验证流程

```
下载新版本 EXE
       │
       ▼
验证 Authenticode 签名有效 ──失败──→ 拒绝，提示签名无效
       │
       │成功
       ▼
检查证书指纹是否在预埋白名单中
       │
       ├─ 匹配 → 通过，继续升级
       │
       └─ 不匹配 → 进入回退验证
              │
              ▼
       ┌────────────────────────────────┐
       │         回退验证（双因素）        │
       │  1. EV 签名有效（Windows 信任）  │
       │  2. 组织名称精确匹配             │
       │  3. 国家代码精确匹配             │
       │  4. CA 在可信列表中              │
       └────────────────────────────────┘
              │
              ├─ 全部通过 → 显示风险提示对话框
              │              │
              │              ├─ 用户确认 → 继续升级
              │              └─ 用户拒绝 → 取消升级
              │
              └─ 任一失败 → 拒绝，提示证书不受信任
```

## 七、升级流程

### 7.1 启动时检查

```
程序启动
    │
    ├─ 检查 AutoCheckUpdate 设置
    │      │
    │      ├─ 禁用 → 跳过检查
    │      │
    │      └─ 启用 → 检查上次检查时间
    │              │
    │              ├─ 间隔 < CheckInterval → 跳过
    │              │
    │              └─ 间隔 >= CheckInterval → 异步检查更新
    │                     │
    │                     ├─ 无更新 → 更新 LastCheck
    │                     │
    │                     └─ 有更新 → 状态栏提示，用户点击后显示详情
    │
    └─ 继续正常启动 GUI
```

### 7.2 用户触发升级

```
用户点击"检查更新" / 点击状态栏提示
    │
    ▼
显示升级对话框
    │
    ├─ 版本信息和更新说明
    ├─ 进度条（下载时显示）
    └─ 按钮：[立即更新] [跳过此版本] [稍后提醒]
    │
    ├─ [立即更新]
    │      │
    │      ▼
    │   下载 EXE (显示进度)
    │      │
    │      ▼
    │   验证 EV 签名
    │      │
    │      ├─ 指纹匹配 → 继续
    │      ├─ 指纹不匹配但双因素验证通过 → 显示风险提示，用户确认
    │      └─ 验证失败 → 提示错误，取消升级
    │      │
    │      ▼
    │   备份当前版本 → 替换 EXE
    │      │
    │      ├─ 成功 → 提示重启
    │      │
    │      └─ 失败 → 自动回滚，提示错误
    │
    ├─ [跳过此版本] → 记录 SkippedVersion
    │
    └─ [稍后提醒] → 关闭对话框
```

## 八、Release API 设计

### 8.1 端点

```
GET {release_url}/latest
GET {release_url}/latest?channel=beta
```

### 8.2 响应格式（GitHub Release 兼容）

```json
{
  "tag_name": "v1.2.0",
  "name": "sslctlw v1.2.0",
  "body": "## 更新内容\n- 新增功能...\n\n<!-- metadata: min_version=1.0.0 -->",
  "prerelease": false,
  "published_at": "2026-02-06T12:00:00Z",
  "assets": [
    {
      "name": "sslctlw.exe",
      "size": 10485760,
      "browser_download_url": "https://example.com/releases/v1.2.0/sslctlw.exe"
    }
  ]
}
```

### 8.3 元数据嵌入

在 `body` 中使用 HTML 注释嵌入元数据：

```
<!-- metadata: min_version=1.0.0; fingerprints=AA:BB:...,CC:DD:... -->
```

## 九、配置扩展

在 `config/config.go` 中添加：

```go
type Config struct {
    // ... 现有字段 ...

    // 升级配置
    UpgradeEnabled   bool   `json:"upgrade_enabled"`    // 启用自动检查，默认 true
    UpgradeChannel   string `json:"upgrade_channel"`    // "stable" | "beta"，默认 "stable"
    UpgradeInterval  int    `json:"upgrade_interval"`   // 检查间隔（小时），默认 24
    LastUpgradeCheck string `json:"last_upgrade_check"` // 上次检查时间
    SkippedVersion   string `json:"skipped_version"`    // 跳过的版本
    ReleaseURL       string `json:"release_url"`        // Release API 地址
}
```

## 十、UI 集成

### 10.1 主窗口修改

- 工具栏添加"检查更新"按钮
- 状态栏显示更新提示（有新版本时）

### 10.2 升级对话框

- 模态对话框显示版本信息
- 进度条显示下载进度
- 风险提示对话框（回退验证时）

## 十一、文件变更清单

### 新增文件

| 文件 | 说明 |
|------|------|
| `upgrade/interfaces.go` | 接口定义 |
| `upgrade/types.go` | 数据结构 |
| `upgrade/checker.go` | 版本检测实现 |
| `upgrade/downloader.go` | 文件下载实现 |
| `upgrade/verifier.go` | 签名验证实现 |
| `upgrade/updater.go` | 自我更新实现 |
| `upgrade/upgrade.go` | 升级流程编排 |
| `upgrade/version.go` | 版本号比较 |
| `ui/dialogs_upgrade.go` | 升级对话框 |

### 修改文件

| 文件 | 修改内容 |
|------|----------|
| `main.go` | 添加版本变量导出，启动时检查 |
| `config/config.go` | 添加升级配置字段 |
| `ui/mainwindow.go` | 添加检查更新按钮，状态栏提示 |

## 十二、实现优先级

| 阶段 | 功能 | 文件 |
|------|------|------|
| P0 | 接口定义和数据结构 | interfaces.go, types.go |
| P0 | 版本检测 | checker.go |
| P0 | 文件下载 | downloader.go |
| P1 | Authenticode 签名验证 | verifier.go |
| P1 | 自我更新（备份+替换+回滚） | updater.go |
| P1 | 升级流程编排 | upgrade.go |
| P2 | GUI 对话框 | dialogs_upgrade.go |
| P2 | 主窗口集成 | mainwindow.go |
| P3 | 定时检查 | 复用现有后台任务 |
| P3 | Beta 通道切换 | 配置界面 |

## 十三、测试策略

### 单元测试

- Mock 所有外部依赖（HTTP、文件系统、Windows API）
- 测试版本比较逻辑
- 测试签名验证逻辑分支

### 集成测试

- 使用 httptest 模拟 Release API
- 测试完整升级流程
- 测试回滚流程

## 十四、安全注意事项

1. **预埋配置不可修改**：证书指纹、可信组织名称等编译时写入
2. **HTTPS 强制**：下载地址必须使用 HTTPS
3. **临时文件清理**：升级完成/失败后清理临时文件
4. **备份保留**：保留最近一个版本的备份，以便手动恢复
