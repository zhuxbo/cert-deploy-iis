# 项目架构

## 概述

sslctlw 是一个 IIS SSL 证书部署工具，使用 Go + windigo 构建，编译为单文件 Windows GUI 应用程序。

## 模块依赖关系

```
┌─────────────────────────────────────────────────────────────┐
│                         main.go                              │
│                      (程序入口)                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                          ui/                                 │
│                    (windigo GUI)                             │
│  mainwindow.go - 主窗口                                      │
│  dialogs_*.go  - 各类对话框                                   │
│  background.go - 后台任务                                    │
└─────────────────────────────────────────────────────────────┘
         │              │              │              │
         ▼              ▼              ▼              ▼
┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐
│   deploy/  │  │    api/    │  │    iis/    │  │   cert/    │
│ (部署逻辑) │  │ (API客户端)│  │ (IIS操作)  │  │ (证书管理) │
└────────────┘  └────────────┘  └────────────┘  └────────────┘
         │              │              │              │
         └──────────────┴──────────────┴──────────────┘
                              │
                              ▼
         ┌────────────────────────────────────────────┐
         │               util/ + config/              │
         │           (工具函数 + 配置管理)             │
         └────────────────────────────────────────────┘
```

## 核心模块说明

### ui/ - 图形界面

| 文件 | 职责 |
|------|------|
| `mainwindow.go` | 主窗口、站点列表、任务面板 |
| `dialogs_api.go` | 部署接口对话框（获取/导入证书） |
| `dialogs_bind.go` | 证书绑定对话框 |
| `dialogs_install.go` | 证书导入对话框 |
| `dialogs_cert_manager.go` | 证书管理器对话框 |
| `background.go` | 后台任务（定时检测） |
| `helpers.go` | UI 辅助组件（ButtonGroup） |
| `log_buffer.go` | 日志缓存组件 |
| `layout.go` | 布局常量 |

### deploy/ - 部署逻辑

| 文件 | 职责 |
|------|------|
| `auto.go` | 自动部署核心逻辑 |
| `interfaces.go` | 依赖注入接口定义 |
| `defaults.go` | 接口默认实现 |

### api/ - API 客户端

| 文件 | 职责 |
|------|------|
| `client.go` | HTTP 客户端、证书查询、CSR 提交、回调 |

### iis/ - IIS 操作

| 文件 | 职责 |
|------|------|
| `appcmd.go` | IIS 站点扫描（appcmd.exe） |
| `netsh.go` | SSL 证书绑定（netsh.exe） |

### cert/ - 证书管理

| 文件 | 职责 |
|------|------|
| `store.go` | Windows 证书存储操作 |
| `pfx.go` | PFX 格式转换 |
| `csr.go` | CSR 生成 |
| `orderstore.go` | 本地订单存储 |

## 核心数据流

### 1. 自动签发模式部署流程

```
用户配置证书 → 定时检测触发
                   │
                   ▼
         API 查询证书状态
         (GetCertByOrderID)
                   │
                   ▼
         检查是否到期/需更新
                   │
                   ▼ (是)
         下载证书 (含私钥)
                   │
                   ▼
         PEM → PFX 转换
                   │
                   ▼
         安装到 Windows 证书存储
                   │
                   ▼
         绑定到 IIS (netsh)
                   │
                   ▼
         发送部署回调
```

### 2. 本机提交模式部署流程

```
用户配置证书 (UseLocalKey=true)
                   │
                   ▼
         检查是否需要续签
                   │
                   ▼ (是)
         本地生成 CSR + 私钥
                   │
                   ▼
         提交 CSR 到 API
         (SubmitCSR)
                   │
                   ▼
         保存私钥到本地
                   │
                   ▼
         等待 CA 签发
         (processing → active)
                   │
                   ▼
         下载证书 (不含私钥)
                   │
                   ▼
         使用本地私钥合成 PFX
                   │
                   ▼
         安装 + 绑定 + 回调
```

## SSL 绑定类型

### SNI 绑定 (IIS 8+)

- 使用 `hostnameport=hostname:port` 参数
- 支持多个证书共用同一 IP:端口
- 客户端通过 SNI 扩展指定主机名

```
netsh http add sslcert hostnameport=www.example.com:443 certhash=... appid=...
```

### IP 绑定 (IIS 7 兼容)

- 使用 `ipport=ip:port` 参数
- 一个 IP:端口 只能绑定一个证书
- 不支持 SNI，需要每个站点单独 IP

```
netsh http add sslcert ipport=0.0.0.0:443 certhash=... appid=...
```

## 配置结构

```json
{
  "api_base_url": "https://api.example.com/deploy",
  "token": "encrypted-token",
  "certificates": [
    {
      "order_id": 12345,
      "domain": "example.com",
      "domains": ["example.com", "www.example.com"],
      "enabled": true,
      "use_local_key": false,
      "auto_bind_mode": true,
      "bind_rules": []
    }
  ],
  "check_interval": 6,
  "renew_days_fetch": 14,
  "renew_days_local": 15
}
```

## 关键设计决策

### 1. 依赖注入

`deploy/interfaces.go` 定义了核心接口，允许测试时使用 Mock 实现：

- `CertConverter` - 证书格式转换
- `CertInstaller` - 证书安装
- `IISBinder` - IIS 绑定
- `APIClient` - API 通信
- `OrderStore` - 订单存储

### 2. 异步 UI

使用 goroutine + `UiThread()` 回调模式，避免 UI 卡死：

```go
go func() {
    result := doSomethingLong()
    app.mainWnd.UiThread(func() {
        updateUI(result)
    })
}()
```

### 3. Context 超时控制

所有 API 调用都使用 context 超时：

```go
ctx, cancel := context.WithTimeout(context.Background(), api.APIQueryTimeout)
defer cancel()
result, err := client.GetCertByOrderID(ctx, orderID)
```

## 测试策略

| 模块 | 测试方式 | 覆盖目标 |
|------|----------|----------|
| api/ | httptest Mock 服务器 | 90%+ |
| deploy/ | 接口 Mock + 集成测试 | 60%+ |
| iis/ | 输出解析测试 + 参数验证 | 55%+ |
| cert/ | 文件系统测试 | 70%+ |
| config/ | 序列化/反序列化测试 | 90%+ |

## 已知限制和设计假设

### 单实例假设

程序假设同一时间只有一个实例运行，没有进程互斥锁。多实例并发运行可能导致：
- 配置文件读写冲突
- 证书重复安装
- 回调重复发送

### Windows 文件权限位

`os.WriteFile(path, data, 0600)` 中的 Unix 权限位（0600）在 Windows 上**不生效**。Windows 使用 ACL 控制文件访问权限。当前代码中的权限位仅作为文档用途，实际安全依赖 Windows NTFS 权限。

### GetWildcardName 域名处理规则

`GetWildcardName` 只替换第一级子域名为通配符：
- `www.example.com` → `*.example.com`
- `a.b.example.com` → `*.b.example.com`（不是 `*.example.com`）
- `example.com`（根域名）→ `*.example.com`

这意味着 IIS7 兼容模式下，多级子域名的证书会绑定到其上一级通配符，而非根域名通配符。

### DPAPI 机器作用域加密

Token 与私钥使用 Windows DPAPI 加密存储，采用**机器作用域**（`CRYPTPROTECT_LOCAL_MACHINE`）。
加密数据绑定到本机（迁移到其他机器无法解密），但同机上的任意账户（含 SYSTEM 计划任务与交互管理员）均可解密——
这是自动续签能在 SYSTEM 计划任务下正常工作的前提。

**机密性权衡**：机器作用域意味着密文的机密性不再由 DPAPI 的账户隔离提供，而完全依赖数据目录的
文件系统 ACL——本机任意能读到 `sslctlw/` 数据目录的账户都能解密其中的 Token 与私钥。
因此**数据目录必须仅限管理员（Administrators/SYSTEM）访问**：默认安装位置（程序同目录）继承
`Program Files` 等受保护目录的 ACL 即可满足；若将程序放在宽松权限目录（如用户目录、根目录），
需自行用 `icacls` 收紧数据目录权限。这是用"账户隔离"换"SYSTEM 自动续签可用"的有意取舍。

旧版本用用户作用域加密的密文（前缀 `v1:` / `v1:dpapi:`）仍兼容解密：能解密时会在配置加载或私钥读取时透明重加密为机器作用域；
若由其他账户加密而无法解密，`GetToken()` 会显式报错提示重新 setup 重录 Token，不再静默失败。

## 扩展点

1. **新验证方法**: 修改 `config.ValidateValidationMethod()` 和 API 调用
2. **新部署目标**: 实现 `IISBinder` 接口的其他服务器类型
3. **新存储后端**: 实现 `OrderStore` 接口的云存储版本
