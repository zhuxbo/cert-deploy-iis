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

### 1. 拉取模式部署流程

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

### 2. 本地私钥模式部署流程

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

## 扩展点

1. **新验证方法**: 修改 `config.ValidateValidationMethod()` 和 API 调用
2. **新部署目标**: 实现 `IISBinder` 接口的其他服务器类型
3. **新存储后端**: 实现 `OrderStore` 接口的云存储版本
