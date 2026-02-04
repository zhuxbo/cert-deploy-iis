# IIS 证书部署工具

一个轻量级的 IIS SSL 证书管理工具，支持证书安装和 HTTPS 绑定。

## 功能

- 扫描 IIS 站点和绑定信息
- 查看已安装的 SSL 证书
- 安装 PFX 证书到本机证书存储
- 为站点绑定 SSL 证书 (SNI 模式)
- 从证书管理 API 自动获取并安装证书

## 系统要求

- Windows Server 2012+ / Windows 8+
- IIS 8.0+ 已安装
- 管理员权限

## 使用方法

### 基本使用

1. 以管理员身份运行 `sslctlw.exe`
2. 程序自动扫描 IIS 站点和已安装的证书
3. 选择站点，点击"绑定证书"进行 SSL 配置
4. 或点击"安装证书"导入新的 PFX 证书

### 从 API 获取证书

1. 点击"部署接口"按钮
2. 输入部署接口地址（如 `http://manager.example.com/api/deploy`）
3. 输入部署 Token
4. 点击"获取证书"，选择要导入的证书
5. 勾选"自动更新"后点击"导入选中"
6. 证书将自动转换为 PFX 格式并安装到本机，同时自动绑定到匹配的 IIS 站点

## API 接口

工具支持以下 API 接口（Bearer Token 认证）：

**部署接口示例**: `http://manager.example.com/api/deploy`

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | `/api/deploy` | 获取证书列表 |
| POST | `/api/deploy` | 提交 CSR（本地私钥模式） |
| POST | `/api/deploy/callback` | 部署回调 |

## 构建

### 依赖

- Go 1.21+
- Windows 环境 (使用 walk GUI 库)

### 编译

```bash
# 安装依赖
go mod download

# 开发构建
go build -o sslctlw.exe

# 发布构建 (隐藏控制台窗口)
go build -ldflags="-s -w -H windowsgui" -o sslctlw.exe
```

### 生成 Windows 资源 (可选)

如需重新生成 manifest 资源：

```bash
go install github.com/akavel/rsrc@latest
rsrc -manifest main.manifest -o rsrc.syso
```

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Go |
| GUI | [walk](https://github.com/lxn/walk) |
| IIS 管理 | appcmd.exe |
| 证书绑定 | netsh http |
| 证书操作 | PowerShell |
| PEM/PFX 转换 | go-pkcs12 |

## 项目结构

```
sslctlw/
├── main.go           # 入口
├── ui/               # GUI 界面
├── iis/              # IIS 操作 (appcmd/netsh)
├── cert/             # 证书管理
├── api/              # API 客户端
├── main.manifest     # Windows 清单
└── rsrc.syso         # 嵌入资源
```

## 许可证

MIT License
