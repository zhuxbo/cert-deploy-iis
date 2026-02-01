# IIS 运维

## appcmd 路径

```go
filepath.Join(os.Getenv("windir"), "System32", "inetsrv", "appcmd.exe")
```

## 列出站点

```bash
appcmd list site /xml
```

```xml
<appcmd>
  <SITE SITE.NAME="Default" SITE.ID="1" bindings="http/*:80:,https/*:443:example.com" state="Started"/>
</appcmd>
```

## 绑定格式解析

`protocol/IP:Port:Host` → `https/*:443:example.com`

```go
parts := strings.SplitN(binding, "/", 2)  // ["https", "*:443:example.com"]
segments := strings.Split(parts[1], ":")  // ["*", "443", "example.com"]
```

## netsh 证书绑定

### 两种绑定类型

| 类型 | 命令参数 | netsh 输出 | 用途 |
|------|---------|-----------|------|
| **SNI 绑定** | `hostnameport=` | `Hostname:port: xxx:443` | 按主机名匹配，支持多证书 |
| **IP 绑定** | `ipport=` | `IP:port: 0.0.0.0:443` | 空主机名，泛匹配 |

### SNI 绑定（推荐）

```bash
# 添加
netsh http add sslcert hostnameport=example.com:443 certhash=THUMBPRINT appid={...} certstorename=MY

# 删除
netsh http delete sslcert hostnameport=example.com:443
```

### IP 绑定（空主机名）

```bash
# 添加（用于通配符泛匹配或 IP 证书）
netsh http add sslcert ipport=0.0.0.0:443 certhash=THUMBPRINT appid={...} certstorename=MY

# 删除
netsh http delete sslcert ipport=0.0.0.0:443
```

**注意**: IP 绑定每端口只能绑定一次（如 `0.0.0.0:443` 只能一个证书）

### 查看绑定

```bash
netsh http show sslcert
```

## 自动部署绑定策略

### 自动处理（SNI 绑定）

- `FindBindingsForDomains` 只查找 SNI 绑定
- 按证书域名匹配已有绑定（支持通配符匹配子域名）
- 自动更新匹配绑定的证书

### 手工处理（IP 绑定）

以下场景需用户通过规则配置或手工绑定：

1. **通配符证书泛匹配** - `*.example.com` 绑定到 `0.0.0.0:443`
2. **IP 地址证书** - 证书 CN 是 IP 地址

原因：IP 绑定每端口只能一个，自动处理可能冲突

### SSLBinding 结构

```go
type SSLBinding struct {
    HostnamePort string
    CertHash     string
    IsIPBinding  bool  // true: IP:port, false: Hostname:port
    // ...
}
```

## 证书存储

| 位置 | 用途 |
|------|------|
| LocalMachine\My | IIS 服务器证书 |
| LocalMachine\Root | 根证书 |
| LocalMachine\CA | 中间证书 |

```powershell
Get-ChildItem Cert:\LocalMachine\My
```

## 常见问题

**绑定失败**:
- 证书需在 `LocalMachine\My`
- 需有私钥 (`HasPrivateKey = True`)
- 指纹格式：无空格、无连字符、大写

**访问拒绝**: 需管理员权限
