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

### SNI 模式（推荐）

```bash
netsh http add sslcert hostnameport=example.com:443 certhash=THUMBPRINT appid={...} certstorename=MY
```

### 删除绑定

```bash
netsh http delete sslcert hostnameport=example.com:443
```

### 查看绑定

```bash
netsh http show sslcert
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
