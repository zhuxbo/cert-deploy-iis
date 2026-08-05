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

## 自动部署任务健康

CLI `status` 与 GUI 统一通过 `GetTaskHealth` 查询任务计划，并用 `EvaluateTaskHealth`
判断健康状态。持久化配置已停止自动部署时直接显示不健康；任务信息查询失败（包括任务
不存在等无法取得健康信息的情况）、从未运行、超过 25 小时未运行或上次结果非零时也统一
显示为不健康，不得把查询失败降级为“未创建”或静默忽略。首次运行已进入运行中或排队状态
时不属于“从未运行”告警。

GUI 的“立即检查”以 10 分钟作为观察超时，而不是工作取消期限。观察超时后部署 worker
继续运行；只有 worker 实际结束后才恢复按钮，数据刷新不参与按钮恢复时机。

`setup` 或 GUI 启用自动部署时，必须先保存启用配置，再触发计划任务首次运行；这样首次
运行的 SYSTEM 进程能读取完整配置，也不会在每日随机执行时间到达前长期显示“从未运行”。
首次运行启动失败须明确报错，但不得删除已成功创建的每日任务或回滚已保存配置。

## 证书存储

| 位置 | 用途 |
|------|------|
| LocalMachine\My | IIS 服务器证书 |
| LocalMachine\Root | 根证书 |
| LocalMachine\CA | 中间证书 |

```powershell
Get-ChildItem Cert:\LocalMachine\My
```

## 注意事项

### netsh 绑定验证

`BindCertificate` 和 `BindCertificateByIP` 在替换前捕获旧绑定完整参数。成功替换与失败回绑复用同一参数构造逻辑，保留捕获到的 AppID，以及高置信度解码的客户端证书协商、CTL 和吊销检查参数；结构化查询不可用而降级 `netsh show` 时只保留已确认的最小字段，并记录高级 SSL 参数无法保真的警告。执行后通过 httpapi 结构化查询验证实际状态，结构化查询不可用时才降级 `netsh show`：

- 目标证书已生效：成功。
- 明确不存在：直接用旧快照恢复。
- 存在异常绑定：先删除异常绑定，再用旧快照恢复。
- 查询失败、状态未知：返回错误且不执行破坏性回滚，避免误删一个可能已经正确生效的新绑定。

恢复后必须再次查询并确认旧证书哈希；不能仅凭 `netsh` 输出判断成功。查询会对瞬时失败或未命中重试一次。

### AddHttpsBindingIfNotExists 只添加绑定不绑证书

`AddHttpsBindingIfNotExists`（原 `AddHttpsBindingWithCert`）通过 appcmd 添加 HTTPS 绑定到 IIS 站点，但**不绑定证书**。证书绑定需要通过 netsh 单独完成。函数已移除未使用的 `certHash` 参数。

### GetWildcardName 多级子域名处理

`GetWildcardName` 将域名转为通配符格式，用于 IIS7 兼容模式。行为：

| 输入 | 输出 | 说明 |
|------|------|------|
| `*.example.com` | `*.example.com` | 已是通配符，不变 |
| `www.example.com` | `*.example.com` | 替换第一级子域名 |
| `a.b.example.com` | `*.b.example.com` | 只替换第一级 |
| `example.com` | `*.example.com` | 根域名加通配符前缀 |
| `localhost` | `localhost` | 无点号，不变 |

## 常见问题

**绑定失败**:
- 证书需在 `LocalMachine\My`
- 需有私钥 (`HasPrivateKey = True`)
- 指纹格式：无空格、无连字符、大写

**访问拒绝**: 需管理员权限
