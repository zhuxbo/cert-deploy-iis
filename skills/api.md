# Deploy API 规范

## 认证

所有请求需要 Bearer Token：

```
Authorization: Bearer <deploy-token>
```

## 接口

### 按域名查询证书

```
GET /api/deploy/cert?domain=example.com
```

**响应** (分页格式):

```json
{
  "code": 1,
  "msg": "success",
  "data": {
    "data": [
      {
        "order_id": 123,
        "domains": "example.com,www.example.com",
        "status": "active",
        "certificate": "-----BEGIN CERTIFICATE-----...",
        "private_key": "-----BEGIN PRIVATE KEY-----...",
        "ca_certificate": "-----BEGIN CERTIFICATE-----...",
        "expires_at": "2025-12-31",
        "issued_at": "2025-01-01"
      }
    ],
    "currentPage": 1,
    "pageSize": 20,
    "total": 1
  }
}
```

**域名匹配规则**:
- 精确匹配 `common_name` 或 `alternative_names`
- 通配符匹配：`api.example.com` 匹配 `*.example.com`

### 按订单 ID 查询证书

```
GET /api/deploy/cert?order_id=123
```

返回格式同上。

### 提交 CSR（本机提交模式）

CSR 只需要 CommonName（主域名），不需要 SAN。服务端根据订单配置自动添加 SAN。

```
POST /api/deploy/csr
Content-Type: application/json

{
  "order_id": 123,        // 重签时使用，新申请时可为 0
  "domain": "example.com",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```

**响应**:

```json
{
  "code": 1,
  "msg": "success",
  "data": {
    "order_id": 123,
    "status": "processing"
  }
}
```

### 部署回调

请求体为三字段 + 可选 `message`（仅 `status=failure` 时携带失败原因摘要，
客户端脱敏 + 按 rune 截断 ≤256，服务端上限 500）。`status` 仅用 `success`/`failure`（回调不发 `pending`）。

**订单级聚合单发**：一个订单内多个绑定的成败合并为**单条**回调（spec §2.8），
全部成功→`success`（不含 message）；任一失败→`failure`（message 取首个失败绑定原因）；
全部冲突跳过而没有处理任何绑定时不产生回调；自动绑定模式找不到目标属于明确部署失败，
产生一条 `failure` 回调。详见“自动部署运行时行为”。

```
POST /api/deploy/callback
Content-Type: application/json

{
  "order_id": 123,
  "status": "success",
  "deployed_at": "2025-01-01 12:00:00"
}
```

失败回调示例：

```
{
  "order_id": 123,
  "status": "failure",
  "deployed_at": "2025-01-01 12:00:00",
  "message": "1/2 绑定失败: www.example.com: netsh 绑定失败"
}
```

## 证书选择逻辑

从列表中选择最佳证书：

```go
// 优先级：1. status=active  2. 域名精确匹配  3. 通配符匹配  4. 过期时间最晚
sort.Slice(certs, func(i, j int) bool {
    // 优先 active 状态
    if certs[i].Status == "active" && certs[j].Status != "active" {
        return true
    }
    // 优先精确匹配（不含通配符）
    // 其次是通配符匹配
    // 按过期时间排序（晚的优先）
    return certs[i].ExpiresAt > certs[j].ExpiresAt
})
```

### 通配符匹配规则

```go
// *.example.com 匹配 www.example.com, api.example.com
// *.example.com 不匹配 example.com（裸域名）
// *.example.com 不匹配 a.b.example.com（多级子域名）
func matchesDomain(pattern, target string) bool {
    if pattern == target {
        return true
    }
    if strings.HasPrefix(pattern, "*.") {
        suffix := pattern[1:] // ".example.com"
        if strings.HasSuffix(target, suffix) {
            prefix := target[:len(target)-len(suffix)]
            return !strings.Contains(prefix, ".") && len(prefix) > 0
        }
    }
    return false
}
```

## Go 客户端用法

```go
client := api.NewClient(baseURL, token)
ctx := context.Background()

// 查询并选择最佳证书
cert, err := client.GetCertByDomain(ctx, "example.com")

// 查询证书列表
certs, err := client.ListCertsByDomain(ctx, "example.com")

// 按订单 ID 查询
cert, err := client.GetCertByOrderID(ctx, orderID)

// 部署回调
client.Callback(&api.CallbackRequest{
    OrderID:    cert.OrderID,
    Status:     "success",
    DeployedAt: time.Now().Format("2006-01-02 15:04:05"),
})
```

## 配置结构

**API 配置在证书级**：每张证书独立的 `api` 字段（`url` + Token），无全局 API 配置。
Windows 平台以 DPAPI 机器作用域加密的 `encrypted_token` 替代 spec §1.4 的明文 `token`
（spec §1.6 允许的安全增强扩展，见 `config.CertAPIConfig`）。

```json
{
  "certificates": [
    {
      "domain": "example.com",
      "domains": ["example.com", "www.example.com"],
      "order_id": 123,
      "use_local_key": false,
      "enabled": true,
      "api": {
        "url": "https://manager.example.com",
        "encrypted_token": "vm:..."
      }
    }
  ],
  "renew_days_local": 15,
  "renew_days_fetch": 13,
  "check_interval": 6
}
```

| 字段 | 说明 |
|------|------|
| `domain` | 主域名（common_name） |
| `domains` | SAN 域名列表 |
| `order_id` | 订单 ID |
| `use_local_key` | 本机提交模式（true）或自动签发模式（false） |
| `api.url` | 证书级部署接口地址 |
| `api.encrypted_token` | 证书级 Token，DPAPI 机器作用域密文（`GetToken()` 解密，禁止直读） |
| `renew_days_local` | 本机提交：到期前多少天发起续签（默认 15，需 > 服务端 14 天） |
| `renew_days_fetch` | 自动签发：到期前多少天开始拉取（默认 13，需 < 服务端 14 天） |
| `check_interval` | 定时检测间隔（小时，默认 6） |

## 部署模式

### 自动签发模式（UseLocalKey = false，默认）

```
查询 OrderID 对应证书
├─ 失败 → 跳过（下次重试）
├─ status != active → 跳过
├─ 剩余天数 > RenewDays(13) → 跳过，未到续签时间
└─ 剩余天数 <= RenewDays(13) → 拉取 API 私钥 + 证书 → 部署
```

**设计意图**：到期前 13 天开始拉取新证书。

### 本机提交模式（UseLocalKey = true）

```
检查 OrderID > 0?
├─ 是 → 查询订单状态
│   ├─ processing → 跳过，等待签发
│   ├─ active → 检查续签时机
│   │   ├─ 剩余天数 > RenewDays(13) → 跳过，未到续签时间
│   │   └─ 剩余天数 <= RenewDays(13) → 检查本地私钥
│   │       ├─ 有私钥且匹配 → 部署证书
│   │       ├─ 有私钥不匹配 → 删除私钥，生成新 CSR 提交
│   │       └─ 无私钥但 API 返回私钥 → 使用 API 私钥部署
│   └─ 查询失败 → 生成新 CSR 提交
└─ 否 → 生成新 CSR 提交
```

**设计意图**：到期前 13 天发起续签，确保使用本地私钥。

**尝试上限**：签发尝试（CSR 提交，`issue_retry_count`）与部署尝试
（`deploy_attempt_count`）分别计数，各自 `>= 10` 时进入 `CAPPED` 并等待人工处理；
新逻辑意图必须先持久化再执行外部动作，崩溃恢复重放、传输层重试和 `processing`
查询不重复计数。全部绑定成功后才清零两类计数；部分失败保留部署状态继续收敛。

**重要**：重新签发（reissue）不会改变 OrderID，只有续费（renew）才会生成新 OrderID。

本地存储目录结构：
```
{程序目录}/data/orders/
  ├── 12345/                    # 订单 ID
  │   ├── private.key           # 私钥（本地生成）
  │   ├── cert.pem              # 证书（从 API 获取）
  │   ├── chain.pem             # 证书链
  │   └── meta.json             # 元数据
  └── 67890/
      └── ...
```

## 自动部署运行时行为

`deploy/auto.go` 的 `AutoDeploy(cfg, d, scatterDelay)` 逐证书执行，运行时行为：

### per-cert client

按"API 配置在证书级"设计，遍历证书时为每张证书用 `NewClientForCert(&cfg.Certificates[i])`
创建独立 API Client（各自的 URL + 解密 Token），不共用全局客户端。

### 分散延迟（deploy --all）

CLI `deploy --all` 传 `scatterDelay=true`，在证书之间插入随机延迟以分散 API 请求压力；
GUI 模式传 `false` 不延迟。区间由启用证书数量 N 决定（`calcSpreadDelay`）：

- 常量：`spreadMin=5`、`spreadMax=120`、`spreadTotalMax=600`（秒）
- 每证书延迟区间上界 = `clamp(600/N, 5, 120)`
- 第一张证书不延迟，其后每张在区间内随机延迟

### 部署成功后回填配置

订单内全部绑定成功且 API 返回证书内容非空时，才完成生命周期并回填配置：

- `updateCertDomains`：`cert.ExtractDomainsFromPEM` 从证书 PEM 提取 CN+SAN，覆盖
  `Domain`/`Domains`；提取失败保持原值（既有值来自 API 查询写入）。
- `updateCertSerial`：回填证书序列号到 `Metadata.CertSerial`。
- 续费导致 `order_id` 变化时同步更新配置中的订单号。

### 订单级聚合回调

一个订单内各绑定的成败在循环内收集，由底层部署函数返回 `deployReport`，编排层在结果
持久化后经 `emitDeployCallback` 生成**单条**订单级回调（spec §2.8）：全成→`success`
（无 message）；任一失败→`failure`，message 为 `"<失败数>/<总数> 绑定失败: <首因>"`；
全部冲突跳过时不回调，自动模式无匹配则明确回调失败。message 由 `api.Client.Callback`
统一脱敏 + 按 rune 截断至 `CallbackMessageMaxRunes = 256`（服务端上限 500）。

## 证书状态

| 状态 | 说明 |
|------|------|
| `active` | 有效，可部署 |
| `processing` | CSR 已提交，等待 CA 签发 |
| `pending` | 等待提交 |
| `approving` | `processing` 与 `active` 之间的短暂中间态 |
| `unpaid` | 未支付 |

客户端将 `pending` / `processing` / `approving` 统一归一为 `processing` 继续等待
（deploy-spec §2.4）；`active` 之后的状态均为订单终态，持久化后停止自动动作。

## 重试机制

### HTTP 层重试（立即）

```go
const maxRetries = 3

func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
    for attempt := 0; attempt <= maxRetries; attempt++ {
        if attempt > 0 {
            time.Sleep(time.Duration(attempt) * time.Second) // 1s, 2s, 3s
        }
        resp, err := c.HTTPClient.Do(req)
        if err == nil {
            return resp, nil
        }
    }
    return nil, fmt.Errorf("请求失败（重试 %d 次）", maxRetries)
}
```

- 仅对**网络错误**重试，业务错误不重试
- 重试间隔递增：1秒、2秒、3秒

### HTTPS 强制

`api.NewClient` 会检查 BaseURL 是否使用 HTTPS。非 HTTPS 且非 localhost 的 URL 会输出警告日志。生产环境应始终使用 HTTPS 传输 Token 和证书私钥。

### 响应体大小限制

所有 HTTP 响应读取使用 `io.LimitReader` 限制为 10MB（`maxResponseSize`），防止异常响应耗尽内存。超过限制时 `io.ReadAll` 会截断。

### sendCallback goroutine 生命周期

`deploy/auto.go` 中的 `sendCallback` 在 goroutine 中执行回调请求。`Deployer` 使用 `callbackWg sync.WaitGroup` 跟踪所有活跃的回调 goroutine。`CheckAndDeploy` 在统计结果前调用 `deployer.WaitCallbacks()` 确保所有回调完成，避免 `-auto` 模式下 `os.Exit` 截断未完成的回调。

### 定时任务重试（延迟）

定时任务每天运行一次，失败的证书下次自动重试：

| 失败点 | HTTP 层 | 定时任务层 |
|--------|---------|-----------|
| 查询订单失败 | 3次重试 | 下次任务重新查询 |
| 提交 CSR 失败 | 3次重试 | 下次任务重新提交 |
| CSR 等待签发 | - | 下次任务查询状态 |
| 私钥不匹配 | - | 删除私钥，重新生成 CSR |
| 部署失败 | - | 下次任务重新部署 |
