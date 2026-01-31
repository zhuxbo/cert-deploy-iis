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

**响应** (证书列表):

```json
{
  "code": 1,
  "msg": "success",
  "data": [
    {
      "id": 123,
      "domain": "example.com",
      "domains": ["example.com", "www.example.com"],
      "status": "active",
      "certificate": "-----BEGIN CERTIFICATE-----...",
      "private_key": "-----BEGIN PRIVATE KEY-----...",
      "ca_certificate": "-----BEGIN CERTIFICATE-----...",
      "expires_at": "2025-12-31",
      "created_at": "2025-01-01"
    }
  ]
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

### 提交 CSR（本地私钥模式）

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

```
POST /api/deploy/callback
Content-Type: application/json

{
  "cert_id": 123,
  "domain": "example.com",
  "status": "success",
  "deployed_at": "2025-01-01 12:00:00",
  "server_type": "IIS",
  "message": ""
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

// 查询并选择最佳证书
cert, err := client.GetCertByDomain("example.com")

// 查询证书列表
certs, err := client.ListCertsByDomain("example.com")

// 部署回调
client.Callback(&api.CallbackRequest{
    CertID:     cert.ID,
    Domain:     "example.com",
    Status:     "success",
    DeployedAt: time.Now().Format("2006-01-02 15:04:05"),
    ServerType: "IIS",
})
```

## 配置结构

```json
{
  "api_base_url": "http://manager.example.com",
  "token": "deploy-api-token",
  "certificates": [
    {
      "domain": "example.com",
      "domains": ["example.com", "www.example.com"],
      "order_id": 123,
      "use_local_key": false,
      "enabled": true
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
| `use_local_key` | 本地私钥模式（true）或拉取模式（false） |
| `renew_days_local` | 本地私钥模式：到期前多少天发起续签（默认 15，需 > 服务端 14 天） |
| `renew_days_fetch` | 拉取模式：到期前多少天开始拉取（默认 13，需 < 服务端 14 天） |
| `check_interval` | 定时检测间隔（小时，默认 6） |

## 部署模式

### 拉取模式（UseLocalKey = false，默认）

```
查询 OrderID 对应证书
├─ 失败 → 跳过（下次重试）
├─ status != active → 跳过
├─ 剩余天数 > RenewDaysFetch(13) → 跳过，等待服务端自动续签
└─ 剩余天数 <= RenewDaysFetch(13) → 拉取 API 私钥 + 证书 → 部署
```

**设计意图**：服务端 14 天自动续签，客户端 13 天开始拉取，确保拿到新证书。

### 本地私钥模式（UseLocalKey = true）

```
检查 OrderID > 0?
├─ 是 → 查询订单状态
│   ├─ processing → 跳过，等待签发
│   ├─ active → 检查续签时机
│   │   ├─ 剩余天数 > RenewDaysLocal(15) → 跳过，未到续签时间
│   │   └─ 剩余天数 <= RenewDaysLocal(15) → 检查本地私钥
│   │       ├─ 有私钥且匹配 → 部署证书
│   │       ├─ 有私钥不匹配 → 删除私钥，生成新 CSR 提交
│   │       └─ 无私钥但 API 返回私钥 → 使用 API 私钥部署
│   └─ 查询失败 → 生成新 CSR 提交
└─ 否 → 生成新 CSR 提交
```

**设计意图**：客户端 15 天发起续签，抢在服务端 14 天自动续签之前，确保使用本地私钥。

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

## 证书状态

| 状态 | 说明 |
|------|------|
| `active` | 有效，可部署 |
| `processing` | CSR 已提交，等待 CA 签发 |
| `pending` | 等待提交 |
| `unpaid` | 未支付 |

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

### 定时任务重试（延迟）

定时任务每 `CheckInterval`（默认 6）小时运行一次，失败的证书下次自动重试：

| 失败点 | HTTP 层 | 定时任务层 |
|--------|---------|-----------|
| 查询订单失败 | 3次重试 | 下次任务重新查询 |
| 提交 CSR 失败 | 3次重试 | 下次任务重新提交 |
| CSR 等待签发 | - | 下次任务查询状态 |
| 私钥不匹配 | - | 删除私钥，重新生成 CSR |
| 部署失败 | - | 下次任务重新部署 |
