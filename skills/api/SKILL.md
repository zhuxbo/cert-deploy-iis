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
  "sites": [
    {
      "domain": "example.com",
      "bind_domains": ["example.com", "www.example.com"],
      "port": 443,
      "enabled": true,
      "order_id": 123,
      "use_local_key": false
    }
  ],
  "check_days": 10
}
```

| 字段 | 说明 |
|------|------|
| `domain` | 查询证书用的域名 |
| `bind_domains` | 要绑定到 IIS 的域名（空则使用证书的所有域名） |
| `order_id` | 关联的订单 ID（本地私钥模式使用） |
| `use_local_key` | 是否使用本地私钥模式（默认 false = API 模式） |

## 部署模式

### API 私钥模式（默认）

```
获取证书 → API 返回证书 + 私钥 → 直接使用
```

### 本地私钥模式

```
获取证书 → 检查本地是否有该订单的私钥
  ├─ 有私钥 → 验证匹配
  │    ├─ 匹配 → 使用本地私钥 + API 证书
  │    └─ 不匹配 → 生成新 CSR → 提交重签
  └─ 无私钥 → 生成 CSR → 提交申请 → 保存私钥到本地
```

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
| `processing` | 处理中 |
| `pending` | 等待提交 |
| `unpaid` | 未支付 |
