# Deploy API 规范

## 认证

所有请求需要 Bearer Token：

```
Authorization: Bearer <deploy-token>
```

URL 安全校验的生产入口使用系统 DNS 解析并拒绝任一私网、链路本地、未指定或云元数据地址。
单元测试必须通过内部解析器注入固定公网/私网结果，不得依赖外部域名在当前网络中的真实解析状态，
也不得为适配开发机或 CI DNS 策略而削弱 SSRF 校验。

## 接口

### 按订单 ID 查询证书

```
GET /api/deploy?order=123
GET /api/deploy?order=123,456
```

`order` 必填，只接受订单 ID；批量最多 100 个。接口不分页，客户端单次取完即止。
空参数、域名、混合 ID/域名都按 `error_code=invalid_order` 拒绝。

**响应**:

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
        "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
        "certificate": "-----BEGIN CERTIFICATE-----...",
        "private_key": "-----BEGIN PRIVATE KEY-----...",
        "ca_certificate": "-----BEGIN CERTIFICATE-----...",
        "expires_at": "2025-12-31",
        "issued_at": "2025-01-01"
      }
    ],
    "renew_before_days": 14
  }
}
```

批量查询部分命中时只返回命中的订单；单 ID 未命中返回
`error_code=order_not_found`。`field=certificate/private_key` 的 URL 拉取模式只供第三方工具，
sslctlw 不使用。

### 提交 CSR（本机提交模式）

CSR 只需要 CommonName（主域名），不需要 SAN。服务端根据订单配置自动添加 SAN。
每次 POST 前必须先 GET 同一订单，只有本次查询明确返回 `active` 才允许提交；服务端同样
拒绝对其他状态接收新 CSR。同一签发动作的 CSR 在任何状态下都不可原地修改；active 提交新 CSR
会创建后继签发动作，不会覆盖当前 active 动作的 CSR。

```
POST /api/deploy
Content-Type: application/json

{
  "order_id": 123,        // 必填：已有正整数订单 ID
  "domains": "example.com",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "validation_method": "file"
}
```

**响应**:

```json
{
  "code": 1,
  "msg": "success",
  "data": {
    "order_id": 123,
    "status": "processing",
    "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
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
  "deployed_at": "2025-01-01T12:00:00Z"
}
```

失败回调示例：

```
{
  "order_id": 123,
  "status": "failure",
  "deployed_at": "2025-01-01T12:00:00Z",
  "message": "1/2 绑定失败: www.example.com: netsh 绑定失败"
}
```

## 证书选择逻辑

先过滤出 `status=active` 的候选；没有 active 时立即停止，不部署、不回调、不写配置、不建任务。
只在 active 子集中选择最佳证书：

```go
// 进入排序前已过滤 status=active；优先级：域名精确匹配、通配符匹配、过期时间最晚
sort.Slice(certs, func(i, j int) bool {
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

// 按订单 ID 查询
cert, err := client.GetCertByOrderID(ctx, orderID)

// 批量按订单 ID 查询（最多 100 个）
certs, err := client.ListCertsByQuery(ctx, "123,456")

// 部署回调
client.Callback(ctx, &api.CallbackRequest{
    OrderID:    cert.OrderID,
    Status:     "success",
    DeployedAt: time.Now().Format(time.RFC3339),
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
      "renew_mode": "pull",
      "validation_method": "",
      "enabled": true,
      "api": {
        "url": "https://manager.example.com",
        "encrypted_token": "vm:..."
      }
    }
  ],
  "schedule": {
    "renew_mode": "pull",
    "renew_before_days": 14
  }
}
```

| 字段 | 说明 |
|------|------|
| `domain` | 主域名（common_name） |
| `domains` | SAN 域名列表 |
| `order_id` | 订单 ID |
| `renew_mode` | `local` / `pull`；空值继承全局 `schedule.renew_mode` |
| `validation_method` | local 模式验证方式：`file` / `delegation` |
| `api.url` | 证书级部署接口地址 |
| `api.encrypted_token` | 证书级 Token，DPAPI 机器作用域密文（`GetToken()` 解密，禁止直读） |
| `schedule.renew_before_days` | 服务端下发的提前续签天数，默认 14，上限 30 |

## 部署模式

### Pull 模式（默认）

```
查询 OrderID 对应证书
├─ 失败 → 跳过（下次重试）
├─ status 属等待/未知类 → 只 GET，等待下轮
├─ status 属终态/链异常 → 记录 last_order_status，状态变化时告警
├─ 剩余天数 > renew_before_days → 健康跳过
└─ 剩余天数 <= renew_before_days → 拉取 API 私钥 + 证书 → 部署
```

### Local 模式

```
检查 OrderID 为正整数
├─ 否 → 零网络请求，保留既有 pending/元数据，提示重新 setup 选择已有订单
└─ 是 → 查询订单状态
    ├─ 等待/未知状态 → 归一 processing，只 GET 等待
    ├─ active 且存在 pending/CSR metadata
    │   ├─ 服务端 CSR 与 pending 私钥配对 → 本机提交已收敛，校验证书后部署
    │   └─ 不配对 → 清理旧 pending/metadata；先尝试 API/正式本地私钥部署当前 active 证书，
    │       全部不可用时才按门禁建立新的 CSR 尝试并重新计数
    ├─ active 且无签发在途 → 检查续签时机
    │   ├─ 剩余天数 > renew_before_days → 健康跳过
    │   └─ 剩余天数 <= renew_before_days → 生成新 CSR 提交
    └─ 终态/链异常 → 记录展示状态，停止本轮并继续每日查询自愈
```

**尝试上限**：签发尝试（CSR 提交，`issue_retry_count`）与部署尝试
（`deploy_attempt_count`）分别计数；`>= 10` 只阻止建立下一次新尝试，已持久化或已被服务端
接受的第 10 次尝试仍可查询、部署和崩溃恢复。新逻辑意图必须先持久化再执行外部动作；
query-first 恢复和 `processing` 查询不重复计数。任一绑定成功即接纳新证书和私钥并清零证书级
签发/部署计数；任一绑定失败时订单级结果仍为 failure，失败绑定使用独立的最多 10 次重试状态，
不得把整张证书转入 CAPPED。local 新 CSR 必须先原子保存 pending 私钥和 CSR metadata，再递增并
持久化本次计数，之后才允许 POST；POST 结果不确定时保留这些状态，下轮只 GET，不重放 POST。

纯查询不计数，另由 `no_progress_since` 提供 14 天绝对边界；时间戳损坏、回拨或跨度超过
60 天时重新锚定。触顶进入 `CAPPED(capped_phase=stalled)` 并清理 pending 私钥、CSR 和验证文件。
Windows 端以平台字段 `pending_cleanup` 记录“状态已落盘、敏感产物尚待删除”的恢复窗口；
该标记及停更状态下残留的验证文件记录会在任何 API 请求和终态门禁前优先收敛。
active 已签发但无可用配对私钥时，不复用旧 CSR 意图：先清理旧 pending/metadata，再按续签窗口、
安全余量和计数门禁决定是否建立一个新的逻辑尝试；新尝试必须重新计数。

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

CLI `deploy --all` 传 `ScatterDelay=true`，在实际发起 API 请求的证书之间插入随机延迟；
GUI 模式传 `false` 不延迟。区间由启用证书数量 N 决定（`calcSpreadDelay`）：

- 常量：`spreadMin=5`、`spreadMax=120`、`spreadTotalMax=600`（秒）
- 每证书延迟区间上界 = `clamp(600/N, 5, 120)`
- 第一张实际发请求的证书不延迟，其后每张在区间内随机延迟；本地门禁或 token 黑名单零请求跳过
  不占延迟

### 轮内凭据组阻断

`rate_limited`、`token_missing`、`token_invalid`、`token_disabled`、
`account_disabled`、`ip_not_allowed` 会按 `(url, token)` 阻断本轮后续请求。黑名单只在内存
活一轮，不落盘；其他 API 地址或 Token 照常运行。轮末只汇总一条 warning，错误文本必须保留
`error_code`，限流时同时保留 `retry_after`。

### 运行报告消费

`CheckAndDeploy` 返回完整 `RunReport`，CLI `deploy --all` 与 GUI 必须逐类消费
`Results`、`Errors`、`Warnings`、`Attention` 和 `AlreadyRunning`。只有这些集合均为空且
`AlreadyRunning=false` 时才能显示“无需更新”；不得仅凭 `Results` 为空推断成功或无操作。

`Warnings` 是非致命提示，必须与成功结果一同可见；`Attention` 表示需要人工处理，GUI
按失败状态突出显示，CLI 明确输出事项；`AlreadyRunning` 表示已有部署占用运行锁，不得
显示为本次无需更新。

### 部署成功后回填配置

订单内任一绑定成功且 API 返回证书内容非空时，即接纳新证书和私钥、完成证书级生命周期并回填配置；
失败绑定另行持久化和有限重试，订单级回调仍为 failure：

- `updateCertDomains`：`cert.ExtractDomainsFromPEM` 从证书 PEM 提取 CN+SAN，覆盖
  `Domain`/`Domains`；提取失败保持原值（既有值来自 API 查询写入）。
- `updateCertSerial`：回填证书序列号到 `Metadata.CertSerial`。
- 续费导致 `order_id` 变化时同步更新配置中的订单号。
- 连续两轮全部绑定成功但证书序列号未变时，递增 `unchanged_cert_rounds` 并把第二轮起改判为
  failure；该计数不随部署成功清零，只在证书身份真正变化时清零。

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
| `pending` / `approving` | 在途等待，归一 processing |
| `unpaid` / `cancelling` | 可自愈中间态，只 GET，不主动 POST |
| `failed` / `cancelled` / `revoked` / `expired` | 真终态，状态变化时告警 |
| `renewed` / `reissued` | 续费链异常，按终态告警 |
| 未知新增值 | 保守当在途等待，由无进展时限兜底 |

服务端值只写 `metadata.last_order_status`；`last_issue_state` 只表达有无在途 CSR，不能混入订单终态。

## 重试机制

### HTTP 层重试（立即）

- GET、部署回调和自动重签开关遇**网络错误或 HTTP 5xx**最多重试 3 次，间隔
  1 秒、2 秒、4 秒；HTTP 200 且 `code != 1` 的业务拒绝不重试
- 携带非空 `csr` 的提交 POST 是例外：请求一旦可能送达，遇超时、断连、HTTP 5xx、
  响应读取或解析失败均不做传输层重试。保留当前 pending 私钥、CSR metadata 和本次计数，
  下一轮先 GET，再用服务端 CSR 公钥与 pending 私钥判断提交归属
- 服务端按 `order_id` 幂等互斥用于约束并发竞态，不作为客户端立即重放 CSR POST 的理由

### HTTPS 强制

`api.NewClient` 会检查 BaseURL 是否使用 HTTPS并执行 SSRF 校验。非 HTTPS 且非 localhost、
私网、链路本地、未指定或云元数据地址会在请求前直接拒绝。

### 响应体大小限制

所有 HTTP 响应读取使用 `io.LimitReader` 限制为 10MB（`maxResponseSize`），防止异常响应耗尽内存。超过限制时 `io.ReadAll` 会截断。

### sendCallback goroutine 生命周期

`deploy/auto.go` 中的 `sendCallback` 在 goroutine 中执行回调请求。`Deployer` 使用 `callbackWg sync.WaitGroup` 跟踪所有活跃的回调 goroutine。`AutoDeploy` 在返回 `RunReport` 前调用 `deployer.WaitCallbacks()` 确保所有回调完成，避免 CLI 或 GUI 提前结束本轮处理。

### 定时任务重试（延迟）

定时任务每天运行一次，失败的证书下次自动重试：

| 失败点 | HTTP 层 | 定时任务层 |
|--------|---------|-----------|
| 查询订单失败 | 3次重试 | 下次任务重新查询 |
| 提交 CSR 传输结果不确定 | 不重试 | 保留 pending 私钥/CSR metadata；下次只查询并比较服务端 CSR，不重放 POST |
| 提交 CSR 首次确定业务拒绝 | 不重试 | 清理本轮新建 pending，按 error_code 停止本轮 |
| CSR 等待签发 | - | 下次任务查询状态 |
| active 的服务端 CSR 与 pending 不配对 | - | 清理旧 pending/metadata；先尝试 API/正式本地私钥，全部不可用时才按门禁建立新逻辑尝试 |
| 在途状态的服务端 CSR 与 pending 不配对 | - | 清理本机 pending/metadata，只 GET 跟随服务端当前动作 |
| active 且已无任何可用配对私钥 | - | 门禁允许时建立一次新签发意图并计数 |
| 部署失败 | - | 下次任务重新部署 |
