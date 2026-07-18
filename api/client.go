package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"sslctlw/config"
	"sslctlw/util"
)

// APIResponse API 通用响应（分页格式）
type APIResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Data            []CertData `json:"data"`
		CurrentPage     int        `json:"page"`
		PageSize        int        `json:"page_size"`
		Total           int        `json:"total"`
		RenewBeforeDays int        `json:"renew_before_days"` // 服务端配置的提前续签天数
	} `json:"data"`
}

// APIError API 错误
type APIError struct {
	StatusCode int
	Code       int
	Message    string
	RawBody    string
}

// FileValidation 文件验证信息
type FileValidation struct {
	Path    string `json:"path"`    // 验证文件路径，由接口返回，必须在 /.well-known/ 目录下
	Content string `json:"content"` // 验证文件内容
}

// CertData 证书数据
type CertData struct {
	OrderID     int             `json:"order_id"`
	Domains     string          `json:"domains"`        // alternative_names (逗号分隔)
	Status      string          `json:"status"`         // active, processing, pending, unpaid
	Certificate string          `json:"certificate"`    // 证书内容
	PrivateKey  string          `json:"private_key"`    // 私钥
	CACert      string          `json:"ca_certificate"` // 中间证书
	IssuedAt    string          `json:"issued_at"`      // 签发日期
	ExpiresAt   string          `json:"expires_at"`     // 过期日期
	File        *FileValidation `json:"file,omitempty"` // 文件验证信息（processing 状态时返回）
}

// Domain 返回主域名（domains 的第一个）
func (c *CertData) Domain() string {
	if c.Domains == "" {
		return ""
	}
	if idx := strings.Index(c.Domains, ","); idx >= 0 {
		return strings.TrimSpace(c.Domains[:idx])
	}
	return strings.TrimSpace(c.Domains)
}

// GetDomainList 返回域名列表
func (c *CertData) GetDomainList() []string {
	if c.Domains == "" {
		return []string{}
	}
	parts := strings.Split(c.Domains, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := strings.TrimSpace(p); d != "" {
			result = append(result, d)
		}
	}
	return result
}

// Client API 客户端
type Client struct {
	BaseURL             string
	Token               string
	HTTPClient          *http.Client
	insecureURL         bool // 非 HTTPS 且非本地地址
	insecureReason      string
	LastRenewBeforeDays int // 最近一次 API 响应中的 renew_before_days（0 表示未返回）
}

// API 客户端配置常量
const (
	// MaxRetries 最大重试次数
	MaxRetries = 3
	// APIQueryTimeout 查询类 API 超时时间
	APIQueryTimeout = 30 * time.Second
	// APISubmitTimeout 提交类 API 超时时间
	APISubmitTimeout = 60 * time.Second
	// APICallbackTimeout 回调类 API 超时时间
	APICallbackTimeout = 60 * time.Second
	// maxResponseSize 响应体大小限制 (10MB)
	maxResponseSize = 10 << 20
)

// NewClient 创建新的 API 客户端
func NewClient(baseURL, token string) *Client {
	c := &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: 120 * time.Second, // 兜底超时，实际超时由调用方 context 控制
		},
	}

	allowed, reason := IsAllowedAPIURL(c.BaseURL)
	if !allowed {
		c.insecureURL = true
		c.insecureReason = reason
	}

	return c
}

// IsAllowedAPIURL 校验 API 地址是否允许
// 规则：HTTPS 必需（localhost 除外）+ SSRF 防护（阻止内网/元数据 IP）
func IsAllowedAPIURL(baseURL string) (bool, string) {
	if baseURL == "" {
		return true, ""
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false, "API 地址无效"
	}

	hostname := parsed.Hostname()
	isLocal := isLoopback(hostname)

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		// HTTPS 仍需 SSRF 检查
		if !isLocal {
			if reason := checkSSRF(hostname); reason != "" {
				return false, reason
			}
		}
		return true, ""
	case "http":
		if isLocal {
			return true, ""
		}
		return false, "API 地址必须使用 HTTPS（localhost/127.0.0.1 除外）"
	default:
		return false, "API 地址必须使用 HTTPS"
	}
}

// isLoopback 判断是否为本地回环地址
func isLoopback(hostname string) bool {
	host := strings.ToLower(hostname)
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// checkSSRF 检查目标地址是否存在 SSRF 风险
// 阻止：私有 IP、链路本地、云元数据、未指定地址
func checkSSRF(hostname string) string {
	// 先尝试直接解析为 IP
	if ip := net.ParseIP(hostname); ip != nil {
		return checkSSRFIP(ip)
	}

	// DNS 解析域名
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "" // DNS 解析失败时放行，由后续 HTTP 请求报错
	}
	for _, ip := range ips {
		if reason := checkSSRFIP(ip); reason != "" {
			return reason
		}
	}
	return ""
}

// checkSSRFIP 检查单个 IP 是否为禁止访问的内网地址
func checkSSRFIP(ip net.IP) string {
	if ip.IsPrivate() {
		return fmt.Sprintf("禁止访问内网地址: %s", ip)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Sprintf("禁止访问链路本地地址: %s", ip)
	}
	if ip.IsUnspecified() {
		return fmt.Sprintf("禁止访问未指定地址: %s", ip)
	}
	// 云元数据地址 169.254.169.254
	if ip.Equal(net.ParseIP("169.254.169.254")) {
		return "禁止访问云元数据地址: 169.254.169.254"
	}
	return ""
}

// doWithRetry 执行带重试的 HTTP 请求，支持 context 取消
func (c *Client) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c.insecureURL {
		if c.insecureReason != "" {
			return nil, fmt.Errorf("%s: %s", c.insecureReason, c.BaseURL)
		}
		return nil, fmt.Errorf("API 地址必须使用 HTTPS（localhost/127.0.0.1 除外）: %s", c.BaseURL)
	}

	var lastErr error

	// 将 context 添加到请求
	req = req.WithContext(ctx)

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		// 检查 context 是否已取消
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("请求被取消: %w", ctx.Err())
		default:
		}

		if attempt > 0 {
			// 带 context 的休眠
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("请求被取消: %w", ctx.Err())
			case <-time.After(time.Duration(1<<uint(attempt-1)) * time.Second):
			}
			// 重置 Body（如果有）
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("重置请求体失败: %w", err)
				}
				req.Body = body
			}
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
			// 检查是否因为 context 取消
			if ctx.Err() != nil {
				return nil, fmt.Errorf("请求被取消: %w", ctx.Err())
			}
			lastErr = err
			continue
		}

		// 5xx 错误时关闭响应体并重试
		if resp.StatusCode >= 500 && attempt < MaxRetries {
			_, _ = io.Copy(io.Discard, resp.Body) // 忽略丢弃数据时的错误
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("请求失败（重试 %d 次）: %w", MaxRetries, lastErr)
}

// Error 实现 error 接口
func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.RawBody != "" {
		// 截取前 200 字节（UTF-8 安全）
		body := e.RawBody
		if len(body) > 200 {
			body = util.TruncateString(body, 200) + "..."
		}
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, body)
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

// handleHTTPError 处理 HTTP 错误响应，提取结构化错误信息
func handleHTTPError(statusCode int, body []byte) *APIError {
	var errResp struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Msg != "" {
		return &APIError{
			StatusCode: statusCode,
			Code:       errResp.Code,
			Message:    errResp.Msg,
		}
	}
	return &APIError{
		StatusCode: statusCode,
		Message:    fmt.Sprintf("HTTP %d: 接口请求失败", statusCode),
		RawBody:    string(body),
	}
}

// checkAPICode 验证 API 响应的 code 字段
// parseResponse 解析 API 分页响应
func parseResponse(body []byte, statusCode int) (*APIResponse, error) {
	if len(body) == 0 {
		return nil, &APIError{
			StatusCode: statusCode,
			Message:    "返回数据为空",
		}
	}

	var resp APIResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &APIError{
			StatusCode: statusCode,
			Message:    "返回数据格式错误（非 JSON）",
			RawBody:    string(body),
		}
	}

	if resp.Code != 1 {
		return nil, &APIError{
			StatusCode: statusCode,
			Code:       resp.Code,
			Message:    resp.Msg,
		}
	}

	return &resp, nil
}

// GetCertByDomain 按域名查询证书，返回最佳匹配（active 且最新）
func (c *Client) GetCertByDomain(ctx context.Context, domain string) (*CertData, error) {
	certs, err := c.ListCertsByDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("未找到匹配的证书")
	}

	// 选择最佳证书：优先 active 状态，然后按过期时间排序
	best := selectBestCert(certs, domain)
	if best == nil {
		return nil, fmt.Errorf("未找到可用的证书")
	}

	return best, nil
}

// ListCertsByDomain 按域名查询证书列表
func (c *Client) ListCertsByDomain(ctx context.Context, domain string) ([]CertData, error) {
	return c.queryCerts(ctx, domain)
}

// selectBestCert 从证书列表中选择最佳证书
// 优先级：1. status=active 2. 域名精确匹配 3. 通配符匹配 4. 过期时间最晚
func selectBestCert(certs []CertData, targetDomain string) *CertData {
	if len(certs) == 0 {
		return nil
	}

	targetDomain = util.NormalizeDomain(targetDomain)

	// 将证书数据与预解析的元数据合并为一个结构体，确保排序时索引同步
	type certWithMeta struct {
		cert          CertData
		domains       []string // 预解析的域名列表
		exactMatch    bool     // 精确匹配
		wildcardMatch bool     // 通配符匹配
	}

	items := make([]certWithMeta, len(certs))
	for i := range certs {
		domains := parseDomainList(certs[i].Domains)
		items[i] = certWithMeta{
			cert:    certs[i],
			domains: domains,
			exactMatch: util.NormalizeDomain(certs[i].Domain()) == targetDomain ||
				isExactMatchList(domains, targetDomain),
			wildcardMatch: containsDomainList(domains, targetDomain) ||
				util.MatchDomain(targetDomain, certs[i].Domain()),
		}
	}

	// 按优先级排序
	sort.Slice(items, func(i, j int) bool {
		// 优先 active 状态
		if items[i].cert.Status == "active" && items[j].cert.Status != "active" {
			return true
		}
		if items[i].cert.Status != "active" && items[j].cert.Status == "active" {
			return false
		}

		// 优先精确匹配（不含通配符）
		if items[i].exactMatch && !items[j].exactMatch {
			return true
		}
		if !items[i].exactMatch && items[j].exactMatch {
			return false
		}

		// 其次是通配符匹配
		if items[i].wildcardMatch && !items[j].wildcardMatch {
			return true
		}
		if !items[i].wildcardMatch && items[j].wildcardMatch {
			return false
		}

		// 按过期时间排序（晚的优先）
		return items[i].cert.ExpiresAt > items[j].cert.ExpiresAt
	})

	// 只返回 active 状态的证书
	if items[0].cert.Status == "active" {
		return &items[0].cert
	}

	return nil
}

// parseDomainList 解析逗号分隔的域名列表
func parseDomainList(domains string) []string {
	if domains == "" {
		return nil
	}
	parts := strings.Split(domains, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := strings.TrimSpace(p); d != "" {
			result = append(result, d)
		}
	}
	return result
}

// containsDomain 检查域名列表是否包含目标域名（支持通配符）
func containsDomain(domains string, target string) bool {
	return containsDomainList(parseDomainList(domains), target)
}

// containsDomainList 检查预解析的域名列表是否包含目标域名（支持通配符）
func containsDomainList(domains []string, target string) bool {
	for _, d := range domains {
		if util.MatchDomain(target, d) {
			return true
		}
	}
	return false
}

// isExactMatch 检查是否精确匹配（不使用通配符）
func isExactMatch(domains string, target string) bool {
	return isExactMatchList(parseDomainList(domains), target)
}

// isExactMatchList 检查预解析的域名列表是否精确匹配
func isExactMatchList(domains []string, target string) bool {
	for _, d := range domains {
		if util.NormalizeDomain(d) == target {
			return true
		}
	}
	return false
}

// CallbackRequest 回调请求
type CallbackRequest struct {
	OrderID    int    `json:"order_id"`
	Status     string `json:"status"` // success or failure
	DeployedAt string `json:"deployed_at,omitempty"`
	// Message 失败原因摘要，仅 status=failure 时携带（spec §2.8）。
	// 由 Callback 统一脱敏 + 按 rune 截断至 CallbackMessageMaxRunes，服务端上限 500。
	Message string `json:"message,omitempty"`
}

// CallbackMessageMaxRunes 回调 message 客户端截断上限（按 rune 计，服务端上限 500）
const CallbackMessageMaxRunes = 256

var (
	// pemPrivateKeyBlockRe 匹配完整 PEM 私钥块（BEGIN..END，含各类私钥类型）
	pemPrivateKeyBlockRe = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// pemPrivateKeyDanglingRe 匹配残缺私钥块（有 BEGIN 无 END，截断后可能残留），从 BEGIN 起整段脱敏
	pemPrivateKeyDanglingRe = regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`)
	// bearerBasicRe 匹配 Authorization 中的 Bearer/Basic 凭据，保留方案名脱敏凭据本身
	bearerBasicRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	// secretKeyValueRe 匹配常见 token/password 键值形式。
	secretKeyValueRe = regexp.MustCompile(`(?i)\b(api[_-]?token|token|password|passwd|pwd)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`)
	// absolutePathRe 匹配 Windows 与 Unix 绝对路径；保留前导分隔字符用于可读性。
	windowsAbsolutePathRe = regexp.MustCompile(`(?i)(^|[\s("'=])([a-z]:[\\/][^,;\r\n]*)`)
	uncAbsolutePathRe     = regexp.MustCompile(`(^|[\s("'=])(\\\\[^,;\r\n]+)`)
	unixAbsolutePathRe    = regexp.MustCompile(`(^|[\s("'=])(/[^,;\r\n]+)`)
)

// SanitizeCallbackMessage 清洗失败原因摘要用于回调上报（纯函数，跨平台可测）：
// 先脱敏（去除私钥、凭据、密码和绝对路径），折叠换行，再按 rune 截断至上限。
// 脱敏先于截断，避免截断切断私钥块导致 END 缺失后残留密钥本体。
func SanitizeCallbackMessage(msg string) string {
	if msg == "" {
		return ""
	}
	// 1. 脱敏：完整私钥块优先，再清理残缺 BEGIN 段，最后处理凭据
	msg = pemPrivateKeyBlockRe.ReplaceAllString(msg, "[REDACTED_PRIVATE_KEY]")
	msg = pemPrivateKeyDanglingRe.ReplaceAllString(msg, "[REDACTED_PRIVATE_KEY]")
	msg = bearerBasicRe.ReplaceAllString(msg, "$1 [REDACTED]")
	msg = secretKeyValueRe.ReplaceAllString(msg, "$1=[REDACTED]")
	msg = windowsAbsolutePathRe.ReplaceAllString(msg, "$1[REDACTED_PATH]")
	msg = uncAbsolutePathRe.ReplaceAllString(msg, "$1[REDACTED_PATH]")
	msg = unixAbsolutePathRe.ReplaceAllString(msg, "$1[REDACTED_PATH]")
	// 2. 折叠换行为空格，回调 message 保持单行，规避下游日志/存储注入
	msg = strings.ReplaceAll(msg, "\r", " ")
	msg = strings.ReplaceAll(msg, "\n", " ")
	msg = strings.TrimSpace(msg)
	// 3. 按 rune 截断（多字节安全）
	if runes := []rune(msg); len(runes) > CallbackMessageMaxRunes {
		msg = string(runes[:CallbackMessageMaxRunes])
	}
	return msg
}

// recordRenewBeforeDays 统一接收各 API 响应中的提前续签天数。
// 超过共享上限的异常值直接拒绝，保留最近一次有效值供调用方持久化。
func (c *Client) recordRenewBeforeDays(days int) {
	if days > 0 && days <= config.MaxRenewBeforeDays {
		c.LastRenewBeforeDays = days
	}
}

// Callback 部署回调
func (c *Client) Callback(ctx context.Context, req *CallbackRequest) error {
	apiURL := c.BaseURL + "/callback"

	// 统一在客户端出口处理 message：仅 failure 携带，脱敏 + 按 rune 截断（防调用方遗漏）。
	// req 为调用方一次性构造的临时对象，此处就地清洗不影响其他状态。
	if req.Status == "failure" {
		req.Message = SanitizeCallbackMessage(req.Message)
	} else {
		req.Message = ""
	}

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %w", err)
	}

	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if readErr != nil {
			return fmt.Errorf("回调失败: HTTP %d (读取响应失败: %v)", resp.StatusCode, readErr)
		}
		return handleHTTPError(resp.StatusCode, body)
	}

	// 读取响应中的 renew_before_days（spec 2.8）
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if len(body) > 0 {
		var cbResp struct {
			Data struct {
				RenewBeforeDays int `json:"renew_before_days"`
			} `json:"data"`
		}
		if json.Unmarshal(body, &cbResp) == nil {
			c.recordRenewBeforeDays(cbResp.Data.RenewBeforeDays)
		}
	}

	return nil
}

// UpdateRequest 更新/续签请求（POST）
type UpdateRequest struct {
	OrderID          int    `json:"order_id"`                    // 订单 ID
	CSR              string `json:"csr,omitempty"`               // PEM 格式 CSR（空则服务端自动生成）
	Domains          string `json:"domains,omitempty"`           // 域名（逗号分隔，空则使用当前域名）
	ValidationMethod string `json:"validation_method,omitempty"` // 验证方法: file 或 delegation
}

// UpdateResponseData 提交 CSR 响应的 data 字段（spec §2.6）
// 单个 CertData + renew_before_days，与查询/回调接口一致（spec §2.9）
type UpdateResponseData struct {
	CertData
	RenewBeforeDays int `json:"renew_before_days"` // 服务端配置的提前续签天数
}

// UpdateResponse 更新响应（返回完整证书数据，spec §2.6）
type UpdateResponse struct {
	Code int                `json:"code"`
	Msg  string             `json:"msg"`
	Data UpdateResponseData `json:"data"`
}

// SubmitCSR 提交 CSR 请求签发/重签证书
func (c *Client) SubmitCSR(ctx context.Context, req *UpdateRequest) (*UpdateResponse, error) {
	apiURL := c.BaseURL

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, handleHTTPError(resp.StatusCode, body)
	}

	var updateResp UpdateResponse
	if err := json.Unmarshal(body, &updateResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if updateResp.Code != 1 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       updateResp.Code,
			Message:    updateResp.Msg,
		}
	}

	c.recordRenewBeforeDays(updateResp.Data.RenewBeforeDays)

	return &updateResp, nil
}

// queryCerts 统一查询接口，使用 order 参数
func (c *Client) queryCerts(ctx context.Context, order string) ([]CertData, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("部署接口地址未配置")
	}
	if c.Token == "" {
		return nil, fmt.Errorf("部署 Token 未配置")
	}

	apiURL := c.BaseURL
	if order != "" {
		apiURL += "?order=" + url.QueryEscape(order)
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, handleHTTPError(resp.StatusCode, body)
	}

	apiResp, err := parseResponse(body, resp.StatusCode)
	if err != nil {
		return nil, err
	}

	c.recordRenewBeforeDays(apiResp.Data.RenewBeforeDays)

	return apiResp.Data.Data, nil
}

// ListCertsByQuery 批量查询证书（逗号分隔的 ID/域名）
func (c *Client) ListCertsByQuery(ctx context.Context, query string) ([]CertData, error) {
	return c.queryCerts(ctx, query)
}

// ListAllCerts 分页查询全部证书
func (c *Client) ListAllCerts(ctx context.Context) ([]CertData, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("部署接口地址未配置")
	}
	if c.Token == "" {
		return nil, fmt.Errorf("部署 Token 未配置")
	}

	var allCerts []CertData
	page := 1
	pageSize := 100

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("请求被取消: %w", ctx.Err())
		default:
		}

		apiURL := fmt.Sprintf("%s?page=%d&page_size=%d", c.BaseURL, page, pageSize)

		req, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("创建请求失败: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.doWithRetry(ctx, req)
		if err != nil {
			return nil, err
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("读取响应失败: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, handleHTTPError(resp.StatusCode, body)
		}

		apiResp, err := parseResponse(body, resp.StatusCode)
		if err != nil {
			return nil, err
		}

		c.recordRenewBeforeDays(apiResp.Data.RenewBeforeDays)

		allCerts = append(allCerts, apiResp.Data.Data...)
		totalPages := (apiResp.Data.Total + pageSize - 1) / pageSize
		if page >= totalPages {
			break
		}
		page++
	}

	return allCerts, nil
}

// GetCertByOrderID 按订单 ID 查询证书
func (c *Client) GetCertByOrderID(ctx context.Context, orderID int) (*CertData, error) {
	certs, err := c.queryCerts(ctx, fmt.Sprintf("%d", orderID))
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("未找到订单 %d", orderID)
	}
	return &certs[0], nil
}

// ToggleAutoReissue 切换订单的自动续签模式
// 非关键路径：失败时调用方仅记日志，不中断流程
func (c *Client) ToggleAutoReissue(ctx context.Context, orderID int, autoReissue bool) error {
	apiURL := c.BaseURL + "/auto-reissue"

	reqBody := struct {
		OrderID     int  `json:"order_id"`
		AutoReissue bool `json:"auto_reissue"`
	}{
		OrderID:     orderID,
		AutoReissue: autoReissue,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("序列化请求失败: %w", err)
	}

	httpReq, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.Token)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.doWithRetry(ctx, httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return handleHTTPError(resp.StatusCode, body)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return fmt.Errorf("读取响应失败: %w", err)
	}
	if len(body) > 0 {
		var apiResp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
			Data struct {
				RenewBeforeDays int `json:"renew_before_days"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return fmt.Errorf("解析响应失败: %w", err)
		}
		if apiResp.Code != 1 {
			return &APIError{StatusCode: resp.StatusCode, Code: apiResp.Code, Message: apiResp.Msg}
		}
		c.recordRenewBeforeDays(apiResp.Data.RenewBeforeDays)
	}

	return nil
}
