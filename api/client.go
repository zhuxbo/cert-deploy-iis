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
	"sort"
	"strings"
	"time"

	"sslctlw/util"
)

// CertListResponse 证书列表响应
type CertListResponse struct {
	Code int        `json:"code"`
	Msg  string     `json:"msg"`
	Data []CertData `json:"data"`
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
	Domain      string          `json:"domain"`         // common_name
	Domains     string          `json:"domains"`        // alternative_names (逗号分隔)
	Status      string          `json:"status"`         // active, processing, pending, unpaid
	Certificate string          `json:"certificate"`    // 证书内容
	PrivateKey  string          `json:"private_key"`    // 私钥
	CACert      string          `json:"ca_certificate"` // 中间证书
	ExpiresAt   string          `json:"expires_at"`     // 过期日期
	CreatedAt   string          `json:"created_at"`     // 创建日期
	File        *FileValidation `json:"file,omitempty"` // 文件验证信息（processing 状态时返回）
}

// GetDomainList 返回域名列表
func (c *CertData) GetDomainList() []string {
	if c.Domains == "" {
		return []string{}
	}
	return strings.Split(c.Domains, ",")
}

// Client API 客户端
type Client struct {
	BaseURL        string
	Token          string
	HTTPClient     *http.Client
	insecureURL    bool // 非 HTTPS 且非本地地址
	insecureReason string
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

	allowed, reason := isAllowedAPIURL(c.BaseURL)
	if !allowed {
		c.insecureURL = true
		c.insecureReason = reason
	}

	return c
}

// isAllowedAPIURL 校验 API 地址是否允许（仅 HTTPS 或本地 HTTP）
func isAllowedAPIURL(baseURL string) (bool, string) {
	if baseURL == "" {
		return true, ""
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false, "API 地址无效"
	}

	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return true, ""
	case "http":
		host := strings.ToLower(parsed.Hostname())
		if host == "localhost" {
			return true, ""
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return true, ""
		}
		return false, "API 地址必须使用 HTTPS（localhost/127.0.0.1 除外）"
	default:
		return false, "API 地址必须使用 HTTPS"
	}
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
func checkAPICode(resp *CertListResponse, statusCode int) error {
	if resp.Code != 1 {
		return &APIError{
			StatusCode: statusCode,
			Code:       resp.Code,
			Message:    resp.Msg,
		}
	}
	return nil
}

// parseAPIResponse 解析 API 响应，验证格式
func parseAPIResponse(body []byte, statusCode int) (*CertListResponse, error) {
	// 检查是否是 JSON
	if len(body) == 0 {
		return nil, &APIError{
			StatusCode: statusCode,
			Message:    "返回数据为空",
		}
	}

	// 尝试解析 JSON
	var resp CertListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		// 不是有效的 JSON
		return nil, &APIError{
			StatusCode: statusCode,
			Message:    "返回数据格式错误（非 JSON）",
			RawBody:    string(body),
		}
	}

	// 检查必要字段
	if resp.Code == 0 && resp.Msg == "" && resp.Data == nil {
		return nil, &APIError{
			StatusCode: statusCode,
			Message:    "返回数据格式错误（缺少必要字段）",
			RawBody:    string(body),
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
	if c.BaseURL == "" {
		return nil, fmt.Errorf("部署接口地址未配置")
	}
	if c.Token == "" {
		return nil, fmt.Errorf("部署 Token 未配置")
	}

	apiURL := c.BaseURL
	if domain != "" {
		apiURL += "?domain=" + url.QueryEscape(domain)
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

	// 先检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return nil, handleHTTPError(resp.StatusCode, body)
	}

	// 解析并验证响应格式
	certResp, err := parseAPIResponse(body, resp.StatusCode)
	if err != nil {
		return nil, err
	}

	if err := checkAPICode(certResp, resp.StatusCode); err != nil {
		return nil, err
	}

	return certResp.Data, nil
}

// selectBestCert 从证书列表中选择最佳证书
// 优先级：1. status=active 2. 域名精确匹配 3. 通配符匹配 4. 过期时间最晚
func selectBestCert(certs []CertData, targetDomain string) *CertData {
	if len(certs) == 0 {
		return nil
	}

	targetDomain = util.NormalizeDomain(targetDomain)

	// 复制切片以避免修改输入参数（副作用）
	sorted := make([]CertData, len(certs))
	copy(sorted, certs)

	// 预解析所有证书的域名列表，避免排序时重复 split
	type certMeta struct {
		domains     []string // 预解析的域名列表
		exactMatch  bool     // 精确匹配
		wildcardMatch bool   // 通配符匹配
	}
	metas := make([]certMeta, len(sorted))
	for i := range sorted {
		metas[i].domains = parseDomainList(sorted[i].Domains)
		metas[i].exactMatch = util.NormalizeDomain(sorted[i].Domain) == targetDomain ||
			isExactMatchList(metas[i].domains, targetDomain)
		metas[i].wildcardMatch = containsDomainList(metas[i].domains, targetDomain) ||
			util.MatchDomain(targetDomain, sorted[i].Domain)
	}

	// 按优先级排序
	sort.Slice(sorted, func(i, j int) bool {
		// 优先 active 状态
		if sorted[i].Status == "active" && sorted[j].Status != "active" {
			return true
		}
		if sorted[i].Status != "active" && sorted[j].Status == "active" {
			return false
		}

		// 优先精确匹配（不含通配符）
		if metas[i].exactMatch && !metas[j].exactMatch {
			return true
		}
		if !metas[i].exactMatch && metas[j].exactMatch {
			return false
		}

		// 其次是通配符匹配
		if metas[i].wildcardMatch && !metas[j].wildcardMatch {
			return true
		}
		if !metas[i].wildcardMatch && metas[j].wildcardMatch {
			return false
		}

		// 按过期时间排序（晚的优先）
		return sorted[i].ExpiresAt > sorted[j].ExpiresAt
	})

	// 只返回 active 状态的证书
	if sorted[0].Status == "active" {
		return &sorted[0]
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
	Domain     string `json:"domain"`
	Status     string `json:"status"` // success or failure
	DeployedAt string `json:"deployed_at,omitempty"`
	ServerType string `json:"server_type,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Callback 部署回调
func (c *Client) Callback(ctx context.Context, req *CallbackRequest) error {
	apiURL := c.BaseURL + "/callback"

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
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		if err != nil {
			return fmt.Errorf("回调失败: HTTP %d (读取响应失败: %v)", resp.StatusCode, err)
		}
		return handleHTTPError(resp.StatusCode, body)
	}

	return nil
}

// CSRRequest CSR 提交请求
type CSRRequest struct {
	OrderID          int    `json:"order_id,omitempty"`          // 订单 ID（重签时使用）
	Domain           string `json:"domain"`                      // 主域名
	CSR              string `json:"csr"`                         // PEM 格式 CSR
	ValidationMethod string `json:"validation_method,omitempty"` // 验证方法: file 或 delegation
}

// CSRResponse CSR 提交响应
type CSRResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		OrderID int    `json:"order_id"` // 新建或重签的订单 ID
		Status  string `json:"status"`   // processing, pending 等
	} `json:"data"`
}

// SubmitCSR 提交 CSR 请求签发/重签证书
func (c *Client) SubmitCSR(ctx context.Context, req *CSRRequest) (*CSRResponse, error) {
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

	var csrResp CSRResponse
	if err := json.Unmarshal(body, &csrResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if csrResp.Code != 1 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       csrResp.Code,
			Message:    csrResp.Msg,
		}
	}

	return &csrResp, nil
}

// GetCertByOrderID 按订单 ID 查询证书
func (c *Client) GetCertByOrderID(ctx context.Context, orderID int) (*CertData, error) {
	if c.BaseURL == "" {
		return nil, fmt.Errorf("部署接口地址未配置")
	}
	if c.Token == "" {
		return nil, fmt.Errorf("部署 Token 未配置")
	}

	// 使用 order_id 参数直接查询
	apiURL := fmt.Sprintf("%s?order_id=%d", c.BaseURL, orderID)

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

	certResp, err := parseAPIResponse(body, resp.StatusCode)
	if err != nil {
		return nil, err
	}

	if err := checkAPICode(certResp, resp.StatusCode); err != nil {
		return nil, err
	}

	if len(certResp.Data) == 0 {
		return nil, fmt.Errorf("未找到订单 %d", orderID)
	}

	return &certResp.Data[0], nil
}
