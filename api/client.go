package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
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
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

// API 客户端配置常量
const (
	// DefaultHTTPTimeout HTTP 请求默认超时时间
	DefaultHTTPTimeout = 30 * time.Second
	// MaxRetries 最大重试次数
	MaxRetries = 3
)

// NewClient 创建新的 API 客户端
func NewClient(baseURL, token string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Token:   token,
		HTTPClient: &http.Client{
			Timeout: DefaultHTTPTimeout,
		},
	}
}

// doWithRetry 执行带重试的 HTTP 请求
func (c *Client) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
			// 重置 Body（如果有）
			if req.GetBody != nil {
				body, _ := req.GetBody()
				req.Body = body
			}
		}

		resp, err := c.HTTPClient.Do(req)
		if err != nil {
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
		// 截取前 200 字符
		body := e.RawBody
		if len(body) > 200 {
			body = body[:200] + "..."
		}
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, body)
	}
	return fmt.Sprintf("HTTP %d", e.StatusCode)
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
func (c *Client) GetCertByDomain(domain string) (*CertData, error) {
	certs, err := c.ListCertsByDomain(domain)
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
func (c *Client) ListCertsByDomain(domain string) ([]CertData, error) {
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

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	// 先检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		// 尝试解析 JSON 错误信息
		var errResp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Msg != "" {
			return nil, &APIError{
				StatusCode: resp.StatusCode,
				Code:       errResp.Code,
				Message:    errResp.Msg,
			}
		}
		// 非 JSON 响应，返回状态码错误
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: 接口请求失败", resp.StatusCode),
			RawBody:    string(body),
		}
	}

	// 解析并验证响应格式
	certResp, err := parseAPIResponse(body, resp.StatusCode)
	if err != nil {
		return nil, err
	}

	if certResp.Code != 1 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       certResp.Code,
			Message:    certResp.Msg,
		}
	}

	return certResp.Data, nil
}

// selectBestCert 从证书列表中选择最佳证书
// 优先级：1. status=active 2. 域名精确匹配 3. 通配符匹配 4. 过期时间最晚
func selectBestCert(certs []CertData, targetDomain string) *CertData {
	if len(certs) == 0 {
		return nil
	}

	// 按优先级排序
	sort.Slice(certs, func(i, j int) bool {
		// 优先 active 状态
		if certs[i].Status == "active" && certs[j].Status != "active" {
			return true
		}
		if certs[i].Status != "active" && certs[j].Status == "active" {
			return false
		}

		// 优先精确匹配（不含通配符）
		iExact := certs[i].Domain == targetDomain || isExactMatch(certs[i].Domains, targetDomain)
		jExact := certs[j].Domain == targetDomain || isExactMatch(certs[j].Domains, targetDomain)
		if iExact && !jExact {
			return true
		}
		if !iExact && jExact {
			return false
		}

		// 其次是通配符匹配
		iMatch := containsDomain(certs[i].Domains, targetDomain) || matchesDomain(certs[i].Domain, targetDomain)
		jMatch := containsDomain(certs[j].Domains, targetDomain) || matchesDomain(certs[j].Domain, targetDomain)
		if iMatch && !jMatch {
			return true
		}
		if !iMatch && jMatch {
			return false
		}

		// 按过期时间排序（晚的优先）
		return certs[i].ExpiresAt > certs[j].ExpiresAt
	})

	// 只返回 active 状态的证书
	if certs[0].Status == "active" {
		return &certs[0]
	}

	return nil
}

// matchesDomain 检查模式是否匹配目标域名（支持通配符）
// pattern: *.example.com 匹配 www.example.com, api.example.com
// pattern: example.com 只匹配 example.com（精确匹配）
// 注意：此函数与 util.MatchDomain 参数顺序不同（pattern 在前，target 在后）
func matchesDomain(pattern, target string) bool {
	// util.MatchDomain(bindingHost, certDomain)
	// 这里 target 是 bindingHost，pattern 是 certDomain
	if pattern == target {
		return true // 精确匹配
	}
	// 通配符匹配：*.example.com 匹配 www.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		// 目标域名必须以 suffix 结尾，且前面只有一级子域名
		if strings.HasSuffix(target, suffix) {
			prefix := target[:len(target)-len(suffix)]
			// 前缀不能包含点（即只能是单级子域名）
			if !strings.Contains(prefix, ".") && len(prefix) > 0 {
				return true
			}
		}
	}
	return false
}

// containsDomain 检查域名列表是否包含目标域名（支持通配符）
func containsDomain(domains string, target string) bool {
	for _, d := range strings.Split(domains, ",") {
		if matchesDomain(strings.TrimSpace(d), target) {
			return true
		}
	}
	return false
}

// isExactMatch 检查是否精确匹配（不使用通配符）
func isExactMatch(domains string, target string) bool {
	for _, d := range strings.Split(domains, ",") {
		if strings.TrimSpace(d) == target {
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
func (c *Client) Callback(req *CallbackRequest) error {
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

	resp, err := c.doWithRetry(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("回调失败: HTTP %d (读取响应失败: %v)", resp.StatusCode, err)
		}
		return fmt.Errorf("回调失败: %d - %s", resp.StatusCode, string(body))
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
func (c *Client) SubmitCSR(req *CSRRequest) (*CSRResponse, error) {
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

	resp, err := c.doWithRetry(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误: %d - %s", resp.StatusCode, string(body))
	}

	var csrResp CSRResponse
	if err := json.Unmarshal(body, &csrResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if csrResp.Code != 1 {
		return nil, fmt.Errorf("API 错误: %s", csrResp.Msg)
	}

	return &csrResp, nil
}

// GetCertByOrderID 按订单 ID 查询证书
func (c *Client) GetCertByOrderID(orderID int) (*CertData, error) {
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

	resp, err := c.doWithRetry(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Code int    `json:"code"`
			Msg  string `json:"msg"`
		}
		if json.Unmarshal(body, &errResp) == nil && errResp.Msg != "" {
			return nil, &APIError{
				StatusCode: resp.StatusCode,
				Code:       errResp.Code,
				Message:    errResp.Msg,
			}
		}
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("HTTP %d: 接口请求失败", resp.StatusCode),
			RawBody:    string(body),
		}
	}

	certResp, err := parseAPIResponse(body, resp.StatusCode)
	if err != nil {
		return nil, err
	}

	if certResp.Code != 1 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Code:       certResp.Code,
			Message:    certResp.Msg,
		}
	}

	if len(certResp.Data) == 0 {
		return nil, fmt.Errorf("未找到订单 %d", orderID)
	}

	return &certResp.Data[0], nil
}
