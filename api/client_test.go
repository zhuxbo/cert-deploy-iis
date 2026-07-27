package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"sslctlw/util"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type callbackReadErrorBody struct{}

func (callbackReadErrorBody) Read([]byte) (int, error) {
	return 0, errors.New("响应读取失败")
}

func (callbackReadErrorBody) Close() error {
	return nil
}

func TestNewClient(t *testing.T) {
	client := NewClient("https://api.example.com/", "test-token")

	if client.BaseURL != "https://api.example.com" {
		t.Errorf("BaseURL 末尾斜杠应被移除, got %q", client.BaseURL)
	}

	if client.Token != "test-token" {
		t.Errorf("Token = %q, want %q", client.Token, "test-token")
	}

	if client.HTTPClient == nil {
		t.Error("HTTPClient 不应为 nil")
	}
}

func TestIsAllowedAPIURL(t *testing.T) {
	lookupIP := func(hostname string) ([]net.IP, error) {
		switch hostname {
		case "private.example.test":
			return []net.IP{net.ParseIP("10.0.0.8")}, nil
		default:
			return []net.IP{net.ParseIP("203.0.113.10")}, nil
		}
	}

	tests := []struct {
		name      string
		baseURL   string
		wantAllow bool
	}{
		{"空地址", "", true},
		{"HTTPS 正常", "https://api.example.com", true},
		{"HTTP localhost", "http://localhost:8080", true},
		{"HTTP 回环 IPv4", "http://127.0.0.1:8080", true},
		{"HTTP 回环 IPv6", "http://[::1]:8080", true},
		{"HTTP 子域名绕过", "http://localhost.evil.com", false},
		{"HTTP 用户信息绕过", "http://127.0.0.1@evil.com", false},
		{"HTTP 非本地", "http://example.com", false},
		{"HTTPS DNS 解析到私网", "https://private.example.test", false},
		{"非 HTTPS 协议", "ftp://example.com", false},
		{"缺少协议", "api.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, reason := isAllowedAPIURL(tt.baseURL, lookupIP)
			if allowed != tt.wantAllow {
				t.Errorf("IsAllowedAPIURL(%q) = %v, want %v (reason: %s)", tt.baseURL, allowed, tt.wantAllow, reason)
			}
			if !allowed && reason == "" {
				t.Errorf("IsAllowedAPIURL(%q) 返回禁止时必须给出原因", tt.baseURL)
			}
		})
	}
}

func TestCertData_GetDomainList(t *testing.T) {
	tests := []struct {
		name    string
		domains string
		want    int
	}{
		{"空字符串", "", 0},
		{"单个域名", "example.com", 1},
		{"多个域名", "example.com,www.example.com,api.example.com", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CertData{Domains: tt.domains}
			got := c.GetDomainList()
			if len(got) != tt.want {
				t.Errorf("GetDomainList() 返回 %d 个域名, want %d", len(got), tt.want)
			}
		})
	}
}

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want string
	}{
		{
			"有消息",
			&APIError{StatusCode: 400, Message: "Bad Request"},
			"Bad Request",
		},
		{
			"有原始响应",
			&APIError{StatusCode: 500, RawBody: "Server Error"},
			"HTTP 500: Server Error",
		},
		{
			"只有状态码",
			&APIError{StatusCode: 404},
			"HTTP 404",
		},
		{
			"长响应被截断",
			&APIError{StatusCode: 500, RawBody: string(make([]byte, 300))},
			"HTTP 500: " + string(make([]byte, 200)) + "...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name       string
		certDomain string
		target     string
		want       bool
	}{
		// 精确匹配
		{"精确匹配", "example.com", "example.com", true},
		{"精确不匹配", "example.com", "other.com", false},

		// 通配符匹配
		{"通配符-www", "*.example.com", "www.example.com", true},
		{"通配符-api", "*.example.com", "api.example.com", true},
		{"通配符-不匹配根域名", "*.example.com", "example.com", false},
		{"通配符-不匹配多级", "*.example.com", "a.b.example.com", false},
		{"通配符-不匹配不同域名", "*.example.com", "www.other.com", false},

		// 边界情况
		{"空模式", "", "example.com", false},
		{"空目标", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := util.MatchDomain(tt.target, tt.certDomain)
			if got != tt.want {
				t.Errorf("util.MatchDomain(%q, %q) = %v, want %v", tt.target, tt.certDomain, got, tt.want)
			}
		})
	}
}

func TestContainsDomain(t *testing.T) {
	tests := []struct {
		name    string
		domains string
		target  string
		want    bool
	}{
		{"包含精确", "example.com,www.example.com", "example.com", true},
		{"包含通配符", "*.example.com", "www.example.com", true},
		{"不包含", "example.com,other.com", "test.com", false},
		{"空列表", "", "example.com", false},
		{"带空格", "example.com, www.example.com", "www.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsDomain(tt.domains, tt.target)
			if got != tt.want {
				t.Errorf("containsDomain(%q, %q) = %v, want %v", tt.domains, tt.target, got, tt.want)
			}
		})
	}
}

func TestIsExactMatch(t *testing.T) {
	tests := []struct {
		name    string
		domains string
		target  string
		want    bool
	}{
		{"精确匹配", "example.com,www.example.com", "example.com", true},
		{"不匹配通配符", "*.example.com", "www.example.com", false},
		{"不匹配", "example.com", "other.com", false},
		{"空列表", "", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isExactMatch(tt.domains, tt.target)
			if got != tt.want {
				t.Errorf("isExactMatch(%q, %q) = %v, want %v", tt.domains, tt.target, got, tt.want)
			}
		})
	}
}

func TestSelectBestCert(t *testing.T) {
	tests := []struct {
		name         string
		certs        []CertData
		targetDomain string
		wantOrderID  int
	}{
		{
			"空列表",
			[]CertData{},
			"example.com",
			0,
		},
		{
			"优先 active 状态",
			[]CertData{
				{OrderID: 1, Domains: "example.com", Status: "pending", ExpiresAt: "2025-01-01"},
				{OrderID: 2, Domains: "example.com", Status: "active", ExpiresAt: "2024-06-01"},
			},
			"example.com",
			2,
		},
		{
			"优先精确匹配",
			[]CertData{
				{OrderID: 1, Domains: "*.example.com", Status: "active", ExpiresAt: "2025-01-01"},
				{OrderID: 2, Domains: "www.example.com", Status: "active", ExpiresAt: "2024-06-01"},
			},
			"www.example.com",
			2,
		},
		{
			"优先过期时间晚",
			[]CertData{
				{OrderID: 1, Domains: "example.com", Status: "active", ExpiresAt: "2024-06-01"},
				{OrderID: 2, Domains: "example.com", Status: "active", ExpiresAt: "2025-01-01"},
			},
			"example.com",
			2,
		},
		{
			"无 active 返回 nil",
			[]CertData{
				{OrderID: 1, Domains: "example.com", Status: "pending", ExpiresAt: "2025-01-01"},
			},
			"example.com",
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectBestCert(tt.certs, tt.targetDomain)
			if tt.wantOrderID == 0 {
				if got != nil {
					t.Errorf("selectBestCert() = %+v, want nil", got)
				}
			} else {
				if got == nil {
					t.Errorf("selectBestCert() = nil, want OrderID=%d", tt.wantOrderID)
				} else if got.OrderID != tt.wantOrderID {
					t.Errorf("selectBestCert().OrderID = %d, want %d", got.OrderID, tt.wantOrderID)
				}
			}
		})
	}
}

func TestParseAPIResponse(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		statusCode int
		wantErr    bool
		wantCode   int
	}{
		{
			"有效响应",
			`{"code":1,"msg":"success","data":{"data":[],"currentPage":1,"pageSize":20,"total":0}}`,
			200,
			false,
			1,
		},
		{
			"空响应",
			"",
			200,
			true,
			0,
		},
		{
			"非 JSON",
			"not json",
			200,
			true,
			0,
		},
		{
			"缺少必要字段",
			`{}`,
			200,
			true,
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResponse([]byte(tt.body), tt.statusCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Code != tt.wantCode {
				t.Errorf("parseResponse().Code = %d, want %d", got.Code, tt.wantCode)
			}
		})
	}
}

func TestListCertsByQuery_Validation(t *testing.T) {
	// 测试配置验证
	tests := []struct {
		name    string
		baseURL string
		token   string
		wantErr bool
	}{
		{"缺少 BaseURL", "", "token", true},
		{"缺少 Token", "https://api.example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.baseURL, tt.token)
			_, err := client.ListCertsByQuery(context.Background(), "123")
			if (err != nil) != tt.wantErr {
				t.Errorf("ListCertsByQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestListCertsByQuery_MockServer(t *testing.T) {
	// 创建 mock 服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证请求头
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0,
				"msg":  "未授权",
			})
			return
		}

		// 返回成功响应
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"order_id":    123,
						"domains":     "example.com",
						"status":      "active",
						"expires_at":  "2025-01-01",
						"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
						"private_key": "-----BEGIN TEST KEY-----\ntest\n-----END TEST KEY-----",
					},
				},
				"currentPage": 1,
				"pageSize":    20,
				"total":       1,
			},
		})
	}))
	defer server.Close()

	// 测试成功请求
	client := NewClient(server.URL, "test-token")
	certs, err := client.ListCertsByQuery(context.Background(), "123")
	if err != nil {
		t.Fatalf("ListCertsByQuery() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("ListCertsByQuery() 返回 %d 个证书, want 1", len(certs))
	}

	if certs[0].OrderID != 123 {
		t.Errorf("certs[0].OrderID = %d, want 123", certs[0].OrderID)
	}

	// 测试未授权
	badClient := NewClient(server.URL, "wrong-token")
	_, err = badClient.ListCertsByQuery(context.Background(), "123")
	if err == nil {
		t.Error("使用错误 token 应该返回错误")
	}
}

func TestGetCertByOrderID_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order := r.URL.Query().Get("order")
		if order == "123" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 1,
				"msg":  "success",
				"data": map[string]interface{}{
					"data": []map[string]interface{}{
						{
							"order_id":   123,
							"domains":    "example.com",
							"status":     "active",
							"expires_at": "2025-01-01",
						},
					},
					"currentPage": 1,
					"pageSize":    20,
					"total":       1,
				},
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 1,
				"msg":  "success",
				"data": map[string]interface{}{
					"data":        []map[string]interface{}{},
					"currentPage": 1,
					"pageSize":    20,
					"total":       0,
				},
			})
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	// 测试存在的订单
	cert, err := client.GetCertByOrderID(context.Background(), 123)
	if err != nil {
		t.Fatalf("GetCertByOrderID(123) error = %v", err)
	}
	if cert.OrderID != 123 {
		t.Errorf("cert.OrderID = %d, want 123", cert.OrderID)
	}

	// 测试不存在的订单
	_, err = client.GetCertByOrderID(context.Background(), 999)
	if err == nil {
		t.Error("GetCertByOrderID(999) 应该返回错误")
	}
}

func TestCallback_RejectsInvalidBusinessResponsesWithoutRecordingRenewDays(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "code为0", body: `{"code":0,"msg":"拒绝回调","data":{"renew_before_days":22}}`},
		{name: "空响应", body: ""},
		{name: "非法JSON", body: `{"code":1`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := NewClient(server.URL+"/api/deploy", "test-token")
			client.LastRenewBeforeDays = 14
			err := client.Callback(context.Background(), &CallbackRequest{
				OrderID:    123,
				Status:     "success",
				DeployedAt: "2026-07-26T12:00:00+08:00",
			})
			if err == nil {
				t.Fatal("Callback() 应拒绝未被 manager 接受的响应")
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("Callback() error 类型 = %T, want *APIError", err)
			}
			if client.LastRenewBeforeDays != 14 {
				t.Fatalf("LastRenewBeforeDays = %d, want 14", client.LastRenewBeforeDays)
			}
		})
	}

	t.Run("响应读取错误", func(t *testing.T) {
		client := NewClient("http://localhost/api/deploy", "test-token")
		client.LastRenewBeforeDays = 14
		client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       callbackReadErrorBody{},
				Request:    req,
			}, nil
		})

		err := client.Callback(context.Background(), &CallbackRequest{
			OrderID:    123,
			Status:     "success",
			DeployedAt: "2026-07-26T12:00:00+08:00",
		})
		if err == nil {
			t.Fatal("Callback() 应返回响应读取错误")
		}
		if !strings.Contains(err.Error(), "读取") {
			t.Fatalf("Callback() error = %v, want 包含读取失败上下文", err)
		}
		if client.LastRenewBeforeDays != 14 {
			t.Fatalf("LastRenewBeforeDays = %d, want 14", client.LastRenewBeforeDays)
		}
	})
}

func TestCallback_AcceptsCodeOneAndRecordsOnlyValidRenewDays(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{name: "缺少data仍成功", body: `{"code":1,"msg":"success"}`, want: 14},
		{name: "recorded不作为成功前提", body: `{"code":1,"msg":"success","data":{"recorded":false}}`, want: 14},
		{name: "缺少renew_before_days", body: `{"code":1,"msg":"success","data":{}}`, want: 14},
		{name: "renew_before_days为0", body: `{"code":1,"msg":"success","data":{"renew_before_days":0}}`, want: 14},
		{name: "renew_before_days超限", body: `{"code":1,"msg":"success","data":{"renew_before_days":31}}`, want: 14},
		{name: "合法renew_before_days", body: `{"code":1,"msg":"success","data":{"renew_before_days":22}}`, want: 22},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			client := NewClient(server.URL+"/api/deploy", "test-token")
			client.LastRenewBeforeDays = 14
			if err := client.Callback(context.Background(), &CallbackRequest{
				OrderID:    123,
				Status:     "success",
				DeployedAt: "2026-07-26T12:00:00+08:00",
			}); err != nil {
				t.Fatalf("Callback() error = %v", err)
			}
			if client.LastRenewBeforeDays != tt.want {
				t.Fatalf("LastRenewBeforeDays = %d, want %d", client.LastRenewBeforeDays, tt.want)
			}
		})
	}
}

func TestCallback_SendsOnlyManagerContractFields(t *testing.T) {
	tests := []struct {
		name        string
		req         CallbackRequest
		wantMessage bool
	}{
		{
			name: "success不发送message",
			req: CallbackRequest{
				OrderID:    101,
				Status:     "success",
				DeployedAt: "2026-07-26T12:00:00+08:00",
				Message:    "调用方误传的失败原因",
			},
		},
		{
			name: "failure在最终出口脱敏并截断",
			req: CallbackRequest{
				OrderID:    102,
				Status:     "failure",
				DeployedAt: "2026-07-26T12:01:00+08:00",
				Message:    "绑定失败 Authorization: Bearer sk-live-secret\n" + strings.Repeat("错", 300),
			},
			wantMessage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if r.URL.Path != "/api/deploy/callback" {
					t.Errorf("path = %s, want /api/deploy/callback", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
					t.Errorf("Authorization = %q, want Bearer test-token", got)
				}
				if got := r.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", got)
				}

				var payload map[string]json.RawMessage
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("解析 callback JSON: %v", err)
				}
				wantKeys := map[string]bool{
					"order_id":    true,
					"status":      true,
					"deployed_at": true,
				}
				if tt.wantMessage {
					wantKeys["message"] = true
				}
				if len(payload) != len(wantKeys) {
					t.Errorf("字段数 = %d, want %d；payload = %s", len(payload), len(wantKeys), payload)
				}
				for key := range payload {
					if !wantKeys[key] {
						t.Errorf("出现非白名单字段 %q", key)
					}
				}
				var orderID int
				if err := json.Unmarshal(payload["order_id"], &orderID); err != nil {
					t.Fatalf("解析 order_id: %v", err)
				}
				if orderID != tt.req.OrderID {
					t.Errorf("order_id = %d, want %d", orderID, tt.req.OrderID)
				}
				var status string
				if err := json.Unmarshal(payload["status"], &status); err != nil {
					t.Fatalf("解析 status: %v", err)
				}
				if status != tt.req.Status {
					t.Errorf("status = %q, want %q", status, tt.req.Status)
				}

				var deployedAt string
				if err := json.Unmarshal(payload["deployed_at"], &deployedAt); err != nil {
					t.Fatalf("解析 deployed_at: %v", err)
				}
				if _, err := time.Parse(time.RFC3339, deployedAt); err != nil {
					t.Errorf("deployed_at = %q，不可按 RFC3339 解析: %v", deployedAt, err)
				}

				if tt.wantMessage {
					var message string
					if err := json.Unmarshal(payload["message"], &message); err != nil {
						t.Fatalf("解析 message: %v", err)
					}
					if strings.Contains(message, "sk-live-secret") {
						t.Errorf("message 泄漏 Bearer 凭据: %q", message)
					}
					if strings.ContainsAny(message, "\r\n") {
						t.Errorf("message 未折叠换行: %q", message)
					}
					if got := len([]rune(message)); got > CallbackMessageMaxRunes {
						t.Errorf("message rune 数 = %d, want <= %d", got, CallbackMessageMaxRunes)
					}
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"code":1,"msg":"success"}`))
			}))
			defer server.Close()

			client := NewClient(server.URL+"/api/deploy/", "test-token")
			originalReq := tt.req
			if err := client.Callback(context.Background(), &tt.req); err != nil {
				t.Fatalf("Callback() error = %v", err)
			}
			if !reflect.DeepEqual(tt.req, originalReq) {
				t.Fatalf("Callback() 修改了调用方请求：got %+v, want %+v", tt.req, originalReq)
			}
		})
	}
}

func TestCallback_RetriesWithIdenticalPayload(t *testing.T) {
	tests := []struct {
		name      string
		firstResp func(*http.Request) (*http.Response, error)
	}{
		{
			name: "5xx",
			firstResp: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("temporary")),
					Request:    req,
				}, nil
			},
		},
		{
			name: "网络错误",
			firstResp: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("temporary network error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payloads [][]byte
			attempt := 0
			client := NewClient("http://localhost/api/deploy", "test-token")
			client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatalf("读取第 %d 次请求体: %v", attempt+1, err)
				}
				payloads = append(payloads, append([]byte(nil), body...))
				attempt++
				if attempt == 1 {
					return tt.firstResp(req)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": []string{"application/json"}},
					Body:       io.NopCloser(strings.NewReader(`{"code":1,"msg":"success"}`)),
					Request:    req,
				}, nil
			})

			err := client.Callback(context.Background(), &CallbackRequest{
				OrderID:    123,
				Status:     "failure",
				DeployedAt: "2026-07-26T12:00:00+08:00",
				Message:    "绑定失败",
			})
			if err != nil {
				t.Fatalf("Callback() error = %v", err)
			}
			if len(payloads) != 2 {
				t.Fatalf("请求次数 = %d, want 2", len(payloads))
			}
			if !bytes.Equal(payloads[0], payloads[1]) {
				t.Fatalf("重试载荷不一致:\n首次 %s\n重试 %s", payloads[0], payloads[1])
			}

			var payload map[string]json.RawMessage
			if err := json.Unmarshal(payloads[0], &payload); err != nil {
				t.Fatalf("解析 callback JSON: %v", err)
			}
			wantKeys := map[string]bool{
				"order_id":    true,
				"status":      true,
				"deployed_at": true,
				"message":     true,
			}
			if len(payload) != len(wantKeys) {
				t.Fatalf("字段数 = %d, want 4；payload = %s", len(payload), payloads[0])
			}
			for key := range payload {
				if !wantKeys[key] {
					t.Errorf("重试载荷出现非白名单字段 %q", key)
				}
			}
		})
	}
}

// TestDoWithRetry_Success 测试首次成功
func TestDoWithRetry_Success(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"data":        []interface{}{},
				"currentPage": 1,
				"pageSize":    20,
				"total":       0,
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")

	if err != nil {
		t.Fatalf("ListCertsByQuery() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("请求次数 = %d, want 1", callCount)
	}
}

// TestDoWithRetry_5xxRetry 测试 5xx 重试
func TestDoWithRetry_5xxRetry(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"data":        []interface{}{},
				"currentPage": 1,
				"pageSize":    20,
				"total":       0,
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")

	if err != nil {
		t.Fatalf("ListCertsByQuery() error = %v", err)
	}
	if callCount != 3 {
		t.Errorf("请求次数 = %d, want 3", callCount)
	}
}

// TestSubmitCSR_MockServer 测试提交 CSR
func TestSubmitCSR_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Method = %s, want POST", r.Method)
		}

		var req UpdateRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Domains != "example.com" {
			t.Errorf("Domains = %s, want example.com", req.Domains)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"order_id": 456,
				"status":   "processing",
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	resp, err := client.SubmitCSR(context.Background(), &UpdateRequest{
		OrderID: 123,
		Domains: "example.com",
		CSR:     "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
	})

	if err != nil {
		t.Fatalf("SubmitCSR() error = %v", err)
	}
	if resp.Data.OrderID != 456 {
		t.Errorf("OrderID = %d, want 456", resp.Data.OrderID)
	}
	if resp.Data.Status != "processing" {
		t.Errorf("Status = %s, want processing", resp.Data.Status)
	}
}

// TestSubmitCSR_APIError 测试 CSR 提交 API 错误
func TestSubmitCSR_APIError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "域名格式错误",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.SubmitCSR(context.Background(), &UpdateRequest{
		OrderID: 123,
		Domains: "invalid",
		CSR:     "test",
	})

	if err == nil {
		t.Error("SubmitCSR() 应该返回错误")
	}
	if callCount != 1 {
		t.Fatalf("请求次数 = %d, want 1", callCount)
	}
	if !strings.Contains(err.Error(), "域名格式错误") {
		t.Fatalf("错误 = %v, want 服务端业务错误", err)
	}
}

// TestDomainQueryRejected 测试客户端在发请求前拒绝已移除的域名查询形态。
func TestDomainQueryRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"order_id":   100,
						"domains":    "example.com",
						"status":     "pending",
						"expires_at": "2025-06-01",
					},
					{
						"order_id":   200,
						"domains":    "example.com",
						"status":     "active",
						"expires_at": "2025-01-01",
					},
					{
						"order_id":   300,
						"domains":    "example.com",
						"status":     "active",
						"expires_at": "2025-12-01",
					},
				},
				"currentPage": 1,
				"pageSize":    20,
				"total":       3,
			},
		})
	}))
	defer server.Close()

	err := ValidateOrderQuery("example.com")
	if apiCode := ErrorCodeOf(err); apiCode != ErrorCodeInvalidOrder {
		t.Fatalf("域名查询应在本地按 invalid_order 拒绝，got err=%v code=%q", err, apiCode)
	}
}

func TestDomainQueryRejectedRegardlessOfServerData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"order_id":   100,
						"domains":    "example.com",
						"status":     "pending",
						"expires_at": "2025-06-01",
					},
				},
				"currentPage": 1,
				"pageSize":    20,
				"total":       1,
			},
		})
	}))
	defer server.Close()

	err := ValidateOrderQuery("example.com")

	if err == nil {
		t.Error("域名查询必须按 invalid_order 拒绝")
	}
}

// TestListCertsByQuery_HTTPError 测试 HTTP 错误
func TestListCertsByQuery_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "Bad Request",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")

	if err == nil {
		t.Error("ListCertsByQuery() 应该返回错误")
	}
}

// TestListCertsByQuery_JSONParseError 测试 JSON 解析失败
func TestListCertsByQuery_JSONParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")

	if err == nil {
		t.Error("ListCertsByQuery() 应该返回 JSON 解析错误")
	}
}

// TestListCertsByQuery_CodeNotOne 测试 code != 1
func TestListCertsByQuery_CodeNotOne(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "Token 无效",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")

	if err == nil {
		t.Error("ListCertsByQuery() 应该返回错误（code != 1）")
	}
}

// TestCertData_Fields 测试 CertData 所有字段
func TestCertData_Fields(t *testing.T) {
	cert := &CertData{
		OrderID:     123,
		Domains:     "example.com,www.example.com",
		Status:      "active",
		Certificate: "-----BEGIN CERTIFICATE-----",
		PrivateKey:  "-----BEGIN TEST KEY-----",
		CACert:      "-----BEGIN CERTIFICATE-----",
		ExpiresAt:   "2025-12-31",
		IssuedAt:    "2024-01-01",
		File: &FileValidation{
			Path:    "/.well-known/acme-challenge/token",
			Content: "token-content",
		},
	}

	if cert.OrderID != 123 {
		t.Errorf("OrderID = %d", cert.OrderID)
	}
	if cert.Domain() != "example.com" {
		t.Errorf("Domain() = %q", cert.Domain())
	}
	if cert.Status != "active" {
		t.Errorf("Status = %q", cert.Status)
	}
	if cert.File == nil {
		t.Error("File 不应为 nil")
	} else if cert.File.Path != "/.well-known/acme-challenge/token" {
		t.Errorf("File.Path = %q", cert.File.Path)
	}
}

// TestUpdateRequest_Fields 测试 UpdateRequest 所有字段
func TestUpdateRequest_Fields(t *testing.T) {
	req := &UpdateRequest{
		OrderID:          123,
		Domains:          "example.com",
		CSR:              "-----BEGIN CERTIFICATE REQUEST-----",
		ValidationMethod: "file",
	}

	if req.OrderID != 123 {
		t.Errorf("OrderID = %d", req.OrderID)
	}
	if req.Domains != "example.com" {
		t.Errorf("Domains = %q", req.Domains)
	}
	if req.CSR != "-----BEGIN CERTIFICATE REQUEST-----" {
		t.Errorf("CSR = %q", req.CSR)
	}
	if req.ValidationMethod != "file" {
		t.Errorf("ValidationMethod = %q", req.ValidationMethod)
	}
}

// TestFileValidation_Fields 测试 FileValidation 所有字段
func TestFileValidation_Fields(t *testing.T) {
	file := &FileValidation{
		Path:    "/.well-known/acme-challenge/token123",
		Content: "verification-content-here",
	}

	if file.Path != "/.well-known/acme-challenge/token123" {
		t.Errorf("Path = %q", file.Path)
	}
	if file.Content != "verification-content-here" {
		t.Errorf("Content = %q", file.Content)
	}
}

// TestGetCertByOrderID_Validation 测试配置验证
func TestGetCertByOrderID_Validation(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		token   string
		wantErr bool
	}{
		{"缺少 BaseURL", "", "token", true},
		{"缺少 Token", "https://api.example.com", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.baseURL, tt.token)
			_, err := client.GetCertByOrderID(context.Background(), 123)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCertByOrderID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestSelectBestCert_ExactMatch 测试精确匹配优先
func TestSelectBestCert_ExactMatch(t *testing.T) {
	certs := []CertData{
		{OrderID: 100, Domains: "*.example.com", Status: "active", ExpiresAt: "2026-01-01"},
		{OrderID: 200, Domains: "www.example.com", Status: "active", ExpiresAt: "2025-01-01"},
	}

	best := selectBestCert(certs, "www.example.com")
	if best == nil {
		t.Fatal("selectBestCert() = nil")
	}
	// 精确匹配应该优先于通配符匹配
	if best.OrderID != 200 {
		t.Errorf("OrderID = %d, want 200（精确匹配）", best.OrderID)
	}
}

// TestSelectBestCert_DomainsField 测试 Domains 字段匹配
func TestSelectBestCert_DomainsField(t *testing.T) {
	certs := []CertData{
		{OrderID: 100, Domains: "example.com,www.example.com,api.example.com", Status: "active", ExpiresAt: "2025-01-01"},
	}

	best := selectBestCert(certs, "api.example.com")
	if best == nil {
		t.Fatal("selectBestCert() = nil")
	}
	if best.OrderID != 100 {
		t.Errorf("OrderID = %d, want 100", best.OrderID)
	}
}

func TestDoWithRetry_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := client.doWithRetry(ctx, req)
	if err == nil {
		t.Error("doWithRetry() should return error with cancelled context")
	}
}

func TestDoWithRetry_GetBodyError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// First request returns 500 to trigger retry
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	req, _ := http.NewRequest("POST", server.URL, strings.NewReader("body"))
	req.GetBody = func() (io.ReadCloser, error) {
		return nil, errors.New("GetBody failed")
	}

	_, err := client.doWithRetry(context.Background(), req)
	if err == nil {
		t.Error("doWithRetry() should return error when GetBody fails")
	}
	if !strings.Contains(err.Error(), "重置请求体失败") {
		t.Errorf("error should contain '重置请求体失败', got: %v", err)
	}
}

func TestSelectBestCert_CaseInsensitive(t *testing.T) {
	certs := []CertData{
		{OrderID: 100, Domains: "*.Example.COM", Status: "active", ExpiresAt: "2025-01-01"},
	}

	// util.MatchDomain normalizes to lowercase, so "www.example.com" should match "*.Example.COM"
	best := selectBestCert(certs, "www.example.com")
	if best == nil {
		t.Fatal("selectBestCert() should match case-insensitively")
	}
	if best.OrderID != 100 {
		t.Errorf("OrderID = %d, want 100", best.OrderID)
	}
}

func TestDoWithRetry_5xxAllFail(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByQuery(context.Background(), "123")
	if err == nil {
		t.Error("应该在所有重试失败后返回错误")
	}
	// MaxRetries is 3, so total calls = initial + 3 retries = 4
	if callCount != 4 {
		t.Errorf("请求次数 = %d, want 4 (1 + MaxRetries)", callCount)
	}
}

func TestHandleHTTPError(t *testing.T) {
	t.Run("JSON 错误响应", func(t *testing.T) {
		body := []byte(`{"code":0,"msg":"Token 无效"}`)
		err := handleHTTPError(401, body)
		if err.Message != "Token 无效" {
			t.Errorf("Message = %q, want 'Token 无效'", err.Message)
		}
		if err.StatusCode != 401 {
			t.Errorf("StatusCode = %d, want 401", err.StatusCode)
		}
	})

	t.Run("非 JSON 响应", func(t *testing.T) {
		body := []byte("Internal Server Error")
		err := handleHTTPError(500, body)
		if err.StatusCode != 500 {
			t.Errorf("StatusCode = %d, want 500", err.StatusCode)
		}
	})
}

// TestSanitizeCallbackMessage 验证回调 message 脱敏与截断（纯函数）
func TestSanitizeCallbackMessage(t *testing.T) {
	t.Run("空串直通", func(t *testing.T) {
		if got := SanitizeCallbackMessage(""); got != "" {
			t.Errorf("空串应返回空，实际 = %q", got)
		}
	})

	t.Run("普通原因不改动", func(t *testing.T) {
		in := "绑定失败: netsh 返回错误码 183"
		if got := SanitizeCallbackMessage(in); got != in {
			t.Errorf("普通原因应原样返回，实际 = %q", got)
		}
	})

	t.Run("Bearer 凭据脱敏", func(t *testing.T) {
		in := "回调失败: Authorization: Bearer sk-live-0123456789abcdef"
		got := SanitizeCallbackMessage(in)
		if strings.Contains(got, "sk-live-0123456789abcdef") {
			t.Errorf("Bearer 凭据未脱敏: %q", got)
		}
		if !strings.Contains(got, "Bearer [REDACTED]") {
			t.Errorf("应保留方案名并脱敏凭据: %q", got)
		}
	})

	t.Run("Basic 凭据脱敏", func(t *testing.T) {
		in := "basic dXNlcjpwYXNzd29yZA=="
		got := SanitizeCallbackMessage(in)
		if strings.Contains(got, "dXNlcjpwYXNzd29yZA==") {
			t.Errorf("Basic 凭据未脱敏: %q", got)
		}
		if !strings.Contains(got, "[REDACTED]") {
			t.Errorf("应包含脱敏占位符: %q", got)
		}
	})

	t.Run("完整私钥块脱敏", func(t *testing.T) {
		in := "转换失败 -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIabc123secretkeymaterial\n-----END EC PRIVATE KEY----- 结束"
		got := SanitizeCallbackMessage(in)
		if strings.Contains(got, "secretkeymaterial") {
			t.Errorf("私钥本体未脱敏: %q", got)
		}
		if !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
			t.Errorf("应包含私钥脱敏占位符: %q", got)
		}
	})

	t.Run("残缺私钥块脱敏", func(t *testing.T) {
		// 有 BEGIN 无 END（上游已截断），从 BEGIN 起整段脱敏，不残留密钥本体
		in := "错误 -----BEGIN PRIVATE KEY-----\nMHcCAQEEIdanglingsecret"
		got := SanitizeCallbackMessage(in)
		if strings.Contains(got, "danglingsecret") {
			t.Errorf("残缺私钥本体未脱敏: %q", got)
		}
		if !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
			t.Errorf("应包含私钥脱敏占位符: %q", got)
		}
	})

	t.Run("按 rune 截断至上限", func(t *testing.T) {
		// 300 个中文 rune，截断后应为 256 个 rune（非字节）
		in := strings.Repeat("错", 300)
		got := SanitizeCallbackMessage(in)
		if n := len([]rune(got)); n != CallbackMessageMaxRunes {
			t.Errorf("截断后 rune 数 = %d, want %d", n, CallbackMessageMaxRunes)
		}
		// 截断不得切裂多字节字符（每个 rune 完整）
		for _, r := range got {
			if r != '错' {
				t.Fatalf("截断产生了非法字符: %q", r)
			}
		}
	})

	t.Run("换行折叠为空格", func(t *testing.T) {
		got := SanitizeCallbackMessage("第一行\n第二行\r\n第三行")
		if strings.ContainsAny(got, "\r\n") {
			t.Errorf("换行未折叠: %q", got)
		}
	})

	t.Run("私钥跨 256 截断边界不泄漏", func(t *testing.T) {
		// 密钥材料落在 256 截断点之内、END 标记在点外；
		// 无论实现顺序如何（本仓另有残缺 BEGIN 兜底正则），最终 message 不得含任何密钥片段
		in := strings.Repeat("x", 150) + "-----BEGIN RSA PRIVATE KEY-----\nLEAKMATERIAL" + strings.Repeat("A", 80) + "\n-----END RSA PRIVATE KEY-----"
		got := SanitizeCallbackMessage(in)
		if strings.Contains(got, "LEAKMATERIAL") {
			t.Errorf("跨界私钥不应泄漏任何片段: %q", got)
		}
		if !strings.Contains(got, "[REDACTED_PRIVATE_KEY]") {
			t.Errorf("应包含私钥脱敏占位符: %q", got)
		}
	})
}

func TestSanitizeCallbackMessage_RedactsKeyValueSecretsAndAbsolutePaths(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		secrets []string
	}{
		{"键值与普通绝对路径", `token=token-secret api_token: api-secret password="pwd-secret"`, []string{"token-secret", "api-secret", "pwd-secret"}},
		{"Windows反斜杠带空格", `写入 C:\Program Files\sslctlw\private.key 失败`, []string{`C:\Program Files`, `sslctlw\private.key`}},
		{"Windows正斜杠", `写入 C:/ProgramData/sslctlw/private.key 失败`, []string{"C:/ProgramData", "sslctlw/private.key"}},
		{"UNC路径", `读取 \\server\share\sslctlw\private.key 失败`, []string{`\\server\share`, `sslctlw\private.key`}},
		{"Unix带空格", `备份 /var/lib/ssl ctl/key.pem 失败`, []string{"/var/lib/ssl", "ctl/key.pem"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeCallbackMessage(tt.input)
			for _, secret := range tt.secrets {
				if strings.Contains(got, secret) {
					t.Fatalf("敏感信息未脱敏 %q: %q", secret, got)
				}
			}
			if !strings.Contains(got, "[REDACTED") {
				t.Fatalf("应包含脱敏占位符: %q", got)
			}
		})
	}
}

func TestToggleAutoReissue_RecordsRenewBeforeDays(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{"renew_before_days":22}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	if err := client.ToggleAutoReissue(context.Background(), 123, true); err != nil {
		t.Fatalf("ToggleAutoReissue() error = %v", err)
	}
	if client.LastRenewBeforeDays != 22 {
		t.Fatalf("LastRenewBeforeDays = %d, want 22", client.LastRenewBeforeDays)
	}
}

func TestClientRejectsRenewBeforeDaysAboveCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{"total":0,"data":[],"renew_before_days":31}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	client.LastRenewBeforeDays = 14
	if _, err := client.ListCertsByQuery(context.Background(), "123"); err != nil {
		t.Fatalf("ListCertsByQuery() error = %v", err)
	}
	if client.LastRenewBeforeDays != 14 {
		t.Fatalf("超限值不应覆盖本地候选值，got %d", client.LastRenewBeforeDays)
	}
}
