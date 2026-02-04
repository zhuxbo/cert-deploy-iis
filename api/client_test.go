package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
		name    string
		pattern string
		target  string
		want    bool
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
			got := matchesDomain(tt.pattern, tt.target)
			if got != tt.want {
				t.Errorf("matchesDomain(%q, %q) = %v, want %v", tt.pattern, tt.target, got, tt.want)
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
				{OrderID: 1, Domain: "example.com", Status: "pending", ExpiresAt: "2025-01-01"},
				{OrderID: 2, Domain: "example.com", Status: "active", ExpiresAt: "2024-06-01"},
			},
			"example.com",
			2,
		},
		{
			"优先精确匹配",
			[]CertData{
				{OrderID: 1, Domain: "*.example.com", Status: "active", ExpiresAt: "2025-01-01"},
				{OrderID: 2, Domain: "www.example.com", Status: "active", ExpiresAt: "2024-06-01"},
			},
			"www.example.com",
			2,
		},
		{
			"优先过期时间晚",
			[]CertData{
				{OrderID: 1, Domain: "example.com", Status: "active", ExpiresAt: "2024-06-01"},
				{OrderID: 2, Domain: "example.com", Status: "active", ExpiresAt: "2025-01-01"},
			},
			"example.com",
			2,
		},
		{
			"无 active 返回 nil",
			[]CertData{
				{OrderID: 1, Domain: "example.com", Status: "pending", ExpiresAt: "2025-01-01"},
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
			`{"code":1,"msg":"success","data":[]}`,
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
			got, err := parseAPIResponse([]byte(tt.body), tt.statusCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAPIResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Code != tt.wantCode {
				t.Errorf("parseAPIResponse().Code = %d, want %d", got.Code, tt.wantCode)
			}
		})
	}
}

func TestListCertsByDomain_Validation(t *testing.T) {
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
			_, err := client.ListCertsByDomain(context.Background(), "example.com")
			if (err != nil) != tt.wantErr {
				t.Errorf("ListCertsByDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestListCertsByDomain_MockServer(t *testing.T) {
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
			"data": []map[string]interface{}{
				{
					"order_id":    123,
					"domain":      "example.com",
					"status":      "active",
					"expires_at":  "2025-01-01",
					"certificate": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					"private_key": "-----BEGIN TEST KEY-----\ntest\n-----END TEST KEY-----",
				},
			},
		})
	}))
	defer server.Close()

	// 测试成功请求
	client := NewClient(server.URL, "test-token")
	certs, err := client.ListCertsByDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListCertsByDomain() error = %v", err)
	}

	if len(certs) != 1 {
		t.Errorf("ListCertsByDomain() 返回 %d 个证书, want 1", len(certs))
	}

	if certs[0].OrderID != 123 {
		t.Errorf("certs[0].OrderID = %d, want 123", certs[0].OrderID)
	}

	// 测试未授权
	badClient := NewClient(server.URL, "wrong-token")
	_, err = badClient.ListCertsByDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("使用错误 token 应该返回错误")
	}
}

func TestGetCertByOrderID_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orderID := r.URL.Query().Get("order_id")
		if orderID == "123" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 1,
				"msg":  "success",
				"data": []map[string]interface{}{
					{
						"order_id":   123,
						"domain":     "example.com",
						"status":     "active",
						"expires_at": "2025-01-01",
					},
				},
			})
		} else {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 1,
				"msg":  "success",
				"data": []map[string]interface{}{},
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

func TestCallback_MockServer(t *testing.T) {
	var receivedReq *CallbackRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req CallbackRequest
		json.NewDecoder(r.Body).Decode(&req)
		receivedReq = &req

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")

	err := client.Callback(context.Background(), &CallbackRequest{
		OrderID:    123,
		Domain:     "example.com",
		Status:     "success",
		DeployedAt: "2024-01-01 00:00:00",
		ServerType: "IIS",
	})

	if err != nil {
		t.Fatalf("Callback() error = %v", err)
	}

	if receivedReq == nil {
		t.Fatal("服务器未收到请求")
	}

	if receivedReq.OrderID != 123 {
		t.Errorf("receivedReq.OrderID = %d, want 123", receivedReq.OrderID)
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
			"data": []interface{}{},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByDomain(context.Background(), "example.com")

	if err != nil {
		t.Fatalf("ListCertsByDomain() error = %v", err)
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
			"data": []interface{}{},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByDomain(context.Background(), "example.com")

	if err != nil {
		t.Fatalf("ListCertsByDomain() error = %v", err)
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

		var req CSRRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.Domain != "example.com" {
			t.Errorf("Domain = %s, want example.com", req.Domain)
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
	resp, err := client.SubmitCSR(context.Background(), &CSRRequest{
		Domain: "example.com",
		CSR:    "-----BEGIN CERTIFICATE REQUEST-----\ntest\n-----END CERTIFICATE REQUEST-----",
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "域名格式错误",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.SubmitCSR(context.Background(), &CSRRequest{
		Domain: "invalid",
		CSR:    "test",
	})

	if err == nil {
		t.Error("SubmitCSR() 应该返回错误")
	}
}

// TestGetCertByDomain_MockServer 测试获取最佳证书
func TestGetCertByDomain_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": []map[string]interface{}{
				{
					"order_id":   100,
					"domain":     "example.com",
					"status":     "pending",
					"expires_at": "2025-06-01",
				},
				{
					"order_id":   200,
					"domain":     "example.com",
					"status":     "active",
					"expires_at": "2025-01-01",
				},
				{
					"order_id":   300,
					"domain":     "example.com",
					"status":     "active",
					"expires_at": "2025-12-01",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	cert, err := client.GetCertByDomain(context.Background(), "example.com")

	if err != nil {
		t.Fatalf("GetCertByDomain() error = %v", err)
	}
	// 应该返回 OrderID=300（active 且过期最晚）
	if cert.OrderID != 300 {
		t.Errorf("OrderID = %d, want 300", cert.OrderID)
	}
}

// TestGetCertByDomain_NoActiveCert 测试没有 active 证书
func TestGetCertByDomain_NoActiveCert(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 1,
			"msg":  "success",
			"data": []map[string]interface{}{
				{
					"order_id":   100,
					"domain":     "example.com",
					"status":     "pending",
					"expires_at": "2025-06-01",
				},
			},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.GetCertByDomain(context.Background(), "example.com")

	if err == nil {
		t.Error("GetCertByDomain() 应该返回错误（没有 active 证书）")
	}
}

// TestListCertsByDomain_HTTPError 测试 HTTP 错误
func TestListCertsByDomain_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "Bad Request",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByDomain(context.Background(), "example.com")

	if err == nil {
		t.Error("ListCertsByDomain() 应该返回错误")
	}
}

// TestListCertsByDomain_JSONParseError 测试 JSON 解析失败
func TestListCertsByDomain_JSONParseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByDomain(context.Background(), "example.com")

	if err == nil {
		t.Error("ListCertsByDomain() 应该返回 JSON 解析错误")
	}
}

// TestListCertsByDomain_CodeNotOne 测试 code != 1
func TestListCertsByDomain_CodeNotOne(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0,
			"msg":  "Token 无效",
			"data": []interface{}{},
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "test-token")
	_, err := client.ListCertsByDomain(context.Background(), "example.com")

	if err == nil {
		t.Error("ListCertsByDomain() 应该返回错误（code != 1）")
	}
}

// TestCertData_Fields 测试 CertData 所有字段
func TestCertData_Fields(t *testing.T) {
	cert := &CertData{
		OrderID:     123,
		Domain:      "example.com",
		Domains:     "example.com,www.example.com",
		Status:      "active",
		Certificate: "-----BEGIN CERTIFICATE-----",
		PrivateKey:  "-----BEGIN TEST KEY-----",
		CACert:      "-----BEGIN CERTIFICATE-----",
		ExpiresAt:   "2025-12-31",
		CreatedAt:   "2024-01-01",
		File: &FileValidation{
			Path:    "/.well-known/acme-challenge/token",
			Content: "token-content",
		},
	}

	if cert.OrderID != 123 {
		t.Errorf("OrderID = %d", cert.OrderID)
	}
	if cert.Domain != "example.com" {
		t.Errorf("Domain = %q", cert.Domain)
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

// TestCSRRequest_Fields 测试 CSRRequest 所有字段
func TestCSRRequest_Fields(t *testing.T) {
	req := &CSRRequest{
		OrderID:          123,
		Domain:           "example.com",
		CSR:              "-----BEGIN CERTIFICATE REQUEST-----",
		ValidationMethod: "file",
	}

	if req.OrderID != 123 {
		t.Errorf("OrderID = %d", req.OrderID)
	}
	if req.Domain != "example.com" {
		t.Errorf("Domain = %q", req.Domain)
	}
	if req.CSR != "-----BEGIN CERTIFICATE REQUEST-----" {
		t.Errorf("CSR = %q", req.CSR)
	}
	if req.ValidationMethod != "file" {
		t.Errorf("ValidationMethod = %q", req.ValidationMethod)
	}
}

// TestCallbackRequest_Fields 测试 CallbackRequest 所有字段
func TestCallbackRequest_Fields(t *testing.T) {
	req := &CallbackRequest{
		OrderID:    123,
		Domain:     "example.com",
		Status:     "success",
		DeployedAt: "2024-01-01 00:00:00",
		ServerType: "IIS",
		Message:    "部署成功",
	}

	if req.OrderID != 123 {
		t.Errorf("OrderID = %d", req.OrderID)
	}
	if req.Domain != "example.com" {
		t.Errorf("Domain = %q", req.Domain)
	}
	if req.Status != "success" {
		t.Errorf("Status = %q", req.Status)
	}
	if req.DeployedAt != "2024-01-01 00:00:00" {
		t.Errorf("DeployedAt = %q", req.DeployedAt)
	}
	if req.ServerType != "IIS" {
		t.Errorf("ServerType = %q", req.ServerType)
	}
	if req.Message != "部署成功" {
		t.Errorf("Message = %q", req.Message)
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
		{OrderID: 100, Domain: "*.example.com", Status: "active", ExpiresAt: "2026-01-01"},
		{OrderID: 200, Domain: "www.example.com", Status: "active", ExpiresAt: "2025-01-01"},
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
		{OrderID: 100, Domain: "example.com", Domains: "example.com,www.example.com,api.example.com", Status: "active", ExpiresAt: "2025-01-01"},
	}

	best := selectBestCert(certs, "api.example.com")
	if best == nil {
		t.Fatal("selectBestCert() = nil")
	}
	if best.OrderID != 100 {
		t.Errorf("OrderID = %d, want 100", best.OrderID)
	}
}
