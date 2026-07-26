package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
)

type testAutoDeployLock struct {
	closed bool
}

func (l *testAutoDeployLock) Close() error {
	l.closed = true
	return nil
}

func successfulAutoDeployDependencies(save func(*config.Config) error) autoDeployDependencies {
	if save == nil {
		save = func(*config.Config) error { return nil }
	}
	return autoDeployDependencies{
		openLock: func(string) (autoDeployLock, error) { return &testAutoDeployLock{}, nil },
		tryLock:  func(autoDeployLock) (bool, error) { return true, nil },
		removeLock: func(string) error {
			return nil
		},
		saveConfig: save,
	}
}

func runReportCertConfig(t *testing.T, certData api.CertData, callbackCode int, calls *atomic.Int32) config.CertConfig {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/callback") {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": callbackCode, "msg": "callback response"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{
				"data":        []api.CertData{certData},
				"currentPage": 1,
				"pageSize":    20,
				"total":       1,
			},
		})
	}))
	t.Cleanup(server.Close)

	certAPI := config.CertAPIConfig{URL: server.URL}
	if err := certAPI.SetToken("test-token"); err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}
	return config.CertConfig{
		OrderID:   certData.OrderID,
		Domain:    certData.Domain(),
		Domains:   []string{certData.Domain()},
		Enabled:   true,
		BindRules: []config.BindRule{{Domain: certData.Domain(), Port: 443}},
		API:       certAPI,
	}
}

// testCertAPI 返回测试用的 CertAPIConfig（使用明文存储，避免 DPAPI 依赖）
func testCertAPI() config.CertAPIConfig {
	return config.CertAPIConfig{
		URL:            "https://api.example.com",
		EncryptedToken: "", // 测试时直接通过 mock client 绕过
	}
}

// TestAutoDeploy_NoCertificates 测试没有配置证书的情况
func TestAutoDeploy_NoCertificates(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{},
	}

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d, RunOptions{}).Results

	if len(results) != 0 {
		t.Errorf("没有配置证书时应该返回空结果，得到 %d 个结果", len(results))
	}
}

// TestAutoDeploy_NoAPIConfig 测试没有配置 API 的证书返回失败
func TestAutoDeploy_NoAPIConfig(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 123, Domain: "example.com", Enabled: true},
		},
	}

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d, RunOptions{}).Results

	// 无 API 配置应该返回失败结果
	if len(results) != 1 {
		t.Fatalf("期望 1 个失败结果，得到 %d 个", len(results))
	}
	if results[0].Success {
		t.Error("无 API 配置时应该失败")
	}
}

// TestAutoDeploy_DisabledCertificate 测试禁用的证书被跳过
func TestAutoDeploy_DisabledCertificate(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 123, Domain: "example.com", Enabled: false},
		},
	}

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d, RunOptions{}).Results

	if len(results) != 0 {
		t.Errorf("禁用的证书应该被跳过，得到 %d 个结果", len(results))
	}
}

func TestRunAutoDeploy_OnlyOrderIDProcessesOnlyMatchingConfig(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 101, Domain: "a.example.com", Enabled: true},
			{OrderID: 202, Domain: "b.example.com", Enabled: true},
		},
	}

	report := runAutoDeploy(
		cfg,
		NewMockDeployer(),
		RunOptions{OnlyOrderID: 202},
		successfulAutoDeployDependencies(nil),
	)

	if len(report.Results) != 1 {
		t.Fatalf("仅应处理目标配置, got %+v", report.Results)
	}
	if got := report.Results[0].OrderID; got != 202 {
		t.Fatalf("处理了错误订单 %d, want 202", got)
	}
}

func TestRunAutoDeploy_CallbackUsesAPIOrderIDAfterRenewal(t *testing.T) {
	const configuredOrderID = 101
	const actualOrderID = 202

	certPEM, keyPEM := genSelfSignedPair(t, "a.example.com")
	callbackOrderID := 0
	callbackCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/callback") {
			var req api.CallbackRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("解析 callback 请求失败: %v", err)
			}
			callbackOrderID = req.OrderID
			callbackCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1,
			"msg":  "ok",
			"data": map[string]any{
				"data": []api.CertData{{
					OrderID:     actualOrderID,
					Domains:     "a.example.com",
					Status:      "active",
					ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
					Certificate: certPEM,
					PrivateKey:  keyPEM,
					CACert:      testCACertPEM,
				}},
				"currentPage": 1,
				"pageSize":    20,
				"total":       1,
			},
		})
	}))
	t.Cleanup(server.Close)

	certAPI := config.CertAPIConfig{URL: server.URL}
	if err := certAPI.SetToken("test-token"); err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Certificates = []config.CertConfig{{
		OrderID:   configuredOrderID,
		Domain:    "a.example.com",
		Domains:   []string{"a.example.com"},
		Enabled:   true,
		BindRules: []config.BindRule{{Domain: "a.example.com", Port: 443}},
		API:       certAPI,
	}}

	report := runAutoDeploy(
		cfg,
		NewMockDeployer(),
		RunOptions{OnlyOrderID: configuredOrderID},
		successfulAutoDeployDependencies(nil),
	)
	if err := report.Err(); err != nil {
		t.Fatalf("runAutoDeploy() error = %v", err)
	}
	if callbackOrderID != actualOrderID {
		t.Fatalf("callback order_id = %d, want API 实际订单 %d", callbackOrderID, actualOrderID)
	}
	if callbackCount != 1 {
		t.Fatalf("callback 次数 = %d, want 1", callbackCount)
	}
}

// TestCheckRenewalNeeded 测试续签检查逻辑
func TestCheckRenewalNeeded(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		expiresAt  string
		renewDays  int
		wantRenew  bool
		wantReason bool // 是否有跳过原因
	}{
		{
			name:       "未到续签时间",
			expiresAt:  now.AddDate(0, 0, 30).Format("2006-01-02"),
			renewDays:  15,
			wantRenew:  false,
			wantReason: true,
		},
		{
			name:       "到达续签时间",
			expiresAt:  now.AddDate(0, 0, 10).Format("2006-01-02"),
			renewDays:  15,
			wantRenew:  true,
			wantReason: false,
		},
		{
			name:       "刚好边界",
			expiresAt:  now.AddDate(0, 0, 15).Format("2006-01-02"),
			renewDays:  15,
			wantRenew:  true,
			wantReason: false,
		},
		{
			name:       "已过期",
			expiresAt:  now.AddDate(0, 0, -5).Format("2006-01-02"),
			renewDays:  15,
			wantRenew:  false, // 已过期需人工介入
			wantReason: true,
		},
		{
			name:       "无效日期格式",
			expiresAt:  "invalid",
			renewDays:  15,
			wantRenew:  false, // 解析失败跳过
			wantReason: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certData := &api.CertData{
				Domains:   "example.com",
				ExpiresAt: tt.expiresAt,
			}

			needRenew, reason := checkRenewalNeeded(certData, tt.renewDays)

			if needRenew != tt.wantRenew {
				t.Errorf("checkRenewalNeeded() needRenew = %v, want %v", needRenew, tt.wantRenew)
			}

			hasReason := reason != ""
			if hasReason != tt.wantReason {
				t.Errorf("checkRenewalNeeded() hasReason = %v, want %v (reason: %q)", hasReason, tt.wantReason, reason)
			}
		})
	}
}

// TestValidateCertConfig 测试证书配置验证
func TestValidateCertConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.CertConfig
		wantErr bool
	}{
		{
			name: "空验证方法-通过",
			cfg: &config.CertConfig{
				Domain:           "example.com",
				ValidationMethod: "",
			},
			wantErr: false,
		},
		{
			name: "文件验证-普通域名-通过",
			cfg: &config.CertConfig{
				Domain:           "example.com",
				Domains:          []string{"www.example.com"},
				ValidationMethod: "file",
			},
			wantErr: false,
		},
		{
			name: "文件验证-通配符域名-失败",
			cfg: &config.CertConfig{
				Domain:           "*.example.com",
				ValidationMethod: "file",
			},
			wantErr: true,
		},
		{
			name: "文件验证-SAN通配符-失败",
			cfg: &config.CertConfig{
				Domain:           "example.com",
				Domains:          []string{"*.example.com"},
				ValidationMethod: "file",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCertConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestHandleProcessingOrder 测试处理中订单的处理逻辑
func TestHandleProcessingOrder(t *testing.T) {
	tests := []struct {
		name       string
		certData   *api.CertData
		wantReason string
	}{
		{
			name: "无文件验证信息",
			certData: &api.CertData{
				OrderID: 123,
				Status:  "processing",
				File:    nil,
			},
			wantReason: "CSR 已提交，等待签发",
		},
		{
			name: "有文件验证信息",
			certData: &api.CertData{
				OrderID: 123,
				Status:  "processing",
				File: &api.FileValidation{
					Path:    "/.well-known/acme-challenge/token",
					Content: "verification-content",
				},
			},
			wantReason: "CSR 已提交，等待签发",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CertConfig{
				OrderID: tt.certData.OrderID,
				Domain:  "example.com",
			}

			d := NewMockDeployer()
			reason, err := handleProcessingOrder(d, cfg, tt.certData)

			if err != nil {
				t.Errorf("handleProcessingOrder() error = %v", err)
			}
			if reason != tt.wantReason {
				t.Errorf("handleProcessingOrder() reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// TestTryUseLocalKey 测试本地私钥使用逻辑
func TestTryUseLocalKey(t *testing.T) {
	t.Run("没有本地私钥", func(t *testing.T) {
		d := NewMockDeployer()
		d.Store.(*MockOrderStore).HasPrivateKeyFunc = func(orderID int) bool { return false }

		certData := makeTestCertData(t, 123, "example.com", "active", "2025-01-01")
		certCfg := &config.CertConfig{OrderID: 123, Domain: "example.com"}
		_, _, ok := tryUseLocalKey(d, certData, certCfg)
		if ok {
			t.Error("没有本地私钥时应返回 false")
		}
	})

	t.Run("加载私钥失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Store.(*MockOrderStore).HasPrivateKeyFunc = func(orderID int) bool { return true }
		d.Store.(*MockOrderStore).LoadPrivateKeyFunc = func(orderID int) (string, error) {
			return "", errors.New("load failed")
		}

		certData := makeTestCertData(t, 123, "example.com", "active", "2025-01-01")
		certCfg := &config.CertConfig{OrderID: 123, Domain: "example.com"}
		_, _, ok := tryUseLocalKey(d, certData, certCfg)
		if ok {
			t.Error("加载私钥失败时应返回 false")
		}
	})
}

// TestDeployer_Interface 测试 Deployer 接口实现
func TestDeployer_Interface(t *testing.T) {
	deployer := NewMockDeployer()

	if deployer.Converter == nil {
		t.Error("Converter 不应为 nil")
	}
	if deployer.Installer == nil {
		t.Error("Installer 不应为 nil")
	}
	if deployer.Binder == nil {
		t.Error("Binder 不应为 nil")
	}
	if deployer.Store == nil {
		t.Error("Store 不应为 nil")
	}
}

// TestMockCertConverter 测试 Mock 证书转换器
func TestMockCertConverter(t *testing.T) {
	t.Run("默认行为", func(t *testing.T) {
		converter := &MockCertConverter{}
		path, err := converter.PEMToPFX("cert", "key", "ca", "")

		if err != nil {
			t.Errorf("PEMToPFX() error = %v", err)
		}
		if path == "" {
			t.Error("PEMToPFX() 应该返回路径")
		}
	})

	t.Run("自定义行为-成功", func(t *testing.T) {
		converter := &MockCertConverter{
			PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
				return "/custom/path.pfx", nil
			},
		}
		path, err := converter.PEMToPFX("cert", "key", "ca", "")

		if err != nil {
			t.Errorf("PEMToPFX() error = %v", err)
		}
		if path != "/custom/path.pfx" {
			t.Errorf("PEMToPFX() path = %q, want /custom/path.pfx", path)
		}
	})

	t.Run("自定义行为-失败", func(t *testing.T) {
		converter := &MockCertConverter{
			PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
				return "", errors.New("conversion failed")
			},
		}
		_, err := converter.PEMToPFX("cert", "key", "ca", "")

		if err == nil {
			t.Error("PEMToPFX() 应该返回错误")
		}
	})
}

// TestMockCertInstaller 测试 Mock 证书安装器
func TestMockCertInstaller(t *testing.T) {
	t.Run("默认安装行为", func(t *testing.T) {
		installer := &MockCertInstaller{}
		result, err := installer.InstallPFX("/path/to/cert.pfx", "")

		if err != nil {
			t.Errorf("InstallPFX() error = %v", err)
		}
		if result == nil || !result.Success {
			t.Error("InstallPFX() 应该返回成功结果")
		}
	})

	t.Run("自定义安装失败", func(t *testing.T) {
		installer := &MockCertInstaller{
			InstallPFXFunc: func(pfxPath, password string) (*cert.InstallResult, error) {
				return &cert.InstallResult{
					Success:      false,
					ErrorMessage: "安装失败",
				}, nil
			},
		}
		result, _ := installer.InstallPFX("/path/to/cert.pfx", "")

		if result.Success {
			t.Error("InstallPFX() 应该返回失败结果")
		}
	})

	t.Run("设置友好名称", func(t *testing.T) {
		installer := &MockCertInstaller{}
		err := installer.SetFriendlyName("ABCD1234", "测试证书")

		if err != nil {
			t.Errorf("SetFriendlyName() error = %v", err)
		}
	})
}

// TestMockIISBinder 测试 Mock IIS 绑定器
func TestMockIISBinder(t *testing.T) {
	t.Run("SNI 绑定", func(t *testing.T) {
		binder := &MockIISBinder{}
		err := binder.BindCertificate("www.example.com", 443, "ABCD1234")

		if err != nil {
			t.Errorf("BindCertificate() error = %v", err)
		}
	})

	t.Run("IP 绑定", func(t *testing.T) {
		binder := &MockIISBinder{}
		err := binder.BindCertificateByIP("0.0.0.0", 443, "ABCD1234")

		if err != nil {
			t.Errorf("BindCertificateByIP() error = %v", err)
		}
	})

	t.Run("查找绑定", func(t *testing.T) {
		binder := &MockIISBinder{
			FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
				return []iis.SSLBinding{
					{HostnamePort: "www.example.com:443", CertHash: "OLD123"},
				}, nil
			},
		}

		bindings, err := binder.FindBindingsForDomains([]string{"www.example.com"})
		if err != nil {
			t.Errorf("FindBindingsForDomains() error = %v", err)
		}
		if len(bindings) != 1 {
			t.Errorf("FindBindingsForDomains() 返回 %d 个绑定，期望 1 个", len(bindings))
		}
	})

}

// TestMockAPIClient 测试 Mock API 客户端
func TestMockAPIClient(t *testing.T) {
	t.Run("获取证书", func(t *testing.T) {
		client := &MockAPIClient{
			GetCertByOrderIDFunc: func(ctx context.Context, orderID int) (*api.CertData, error) {
				return &api.CertData{
					OrderID: orderID,
					Domains: "example.com",
					Status:  "active",
				}, nil
			},
		}

		certData, err := client.GetCertByOrderID(context.Background(), 123)
		if err != nil {
			t.Errorf("GetCertByOrderID() error = %v", err)
		}
		if certData.OrderID != 123 {
			t.Errorf("GetCertByOrderID() OrderID = %d, want 123", certData.OrderID)
		}
	})

	t.Run("提交 CSR", func(t *testing.T) {
		client := &MockAPIClient{
			SubmitCSRFunc: func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
				return &api.UpdateResponse{
					Code: 1,
					Msg:  "success",
					Data: api.UpdateResponseData{CertData: api.CertData{
						OrderID: 456,
						Status:  "processing",
					}},
				}, nil
			},
		}

		resp, err := client.SubmitCSR(context.Background(), &api.UpdateRequest{
			Domains: "example.com",
			CSR:     "test-csr",
		})
		if err != nil {
			t.Errorf("SubmitCSR() error = %v", err)
		}
		if resp.Data.OrderID != 456 {
			t.Errorf("SubmitCSR() OrderID = %d, want 456", resp.Data.OrderID)
		}
	})

	t.Run("回调", func(t *testing.T) {
		callbackCalled := false
		client := &MockAPIClient{
			CallbackFunc: func(ctx context.Context, req *api.CallbackRequest) error {
				callbackCalled = true
				return nil
			},
		}

		err := client.Callback(context.Background(), &api.CallbackRequest{
			OrderID: 123,
			Status:  "success",
		})
		if err != nil {
			t.Errorf("Callback() error = %v", err)
		}
		if !callbackCalled {
			t.Error("Callback() 应该被调用")
		}
	})
}

// TestMockOrderStore 测试 Mock 订单存储
func TestMockOrderStore(t *testing.T) {
	t.Run("检查私钥存在", func(t *testing.T) {
		store := &MockOrderStore{
			HasPrivateKeyFunc: func(orderID int) bool {
				return orderID == 123
			},
		}

		if !store.HasPrivateKey(123) {
			t.Error("HasPrivateKey(123) 应该返回 true")
		}
		if store.HasPrivateKey(456) {
			t.Error("HasPrivateKey(456) 应该返回 false")
		}
	})

	t.Run("保存和加载私钥", func(t *testing.T) {
		savedKey := ""
		store := &MockOrderStore{
			SavePrivateKeyFunc: func(orderID int, keyPEM string) error {
				savedKey = keyPEM
				return nil
			},
			LoadPrivateKeyFunc: func(orderID int) (string, error) {
				return savedKey, nil
			},
		}

		err := store.SavePrivateKey(123, "test-key")
		if err != nil {
			t.Errorf("SavePrivateKey() error = %v", err)
		}

		key, err := store.LoadPrivateKey(123)
		if err != nil {
			t.Errorf("LoadPrivateKey() error = %v", err)
		}
		if key != "test-key" {
			t.Errorf("LoadPrivateKey() = %q, want test-key", key)
		}
	})

	t.Run("保存证书", func(t *testing.T) {
		store := &MockOrderStore{}
		err := store.SaveCertificate(123, "cert-pem", "chain-pem")
		if err != nil {
			t.Errorf("SaveCertificate() error = %v", err)
		}
	})

	t.Run("删除订单", func(t *testing.T) {
		deleted := false
		store := &MockOrderStore{
			DeleteOrderFunc: func(orderID int) error {
				deleted = true
				return nil
			},
		}

		err := store.DeleteOrder(123)
		if err != nil {
			t.Errorf("DeleteOrder() error = %v", err)
		}
		if !deleted {
			t.Error("DeleteOrder() 应该被调用")
		}
	})
}

// TestCallbackTimeout 测试回调超时常量
func TestCallbackTimeout(t *testing.T) {
	if CallbackTimeout != 60*time.Second {
		t.Errorf("CallbackTimeout = %v, want 60s", CallbackTimeout)
	}
}

// =============================================================================
// deployCertWithRules 测试
// =============================================================================

func TestDeployCertWithRules(t *testing.T) {
	t.Run("成功路径", func(t *testing.T) {
		d := NewMockDeployer()

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := makeTestCertConfig(100, "example.com", true)
		conflicts := map[iis.EndpointKey][]int{}
		allCerts := []config.CertConfig{certCfg}

		results, _ := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, certCfg, 0, conflicts, allCerts)

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		r := results[0]
		if !r.Success {
			t.Errorf("期望成功，得到失败: %s", r.Message)
		}
		if r.Domain != "example.com" {
			t.Errorf("期望域名 example.com，得到 %s", r.Domain)
		}
		if r.Thumbprint != "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234" {
			t.Errorf("期望指纹 ABCD1234...，得到 %s", r.Thumbprint)
		}
		if r.OrderID != 100 {
			t.Errorf("期望 OrderID=100，得到 %d", r.OrderID)
		}
	})

	t.Run("PFX转换失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Converter.(*MockCertConverter).PEMToPFXFunc = func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
			return "", errors.New("PFX 转换错误")
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "example.com", Port: 443},
				{Domain: "www.example.com", Port: 443},
			},
		}
		conflicts := map[iis.EndpointKey][]int{}
		allCerts := []config.CertConfig{certCfg}

		results, _ := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, certCfg, 0, conflicts, allCerts)

		if len(results) != 2 {
			t.Fatalf("期望 2 个结果（每个 BindRule 域名一个），得到 %d 个", len(results))
		}
		for _, r := range results {
			if r.Success {
				t.Errorf("域名 %s 期望失败，但成功了", r.Domain)
			}
			if !strings.Contains(r.Message, "转换 PFX 失败") {
				t.Errorf("期望消息包含 '转换 PFX 失败'，得到 %s", r.Message)
			}
		}
	})

	t.Run("安装失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Installer.(*MockCertInstaller).InstallPFXFunc = func(pfxPath, password string) (*cert.InstallResult, error) {
			return &cert.InstallResult{
				Success:      false,
				ErrorMessage: "安装失败",
			}, nil
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := makeTestCertConfig(100, "example.com", true)
		conflicts := map[iis.EndpointKey][]int{}
		allCerts := []config.CertConfig{certCfg}

		results, _ := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, certCfg, 0, conflicts, allCerts)

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		r := results[0]
		if r.Success {
			t.Error("期望失败，但成功了")
		}
		if !strings.Contains(r.Message, "安装证书失败") {
			t.Errorf("期望消息包含 '安装证书失败'，得到 %s", r.Message)
		}
	})

	t.Run("绑定失败", func(t *testing.T) {
		d := NewMockDeployer()
		// 第一个域名绑定失败，第二个成功
		callCount := 0
		d.Binder.(*MockIISBinder).BindCertificateFunc = func(hostname string, port int, certHash string) error {
			callCount++
			if callCount == 1 {
				return errors.New("绑定超时")
			}
			return nil
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "fail.example.com", Port: 443},
				{Domain: "ok.example.com", Port: 443},
			},
		}
		conflicts := map[iis.EndpointKey][]int{}
		allCerts := []config.CertConfig{certCfg}

		results, _ := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, certCfg, 0, conflicts, allCerts)

		if len(results) != 2 {
			t.Fatalf("期望 2 个结果，得到 %d 个", len(results))
		}

		// 第一个应该失败
		if results[0].Success {
			t.Error("第一个域名期望失败")
		}
		if !strings.Contains(results[0].Message, "绑定失败") {
			t.Errorf("期望消息包含 '绑定失败'，得到 %s", results[0].Message)
		}

		// 第二个应该成功
		if !results[1].Success {
			t.Errorf("第二个域名期望成功，得到失败: %s", results[1].Message)
		}
	})

	t.Run("域名冲突跳过", func(t *testing.T) {
		d := NewMockDeployer()

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		// 证书1: OrderID=100, 域名 shared.com 和 unique.com
		certCfg := config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "shared.com", Port: 443},
				{Domain: "unique.com", Port: 443},
			},
		}
		// 证书2: OrderID=200, 域名 shared.com, 到期更晚
		certCfg2 := config.CertConfig{
			OrderID:  200,
			Domain:   "other.com",
			Enabled:  true,
			Metadata: config.CertMetadata{CertExpiresAt: "2099-12-31"},
			BindRules: []config.BindRule{
				{Domain: "shared.com", Port: 443},
			},
		}
		allCerts := []config.CertConfig{certCfg, certCfg2}
		// shared.com 冲突：索引 0 和 1
		conflicts := map[iis.EndpointKey][]int{
			{Host: "shared.com", Port: 443}: {0, 1},
		}

		results, _ := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, certCfg, 0, conflicts, allCerts)

		// shared.com 应该被跳过（certCfg2 的 ExpiresAt 更晚，OrderID=200 优先）
		// 只有 unique.com 会被处理
		if len(results) != 1 {
			t.Fatalf("期望 1 个结果（shared.com 被跳过），得到 %d 个", len(results))
		}
		if results[0].Domain != "unique.com" {
			t.Errorf("期望域名 unique.com，得到 %s", results[0].Domain)
		}
		if !results[0].Success {
			t.Errorf("期望成功，得到失败: %s", results[0].Message)
		}
	})
}

// =============================================================================
// deployCertAutoMode 测试
// =============================================================================

func TestDeployCertAutoMode(t *testing.T) {
	t.Run("成功路径", func(t *testing.T) {
		d := NewMockDeployer()
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) ([]iis.SSLBinding, error) {
			return []iis.SSLBinding{
				{HostnamePort: "example.com:443", CertHash: "OLD_HASH"},
			}, nil
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results, _ := deployCertAutoMode(d, NewMockClient(), certData, certData.PrivateKey, certCfg)

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		if !results[0].Success {
			t.Errorf("期望成功，得到失败: %s", results[0].Message)
		}
		if results[0].Thumbprint != "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234" {
			t.Errorf("期望指纹 ABCD1234...，得到 %s", results[0].Thumbprint)
		}
	})

	t.Run("无匹配绑定", func(t *testing.T) {
		d := NewMockDeployer()
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) ([]iis.SSLBinding, error) {
			return nil, nil
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results, _ := deployCertAutoMode(d, NewMockClient(), certData, certData.PrivateKey, certCfg)

		if len(results) != 1 {
			t.Fatalf("无匹配绑定时期望 1 个失败结果，得到 %d 个", len(results))
		}
		if results[0].Success {
			t.Fatal("无匹配绑定时不应报告成功")
		}
		if !strings.Contains(results[0].Message, "未找到匹配") {
			t.Fatalf("失败原因应说明未找到匹配绑定，得到 %q", results[0].Message)
		}
	})

	t.Run("安装成功绑定失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) ([]iis.SSLBinding, error) {
			return []iis.SSLBinding{
				{HostnamePort: "example.com:443", CertHash: "OLD_HASH"},
			}, nil
		}
		d.Binder.(*MockIISBinder).BindCertificateFunc = func(hostname string, port int, certHash string) error {
			return errors.New("netsh 绑定失败")
		}

		certData := makeTestCertData(t, 100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results, _ := deployCertAutoMode(d, NewMockClient(), certData, certData.PrivateKey, certCfg)

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		if results[0].Success {
			t.Error("期望失败，但成功了")
		}
		if !strings.Contains(results[0].Message, "netsh 绑定失败") {
			t.Errorf("期望消息包含 'netsh 绑定失败'，得到 %s", results[0].Message)
		}
		// 即使绑定失败，指纹仍应存在（因为安装成功了）
		if results[0].Thumbprint == "" {
			t.Error("安装成功后指纹不应为空")
		}
	})
}

func TestDeployCertWithRules_PreflightBeforeCertificateInstallation(t *testing.T) {
	certData := makeTestCertData(t, 701, "www.example.com", "active", "2099-12-31")

	tests := []struct {
		name      string
		certCfg   config.CertConfig
		allCerts  []config.CertConfig
		conflicts map[iis.EndpointKey][]int
	}{
		{
			name:     "空规则",
			certCfg:  config.CertConfig{OrderID: 701, Domain: "www.example.com", Enabled: true},
			allCerts: nil,
		},
		{
			name: "全部冲突",
			certCfg: config.CertConfig{
				OrderID: 701,
				Domain:  "www.example.com",
				Enabled: true,
				BindRules: []config.BindRule{
					{Domain: "www.example.com", Port: 443},
				},
			},
			allCerts: []config.CertConfig{
				{
					OrderID: 701, Enabled: true, Metadata: config.CertMetadata{CertExpiresAt: "2025-01-01"},
					BindRules: []config.BindRule{{Domain: "www.example.com", Port: 443}},
				},
				{
					OrderID: 702, Enabled: true, Metadata: config.CertMetadata{CertExpiresAt: "2099-01-01"},
					BindRules: []config.BindRule{{Domain: "WWW.EXAMPLE.COM", Port: 0}},
				},
			},
			conflicts: map[iis.EndpointKey][]int{{Host: "www.example.com", Port: 443}: {0, 1}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted := false
			installed := false
			d := NewMockDeployer()
			d.Converter = &MockCertConverter{PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
				converted = true
				return "unused.pfx", nil
			}}
			d.Installer = &MockCertInstaller{InstallPFXFunc: func(pfxPath, password string) (*cert.InstallResult, error) {
				installed = true
				return &cert.InstallResult{Success: true, Thumbprint: "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"}, nil
			}}

			_, rep := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, tt.certCfg, 0, tt.conflicts, tt.allCerts)
			if converted || installed {
				t.Fatalf("目标预检失败仍转换/安装: converted=%v installed=%v", converted, installed)
			}
			if tt.name == "全部冲突" && rep.report {
				t.Fatalf("全部冲突不得产生 callback 报告: %+v", rep)
			}
		})
	}
}

func TestDeployCertWithRules_DuplicateOrderIDUsesWinningIndex(t *testing.T) {
	certData := makeTestCertData(t, 801, "shared.example.com", "active", "2099-12-31")
	loser := config.CertConfig{
		OrderID: 801,
		Domain:  "loser.example.com",
		Enabled: true,
		Metadata: config.CertMetadata{
			CertExpiresAt: "2025-01-01",
		},
		BindRules: []config.BindRule{{Domain: "shared.example.com", Port: 443}},
	}
	winner := config.CertConfig{
		OrderID: 801,
		Domain:  "winner.example.com",
		Enabled: true,
		Metadata: config.CertMetadata{
			CertExpiresAt: "2099-01-01",
		},
		BindRules: []config.BindRule{{Domain: "SHARED.EXAMPLE.COM", Port: 0}},
	}
	allCerts := []config.CertConfig{loser, winner}
	conflicts := checkDomainConflicts(allCerts)

	converted := false
	d := NewMockDeployer()
	d.Converter = &MockCertConverter{PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
		converted = true
		return "unused.pfx", nil
	}}

	results, rep := deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, loser, 0, conflicts, allCerts)
	if converted || len(results) != 0 || rep.report {
		t.Fatalf("重复 OrderID 的非选优索引不应执行: converted=%v results=%+v report=%+v", converted, results, rep)
	}

	results, rep = deployCertWithRules(d, NewMockClient(), certData, certData.PrivateKey, winner, 1, conflicts, allCerts)
	if !converted || len(results) != 1 || !results[0].Success || !rep.report || !rep.success {
		t.Fatalf("重复 OrderID 只能由选优索引执行: converted=%v results=%+v report=%+v", converted, results, rep)
	}
}

func TestDeployCertAutoMode_DiscoversTargetsBeforeCertificateInstallation(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 703, "www.example.com")

	tests := []struct {
		name string
		find func([]string) ([]iis.SSLBinding, error)
	}{
		{name: "发现失败", find: func([]string) ([]iis.SSLBinding, error) {
			return nil, errors.New("netsh 查询失败")
		}},
		{name: "零目标", find: func([]string) ([]iis.SSLBinding, error) {
			return nil, nil
		}},
		{name: "坏端口", find: func([]string) ([]iis.SSLBinding, error) {
			return []iis.SSLBinding{{HostnamePort: "www.example.com:not-a-port"}}, nil
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			converted := false
			installed := false
			d := NewMockDeployer()
			d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = tt.find
			d.Converter = &MockCertConverter{PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
				converted = true
				return "unused.pfx", nil
			}}
			d.Installer = &MockCertInstaller{InstallPFXFunc: func(pfxPath, password string) (*cert.InstallResult, error) {
				installed = true
				return &cert.InstallResult{Success: true, Thumbprint: "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234"}, nil
			}}

			_, _ = deployCertAutoMode(d, NewMockClient(), certData, keyPEM, certCfg)
			if converted || installed {
				t.Fatalf("发现阶段无可执行目标仍转换/安装: converted=%v installed=%v", converted, installed)
			}
		})
	}
}

// =============================================================================
// handleLocalKeyMode 测试
// =============================================================================

func TestHandleLocalKeyMode(t *testing.T) {
	t.Run("processing状态", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 100,
				Domains: "example.com",
				Status:  "processing",
			}, nil
		}

		certCfg := &config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
		}

		certData, privateKey, reason, err := handleLocalKeyMode(d, mockClient, certCfg, 15)

		if err != nil {
			t.Errorf("不期望错误，得到: %v", err)
		}
		if certData != nil {
			t.Error("processing 状态下 certData 应为 nil")
		}
		if privateKey != "" {
			t.Error("processing 状态下 privateKey 应为空")
		}
		if reason != "CSR 已提交，等待签发" {
			t.Errorf("期望原因 'CSR 已提交，等待签发'，得到 %q", reason)
		}
	})

	t.Run("异步签发active忽略新证书续签窗口并使用pending私钥", func(t *testing.T) {
		d := NewMockDeployer()
		certPEM, pendingKey := genSelfSignedPair(t, "example.com")
		mockClient := NewMockClient()
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     orderID,
				Domains:     "example.com",
				Status:      "active",
				ExpiresAt:   time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
				Certificate: certPEM,
				CACert:      testCACertPEM,
			}, nil
		}
		store := d.Store.(*MockOrderStore)
		store.HasPrivateKeyFunc = func(orderID int) bool { return false }
		store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
		store.LoadPendingPrivateKeyFunc = func(certName string) (string, error) { return pendingKey, nil }

		certCfg := &config.CertConfig{
			CertName: "example.com-100",
			OrderID:  100,
			Domain:   "example.com",
			Metadata: config.CertMetadata{LastIssueState: "processing"},
		}
		certData, privateKey, reason, err := handleLocalKeyMode(d, mockClient, certCfg, 30)
		if err != nil {
			t.Fatalf("handleLocalKeyMode() error = %v", err)
		}
		if certData == nil || certData.Status != "active" {
			t.Fatalf("异步签发完成后应返回 active 证书，got %+v", certData)
		}
		if privateKey != pendingKey {
			t.Fatal("异步签发完成后应使用配对的 pending 私钥")
		}
		if reason != "" {
			t.Fatalf("不应按新证书有效期跳过，reason = %q", reason)
		}
	})

	t.Run("metadata缺失但pending存在时仍恢复异步active", func(t *testing.T) {
		d := NewMockDeployer()
		certPEM, pendingKey := genSelfSignedPair(t, "example.com")
		mockClient := NewMockClient()
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     orderID,
				Domains:     "example.com",
				Status:      "active",
				ExpiresAt:   time.Now().AddDate(1, 0, 0).Format("2006-01-02"),
				Certificate: certPEM,
				CACert:      testCACertPEM,
			}, nil
		}
		store := d.Store.(*MockOrderStore)
		store.HasPrivateKeyFunc = func(orderID int) bool { return false }
		store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
		store.LoadPendingPrivateKeyFunc = func(certName string) (string, error) { return pendingKey, nil }
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com"}

		certData, privateKey, reason, err := handleLocalKeyMode(d, mockClient, certCfg, 30)
		if err != nil {
			t.Fatalf("handleLocalKeyMode() error = %v", err)
		}
		if certData == nil || privateKey != pendingKey || reason != "" {
			t.Fatalf("pending 恢复失败: cert=%+v keyMatch=%v reason=%q", certData, privateKey == pendingKey, reason)
		}
	})

	t.Run("active且未到续签时间", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()
		// 设置过期时间为未来很远
		futureExpiry := time.Now().AddDate(0, 6, 0).Format("2006-01-02")
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     100,
				Domains:     "example.com",
				Status:      "active",
				ExpiresAt:   futureExpiry,
				Certificate: testCertPEM,
				PrivateKey:  testKeyPEM,
			}, nil
		}

		certCfg := &config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
		}

		certData, _, reason, err := handleLocalKeyMode(d, mockClient, certCfg, 15)

		if err != nil {
			t.Errorf("不期望错误，得到: %v", err)
		}
		if certData != nil {
			t.Error("未到续签时间时 certData 应为 nil")
		}
		if !strings.Contains(reason, "未到续签时间") {
			t.Errorf("期望原因包含 '未到续签时间'，得到 %q", reason)
		}
	})

	t.Run("初始active进入续签窗口时提交CSR而非重部署旧证书", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()
		// 设置过期时间为很快过期
		soonExpiry := time.Now().AddDate(0, 0, 5).Format("2006-01-02")
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     100,
				Domains:     "example.com",
				Status:      "active",
				ExpiresAt:   soonExpiry,
				Certificate: testCertPEM,
				PrivateKey:  testKeyPEM,
				CACert:      testCACertPEM,
			}, nil
		}
		// 没有本地私钥
		d.Store.(*MockOrderStore).HasPrivateKeyFunc = func(orderID int) bool { return false }
		submitted := false
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitted = true
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 101,
				Status:  "processing",
			}}}, nil
		}

		certCfg := &config.CertConfig{
			CertName: "example.com-100",
			OrderID:  100,
			Domain:   "example.com",
		}

		certData, privateKey, reason, err := handleLocalKeyMode(d, mockClient, certCfg, 100)

		if err != nil {
			t.Errorf("不期望错误，得到: %v", err)
		}
		if !submitted {
			t.Fatal("进入续签窗口后应提交新 CSR")
		}
		if certData != nil || privateKey != "" {
			t.Fatal("提交 CSR 的轮次不应重部署当前旧证书")
		}
		if reason == "" {
			t.Fatal("应返回等待异步签发的原因")
		}
	})
}

func TestFinalizeSuccessfulDeployment_PromotesPendingBeforeClearingState(t *testing.T) {
	d := NewMockDeployer()
	store := d.Store.(*MockOrderStore)
	promoted := false
	store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
	store.PromotePendingPrivateKeyFunc = func(certName string, orderID int, deployedKey string) error {
		promoted = true
		if certName != "example.com-100" || orderID != 200 || deployedKey != "pending-key" {
			t.Fatalf("转正参数错误: certName=%q orderID=%d key=%q", certName, orderID, deployedKey)
		}
		return nil
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-100",
		OrderID:  200,
		Metadata: config.CertMetadata{LastIssueState: "processing", IssueRetryCount: 2},
	}
	certData := &api.CertData{OrderID: 200, ExpiresAt: "2027-07-18"}

	if !finalizeSuccessfulDeployment(d, certCfg, certData, "pending-key", true) {
		t.Fatal("pending 私钥转正成功后应完成状态收敛")
	}
	if !promoted {
		t.Fatal("部署成功后应转正 pending 私钥")
	}
	if certCfg.Metadata.LastIssueState != "" || certCfg.Metadata.IssueRetryCount != 0 {
		t.Fatalf("转正成功后应清理签发状态: %+v", certCfg.Metadata)
	}
}

func TestFinalizeSuccessfulDeployment_PromotionFailureKeepsIssueState(t *testing.T) {
	d := NewMockDeployer()
	store := d.Store.(*MockOrderStore)
	store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
	store.PromotePendingPrivateKeyFunc = func(certName string, orderID int, deployedKey string) error {
		return errors.New("disk full")
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-100",
		OrderID:  200,
		Metadata: config.CertMetadata{LastIssueState: "processing", IssueRetryCount: 2},
	}
	certData := &api.CertData{OrderID: 200, ExpiresAt: "2027-07-18"}

	if finalizeSuccessfulDeployment(d, certCfg, certData, "pending-key", true) {
		t.Fatal("pending 私钥转正失败时不应清理签发状态")
	}
	if certCfg.Metadata.LastIssueState != "processing" || certCfg.Metadata.IssueRetryCount != 2 {
		t.Fatalf("转正失败应保留签发状态: %+v", certCfg.Metadata)
	}
}

// =============================================================================
// submitNewCSR 测试
// =============================================================================

func TestSubmitNewCSR(t *testing.T) {
	t.Run("CSR提交成功-processing", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			return &api.UpdateResponse{
				Code: 1,
				Msg:  "success",
				Data: api.UpdateResponseData{CertData: api.CertData{
					OrderID: 200,
					Status:  "processing",
				}},
			}, nil
		}

		certCfg := &config.CertConfig{
			OrderID: 0,
			Domain:  "example.com",
			Domains: []string{"example.com"},
		}

		certData, _, reason, err := submitNewCSR(d, mockClient, certCfg)

		if err != nil {
			t.Errorf("不期望错误，得到: %v", err)
		}
		if certData != nil {
			t.Error("processing 状态下 certData 应为 nil")
		}
		if reason != "CSR 已提交，等待签发" {
			t.Errorf("期望原因 'CSR 已提交，等待签发'，得到 %q", reason)
		}
		// 验证 OrderID 被更新
		if certCfg.OrderID != 200 {
			t.Errorf("期望 certCfg.OrderID 被更新为 200，得到 %d", certCfg.OrderID)
		}
	})

	t.Run("active响应也必须等待后续轮次查询", func(t *testing.T) {
		d := NewMockDeployer()
		queryCalled := false
		mockClient := NewMockClient()
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 200,
				Status:  "active",
			}}}, nil
		}
		mockClient.GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			queryCalled = true
			return &api.CertData{OrderID: orderID, Status: "active"}, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com"}

		certData, privateKey, reason, err := submitNewCSR(d, mockClient, certCfg)
		if err != nil {
			t.Fatalf("submitNewCSR() error = %v", err)
		}
		if queryCalled {
			t.Fatal("CSR 提交响应为 active 时不应在本轮立即查询")
		}
		if certData != nil || privateKey != "" {
			t.Fatal("CSR 提交轮次不应直接返回待部署证书或私钥")
		}
		if reason == "" {
			t.Fatal("应返回等待后续查询的原因")
		}
	})

	t.Run("CSR提交失败", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, errors.New("网络错误")
		}

		certCfg := &config.CertConfig{
			OrderID: 0,
			Domain:  "example.com",
			Domains: []string{"example.com"},
		}

		_, _, _, err := submitNewCSR(d, mockClient, certCfg)

		if err == nil {
			t.Error("期望错误，但成功了")
		}
		if !strings.Contains(err.Error(), "提交 CSR 失败") {
			t.Errorf("期望错误包含 '提交 CSR 失败'，得到 %s", err.Error())
		}
		if certCfg.Metadata.LastIssueState != config.IssueStateProcessing {
			t.Fatalf("请求结果不确定时应保留在途 processing 状态，got %q", certCfg.Metadata.LastIssueState)
		}
	})

	t.Run("已有pending时重放同一CSR且不覆盖私钥", func(t *testing.T) {
		d := NewMockDeployer()
		store := d.Store.(*MockOrderStore)
		pendingKey, pendingCSR, err := cert.GenerateCSR("example.com")
		if err != nil {
			t.Fatalf("GenerateCSR() error = %v", err)
		}
		store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
		store.LoadPendingCSRFunc = func(certName string) (string, error) { return pendingCSR, nil }
		store.LoadPendingPrivateKeyFunc = func(certName string) (string, error) { return pendingKey, nil }
		store.SavePendingPrivateKeyFunc = func(certName, keyPEM string) error {
			t.Fatal("不应覆盖已有 pending 私钥")
			return nil
		}
		mockClient := NewMockClient()
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			if req.CSR != pendingCSR {
				t.Fatalf("应重放原 CSR，got %q", req.CSR)
			}
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 100,
				Status:  "processing",
			}}}, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com"}

		_, _, reason, err := submitNewCSR(d, mockClient, certCfg)
		if err != nil {
			t.Fatalf("submitNewCSR() error = %v", err)
		}
		if reason != "CSR 已提交，等待签发" {
			t.Fatalf("应返回等待签发提示，got %q", reason)
		}
	})

	t.Run("网络失败后再次调用重放相同CSR和私钥对", func(t *testing.T) {
		d := NewMockDeployer()
		store := d.Store.(*MockOrderStore)
		var pending bool
		var storedCSR string
		var storedKey string
		saveKeyCount := 0
		store.HasPendingPrivateKeyFunc = func(certName string) bool { return pending }
		store.SavePendingCSRFunc = func(certName, csrPEM string) error {
			storedCSR = csrPEM
			return nil
		}
		store.SavePendingPrivateKeyFunc = func(certName, keyPEM string) error {
			pending = true
			storedKey = keyPEM
			saveKeyCount++
			return nil
		}
		store.LoadPendingCSRFunc = func(certName string) (string, error) { return storedCSR, nil }
		store.LoadPendingPrivateKeyFunc = func(certName string) (string, error) { return storedKey, nil }

		mockClient := NewMockClient()
		var firstCSR string
		calls := 0
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			calls++
			if calls == 1 {
				firstCSR = req.CSR
				return nil, errors.New("connection reset")
			}
			if req.CSR != firstCSR {
				t.Fatalf("重试必须重放同一 CSR")
			}
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 200,
				Status:  "processing",
			}}}, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com"}

		if _, _, _, err := submitNewCSR(d, mockClient, certCfg); err == nil {
			t.Fatal("首次网络失败应返回错误")
		}
		if _, _, reason, err := submitNewCSR(d, mockClient, certCfg); err != nil {
			t.Fatalf("第二次重放失败: %v", err)
		} else if reason != "CSR 已提交，等待签发" {
			t.Fatalf("重放成功提示不正确: %q", reason)
		}
		if calls != 2 || saveKeyCount != 1 {
			t.Fatalf("应提交两次但只生成保存一次私钥，calls=%d saveKeyCount=%d", calls, saveKeyCount)
		}
	})

	t.Run("pending CSR与私钥不匹配时拒绝重放", func(t *testing.T) {
		d := NewMockDeployer()
		store := d.Store.(*MockOrderStore)
		keyPEM, _, err := cert.GenerateCSR("example.com")
		if err != nil {
			t.Fatalf("GenerateCSR(key) error = %v", err)
		}
		_, otherCSR, err := cert.GenerateCSR("other.example.com")
		if err != nil {
			t.Fatalf("GenerateCSR(csr) error = %v", err)
		}
		store.HasPendingPrivateKeyFunc = func(certName string) bool { return true }
		store.LoadPendingCSRFunc = func(certName string) (string, error) { return otherCSR, nil }
		store.LoadPendingPrivateKeyFunc = func(certName string) (string, error) { return keyPEM, nil }
		mockClient := NewMockClient()
		mockClient.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			t.Fatal("不匹配的 CSR 与私钥不得提交")
			return nil, nil
		}

		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com"}
		if _, _, _, err := submitNewCSR(d, mockClient, certCfg); err == nil || !strings.Contains(err.Error(), "不匹配") {
			t.Fatalf("应拒绝不匹配的 pending CSR/私钥，got %v", err)
		}
	})
}

// =============================================================================
// sendCallback 测试
// =============================================================================

func TestSendCallback(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()

		var callCount int32
		var wg sync.WaitGroup
		wg.Add(1)

		mockClient.CallbackFunc = func(ctx context.Context, req *api.CallbackRequest) error {
			atomic.AddInt32(&callCount, 1)
			wg.Done()
			return nil
		}

		sendCallback(d, mockClient, 100, "example.com", true, "")

		wg.Wait()

		if atomic.LoadInt32(&callCount) != 1 {
			t.Errorf("期望调用 1 次，实际调用 %d 次", atomic.LoadInt32(&callCount))
		}
	})

	t.Run("失败只调用一次-依赖内部重试", func(t *testing.T) {
		d := NewMockDeployer()
		mockClient := NewMockClient()

		var callCount int32

		mockClient.CallbackFunc = func(ctx context.Context, req *api.CallbackRequest) error {
			atomic.AddInt32(&callCount, 1)
			return errors.New("回调失败")
		}

		sendCallback(d, mockClient, 100, "example.com", false, "部署失败")

		d.callbackWg.Wait()

		finalCount := atomic.LoadInt32(&callCount)
		if finalCount != 1 {
			t.Errorf("期望调用 1 次（重试由 Client 内部处理），实际调用 %d 次", finalCount)
		}
	})
}

// =============================================================================
// AutoDeploy 集成测试（per-cert client 模式）
// =============================================================================

func TestAutoDeploy_Integration_NoAPI(t *testing.T) {
	t.Run("无API配置-全部失败", func(t *testing.T) {
		d := NewMockDeployer()

		cfg := &config.Config{
			Schedule: config.Schedule{RenewBeforeDays: 13},
			Certificates: []config.CertConfig{
				{
					OrderID: 100,
					Domain:  "example.com",
					Domains: []string{"example.com"},
					Enabled: true,
					BindRules: []config.BindRule{
						{Domain: "example.com", Port: 443},
					},
					// 无 API 配置
				},
			},
		}

		results := AutoDeploy(cfg, d, RunOptions{}).Results

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		if results[0].Success {
			t.Error("无 API 配置时期望失败")
		}
		if !strings.Contains(results[0].Message, "API 配置错误") {
			t.Errorf("期望消息包含 'API 配置错误'，得到 %s", results[0].Message)
		}
	})

	t.Run("混合-部分有API部分无API", func(t *testing.T) {
		d := NewMockDeployer()

		cfg := &config.Config{
			Schedule: config.Schedule{RenewBeforeDays: 13},
			Certificates: []config.CertConfig{
				{
					OrderID: 100,
					Domain:  "no-api.com",
					Enabled: true,
					BindRules: []config.BindRule{
						{Domain: "no-api.com", Port: 443},
					},
					// 无 API 配置
				},
				{
					OrderID: 200,
					Domain:  "no-token.com",
					Enabled: true,
					BindRules: []config.BindRule{
						{Domain: "no-token.com", Port: 443},
					},
					API: config.CertAPIConfig{URL: "https://api.example.com"},
					// 无 Token
				},
			},
		}

		results := AutoDeploy(cfg, d, RunOptions{}).Results

		if len(results) != 2 {
			t.Fatalf("期望 2 个结果，得到 %d 个", len(results))
		}
		for _, r := range results {
			if r.Success {
				t.Errorf("域名 %s 期望失败", r.Domain)
			}
		}
	})
}

func TestRunReportErr_AggregatesIndependentFailuresWithoutTextDeduplication(t *testing.T) {
	shared := errors.New("disk full")
	report := RunReport{
		Results: []Result{
			{OrderID: 101, Domain: "bad.example.com", Success: false, Message: shared.Error()},
			{OrderID: 104, Domain: "other.example.com", Success: false, Message: shared.Error()},
			{OrderID: 102, Domain: "ok.example.com", Success: true, Message: "deployed"},
		},
		Errors:         []error{shared, errors.New("final save failed")},
		Warnings:       []string{"callback rejected"},
		Attention:      []CertAttention{{OrderID: 103, Domain: "manual.example.com", Reason: "CAPPED"}},
		AlreadyRunning: true,
	}

	err := report.Err()
	if err == nil {
		t.Fatal("失败 Result 与运行级错误必须通过 Err 暴露")
	}
	got := err.Error()
	if strings.Count(got, shared.Error()) != 3 {
		t.Fatalf("不同证书和运行级错误即使文本相同也必须全部保留: %q", got)
	}
	if !errors.Is(err, shared) {
		t.Fatalf("聚合后必须保留运行级错误链: %v", err)
	}
	if !strings.Contains(got, "final save failed") {
		t.Fatalf("运行级错误未聚合: %q", got)
	}
	if strings.Contains(got, "callback rejected") || strings.Contains(got, "CAPPED") {
		t.Fatalf("warning/attention 不得进入 Err: %q", got)
	}
}

func TestRunReportErr_NonErrorStatesAreNil(t *testing.T) {
	report := RunReport{
		Warnings:       []string{"callback rejected"},
		Attention:      []CertAttention{{OrderID: 103, Domain: "manual.example.com", Reason: "EXPIRED"}},
		AlreadyRunning: true,
	}
	if err := report.Err(); err != nil {
		t.Fatalf("正常锁占用、warning 与 attention 都不是运行错误: %v", err)
	}
}

func TestRunAutoDeploy_LockFailuresStopBeforeExternalCalls(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*autoDeployDependencies)
		wantText  string
	}{
		{
			name: "open error",
			configure: func(deps *autoDeployDependencies) {
				deps.openLock = func(string) (autoDeployLock, error) {
					return nil, errors.New("open denied")
				}
			},
			wantText: "open denied",
		},
		{
			name: "lock error",
			configure: func(deps *autoDeployDependencies) {
				deps.tryLock = func(autoDeployLock) (bool, error) {
					return false, errors.New("lock denied")
				}
			},
			wantText: "lock denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			certData := *makeTestCertData(t, 501, "locked.example.com", "active",
				time.Now().AddDate(0, 0, 5).Format("2006-01-02"))
			cfg := config.DefaultConfig()
			cfg.Certificates = []config.CertConfig{runReportCertConfig(t, certData, 1, &calls)}

			deps := successfulAutoDeployDependencies(nil)
			tt.configure(&deps)
			report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, deps)

			if calls.Load() != 0 {
				t.Fatalf("锁失败后不得发起外部调用，got %d", calls.Load())
			}
			if len(report.Results) != 0 || len(report.Errors) != 1 {
				t.Fatalf("锁失败只能产生一个运行级错误: %+v", report)
			}
			if err := report.Err(); err == nil || !strings.Contains(err.Error(), tt.wantText) {
				t.Fatalf("锁错误必须通过 Err 暴露: %v", err)
			}
		})
	}
}

func TestRunAutoDeploy_AlreadyRunningIsNotAnError(t *testing.T) {
	deps := successfulAutoDeployDependencies(nil)
	deps.tryLock = func(autoDeployLock) (bool, error) { return false, nil }
	cfg := &config.Config{Certificates: []config.CertConfig{{OrderID: 502, Domain: "busy.example.com", Enabled: true}}}

	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, deps)
	if !report.AlreadyRunning {
		t.Fatal("正常锁占用必须设置 AlreadyRunning")
	}
	if err := report.Err(); err != nil {
		t.Fatalf("正常锁占用不是错误: %v", err)
	}
}

func TestRunAutoDeploy_PersistFailuresAreClassified(t *testing.T) {
	t.Run("per certificate save is a Result", func(t *testing.T) {
		saveCalls := 0
		deps := successfulAutoDeployDependencies(func(*config.Config) error {
			saveCalls++
			if saveCalls == 1 {
				return errors.New("certificate state save failed")
			}
			return nil
		})
		cfg := &config.Config{Certificates: []config.CertConfig{{
			OrderID: 503, Domain: "persist.example.com", Enabled: true,
		}}}

		report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, deps)
		if len(report.Errors) != 0 {
			t.Fatalf("逐证书保存错误不得进入运行级 Errors: %v", report.Errors)
		}
		found := false
		for _, result := range report.Results {
			if !result.Success && strings.Contains(result.Message, "certificate state save failed") {
				found = result.OrderID == 503 && result.Domain == "persist.example.com"
			}
		}
		if !found {
			t.Fatalf("逐证书保存错误必须保留订单/域名语义: %+v", report.Results)
		}
		if err := report.Err(); err == nil || !strings.Contains(err.Error(), "certificate state save failed") {
			t.Fatalf("逐证书保存错误必须通过 Err 暴露: %v", err)
		}
	})

	t.Run("final save is a runtime Error", func(t *testing.T) {
		deps := successfulAutoDeployDependencies(func(*config.Config) error {
			return errors.New("final config save failed")
		})
		cfg := &config.Config{Certificates: []config.CertConfig{{Enabled: false}}}

		report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, deps)
		if len(report.Results) != 0 || len(report.Errors) != 1 {
			t.Fatalf("最终保存失败只能进入运行级 Errors: %+v", report)
		}
		if err := report.Err(); err == nil || !strings.Contains(err.Error(), "final config save failed") {
			t.Fatalf("最终保存错误必须通过 Err 暴露: %v", err)
		}
	})
}

func TestRunAutoDeploy_CertificateValidationFailuresAreResults(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*api.CertData)
		wantText string
	}{
		{"invalid expiry", func(certData *api.CertData) { certData.ExpiresAt = "not-a-date" }, "过期时间"},
		{"oversized chain", func(certData *api.CertData) { certData.CACert = strings.Repeat("x", cert.MaxCertChainSize+1) }, "证书链"},
		{"oversized private key", func(certData *api.CertData) { certData.PrivateKey = strings.Repeat("x", cert.MaxPrivateKeySize+1) }, "私钥"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			certData := *makeTestCertData(t, 504, "invalid.example.com", "active",
				time.Now().AddDate(0, 0, 5).Format("2006-01-02"))
			tt.mutate(&certData)
			cfg := config.DefaultConfig()
			cfg.Certificates = []config.CertConfig{runReportCertConfig(t, certData, 1, &calls)}

			report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, successfulAutoDeployDependencies(nil))
			if len(report.Errors) != 0 || len(report.Results) != 1 || report.Results[0].Success {
				t.Fatalf("证书级校验失败必须是失败 Result: %+v", report)
			}
			if !strings.Contains(report.Results[0].Message, tt.wantText) {
				t.Fatalf("失败原因 = %q, want contains %q", report.Results[0].Message, tt.wantText)
			}
			if err := report.Err(); err == nil {
				t.Fatal("证书级校验失败必须通过 Err 暴露")
			}
		})
	}
}

func TestRunAutoDeploy_NonErrorStates(t *testing.T) {
	t.Run("processing", func(t *testing.T) {
		var calls atomic.Int32
		certData := *makeTestCertData(t, 505, "processing.example.com", "processing",
			time.Now().AddDate(0, 0, 5).Format("2006-01-02"))
		cfg := config.DefaultConfig()
		cfg.Certificates = []config.CertConfig{runReportCertConfig(t, certData, 1, &calls)}

		report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, successfulAutoDeployDependencies(nil))
		if len(report.Results) != 0 || len(report.Attention) != 0 || report.Err() != nil {
			t.Fatalf("processing 只等待，不是错误或 attention: %+v", report)
		}
	})

	t.Run("API expired certificate", func(t *testing.T) {
		var calls atomic.Int32
		certData := *makeTestCertData(t, 505, "expired-api.example.com", "active",
			time.Now().AddDate(0, 0, -1).Format("2006-01-02"))
		cfg := config.DefaultConfig()
		cfg.Certificates = []config.CertConfig{runReportCertConfig(t, certData, 1, &calls)}

		report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, successfulAutoDeployDependencies(nil))
		if len(report.Attention) != 1 || report.Attention[0].Reason != "EXPIRED" {
			t.Fatalf("API 返回的已过期证书必须进入 Attention: %+v", report)
		}
		if report.Err() != nil {
			t.Fatalf("EXPIRED attention 不是运行错误: %v", report.Err())
		}
	})

	tests := []struct {
		name string
		meta config.CertMetadata
	}{
		{"CAPPED", config.CertMetadata{LastIssueState: config.IssueStateCapped}},
		{"EXPIRED", config.CertMetadata{LastIssueState: config.IssueStateExpired}},
		{"policy", config.CertMetadata{LastIssueState: config.IssueStatePolicyBlocked}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{Certificates: []config.CertConfig{{
				OrderID: 506, Domain: "attention.example.com", Enabled: true, Metadata: tt.meta,
			}}}
			report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, successfulAutoDeployDependencies(nil))
			if len(report.Attention) != 1 || report.Attention[0].OrderID != 506 {
				t.Fatalf("人工状态必须进入 Attention: %+v", report)
			}
			if len(report.Results) != 0 || report.Err() != nil {
				t.Fatalf("attention 不得变成失败结果: %+v", report)
			}
		})
	}
}

func TestRunAutoDeploy_WaitsAndCollectsCallbackWarning(t *testing.T) {
	var calls atomic.Int32
	certData := *makeTestCertData(t, 507, "callback-warning.example.com", "active",
		time.Now().AddDate(0, 0, 5).Format("2006-01-02"))
	cfg := config.DefaultConfig()
	cfg.Certificates = []config.CertConfig{runReportCertConfig(t, certData, 0, &calls)}

	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{}, successfulAutoDeployDependencies(nil))
	if len(report.Results) == 0 || !report.Results[0].Success {
		t.Fatalf("callback 失败不得改写已成功部署结果: %+v", report.Results)
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "callback") {
		t.Fatalf("AutoDeploy 必须等待并汇总 callback warning: %+v", report.Warnings)
	}
	if err := report.Err(); err != nil {
		t.Fatalf("callback warning 不得进入 Err: %v", err)
	}
}
