package deploy

import (
	"context"
	"errors"
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

// TestAutoDeploy_NoCertificates 测试没有配置证书的情况
func TestAutoDeploy_NoCertificates(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{},
		APIBaseURL:   "https://api.example.com",
	}
	cfg.SetToken("test-token")

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d)

	if len(results) != 0 {
		t.Errorf("没有配置证书时应该返回空结果，得到 %d 个结果", len(results))
	}
}

// TestAutoDeploy_NoToken 测试没有配置 Token 的情况
func TestAutoDeploy_NoToken(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 123, Domain: "example.com", Enabled: true},
		},
		APIBaseURL: "https://api.example.com",
	}
	// 不设置 Token

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d)

	if len(results) != 0 {
		t.Errorf("没有配置 Token 时应该返回空结果，得到 %d 个结果", len(results))
	}
}

// TestAutoDeploy_DisabledCertificate 测试禁用的证书被跳过
func TestAutoDeploy_DisabledCertificate(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 123, Domain: "example.com", Enabled: false},
		},
		APIBaseURL: "https://api.example.com",
	}
	cfg.SetToken("test-token")

	d := NewMockDeployer()
	results := AutoDeploy(cfg, d)

	if len(results) != 0 {
		t.Errorf("禁用的证书应该被跳过，得到 %d 个结果", len(results))
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
			wantRenew:  true,
			wantReason: false,
		},
		{
			name:       "无效日期格式",
			expiresAt:  "invalid",
			renewDays:  15,
			wantRenew:  true, // 解析失败时继续处理
			wantReason: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certData := &api.CertData{
				Domain:    "example.com",
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

			reason, err := handleProcessingOrder(cfg, tt.certData)

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

		certData := makeTestCertData(123, "example.com", "active", "2025-01-01")
		_, _, ok := tryUseLocalKey(d, certData, 123)
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

		certData := makeTestCertData(123, "example.com", "active", "2025-01-01")
		_, _, ok := tryUseLocalKey(d, certData, 123)
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
	if deployer.Client == nil {
		t.Error("Client 不应为 nil")
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
			FindBindingsForDomainsFunc: func(domains []string) (map[string]*iis.SSLBinding, error) {
				return map[string]*iis.SSLBinding{
					"www.example.com": {HostnamePort: "www.example.com:443", CertHash: "OLD123"},
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

	t.Run("IIS7 检测", func(t *testing.T) {
		binder := &MockIISBinder{
			IsIIS7Func: func() bool { return true },
		}

		if !binder.IsIIS7() {
			t.Error("IsIIS7() 应该返回 true")
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
					Domain:  "example.com",
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
			SubmitCSRFunc: func(ctx context.Context, req *api.CSRRequest) (*api.CSRResponse, error) {
				return &api.CSRResponse{
					Code: 1,
					Msg:  "success",
					Data: struct {
						OrderID int    `json:"order_id"`
						Status  string `json:"status"`
					}{
						OrderID: 456,
						Status:  "processing",
					},
				}, nil
			},
		}

		resp, err := client.SubmitCSR(context.Background(), &api.CSRRequest{
			Domain: "example.com",
			CSR:    "test-csr",
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
			Domain:  "example.com",
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

	t.Run("保存元数据", func(t *testing.T) {
		store := &MockOrderStore{}
		err := store.SaveMeta(123, &cert.OrderMeta{
			OrderID: 123,
			Domain:  "example.com",
		})
		if err != nil {
			t.Errorf("SaveMeta() error = %v", err)
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

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := makeTestCertConfig(100, "example.com", true)
		conflicts := map[string][]int{}
		allCerts := []config.CertConfig{certCfg}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

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

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "example.com", Port: 443},
				{Domain: "www.example.com", Port: 443},
			},
		}
		conflicts := map[string][]int{}
		allCerts := []config.CertConfig{certCfg}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

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

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := makeTestCertConfig(100, "example.com", true)
		conflicts := map[string][]int{}
		allCerts := []config.CertConfig{certCfg}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

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

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "fail.example.com", Port: 443},
				{Domain: "ok.example.com", Port: 443},
			},
		}
		conflicts := map[string][]int{}
		allCerts := []config.CertConfig{certCfg}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

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

	t.Run("IIS7模式", func(t *testing.T) {
		d := NewMockDeployer()
		d.Binder.(*MockIISBinder).IsIIS7Func = func() bool { return true }

		bindByIPCalled := false
		d.Binder.(*MockIISBinder).BindCertificateByIPFunc = func(ip string, port int, certHash string) error {
			bindByIPCalled = true
			if ip != "0.0.0.0" {
				t.Errorf("期望 IP 为 0.0.0.0，得到 %s", ip)
			}
			return nil
		}

		sniCalled := false
		d.Binder.(*MockIISBinder).BindCertificateFunc = func(hostname string, port int, certHash string) error {
			sniCalled = true
			return nil
		}

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := makeTestCertConfig(100, "example.com", true)
		conflicts := map[string][]int{}
		allCerts := []config.CertConfig{certCfg}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

		if !bindByIPCalled {
			t.Error("IIS7 模式下应该调用 BindCertificateByIP")
		}
		if sniCalled {
			t.Error("IIS7 模式下不应该调用 BindCertificate (SNI)")
		}
		if len(results) != 1 || !results[0].Success {
			t.Errorf("期望 1 个成功结果，得到 %d 个", len(results))
		}
	})

	t.Run("域名冲突跳过", func(t *testing.T) {
		d := NewMockDeployer()

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
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
			OrderID:   200,
			Domain:    "other.com",
			Enabled:   true,
			ExpiresAt: "2099-12-31",
			BindRules: []config.BindRule{
				{Domain: "shared.com", Port: 443},
			},
		}
		allCerts := []config.CertConfig{certCfg, certCfg2}
		// shared.com 冲突：索引 0 和 1
		conflicts := map[string][]int{
			"shared.com": {0, 1},
		}

		results := deployCertWithRules(d, certData, testKeyPEM, certCfg, conflicts, allCerts)

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
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) (map[string]*iis.SSLBinding, error) {
			return map[string]*iis.SSLBinding{
				"example.com": {HostnamePort: "example.com:443", CertHash: "OLD_HASH"},
			}, nil
		}

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results := deployCertAutoMode(d, certData, testKeyPEM, certCfg)

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
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) (map[string]*iis.SSLBinding, error) {
			return map[string]*iis.SSLBinding{}, nil
		}

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results := deployCertAutoMode(d, certData, testKeyPEM, certCfg)

		if len(results) != 0 {
			t.Errorf("无匹配绑定时期望 0 个结果，得到 %d 个", len(results))
		}
	})

	t.Run("安装成功绑定失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Binder.(*MockIISBinder).FindBindingsForDomainsFunc = func(domains []string) (map[string]*iis.SSLBinding, error) {
			return map[string]*iis.SSLBinding{
				"example.com": {HostnamePort: "example.com:443", CertHash: "OLD_HASH"},
			}, nil
		}
		d.Binder.(*MockIISBinder).BindCertificateFunc = func(hostname string, port int, certHash string) error {
			return errors.New("netsh 绑定失败")
		}

		certData := makeTestCertData(100, "example.com", "active", "2025-12-31")
		certCfg := config.CertConfig{
			OrderID:      100,
			Domain:       "example.com",
			Domains:      []string{"example.com"},
			Enabled:      true,
			AutoBindMode: true,
		}

		results := deployCertAutoMode(d, certData, testKeyPEM, certCfg)

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

// =============================================================================
// handleLocalKeyMode 测试
// =============================================================================

func TestHandleLocalKeyMode(t *testing.T) {
	t.Run("processing状态", func(t *testing.T) {
		d := NewMockDeployer()
		d.Client.(*MockAPIClient).GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 100,
				Domain:  "example.com",
				Status:  "processing",
			}, nil
		}

		certCfg := &config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
		}

		certData, privateKey, reason, err := handleLocalKeyMode(d, certCfg, 15)

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

	t.Run("active且未到续签时间", func(t *testing.T) {
		d := NewMockDeployer()
		// 设置过期时间为未来很远
		futureExpiry := time.Now().AddDate(0, 6, 0).Format("2006-01-02")
		d.Client.(*MockAPIClient).GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     100,
				Domain:      "example.com",
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

		certData, _, reason, err := handleLocalKeyMode(d, certCfg, 15)

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

	t.Run("active有API私钥且需要续签", func(t *testing.T) {
		d := NewMockDeployer()
		// 设置过期时间为很快过期
		soonExpiry := time.Now().AddDate(0, 0, 5).Format("2006-01-02")
		d.Client.(*MockAPIClient).GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     100,
				Domain:      "example.com",
				Status:      "active",
				ExpiresAt:   soonExpiry,
				Certificate: testCertPEM,
				PrivateKey:  testKeyPEM,
				CACert:      testCACertPEM,
			}, nil
		}
		// 没有本地私钥
		d.Store.(*MockOrderStore).HasPrivateKeyFunc = func(orderID int) bool { return false }

		certCfg := &config.CertConfig{
			OrderID: 100,
			Domain:  "example.com",
		}

		certData, privateKey, reason, err := handleLocalKeyMode(d, certCfg, 100)

		if err != nil {
			t.Errorf("不期望错误，得到: %v", err)
		}
		if certData == nil {
			t.Fatal("期望返回 certData，得到 nil")
		}
		if certData.OrderID != 100 {
			t.Errorf("期望 OrderID=100，得到 %d", certData.OrderID)
		}
		if privateKey != testKeyPEM {
			t.Error("期望返回 API 的私钥")
		}
		if reason != "" {
			t.Errorf("不期望跳过原因，得到 %q", reason)
		}
	})
}

// =============================================================================
// submitNewCSR 测试
// =============================================================================

func TestSubmitNewCSR(t *testing.T) {
	t.Run("CSR提交成功-processing", func(t *testing.T) {
		d := NewMockDeployer()
		d.Client.(*MockAPIClient).SubmitCSRFunc = func(ctx context.Context, req *api.CSRRequest) (*api.CSRResponse, error) {
			return &api.CSRResponse{
				Code: 1,
				Msg:  "success",
				Data: struct {
					OrderID int    `json:"order_id"`
					Status  string `json:"status"`
				}{
					OrderID: 200,
					Status:  "processing",
				},
			}, nil
		}

		certCfg := &config.CertConfig{
			OrderID: 0,
			Domain:  "example.com",
			Domains: []string{"example.com"},
		}

		certData, _, reason, err := submitNewCSR(d, certCfg)

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

	t.Run("CSR提交失败", func(t *testing.T) {
		d := NewMockDeployer()
		d.Client.(*MockAPIClient).SubmitCSRFunc = func(ctx context.Context, req *api.CSRRequest) (*api.CSRResponse, error) {
			return nil, errors.New("网络错误")
		}

		certCfg := &config.CertConfig{
			OrderID: 0,
			Domain:  "example.com",
			Domains: []string{"example.com"},
		}

		_, _, _, err := submitNewCSR(d, certCfg)

		if err == nil {
			t.Error("期望错误，但成功了")
		}
		if !strings.Contains(err.Error(), "提交 CSR 失败") {
			t.Errorf("期望错误包含 '提交 CSR 失败'，得到 %s", err.Error())
		}
	})
}

// =============================================================================
// sendCallback 测试
// =============================================================================

func TestSendCallback(t *testing.T) {
	t.Run("成功", func(t *testing.T) {
		d := NewMockDeployer()

		var callCount int32
		var wg sync.WaitGroup
		wg.Add(1)

		d.Client.(*MockAPIClient).CallbackFunc = func(ctx context.Context, req *api.CallbackRequest) error {
			atomic.AddInt32(&callCount, 1)
			wg.Done()
			return nil
		}

		sendCallback(d, 100, "example.com", true, "")

		wg.Wait()

		if atomic.LoadInt32(&callCount) != 1 {
			t.Errorf("期望调用 1 次，实际调用 %d 次", atomic.LoadInt32(&callCount))
		}
	})

	t.Run("失败只调用一次-依赖内部重试", func(t *testing.T) {
		d := NewMockDeployer()

		var callCount int32

		d.Client.(*MockAPIClient).CallbackFunc = func(ctx context.Context, req *api.CallbackRequest) error {
			atomic.AddInt32(&callCount, 1)
			return errors.New("回调失败")
		}

		sendCallback(d, 100, "example.com", false, "部署失败")

		d.callbackWg.Wait()

		finalCount := atomic.LoadInt32(&callCount)
		if finalCount != 1 {
			t.Errorf("期望调用 1 次（重试由 Client 内部处理），实际调用 %d 次", finalCount)
		}
	})
}

// =============================================================================
// AutoDeploy 集成测试
// =============================================================================

func TestAutoDeploy_Integration(t *testing.T) {
	t.Run("拉取模式-成功", func(t *testing.T) {
		d := NewMockDeployer()

		// 设置过期时间为快过期（确保触发部署）
		soonExpiry := time.Now().AddDate(0, 0, 5).Format("2006-01-02")

		d.Client.(*MockAPIClient).GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			return &api.CertData{
				OrderID:     orderID,
				Domain:      "example.com",
				Domains:     "example.com",
				Status:      "active",
				ExpiresAt:   soonExpiry,
				Certificate: testCertPEM,
				PrivateKey:  testKeyPEM,
				CACert:      testCACertPEM,
			}, nil
		}

		cfg := &config.Config{
			APIBaseURL:     "https://api.example.com",
			RenewDaysFetch: 13,
			RenewDaysLocal: 15,
			Certificates: []config.CertConfig{
				{
					OrderID:     100,
					Domain:      "example.com",
					Domains:     []string{"example.com"},
					Enabled:     true,
					UseLocalKey: false,
					BindRules: []config.BindRule{
						{Domain: "example.com", Port: 443},
					},
				},
			},
		}
		cfg.SetToken("test-token")

		results := AutoDeploy(cfg, d)

		if len(results) != 1 {
			t.Fatalf("期望 1 个结果，得到 %d 个", len(results))
		}
		if !results[0].Success {
			t.Errorf("期望成功，得到失败: %s", results[0].Message)
		}
		if results[0].Domain != "example.com" {
			t.Errorf("期望域名 example.com，得到 %s", results[0].Domain)
		}
		if results[0].Thumbprint == "" {
			t.Error("期望指纹不为空")
		}
	})

	t.Run("多证书-部分失败", func(t *testing.T) {
		d := NewMockDeployer()

		soonExpiry := time.Now().AddDate(0, 0, 5).Format("2006-01-02")

		d.Client.(*MockAPIClient).GetCertByOrderIDFunc = func(ctx context.Context, orderID int) (*api.CertData, error) {
			if orderID == 100 {
				return nil, errors.New("API 错误: 订单不存在")
			}
			return &api.CertData{
				OrderID:     orderID,
				Domain:      "success.com",
				Domains:     "success.com",
				Status:      "active",
				ExpiresAt:   soonExpiry,
				Certificate: testCertPEM,
				PrivateKey:  testKeyPEM,
				CACert:      testCACertPEM,
			}, nil
		}

		cfg := &config.Config{
			APIBaseURL:     "https://api.example.com",
			RenewDaysFetch: 13,
			RenewDaysLocal: 15,
			Certificates: []config.CertConfig{
				{
					OrderID:     100,
					Domain:      "fail.com",
					Domains:     []string{"fail.com"},
					Enabled:     true,
					UseLocalKey: false,
					BindRules: []config.BindRule{
						{Domain: "fail.com", Port: 443},
					},
				},
				{
					OrderID:     200,
					Domain:      "success.com",
					Domains:     []string{"success.com"},
					Enabled:     true,
					UseLocalKey: false,
					BindRules: []config.BindRule{
						{Domain: "success.com", Port: 443},
					},
				},
			},
		}
		cfg.SetToken("test-token")

		results := AutoDeploy(cfg, d)

		if len(results) != 2 {
			t.Fatalf("期望 2 个结果，得到 %d 个", len(results))
		}

		// 验证两个证书独立处理
		var failResult, successResult *Result
		for i := range results {
			if results[i].Domain == "fail.com" {
				failResult = &results[i]
			} else if results[i].Domain == "success.com" {
				successResult = &results[i]
			}
		}

		if failResult == nil {
			t.Fatal("未找到 fail.com 的结果")
		}
		if failResult.Success {
			t.Error("fail.com 期望失败")
		}
		if !strings.Contains(failResult.Message, "获取证书失败") {
			t.Errorf("fail.com 期望消息包含 '获取证书失败'，得到 %s", failResult.Message)
		}

		if successResult == nil {
			t.Fatal("未找到 success.com 的结果")
		}
		if !successResult.Success {
			t.Errorf("success.com 期望成功，得到失败: %s", successResult.Message)
		}
	})
}

// =============================================================================
// handleFileValidation 测试
// =============================================================================

func TestHandleFileValidation(t *testing.T) {
	t.Run("验证信息不完整-nil", func(t *testing.T) {
		err := handleFileValidation("example.com", nil)
		if err == nil {
			t.Error("file 为 nil 时期望返回错误")
		}
		if !strings.Contains(err.Error(), "验证文件信息不完整") {
			t.Errorf("期望错误包含 '验证文件信息不完整'，得到 %s", err.Error())
		}
	})

	t.Run("验证信息不完整-空路径", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "",
			Content: "some content",
		})
		if err == nil {
			t.Error("空路径时期望返回错误")
		}
		if !strings.Contains(err.Error(), "验证文件信息不完整") {
			t.Errorf("期望错误包含 '验证文件信息不完整'，得到 %s", err.Error())
		}
	})

	t.Run("验证信息不完整-空内容", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/acme-challenge/token",
			Content: "",
		})
		if err == nil {
			t.Error("空内容时期望返回错误")
		}
		if !strings.Contains(err.Error(), "验证文件信息不完整") {
			t.Errorf("期望错误包含 '验证文件信息不完整'，得到 %s", err.Error())
		}
	})

	t.Run("危险扩展名-exe", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/acme-challenge/malware.exe",
			Content: "dangerous content",
		})
		if err == nil {
			t.Error("危险扩展名 .exe 时期望返回错误")
		}
		if !strings.Contains(err.Error(), "不允许创建") || !strings.Contains(err.Error(), ".exe") {
			t.Errorf("期望错误提及 .exe 扩展名限制，得到 %s", err.Error())
		}
	})

	t.Run("危险扩展名-dll", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/test.dll",
			Content: "dangerous content",
		})
		if err == nil {
			t.Error("危险扩展名 .dll 时期望返回错误")
		}
		if !strings.Contains(err.Error(), ".dll") {
			t.Errorf("期望错误提及 .dll，得到 %s", err.Error())
		}
	})

	t.Run("危险扩展名-bat", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/test.bat",
			Content: "dangerous content",
		})
		if err == nil {
			t.Error("危险扩展名 .bat 时期望返回错误")
		}
	})

	t.Run("危险扩展名-ps1", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/test.ps1",
			Content: "dangerous content",
		})
		if err == nil {
			t.Error("危险扩展名 .ps1 时期望返回错误")
		}
	})

	t.Run("危险扩展名-aspx", func(t *testing.T) {
		err := handleFileValidation("example.com", &api.FileValidation{
			Path:    "/.well-known/test.aspx",
			Content: "dangerous content",
		})
		if err == nil {
			t.Error("危险扩展名 .aspx 时期望返回错误")
		}
	})
}
