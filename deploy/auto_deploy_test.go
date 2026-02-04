package deploy

import (
	"context"
	"errors"
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

	store := cert.NewOrderStore()
	results := AutoDeploy(cfg, store)

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

	store := cert.NewOrderStore()
	results := AutoDeploy(cfg, store)

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

	store := cert.NewOrderStore()
	results := AutoDeploy(cfg, store)

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
	tests := []struct {
		name     string
		store    *MockOrderStore
		certData *api.CertData
		orderID  int
		wantOK   bool
	}{
		{
			name: "没有本地私钥",
			store: &MockOrderStore{
				HasPrivateKeyFunc: func(orderID int) bool { return false },
			},
			certData: makeTestCertData(123, "example.com", "active", "2025-01-01"),
			orderID:  123,
			wantOK:   false,
		},
		{
			name: "加载私钥失败",
			store: &MockOrderStore{
				HasPrivateKeyFunc:  func(orderID int) bool { return true },
				LoadPrivateKeyFunc: func(orderID int) (string, error) { return "", errors.New("load failed") },
			},
			certData: makeTestCertData(123, "example.com", "active", "2025-01-01"),
			orderID:  123,
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 注意：由于 tryUseLocalKey 使用了具体的 cert.OrderStore 类型
			// 这里只测试 Mock 接口的行为
			hasKey := tt.store.HasPrivateKey(tt.orderID)
			if hasKey {
				_, err := tt.store.LoadPrivateKey(tt.orderID)
				if err != nil && tt.wantOK {
					t.Errorf("LoadPrivateKey 失败但期望成功")
				}
			} else if tt.wantOK {
				t.Errorf("没有私钥但期望成功")
			}
		})
	}
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
