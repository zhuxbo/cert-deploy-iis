package deploy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/config"
)

// newCertAPIServer 返回一个按订单号回复固定 CertData 的本地 API 服务器。
// 回环地址通过 api.IsAllowedAPIURL 的 HTTPS 豁免，可直接驱动 processOneCert 全链路。
func newCertAPIServer(t *testing.T, certData api.CertData) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/callback" {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok", "data": map[string]any{}})
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
	t.Cleanup(srv.Close)
	return srv
}

// TestProcessOneCert_PromoteFailureKeepsAttemptConverging 坐实：
// local 模式下 pending 私钥转正失败时，编排层必须清掉在途标记让部署计数继续推进。
// 否则 DeployStartedAt 永久残留 → 每轮都被判为“崩溃恢复重放”不计数 →
// 部署触顶（CAPPED）兜底被绕过，且每轮重复上报一次 success 回调。
func TestProcessOneCert_PromoteFailureKeepsAttemptConverging(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "example.com")
	csrPEM := genCSRForTestKey(t, "example.com", keyPEM)
	srv := newCertAPIServer(t, api.CertData{
		OrderID:     100,
		Domains:     "example.com",
		Status:      "active",
		ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
		Certificate: certPEM,
		CACert:      testCACertPEM,
		CSR:         csrPEM,
	})

	d := NewMockDeployer()
	store := d.Store.(*MockOrderStore)
	store.HasPendingPrivateKeyFunc = func(string) bool { return true }
	store.LoadPendingPrivateKeyFunc = func(string) (string, error) { return keyPEM, nil }
	store.PromotePendingPrivateKeyFunc = func(string, int, string) error {
		return errors.New("pending 私钥转正失败")
	}

	certAPI := config.CertAPIConfig{URL: srv.URL}
	if err := certAPI.SetToken("test-token"); err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Schedule.RenewMode = "local"
	cfg.Certificates = []config.CertConfig{{
		CertName:  "example.com-100",
		OrderID:   100,
		Domain:    "example.com",
		Domains:   []string{"example.com"},
		Enabled:   true,
		BindRules: []config.BindRule{{Domain: "example.com", Port: 443}},
		API:       certAPI,
		Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateProcessing,
			LastCSRHash:    mustCSRHash(t, csrPEM),
			CSRSubmittedAt: "2026-07-01T00:00:00Z",
		},
	}}

	if _, attempted := processOneCert(cfg, d, 0, nil); !attempted {
		t.Fatal("应执行一次部署尝试")
	}
	d.WaitCallbacks()

	meta := cfg.Certificates[0].Metadata
	if meta.DeployAttemptCount != 1 {
		t.Fatalf("首轮应记一次部署尝试, got %d", meta.DeployAttemptCount)
	}
	if meta.DeployStartedAt != "" {
		t.Fatalf("转正失败仍属本轮已结束，必须清掉在途标记, got %q", meta.DeployStartedAt)
	}

	// 第二轮：同样失败，计数必须继续推进，否则 CAPPED 兜底永远不会触发
	if _, attempted := processOneCert(cfg, d, 0, nil); !attempted {
		t.Fatal("第二轮应继续尝试")
	}
	d.WaitCallbacks()
	if got := cfg.Certificates[0].Metadata.DeployAttemptCount; got != 2 {
		t.Fatalf("第二轮部署计数应推进到 2, got %d（在途标记残留会绕过触顶兜底）", got)
	}
}

// TestProcessOneCert_PromoteFailureReachesCap 转正持续失败必须在 MaxDeployAttempts 轮后
// 进入 CAPPED 静默，而不是每轮都重新部署并重复上报 success 回调。
func TestProcessOneCert_PromoteFailureReachesCap(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "example.com")
	csrPEM := genCSRForTestKey(t, "example.com", keyPEM)
	var callbacks []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/callback" {
			var req api.CallbackRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			callbacks = append(callbacks, req.Status)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok", "data": map[string]any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok", "data": map[string]any{
			"data": []api.CertData{{
				OrderID: 100, Domains: "example.com", Status: "active",
				ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
				Certificate: certPEM, CACert: testCACertPEM, CSR: csrPEM,
			}},
			"currentPage": 1, "pageSize": 20, "total": 1,
		}})
	}))
	defer srv.Close()

	d := NewMockDeployer()
	store := d.Store.(*MockOrderStore)
	store.HasPendingPrivateKeyFunc = func(string) bool { return true }
	store.LoadPendingPrivateKeyFunc = func(string) (string, error) { return keyPEM, nil }
	store.PromotePendingPrivateKeyFunc = func(string, int, string) error {
		return errors.New("pending 私钥转正失败")
	}

	certAPI := config.CertAPIConfig{URL: srv.URL}
	if err := certAPI.SetToken("test-token"); err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.Schedule.RenewMode = "local"
	cfg.Certificates = []config.CertConfig{{
		CertName: "example.com-100", OrderID: 100, Domain: "example.com",
		Domains: []string{"example.com"}, Enabled: true,
		BindRules: []config.BindRule{{Domain: "example.com", Port: 443}},
		API:       certAPI,
		Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateProcessing,
			LastCSRHash:    mustCSRHash(t, csrPEM),
			CSRSubmittedAt: "2026-07-01T00:00:00Z",
		},
	}}

	for round := 1; round <= config.MaxDeployAttempts+2; round++ {
		results, _ := processOneCert(cfg, d, 0, nil)
		d.WaitCallbacks()
		if round <= config.MaxDeployAttempts {
			foundFailure := false
			for _, result := range results {
				if !result.Success && strings.Contains(result.Message, "pending 私钥转正失败") {
					foundFailure = true
				}
			}
			if !foundFailure {
				t.Fatalf("第 %d 轮转正失败必须进入失败 Result: %+v", round, results)
			}
		}
	}

	meta := cfg.Certificates[0].Metadata
	if !meta.IsCapped() || meta.CapPhase != config.CapPhaseDeploy {
		t.Fatalf("持续转正失败应进入部署触顶静默, state=%q phase=%q count=%d",
			meta.LastIssueState, meta.CapPhase, meta.DeployAttemptCount)
	}
	if meta.DeployAttemptCount != config.MaxDeployAttempts {
		t.Errorf("部署尝试不得超过上限 %d, got %d", config.MaxDeployAttempts, meta.DeployAttemptCount)
	}
	for i, status := range callbacks {
		if status != "failure" {
			t.Fatalf("生命周期未收敛不得上报成功, 第 %d 条回调为 %q", i+1, status)
		}
	}
	if len(callbacks) != config.MaxDeployAttempts {
		t.Errorf("触顶后应停止回调, 共 %d 条", len(callbacks))
	}
}

func TestProcessOneCert_PersistenceFailuresBecomeFailedResults(t *testing.T) {
	tests := []struct {
		name               string
		saveCertificateErr error
		finalSaveErr       error
		wantMessage        string
		wantCallbackStatus string
	}{
		{
			name:               "save deployed certificate",
			saveCertificateErr: errors.New("certificate cache disk full"),
			wantMessage:        "certificate cache disk full",
			wantCallbackStatus: "failure",
		},
		{
			name:         "save deployment result",
			finalSaveErr: errors.New("config disk full"),
			wantMessage:  "config disk full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certPEM, keyPEM := genSelfSignedPair(t, "persist-result.example.com")
			var callbackStatuses []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/callback" {
					var req api.CallbackRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					callbackStatuses = append(callbackStatuses, req.Status)
					_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok"})
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok", "data": map[string]any{
					"data": []api.CertData{{
						OrderID: 601, Domains: "persist-result.example.com", Status: "active",
						ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
						Certificate: certPEM, PrivateKey: keyPEM, CACert: testCACertPEM,
					}},
					"currentPage": 1, "pageSize": 20, "total": 1,
				}})
			}))
			defer srv.Close()

			certAPI := config.CertAPIConfig{URL: srv.URL}
			if err := certAPI.SetToken("test-token"); err != nil {
				t.Fatalf("SetToken() error = %v", err)
			}
			cfg := config.DefaultConfig()
			cfg.Schedule.RenewMode = "pull"
			cfg.Certificates = []config.CertConfig{{
				OrderID: 601, Domain: "persist-result.example.com", Enabled: true,
				BindRules: []config.BindRule{{Domain: "persist-result.example.com", Port: 443}},
				API:       certAPI,
			}}
			d := NewMockDeployer()
			d.Store.(*MockOrderStore).SaveCertificateFunc = func(int, string, string) error {
				return tt.saveCertificateErr
			}
			saveCalls := 0
			results, _ := processOneCertWithSave(cfg, d, 0, nil, func() error {
				saveCalls++
				if saveCalls == 2 {
					return tt.finalSaveErr
				}
				return nil
			})
			d.WaitCallbacks()

			found := false
			for _, result := range results {
				if !result.Success && strings.Contains(result.Message, tt.wantMessage) {
					found = true
				}
			}
			if !found {
				t.Fatalf("持久化失败必须进入失败 Result: %+v", results)
			}
			if tt.wantCallbackStatus == "" {
				if len(callbackStatuses) != 0 {
					t.Fatalf("部署结果未保存时不得 callback: %v", callbackStatuses)
				}
				if cfg.Certificates[0].Metadata.DeployStartedAt == "" {
					t.Fatal("部署结果未保存时必须恢复已落盘的在途状态，供下轮重放")
				}
				replayResults, _ := processOneCertWithSave(cfg, d, 0, nil, func() error { return nil })
				d.WaitCallbacks()
				if len(callbackStatuses) != 1 || callbackStatuses[0] != "success" {
					t.Fatalf("下轮重放必须完成并 callback: %v，results=%+v", callbackStatuses, replayResults)
				}
			} else if len(callbackStatuses) != 1 || callbackStatuses[0] != tt.wantCallbackStatus {
				t.Fatalf("callback = %v, want [%s]", callbackStatuses, tt.wantCallbackStatus)
			}
		})
	}
}
