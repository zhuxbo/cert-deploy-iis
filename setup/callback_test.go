package setup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"sslctlw/api"
	"sslctlw/config"
)

// TestSendSetupCallback 验证 setup 部署回调按结果发送 success/failure，
// 且 failure 携带脱敏后的原因摘要、success 不含 message（端到端）
func TestSendSetupCallback(t *testing.T) {
	var mu sync.Mutex
	var received []api.CallbackRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.CallbackRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			mu.Lock()
			received = append(received, req)
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{}}`))
	}))
	defer server.Close()

	client := api.NewClient(server.URL, "test-token")

	sendSetupCallback(client, 301, "ok.example.com", true, "")
	// 失败原因内嵌 Bearer 凭据，验证端到端脱敏
	sendSetupCallback(client, 302, "fail.example.com", false, "安装证书失败: Authorization: Bearer sk-secret-abc123")

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 2 {
		t.Fatalf("回调数量 = %d, want 2", len(received))
	}
	if received[0].OrderID != 301 || received[0].Status != "success" {
		t.Errorf("第一条回调 = %+v, want 301/success", received[0])
	}
	if received[0].DeployedAt == "" {
		t.Error("回调应包含 deployed_at")
	}
	if received[0].Message != "" {
		t.Errorf("success 回调不应携带 message，实际 = %q", received[0].Message)
	}
	if received[1].OrderID != 302 || received[1].Status != "failure" {
		t.Errorf("第二条回调 = %+v, want 302/failure", received[1])
	}
	if !strings.Contains(received[1].Message, "安装证书失败") {
		t.Errorf("failure 回调应携带原因摘要，实际 = %q", received[1].Message)
	}
	if strings.Contains(received[1].Message, "sk-secret-abc123") {
		t.Errorf("failure 回调 message 未脱敏，泄漏凭据: %q", received[1].Message)
	}
	if !strings.Contains(received[1].Message, "[REDACTED]") {
		t.Errorf("failure 回调 message 应包含脱敏占位符，实际 = %q", received[1].Message)
	}
}

func TestApplySetupRenewBeforeDays(t *testing.T) {
	cfg := &config.Config{Schedule: config.Schedule{RenewBeforeDays: config.DefaultRenewBeforeDays}}
	applySetupRenewBeforeDays(cfg, 22)
	if cfg.Schedule.RenewBeforeDays != 22 {
		t.Fatalf("有效响应值未应用，got %d", cfg.Schedule.RenewBeforeDays)
	}
	applySetupRenewBeforeDays(cfg, config.MaxRenewBeforeDays+1)
	if cfg.Schedule.RenewBeforeDays != 22 {
		t.Fatalf("超限响应值不应覆盖配置，got %d", cfg.Schedule.RenewBeforeDays)
	}
}
