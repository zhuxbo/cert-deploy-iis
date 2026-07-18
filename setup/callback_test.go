package setup

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"sslctlw/api"
)

// TestSendSetupCallback 验证 setup 部署回调按结果发送 success/failure
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

	sendSetupCallback(client, 301, "ok.example.com", true)
	sendSetupCallback(client, 302, "fail.example.com", false)

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
	if received[1].OrderID != 302 || received[1].Status != "failure" {
		t.Errorf("第二条回调 = %+v, want 302/failure", received[1])
	}
}
