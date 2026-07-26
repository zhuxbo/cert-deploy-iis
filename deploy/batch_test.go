package deploy

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/config"
)

func TestSelectBatch(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 1, Enabled: true},
		{OrderID: 2, Enabled: false},
		{OrderID: 3, Enabled: true},
		{OrderID: 4, Enabled: true},
	}
	tests := []struct {
		name       string
		start      int
		limit      int
		want       []int
		wantCursor int
	}{
		{"from beginning", 0, 2, []int{0, 2}, 4},
		{"from cursor to tail", 3, 2, []int{2, 3}, 0},
		{"deleted cursor starts over", 99, 2, []int{0, 2}, 4},
		{"disabled cursor starts over", 2, 2, []int{0, 2}, 4},
		{"all enabled fit", 0, 10, []int{0, 2, 3}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, cursor := selectBatch(certs, tt.start, tt.limit)
			if len(got) != len(tt.want) {
				t.Fatalf("indexes=%v want=%v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("indexes=%v want=%v", got, tt.want)
				}
			}
			if cursor != tt.wantCursor {
				t.Fatalf("cursor=%d want=%d", cursor, tt.wantCursor)
			}
		})
	}
}

func newBatchProcessingServer(t *testing.T, calls *[]int, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orderID, _ := strconv.Atoi(r.URL.Query().Get("order"))
		mu.Lock()
		*calls = append(*calls, orderID)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data":        []api.CertData{{OrderID: orderID, Domains: "batch.example.com", Status: "processing"}},
				"currentPage": 1, "pageSize": 20, "total": 1,
			},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func batchConfig(t *testing.T, count int, apiURL string) *config.Config {
	t.Helper()
	certAPI := config.CertAPIConfig{URL: apiURL}
	if err := certAPI.SetToken("token"); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	for id := 1; id <= count; id++ {
		cfg.Certificates = append(cfg.Certificates, config.CertConfig{
			OrderID: id, Domain: "batch.example.com", Domains: []string{"batch.example.com"},
			Enabled: true, API: certAPI,
		})
	}
	return cfg
}

func TestRunAutoDeployBatchLimitsAllPerCertCallsAndAdvancesCursor(t *testing.T) {
	var calls []int
	var mu sync.Mutex
	server := newBatchProcessingServer(t, &calls, &mu)
	cfg := batchConfig(t, 101, server.URL)

	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{MaxCertificates: 1000}, successfulAutoDeployDependencies(nil))
	if report.Err() != nil {
		t.Fatalf("first report error=%v", report.Err())
	}
	if len(calls) != 100 || calls[0] != 1 || calls[99] != 100 {
		t.Fatalf("first calls count=%d head/tail=%v/%v", len(calls), calls[0], calls[len(calls)-1])
	}
	if cfg.NextBatchOrderID != 101 {
		t.Fatalf("cursor=%d want=101", cfg.NextBatchOrderID)
	}

	calls = nil
	report = runAutoDeploy(cfg, NewMockDeployer(), RunOptions{MaxCertificates: 1000}, successfulAutoDeployDependencies(nil))
	if report.Err() != nil {
		t.Fatalf("second report error=%v", report.Err())
	}
	if len(calls) != 1 || calls[0] != 101 || cfg.NextBatchOrderID != 0 {
		t.Fatalf("second calls=%v cursor=%d", calls, cfg.NextBatchOrderID)
	}
}

func TestRunAutoDeployOnlyOrderIgnoresAndPreservesCursor(t *testing.T) {
	var calls []int
	var mu sync.Mutex
	server := newBatchProcessingServer(t, &calls, &mu)
	cfg := batchConfig(t, 3, server.URL)
	cfg.NextBatchOrderID = 999
	deps := successfulAutoDeployDependencies(func(saved *config.Config) error {
		if saved.NextBatchOrderID != 999 {
			t.Fatalf("OnlyOrderID 不得推进 cursor: %d", saved.NextBatchOrderID)
		}
		return nil
	})
	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{OnlyOrderID: 2}, deps)
	if report.Err() != nil || len(calls) != 1 || calls[0] != 2 || cfg.NextBatchOrderID != 999 {
		t.Fatalf("report=%+v calls=%v cursor=%d", report, calls, cfg.NextBatchOrderID)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("OnlyOrderID 不应产生批次积压警告: %v", report.Warnings)
	}
}

func TestRunAutoDeployOnlyOrderProcessesAllEnabledDuplicateOrderIDs(t *testing.T) {
	var calls []int
	var mu sync.Mutex
	server := newBatchProcessingServer(t, &calls, &mu)
	cfg := batchConfig(t, 3, server.URL)
	cfg.Certificates[2].OrderID = 2

	report := runAutoDeploy(
		cfg, NewMockDeployer(), RunOptions{OnlyOrderID: 2},
		successfulAutoDeployDependencies(nil),
	)
	if report.Err() != nil {
		t.Fatalf("report error=%v", report.Err())
	}
	if len(calls) != 2 || calls[0] != 2 || calls[1] != 2 {
		t.Fatalf("OnlyOrderID 应处理全部启用匹配项: calls=%v", calls)
	}
}

func TestRunAutoDeployCursorSaveFailureRestoresAndRepeatsBatch(t *testing.T) {
	var calls []int
	var mu sync.Mutex
	server := newBatchProcessingServer(t, &calls, &mu)
	cfg := batchConfig(t, 2, server.URL)
	saveCalls := 0
	var savedCursors []int
	deps := successfulAutoDeployDependencies(func(saved *config.Config) error {
		saveCalls++
		savedCursors = append(savedCursors, saved.NextBatchOrderID)
		if saveCalls == 2 {
			return errors.New("cursor save failed")
		}
		return nil
	})
	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{MaxCertificates: 1}, deps)
	if len(report.Errors) != 1 || cfg.NextBatchOrderID != 0 || len(calls) != 1 || calls[0] != 1 {
		t.Fatalf("report=%+v cursor=%d calls=%v savedCursors=%v", report, cfg.NextBatchOrderID, calls, savedCursors)
	}
	if len(savedCursors) != 2 || savedCursors[0] != 0 || savedCursors[1] != 2 {
		t.Fatalf("逐证书保存应看到旧 cursor，最终保存才看到新 cursor: %v", savedCursors)
	}
	calls = nil
	report = runAutoDeploy(cfg, NewMockDeployer(), RunOptions{MaxCertificates: 1}, successfulAutoDeployDependencies(nil))
	if report.Err() != nil || len(calls) != 1 || calls[0] != 1 {
		t.Fatalf("retry report=%+v calls=%v", report, calls)
	}
}

func TestRunAutoDeployGetCSRDeployCountsAsOneCertificate(t *testing.T) {
	var getOrders, postOrders []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var req api.UpdateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			postOrders = append(postOrders, req.OrderID)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code": 1, "msg": "ok", "data": map[string]any{"order_id": req.OrderID, "status": "processing"},
			})
			return
		}
		orderID, _ := strconv.Atoi(r.URL.Query().Get("order"))
		getOrders = append(getOrders, orderID)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data": []api.CertData{{
					OrderID: orderID, Domains: "local.example.com", Status: "active",
					ExpiresAt: time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
				}},
				"currentPage": 1, "pageSize": 20, "total": 1,
			},
		})
	}))
	defer server.Close()
	cfg := batchConfig(t, 2, server.URL)
	cfg.Schedule.RenewMode = "local"
	for i := range cfg.Certificates {
		cfg.Certificates[i].Domain = "local.example.com"
		cfg.Certificates[i].Domains = []string{"local.example.com"}
		cfg.Certificates[i].CertName = "local-" + strconv.Itoa(i+1)
	}
	report := runAutoDeploy(cfg, NewMockDeployer(), RunOptions{MaxCertificates: 1}, successfulAutoDeployDependencies(nil))
	if report.Err() != nil || len(getOrders) != 1 || len(postOrders) != 1 ||
		getOrders[0] != 1 || postOrders[0] != 1 {
		t.Fatalf("report=%+v GET=%v POST=%v", report, getOrders, postOrders)
	}
}

func TestRunAutoDeployConflictWinnerOutsideBatchStillBlocksSelectedCertificate(t *testing.T) {
	certData := makeTestCertData(
		t, 1, "shared.example.com", "active",
		time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
	)
	apiCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data": []api.CertData{*certData}, "currentPage": 1, "pageSize": 20, "total": 1,
			},
		})
	}))
	defer server.Close()

	cfg := batchConfig(t, 2, server.URL)
	for i := range cfg.Certificates {
		cfg.Certificates[i].Domain = "shared.example.com"
		cfg.Certificates[i].Domains = []string{"shared.example.com"}
		cfg.Certificates[i].BindRules = []config.BindRule{{Domain: "shared.example.com", Port: 443}}
	}
	cfg.Certificates[0].Metadata.CertExpiresAt = time.Now().AddDate(0, 2, 0).Format("2006-01-02")
	cfg.Certificates[1].Metadata.CertExpiresAt = time.Now().AddDate(1, 0, 0).Format("2006-01-02")

	converted := 0
	d := NewMockDeployer()
	d.Converter = &MockCertConverter{PEMToPFXFunc: func(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
		converted++
		return "unused.pfx", nil
	}}

	report := runAutoDeploy(cfg, d, RunOptions{MaxCertificates: 1}, successfulAutoDeployDependencies(nil))
	if report.Err() != nil {
		t.Fatalf("report error=%v", report.Err())
	}
	if apiCalls != 1 || converted != 0 {
		t.Fatalf("批外胜者应阻断选中证书部署: apiCalls=%d converted=%d results=%+v", apiCalls, converted, report.Results)
	}
}
