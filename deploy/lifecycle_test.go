package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
)

type lifecycleRoundTripFunc func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestClassifyOrderStatus(t *testing.T) {
	tests := []struct {
		status string
		want   orderClass
	}{
		{config.OrderStatusActive, orderClassActive},
		{config.OrderStatusPending, orderClassWaiting},
		{config.OrderStatusProcessing, orderClassWaiting},
		{config.OrderStatusApproving, orderClassWaiting},
		{config.OrderStatusUnpaid, orderClassWaiting},
		{config.OrderStatusCancelling, orderClassWaiting},
		{config.OrderStatusFailed, orderClassTerminal},
		{config.OrderStatusCancelled, orderClassTerminal},
		{config.OrderStatusRevoked, orderClassTerminal},
		{config.OrderStatusExpired, orderClassTerminal},
		{config.OrderStatusRenewed, orderClassChainAnomaly},
		{config.OrderStatusReissued, orderClassChainAnomaly},
		{"future-status", orderClassUnknown},
	}
	for _, tt := range tests {
		if got := classifyOrderStatus(tt.status); got != tt.want {
			t.Errorf("classifyOrderStatus(%q) = %v, want %v", tt.status, got, tt.want)
		}
	}
}

func TestCheckPendingOwnershipFromServerCSR(t *testing.T) {
	pendingKey, pendingCSR, err := cert.GenerateCSR("example.com")
	if err != nil {
		t.Fatal(err)
	}
	pendingHash, err := cert.CSRDERHash(pendingCSR)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("匹配后确认且不重放", func(t *testing.T) {
		removed := 0
		persisted := 0
		d := &Deployer{Store: &MockOrderStore{
			HasPendingPrivateKeyFunc:  func(string) bool { return true },
			LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
			LoadPendingCSRFunc:        func(string) (string, error) { return pendingCSR, nil },
			RemovePendingArtifactsFunc: func(string) error {
				removed++
				return nil
			},
		}}
		cfg := &config.CertConfig{
			CertName: "example.com-1", Domain: "example.com",
			Metadata: config.CertMetadata{
				LastCSRHash: pendingHash, CSRSubmittedAt: "2026-07-01T00:00:00Z",
				LastIssueState: config.IssueStateProcessing, ResubmitRequired: true,
			},
		}
		ownership, reason, err := checkPendingOwnership(
			d,
			cfg,
			&api.CertData{Status: config.OrderStatusProcessing, CSR: pendingCSR},
			func() error { persisted++; return nil },
		)
		if err != nil || ownership != pendingOwnershipConfirmed || reason != "" {
			t.Fatalf("归属确认失败: ownership=%v reason=%q err=%v", ownership, reason, err)
		}
		if removed != 0 || cfg.Metadata.ResubmitRequired || persisted != 1 {
			t.Fatalf("确认归属不得删除或重放: removed=%d persisted=%d metadata=%+v",
				removed, persisted, cfg.Metadata)
		}
	})

	t.Run("合法但不匹配时清理", func(t *testing.T) {
		_, otherCSR, err := cert.GenerateCSR("other.example.com")
		if err != nil {
			t.Fatal(err)
		}
		removed := 0
		d := &Deployer{Store: &MockOrderStore{
			HasPendingPrivateKeyFunc:  func(string) bool { return true },
			LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
			LoadPendingCSRFunc:        func(string) (string, error) { return pendingCSR, nil },
			RemovePendingArtifactsFunc: func(string) error {
				removed++
				return nil
			},
		}}
		cfg := &config.CertConfig{
			CertName: "example.com-1", Domain: "example.com",
			Metadata: config.CertMetadata{
				LastCSRHash: pendingHash, CSRSubmittedAt: "2026-07-01T00:00:00Z",
				LastIssueState: config.IssueStateProcessing, ResubmitRequired: true,
			},
		}
		ownership, _, err := checkPendingOwnership(
			d,
			cfg,
			&api.CertData{Status: config.OrderStatusProcessing, CSR: otherCSR},
			func() error { return nil },
		)
		if err != nil || ownership != pendingOwnershipMismatch {
			t.Fatalf("不匹配处理失败: ownership=%v err=%v", ownership, err)
		}
		if removed != 1 || cfg.Metadata.LastCSRHash != "" || cfg.Metadata.PendingCleanup {
			t.Fatalf("不匹配 CSR 应可靠清理: removed=%d metadata=%+v", removed, cfg.Metadata)
		}
	})

	t.Run("缺失CSR时保留", func(t *testing.T) {
		removed := 0
		d := &Deployer{Store: &MockOrderStore{
			HasPendingPrivateKeyFunc:  func(string) bool { return true },
			LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
			RemovePendingArtifactsFunc: func(string) error {
				removed++
				return nil
			},
		}}
		cfg := &config.CertConfig{
			CertName: "example.com-1", Domain: "example.com",
			Metadata: config.CertMetadata{
				LastCSRHash: pendingHash, CSRSubmittedAt: "2026-07-01T00:00:00Z",
			},
		}
		ownership, reason, err := checkPendingOwnership(
			d,
			cfg,
			&api.CertData{Status: config.OrderStatusProcessing},
			func() error { return nil },
		)
		if err != nil || ownership != pendingOwnershipUnknown || reason == "" || removed != 0 {
			t.Fatalf("缺失 CSR 必须保留: ownership=%v reason=%q removed=%d err=%v",
				ownership, reason, removed, err)
		}
	})
}

func TestNoProgressLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	certCfg := &config.CertConfig{OrderID: 1}
	before := snapshotProgress(certCfg)
	settleNoProgress(certCfg, before, true, now)
	if certCfg.Metadata.NoProgressSince != now.Format(time.RFC3339) {
		t.Fatalf("首次无进展锚点 = %q", certCfg.Metadata.NoProgressSince)
	}
	settleNoProgress(certCfg, before, true, now.Add(24*time.Hour))
	if certCfg.Metadata.NoProgressSince != now.Format(time.RFC3339) {
		t.Fatal("无进展锚点不得滑动")
	}
	if !stalledTooLong(certCfg, now.Add(config.MaxNoProgressDays*24*time.Hour)) {
		t.Fatal("到达 14 天应判定停更")
	}

	certCfg.Metadata.CertSerial = "new"
	settleNoProgress(certCfg, before, true, now.Add(time.Hour))
	if certCfg.Metadata.NoProgressSince != "" {
		t.Fatal("真实进展应清零计时")
	}
}

func TestNoProgressClockAnomalyReanchors(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	for _, since := range []time.Time{
		now.Add(time.Hour),
		now.Add(-(config.ClockSanityMaxDays + 1) * 24 * time.Hour),
	} {
		certCfg := &config.CertConfig{}
		certCfg.Metadata.NoProgressSince = since.Format(time.RFC3339)
		if stalledTooLong(certCfg, now) {
			t.Fatal("异常时钟不得直接停车")
		}
		if certCfg.Metadata.NoProgressSince != now.Format(time.RFC3339) {
			t.Fatalf("异常时钟应重锚到当前时间，got %q", certCfg.Metadata.NoProgressSince)
		}
	}
}

func TestAuthGateGroupsByURLAndToken(t *testing.T) {
	gate := &authGate{}
	first := api.NewClient("https://api.example.com", "same")
	same := api.NewClient("https://api.example.com/", "same")
	other := api.NewClient("https://api.example.com", "other")
	err := &api.APIError{
		StatusCode: 200,
		Code:       0,
		Message:    "limited",
		ErrorCode:  api.ErrorCodeRateLimited,
		RetryAfter: 100,
	}
	if !gate.record(first, err) {
		t.Fatal("rate_limited 应阻断凭据组")
	}
	if block, ok := gate.blockedBy(same); !ok || block.retryAfter != 100 {
		t.Fatalf("同组未命中阻断: %+v ok=%v", block, ok)
	}
	if _, ok := gate.blockedBy(other); ok {
		t.Fatal("不同 token 不得被连带阻断")
	}
	if gate.record(other, errors.New("network")) {
		t.Fatal("普通网络错误不得阻断整批")
	}
	gate.markSkipped()
	if summary := gate.summary(); !strings.Contains(summary, api.ErrorCodeRateLimited) ||
		!strings.Contains(summary, "100 秒") || !strings.Contains(summary, "1 张") {
		t.Fatalf("汇总缺少关键信息: %q", summary)
	}
}

func TestTrackedAPIClientRunsScatterHookOnlyBeforeFirstRequest(t *testing.T) {
	calls := 0
	hookCalls := 0
	mock := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			calls++
			return &api.CertData{OrderID: 1}, nil
		},
	}
	tracked := &trackedAPIClient{
		APIClient: mock,
		concrete:  api.NewClient("https://api.example.com", "token"),
		gate:      &authGate{},
		tracker:   &apiCallTracker{},
		beforeFirstCall: func() {
			hookCalls++
		},
	}
	_, _ = tracked.GetCertByOrderID(context.Background(), 1)
	_, _ = tracked.GetCertByOrderID(context.Background(), 1)
	if calls != 2 || hookCalls != 1 {
		t.Fatalf("API 调用=%d，分散延迟钩子=%d；want 2/1", calls, hookCalls)
	}
}

func TestSubmitPendingCSRAuthBlockRollsBackQuotaAndArtifacts(t *testing.T) {
	removed := 0
	saves := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "token disabled",
				ErrorCode: api.ErrorCodeTokenDisabled,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}
	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error {
		saves++
		return nil
	})
	if api.ErrorCodeOf(err) != api.ErrorCodeTokenDisabled {
		t.Fatalf("错误应保留 error_code: %v", err)
	}
	if certCfg.Metadata.IssueRetryCount != 2 || certCfg.Metadata.LastIssueState != "" {
		t.Fatalf("认证阻断应完整回滚元数据: %+v", certCfg.Metadata)
	}
	if removed != 1 || saves != 3 {
		t.Fatalf("清理次数=%d 保存次数=%d，want 1/3", removed, saves)
	}
}

func TestSubmitPendingCSRAuthBlockCleanupFailureStillRollsBack(t *testing.T) {
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error { return errors.New("disk busy") },
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "token disabled",
				ErrorCode: api.ErrorCodeTokenDisabled,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}
	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if api.ErrorCodeOf(err) != api.ErrorCodeTokenDisabled {
		t.Fatalf("组合错误仍应保留原 error_code: %v", err)
	}
	if certCfg.Metadata.IssueRetryCount != 2 || certCfg.Metadata.LastIssueState != "" {
		t.Fatalf("清理失败不得阻止额度回滚: %+v", certCfg.Metadata)
	}
	if !certCfg.Metadata.PendingCleanup {
		t.Fatal("清理失败必须留下持久恢复标记")
	}
}

func TestSubmitPendingCSRReplayAuthBlockPreservesExistingPending(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "token disabled",
				ErrorCode: api.ErrorCodeTokenDisabled,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 2, CSRSubmittedAt: "2026-07-01T00:00:00Z",
			LastCSRHash: "existing", LastIssueState: config.IssueStateProcessing,
		},
	}
	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if api.ErrorCodeOf(err) != api.ErrorCodeTokenDisabled {
		t.Fatalf("错误应保留 error_code: %v", err)
	}
	if removed != 1 || certCfg.Metadata.LastCSRHash != "existing" ||
		certCfg.Metadata.LastIssueState != config.IssueStateProcessing {
		t.Fatalf("本次确定认证拒绝应清理本次 pending 并回滚旧元数据: removed=%d metadata=%+v", removed, certCfg.Metadata)
	}
}

func TestSubmitPendingCSRNewOrderInProgressDropsUnacceptedKey(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "in progress",
				ErrorCode: api.ErrorCodeOrderInProgress,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}
	_, _, reason, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err != nil {
		t.Fatalf("order_in_progress 不应作为本轮失败返回: %v", err)
	}
	if reason != "订单已在途，等待签发" {
		t.Fatalf("等待原因=%q", reason)
	}
	if certCfg.Metadata.IssueRetryCount != 3 {
		t.Fatalf("单条目拒绝保留尝试计数，got %d", certCfg.Metadata.IssueRetryCount)
	}
	if certCfg.Metadata.LastIssueState != config.IssueStateProcessing {
		t.Fatalf("order_in_progress 应归一 processing，got %q", certCfg.Metadata.LastIssueState)
	}
	if certCfg.Metadata.LastCSRHash != "" {
		t.Fatal("新 CSR 未被接收时不得保留不匹配的哈希")
	}
	if removed != 1 {
		t.Fatal("新 CSR 未被服务端接收时应删除不匹配的 pending 私钥")
	}
}

func TestSubmitPendingCSRRetryOrderInProgressPreservesUncertainIntent(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200,
				Code:       0,
				Message:    "in progress after retry",
				ErrorCode:  api.ErrorCodeOrderInProgress,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}

	_, _, reason, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err != nil {
		t.Fatalf("不确定尝试后的 order_in_progress 应进入等待: %v", err)
	}
	if reason != "订单已在途，等待签发" {
		t.Fatalf("等待原因=%q", reason)
	}
	if removed != 1 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("确定 order_in_progress 应删除未接收的 pending: removed=%d metadata=%+v",
			removed, certCfg.Metadata)
	}
	if certCfg.Metadata.IssueRetryCount != 3 ||
		certCfg.Metadata.LastIssueState != config.IssueStateProcessing ||
		certCfg.Metadata.LastCSRHash != "" ||
		certCfg.Metadata.ResubmitRequired {
		t.Fatalf("必须清理未接收意图并进入 query-only: %+v", certCfg.Metadata)
	}
}

func TestSubmitPendingCSRRealClientRetryOrderInProgressPreservesUncertainIntent(t *testing.T) {
	var bodies [][]byte
	calls := 0
	removed := 0
	client := api.NewClient("http://127.0.0.1", "token")
	client.HTTPClient.Transport = lifecycleRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("读取请求体失败: %v", err)
		}
		bodies = append(bodies, body)
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader("temporary")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":0,"msg":"already processing","errors":{"error_code":"order_in_progress"}}`,
			)),
			Header:  make(http.Header),
			Request: req,
		}, nil
	})
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}

	_, _, reason, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err == nil || reason != "" {
		t.Fatalf("首个 503 应作为不确定结果返回且不重试: reason=%q err=%v", reason, err)
	}
	if calls != 1 || len(bodies) != 1 {
		t.Fatalf("CSR POST 不得传输重试: calls=%d bodies=%q", calls, bodies)
	}
	if removed != 0 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("不得删除可能已被服务端接收的 pending: removed=%d metadata=%+v",
			removed, certCfg.Metadata)
	}
	if certCfg.Metadata.IssueRetryCount != 3 ||
		certCfg.Metadata.LastIssueState != config.IssueStateProcessing ||
		certCfg.Metadata.LastCSRHash == "" ||
		!certCfg.Metadata.ResubmitRequired {
		t.Fatalf("必须保留当前逻辑尝试供 query-first 恢复: %+v", certCfg.Metadata)
	}
}

func TestSubmitPendingCSRRealClientRetrySuccessClearsRecoveryMarker(t *testing.T) {
	var bodies [][]byte
	calls := 0
	removed := 0
	persistCalls := 0
	client := api.NewClient("http://127.0.0.1", "token")
	client.HTTPClient.Transport = lifecycleRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("读取请求体失败: %v", err)
		}
		bodies = append(bodies, body)
		calls++
		if calls == 1 {
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader("temporary")),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"code":1,"msg":"accepted","data":{"order_id":1,"status":"processing"}}`,
			)),
			Header:  make(http.Header),
			Request: req,
		}, nil
	})
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}

	_, _, reason, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error {
		persistCalls++
		return nil
	})
	if err == nil || reason != "" {
		t.Fatalf("首个 503 后不得通过重试伪造成功: reason=%q err=%v", reason, err)
	}
	if calls != 1 || len(bodies) != 1 {
		t.Fatalf("CSR POST 不得传输重试: calls=%d bodies=%q", calls, bodies)
	}
	if persistCalls != 1 {
		t.Fatalf("不确定结果只应留下请求前意图，persistCalls=%d want=1", persistCalls)
	}
	if removed != 0 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("服务端已接收 CSR 时不得清理 pending: removed=%d metadata=%+v",
			removed, certCfg.Metadata)
	}
	if certCfg.Metadata.IssueRetryCount != 3 ||
		certCfg.Metadata.LastIssueState != config.IssueStateProcessing ||
		certCfg.Metadata.LastCSRHash == "" ||
		!certCfg.Metadata.ResubmitRequired {
		t.Fatalf("不确定结果应保留 query-first 恢复标记: %+v", certCfg.Metadata)
	}
}

func TestSubmitPendingCSRRetryBusinessRejectPreservesUncertainIntent(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200,
				Code:       0,
				Message:    "balance changed after retry",
				ErrorCode:  api.ErrorCodeInsufficientBalance,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}

	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err == nil || api.ErrorCodeOf(err) != api.ErrorCodeInsufficientBalance {
		t.Fatalf("业务拒绝应保留结构化错误: %v", err)
	}
	if removed != 1 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("确定业务拒绝应清理未接收 pending: removed=%d metadata=%+v",
			removed, certCfg.Metadata)
	}
	if certCfg.Metadata.IssueRetryCount != 3 ||
		certCfg.Metadata.LastIssueState != "" ||
		certCfg.Metadata.LastCSRHash != "" ||
		certCfg.Metadata.ResubmitRequired {
		t.Fatalf("确定拒绝应清理本次意图并保留计数: %+v", certCfg.Metadata)
	}
}

func TestProcessOneCertRejectsZeroOrderWithoutSideEffects(t *testing.T) {
	storeCalls := 0
	saveCalls := 0
	cfg := &config.Config{Certificates: []config.CertConfig{{
		CertName: "legacy-zero",
		OrderID:  0,
		Domain:   "example.com",
		Enabled:  true,
		Metadata: config.CertMetadata{
			IssueRetryCount:  2,
			LastIssueState:   config.IssueStateProcessing,
			LastCSRHash:      "existing",
			ResubmitRequired: true,
		},
	}}}
	before := cfg.Certificates[0].Metadata
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			storeCalls++
			return nil
		},
		SavePendingCSRFunc: func(string, string) error {
			storeCalls++
			return nil
		},
		SavePendingPrivateKeyFunc: func(string, string) error {
			storeCalls++
			return nil
		},
	}}

	results, attempted := processOneCertWithSaveAndGate(
		cfg,
		d,
		0,
		nil,
		func() error {
			saveCalls++
			return nil
		},
		nil,
		nil,
	)
	if attempted {
		t.Fatal("无效订单不得计为已尝试 API")
	}
	if len(results) != 1 || results[0].Success ||
		!strings.Contains(results[0].Message, "重新运行 setup") {
		t.Fatalf("应返回可操作的配置错误: %+v", results)
	}
	if storeCalls != 0 || saveCalls != 0 {
		t.Fatalf("无效订单不得生成、清理或保存状态: store=%d save=%d", storeCalls, saveCalls)
	}
	if !reflect.DeepEqual(cfg.Certificates[0].Metadata, before) {
		t.Fatalf("旧配置的恢复元数据必须原样保留: before=%+v after=%+v",
			before, cfg.Certificates[0].Metadata)
	}
}

func TestSubmitPendingCSRReplayOrderInProgressPreservesPendingKey(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "in progress",
				ErrorCode: api.ErrorCodeOrderInProgress,
			}
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 2, CSRSubmittedAt: "2026-07-01T00:00:00Z", LastCSRHash: "old",
			ResubmitRequired: true,
		},
	}
	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err != nil {
		t.Fatalf("order_in_progress 应进入等待: %v", err)
	}
	if certCfg.Metadata.LastCSRHash != "" || removed != 1 {
		t.Fatalf("确定未接收时必须清理 pending: hash=%q removed=%d",
			certCfg.Metadata.LastCSRHash, removed)
	}
	if certCfg.Metadata.ResubmitRequired {
		t.Fatal("order_in_progress 后不得保留 POST 重放标记")
	}
}

func TestSubmitPendingCSRReplayDoesNotRefreshProgressTimestamp(t *testing.T) {
	d := &Deployer{Store: &MockOrderStore{}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, errors.New("connection reset")
		},
	}
	const submittedAt = "2026-07-01T00:00:00Z"
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 2, CSRSubmittedAt: submittedAt, LastIssueState: config.IssueStateProcessing,
		},
	}
	_, _, _, _ = submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if certCfg.Metadata.CSRSubmittedAt == submittedAt {
		t.Fatalf("新的逻辑尝试应写入新的持久化时间: %q", certCfg.Metadata.CSRSubmittedAt)
	}
}

func TestActiveWithoutUsableIssueKeyResetsThenResubmitsOnce(t *testing.T) {
	issuedCert, _ := genSelfSignedPair(t, "example.com")
	_, wrongLocalKey := genSelfSignedPair(t, "other.example.com")
	submitCalls := 0
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
				Certificate: issuedCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitCalls++
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 1, Status: config.OrderStatusProcessing,
			}}}, nil
		},
	}
	d := &Deployer{Store: &MockOrderStore{
		HasPrivateKeyFunc: func(int) bool { return true },
		LoadPrivateKeyFunc: func(int) (string, error) {
			return wrongLocalKey, nil
		},
	}}
	persistCalls := 0
	persist := func() error {
		persistCalls++
		return nil
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 3, LastIssueState: config.IssueStateProcessing,
			CSRSubmittedAt: "2026-07-01T00:00:00Z", LastCSRHash: "rejected-csr",
		},
	}

	_, _, reason, err := handleLocalKeyMode(d, client, certCfg, 14, persist)
	if err != nil {
		t.Fatalf("重置后同轮重新提交 CSR 失败: %v", err)
	}
	if reason != "CSR 已提交，等待签发" {
		t.Fatalf("重新提交后的等待原因=%q", reason)
	}
	if certCfg.Metadata.IssueRetryCount != 4 || submitCalls != 1 {
		t.Fatalf("同轮应只新增一次计数并提交一次: count=%d submit=%d",
			certCfg.Metadata.IssueRetryCount, submitCalls)
	}
	if persistCalls < 2 {
		t.Fatalf("重置与新意图均应持久化，calls=%d", persistCalls)
	}
	if certCfg.Metadata.ResubmitRequired {
		t.Fatal("新签发意图落盘后应清除可恢复重签标记")
	}
}

func TestResubmitMarkerRecoversAfterPendingWriteFailureAndReload(t *testing.T) {
	issuedCert, _ := genSelfSignedPair(t, "example.com")
	_, wrongLocalKey := genSelfSignedPair(t, "other.example.com")
	pendingWriteCalls := 0
	submitCalls := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPrivateKeyFunc: func(int) bool { return true },
		LoadPrivateKeyFunc: func(int) (string, error) {
			return wrongLocalKey, nil
		},
		SavePendingCSRFunc: func(string, string) error {
			pendingWriteCalls++
			if pendingWriteCalls == 1 {
				return errors.New("disk busy")
			}
			return nil
		},
	}}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
				Certificate: issuedCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitCalls++
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 1, Status: config.OrderStatusProcessing,
			}}}, nil
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 3, LastIssueState: config.IssueStateProcessing,
			CertExpiresAt: time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		},
	}
	persist := func() error { return nil }

	if _, _, _, err := handleLocalKeyMode(d, client, certCfg, 14, persist); err == nil ||
		!strings.Contains(err.Error(), "保存 pending CSR 失败") {
		t.Fatalf("首次 pending 写失败应返回错误: %v", err)
	}
	if !certCfg.Metadata.ResubmitRequired || certCfg.Metadata.IssueRetryCount != 3 || submitCalls != 0 {
		t.Fatalf("失败后应保留可恢复标记且不计数/POST: metadata=%+v submit=%d",
			certCfg.Metadata, submitCalls)
	}

	raw, err := json.Marshal(certCfg)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded config.CertConfig
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	if !reloaded.Metadata.ResubmitRequired {
		t.Fatal("resubmit_required 必须跨重启持久化")
	}
	reloaded.Metadata.CertExpiresAt = time.Now().Add(time.Hour).Format(time.RFC3339)
	if skip, reason := evaluateAutoActionGate(&reloaded, time.Now()); skip {
		t.Fatalf("可恢复重签不得被安全余量/普通门禁跳过: %s", reason)
	}

	_, _, reason, err := handleLocalKeyMode(d, client, &reloaded, 14, persist)
	if err != nil {
		t.Fatalf("重载后恢复提交失败: %v", err)
	}
	if !strings.Contains(reason, "安全余量") ||
		reloaded.Metadata.IssueRetryCount != 3 ||
		!reloaded.Metadata.ResubmitRequired ||
		submitCalls != 0 {
		t.Fatalf("安全余量内不得建立新意图: reason=%q metadata=%+v submit=%d",
			reason, reloaded.Metadata, submitCalls)
	}
}

func TestResubmitMarkerRecoversPendingAfterIntentSaveFailure(t *testing.T) {
	issuedCert, _ := genSelfSignedPair(t, "example.com")
	_, wrongLocalKey := genSelfSignedPair(t, "other.example.com")
	var pendingCSR, pendingKey string
	submitCalls := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPrivateKeyFunc: func(int) bool { return true },
		LoadPrivateKeyFunc: func(int) (string, error) {
			return wrongLocalKey, nil
		},
		HasPendingPrivateKeyFunc: func(string) bool { return pendingKey != "" },
		SavePendingCSRFunc:       func(_ string, value string) error { pendingCSR = value; return nil },
		SavePendingPrivateKeyFunc: func(_ string, value string) error {
			pendingKey = value
			return nil
		},
		LoadPendingCSRFunc:        func(string) (string, error) { return pendingCSR, nil },
		LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
		RemovePendingArtifactsFunc: func(string) error {
			pendingCSR, pendingKey = "", ""
			return nil
		},
	}}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
				Certificate: issuedCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitCalls++
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 1, Status: config.OrderStatusProcessing,
			}}}, nil
		},
	}
	persistCalls := 0
	persist := func() error {
		persistCalls++
		if persistCalls == 2 {
			return errors.New("config busy")
		}
		return nil
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 3, LastIssueState: config.IssueStateProcessing,
		},
	}

	if _, _, _, err := handleLocalKeyMode(d, client, certCfg, 14, persist); err == nil ||
		!strings.Contains(err.Error(), "持久化签发意图失败") {
		t.Fatalf("新意图保存失败应返回错误: %v", err)
	}
	if !certCfg.Metadata.ResubmitRequired || certCfg.Metadata.IssueRetryCount != 3 ||
		pendingCSR == "" || pendingKey == "" || submitCalls != 0 {
		t.Fatalf("失败窗口必须可恢复且未消耗计数/POST: metadata=%+v pending=%t/%t submit=%d",
			certCfg.Metadata, pendingCSR != "", pendingKey != "", submitCalls)
	}

	raw, err := json.Marshal(certCfg)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded config.CertConfig
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	_, _, reason, err := handleLocalKeyMode(d, client, &reloaded, 14, persist)
	if err != nil {
		t.Fatalf("重载后 pending 恢复提交失败: %v", err)
	}
	if reason != "CSR 已提交，等待签发" ||
		reloaded.Metadata.IssueRetryCount != 4 ||
		reloaded.Metadata.ResubmitRequired ||
		submitCalls != 1 {
		t.Fatalf("恢复 pending 应建立且只建立一个新意图: reason=%q metadata=%+v submit=%d",
			reason, reloaded.Metadata, submitCalls)
	}
}

func TestOrdinaryRenewalMarkerRecoversPendingAfterIntentSaveFailure(t *testing.T) {
	oldCert, oldKey := genSelfSignedPair(t, "example.com")
	var pendingCSR, pendingKey string
	submitCalls := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPrivateKeyFunc:         func(int) bool { return true },
		LoadPrivateKeyFunc:        func(int) (string, error) { return oldKey, nil },
		HasPendingPrivateKeyFunc:  func(string) bool { return pendingKey != "" },
		SavePendingCSRFunc:        func(_ string, value string) error { pendingCSR = value; return nil },
		SavePendingPrivateKeyFunc: func(_ string, value string) error { pendingKey = value; return nil },
		LoadPendingCSRFunc:        func(string) (string, error) { return pendingCSR, nil },
		LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
		RemovePendingArtifactsFunc: func(string) error {
			pendingCSR, pendingKey = "", ""
			return nil
		},
	}}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(48 * time.Hour).Format(time.RFC3339),
				Certificate: oldCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitCalls++
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 1, Status: config.OrderStatusProcessing,
			}}}, nil
		},
	}
	persistCalls := 0
	persist := func() error {
		persistCalls++
		if persistCalls == 2 {
			return errors.New("config busy")
		}
		return nil
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
	}

	if _, _, _, err := submitNewCSR(d, client, certCfg, persist); err == nil ||
		!strings.Contains(err.Error(), "持久化签发意图失败") {
		t.Fatalf("普通续签新意图保存失败应返回错误: %v", err)
	}
	if !certCfg.Metadata.ResubmitRequired ||
		certCfg.Metadata.IssueRetryCount != 0 ||
		certCfg.Metadata.LastCSRHash != "" ||
		pendingCSR == "" || pendingKey == "" ||
		submitCalls != 0 {
		t.Fatalf("普通续签失败窗口必须保留未计数恢复入口: metadata=%+v pending=%t/%t submit=%d",
			certCfg.Metadata, pendingCSR != "", pendingKey != "", submitCalls)
	}

	raw, err := json.Marshal(certCfg)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded config.CertConfig
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	certData, key, reason, err := handleLocalKeyMode(d, client, &reloaded, 14, persist)
	if err != nil {
		t.Fatalf("普通续签重载恢复失败: %v", err)
	}
	if certData == nil || key != oldKey || reason != "" ||
		reloaded.Metadata.IssueRetryCount != 0 ||
		reloaded.Metadata.ResubmitRequired ||
		submitCalls != 0 {
		t.Fatalf("当前 active 有配对正式私钥时应直接部署: cert=%v keyMatch=%v reason=%q metadata=%+v submit=%d",
			certData != nil, key == oldKey, reason, reloaded.Metadata, submitCalls)
	}
}

func TestResubmitMarkerSurvivesCrashAfterIntentPersistBeforePost(t *testing.T) {
	issuedCert, _ := genSelfSignedPair(t, "example.com")
	_, wrongLocalKey := genSelfSignedPair(t, "other.example.com")
	var pendingCSR, pendingKey string
	submitEntries := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPrivateKeyFunc: func(int) bool { return true },
		LoadPrivateKeyFunc: func(int) (string, error) {
			return wrongLocalKey, nil
		},
		HasPendingPrivateKeyFunc:  func(string) bool { return pendingKey != "" },
		SavePendingCSRFunc:        func(_ string, value string) error { pendingCSR = value; return nil },
		SavePendingPrivateKeyFunc: func(_ string, value string) error { pendingKey = value; return nil },
		LoadPendingCSRFunc:        func(string) (string, error) { return pendingCSR, nil },
		LoadPendingPrivateKeyFunc: func(string) (string, error) { return pendingKey, nil },
	}}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
				Certificate: issuedCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitEntries++
			if submitEntries == 1 {
				panic("simulated crash before transport")
			}
			return &api.UpdateResponse{Code: 1, Data: api.UpdateResponseData{CertData: api.CertData{
				OrderID: 1, Status: config.OrderStatusProcessing,
			}}}, nil
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 3, LastIssueState: config.IssueStateProcessing,
		},
	}
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("应模拟 intent 落盘后的进程崩溃")
			}
		}()
		_, _, _, _ = handleLocalKeyMode(d, client, certCfg, 14, func() error { return nil })
	}()
	if !certCfg.Metadata.ResubmitRequired ||
		certCfg.Metadata.IssueRetryCount != 4 ||
		certCfg.Metadata.LastCSRHash == "" ||
		pendingCSR == "" || pendingKey == "" {
		t.Fatalf("POST 前崩溃必须保留已计数意图与恢复标记: %+v", certCfg.Metadata)
	}

	raw, err := json.Marshal(certCfg)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded config.CertConfig
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	_, _, reason, err := handleLocalKeyMode(d, client, &reloaded, 14, func() error { return nil })
	if err != nil {
		t.Fatalf("重载后 query-first 恢复失败: %v", err)
	}
	if !strings.Contains(reason, "缺少 CSR") ||
		reloaded.Metadata.IssueRetryCount != 4 ||
		!reloaded.Metadata.ResubmitRequired ||
		submitEntries != 1 {
		t.Fatalf("无法证明归属时不得重放 POST: reason=%q metadata=%+v entries=%d",
			reason, reloaded.Metadata, submitEntries)
	}
}

func TestResubmitMarkerActiveMatchingPendingDeploysWithoutPost(t *testing.T) {
	issuedCert, issuedKey := genSelfSignedPair(t, "example.com")
	submitCalls := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPendingPrivateKeyFunc:  func(string) bool { return true },
		LoadPendingPrivateKeyFunc: func(string) (string, error) { return issuedKey, nil },
	}}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Domains: "example.com", Status: config.OrderStatusActive,
				ExpiresAt:   time.Now().Add(180 * 24 * time.Hour).Format(time.RFC3339),
				Certificate: issuedCert,
			}, nil
		},
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			submitCalls++
			return nil, errors.New("不应重放")
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			IssueRetryCount: 4, LastIssueState: config.IssueStateProcessing,
			LastCSRHash: "persisted", CSRSubmittedAt: "2026-07-01T00:00:00Z",
			ResubmitRequired: true,
		},
	}

	certData, key, reason, err := handleLocalKeyMode(d, client, certCfg, 14, func() error { return nil })
	if err != nil {
		t.Fatalf("匹配 pending 应直接恢复部署: %v", err)
	}
	if certData != nil || key != "" || !strings.Contains(reason, "缺少 CSR") || submitCalls != 0 {
		t.Fatalf("服务端缺少 CSR 时必须保留 pending 且不得 POST: cert=%v key=%q reason=%q submit=%d",
			certData != nil, key, reason, submitCalls)
	}
	if !certCfg.Metadata.ResubmitRequired {
		t.Fatal("服务端缺少 CSR 时不得清除恢复标记")
	}
	if certCfg.Metadata.IssueRetryCount != 4 {
		t.Fatalf("query-first 恢复不得重复计数: %d", certCfg.Metadata.IssueRetryCount)
	}
}

func TestSubmitPendingCSRReplayBusinessRejectPreservesPending(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "balance changed",
				ErrorCode: api.ErrorCodeInsufficientBalance,
			}
		},
	}
	before := config.CertMetadata{
		IssueRetryCount: 2, LastIssueState: config.IssueStateProcessing,
		CSRSubmittedAt: "2026-07-01T00:00:00Z", LastCSRHash: "old",
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com", Metadata: before,
	}

	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), func() error { return nil })
	if err == nil {
		t.Fatal("业务拒绝仍应返回错误")
	}
	if removed != 1 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("确定业务拒绝应清理本次 pending: removed=%d metadata=%+v",
			removed, certCfg.Metadata)
	}
	if certCfg.Metadata.IssueRetryCount != before.IssueRetryCount+1 ||
		certCfg.Metadata.LastIssueState != "" ||
		certCfg.Metadata.CSRSubmittedAt != "" ||
		certCfg.Metadata.LastCSRHash != "" {
		t.Fatalf("确定拒绝应保留新尝试计数并清理意图: before=%+v after=%+v", before, certCfg.Metadata)
	}
}

func TestActivePendingReadFailureDoesNotResetIssueState(t *testing.T) {
	issuedCert, _ := genSelfSignedPair(t, "example.com")
	_, pendingCSR, err := cert.GenerateCSR("example.com")
	if err != nil {
		t.Fatal(err)
	}
	client := &MockAPIClient{
		GetCertByOrderIDFunc: func(context.Context, int) (*api.CertData, error) {
			return &api.CertData{
				OrderID: 1, Status: config.OrderStatusActive, Certificate: issuedCert, CSR: pendingCSR,
			}, nil
		},
	}
	d := &Deployer{Store: &MockOrderStore{
		HasPendingPrivateKeyFunc: func(string) bool { return true },
		LoadPendingPrivateKeyFunc: func(string) (string, error) {
			return "", errors.New("disk busy")
		},
	}}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateProcessing,
			CSRSubmittedAt: "2026-07-01T00:00:00Z", LastCSRHash: mustCSRHash(t, pendingCSR),
		},
	}

	if _, _, _, err := handleLocalKeyMode(d, client, certCfg, 14, func() error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "加载 pending 私钥失败") {
		t.Fatalf("pending 读取失败应原样返回: %v", err)
	}
	if certCfg.Metadata.LastIssueState != config.IssueStateProcessing ||
		certCfg.Metadata.LastCSRHash != mustCSRHash(t, pendingCSR) {
		t.Fatalf("pending 仍存在时不得重置签发状态: %+v", certCfg.Metadata)
	}
}

func TestResetIssueStatePersistenceFailureRollsBackMetadata(t *testing.T) {
	certCfg := &config.CertConfig{Metadata: config.CertMetadata{
		IssueRetryCount: 2, LastIssueState: config.IssueStateActive,
		CSRSubmittedAt: "2026-07-01T00:00:00Z", LastCSRHash: "pending",
	}}
	err := resetIssueStateForResubmit(certCfg, errNoUsableIssuedKey, func() error {
		return errors.New("save failed")
	})
	if err == nil || !strings.Contains(err.Error(), "重置失效签发状态失败") {
		t.Fatalf("应返回持久化失败: %v", err)
	}
	if certCfg.Metadata.LastIssueState != config.IssueStateActive ||
		certCfg.Metadata.CSRSubmittedAt == "" ||
		certCfg.Metadata.LastCSRHash != "pending" ||
		certCfg.Metadata.IssueRetryCount != 2 {
		t.Fatalf("持久化失败应回滚内存状态: %+v", certCfg.Metadata)
	}
}

func TestPendingCleanupBlocksReplayUntilLocalCleanupSucceeds(t *testing.T) {
	apiCalls := 0
	d := &Deployer{Store: &MockOrderStore{
		HasPendingPrivateKeyFunc: func(string) bool { return true },
		RemovePendingArtifactsFunc: func(string) error {
			return errors.New("disk busy")
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			apiCalls++
			return nil, nil
		},
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com",
		Metadata: config.CertMetadata{PendingCleanup: true},
	}
	_, _, _, err := submitNewCSR(d, client, certCfg, func() error { return nil })
	if err == nil {
		t.Fatal("本地清理失败应停止本轮")
	}
	if apiCalls != 0 {
		t.Fatalf("待清理残留不得被重放，API 调用=%d", apiCalls)
	}
	if !certCfg.Metadata.PendingCleanup {
		t.Fatal("清理失败必须保留恢复标记")
	}
}

func TestCSRRejectPersistFailureLeavesRecoverableCleanupMarker(t *testing.T) {
	removed := 0
	saves := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	client := &MockAPIClient{
		SubmitCSRFunc: func(context.Context, *api.UpdateRequest) (*api.UpdateResponse, error) {
			return nil, &api.APIError{
				StatusCode: 200, Code: 0, Message: "balance low",
				ErrorCode: api.ErrorCodeInsufficientBalance,
			}
		},
	}
	certCfg := &config.CertConfig{CertName: "example.com-1", OrderID: 1, Domain: "example.com"}
	persist := func() error {
		saves++
		if saves == 2 {
			return errors.New("disk full")
		}
		return nil
	}
	_, _, _, err := submitPendingCSR(d, client, certCfg, validTestCSR(t), persist)
	if err == nil {
		t.Fatal("拒绝状态保存失败应返回错误")
	}
	if !certCfg.Metadata.PendingCleanup || certCfg.Metadata.LastIssueState != "" {
		t.Fatalf("内存必须保留可由外层保存的拒绝/清理状态: %+v", certCfg.Metadata)
	}
	if removed != 0 {
		t.Fatal("拒绝状态未落盘前不得清理 pending")
	}
	if handled, _, recoverErr := recoverPendingCleanup(d, certCfg, func() error { return nil }); !handled || recoverErr != nil {
		t.Fatalf("外层保存状态后应可恢复清理: handled=%v err=%v", handled, recoverErr)
	}
	if removed != 1 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("恢复清理未收敛: removed=%d metadata=%+v", removed, certCfg.Metadata)
	}
}

func TestMarkStalledPersistsTerminalStateBeforeCleanup(t *testing.T) {
	removed := 0
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	certCfg := &config.CertConfig{
		CertName: "example.com-1", Domain: "example.com",
		Metadata: config.CertMetadata{
			LastIssueState:  config.IssueStateProcessing,
			CSRSubmittedAt:  "2026-07-01T00:00:00Z",
			LastCSRHash:     "hash",
			NoProgressSince: "2026-07-01T00:00:00Z",
		},
	}
	supplemental := &runSupplemental{}
	markStalled(d, certCfg, func() error { return errors.New("disk full") }, supplemental)
	if removed != 0 {
		t.Fatal("CAPPED 落盘失败时不得删除 pending 产物")
	}
	if len(supplemental.Errors) != 1 {
		t.Fatalf("应记录持久化失败: %+v", supplemental.Errors)
	}
	if !certCfg.Metadata.PendingCleanup {
		t.Fatal("外层后续保存 CAPPED 时必须同时带上清理恢复标记")
	}
	if handled, _, err := recoverPendingCleanup(d, certCfg, func() error { return nil }); !handled || err != nil {
		t.Fatalf("CAPPED 保存恢复后应继续清理: handled=%v err=%v", handled, err)
	}
	if removed != 1 || certCfg.Metadata.PendingCleanup {
		t.Fatalf("停更清理未收敛: removed=%d metadata=%+v", removed, certCfg.Metadata)
	}
}

func TestPendingCleanupRunsBeforeCappedGate(t *testing.T) {
	removed := 0
	cfg := &config.Config{Certificates: []config.CertConfig{{
		CertName: "example.com-1", OrderID: 1, Domain: "example.com", Enabled: true,
		Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateCapped, CapPhase: config.CapPhaseStalled,
			PendingCleanup: true,
		},
	}}}
	d := &Deployer{Store: &MockOrderStore{
		RemovePendingArtifactsFunc: func(string) error {
			removed++
			return nil
		},
	}}
	results, _ := processOneCertWithSaveAndGate(cfg, d, 0, nil, func() error { return nil }, nil, nil)
	if len(results) != 0 || removed != 1 || cfg.Certificates[0].Metadata.PendingCleanup {
		t.Fatalf("CAPPED 门禁前清理未执行: results=%+v removed=%d metadata=%+v",
			results, removed, cfg.Certificates[0].Metadata)
	}
}

func TestTrackCertUnchanged(t *testing.T) {
	certCfg := &config.CertConfig{Domain: "example.com"}
	certCfg.Metadata.CertSerial = "ABC"
	if msg := trackCertUnchanged(certCfg, "ABC", "2026-08-01"); msg != "" {
		t.Fatalf("首轮相同应容忍，got %q", msg)
	}
	if msg := trackCertUnchanged(certCfg, "ABC", "2026-08-01"); msg == "" {
		t.Fatal("连续第二轮相同应改判失败")
	}
	if certCfg.Metadata.UnchangedCertRounds != config.CertUnchangedRounds {
		t.Fatalf("轮数 = %d", certCfg.Metadata.UnchangedCertRounds)
	}
	certCfg.Metadata.CertSerial = "DEF"
	if msg := trackCertUnchanged(certCfg, "ABC", "2026-08-01"); msg != "" {
		t.Fatalf("新序列号不得误判: %q", msg)
	}
	if certCfg.Metadata.UnchangedCertRounds != 0 {
		t.Fatal("序列号变化应清零轮数")
	}
}

func TestUpdateCertMetadataPreservesUnchangedRounds(t *testing.T) {
	certCfg := &config.CertConfig{}
	certCfg.Metadata.UnchangedCertRounds = 1
	updateCertMetadata(certCfg, &api.CertData{ExpiresAt: "2026-08-01"})
	if certCfg.Metadata.UnchangedCertRounds != 1 {
		t.Fatal("部署成功不得清零 unchanged_cert_rounds")
	}
}

func TestUnchangedFailurePreservesAttemptAndProgressBoundary(t *testing.T) {
	before := config.CertMetadata{
		DeployAttemptCount: config.MaxDeployAttempts,
		DeployStartedAt:    "2026-07-26T00:00:00Z",
		LastDeployAt:       "2026-07-01T00:00:00Z",
		CertExpiresAt:      "2026-08-01T00:00:00Z",
		CertSerial:         "ABC",
		NoProgressSince:    "2026-07-10T00:00:00Z",
	}
	meta := config.CertMetadata{
		UnchangedCertRounds: config.CertUnchangedRounds,
		LastDeployAt:        "2026-07-26T00:00:00Z",
		CertExpiresAt:       "2026-08-01T00:00:00Z",
		CertSerial:          "ABC",
	}

	preserveUnchangedFailureState(&meta, before)
	reconcileFailedDeploy(&meta, true, false)

	if meta.DeployAttemptCount != config.MaxDeployAttempts ||
		meta.CapPhase != config.CapPhaseDeploy ||
		meta.LastIssueState != config.IssueStateCapped {
		t.Fatalf("证书未更替失败应按部署计数触顶: %+v", meta)
	}
	if meta.NoProgressSince != before.NoProgressSince ||
		meta.LastDeployAt != before.LastDeployAt {
		t.Fatalf("证书未更替不得伪造进展: %+v", meta)
	}
	if meta.UnchangedCertRounds != config.CertUnchangedRounds {
		t.Fatalf("未更替轮数不得被恢复覆盖: %d", meta.UnchangedCertRounds)
	}
}
