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

// TestPersistDeployAttempt_FailureStopsAttempt 持久化失败时不得留下虚假在途状态或继续部署。
func TestPersistDeployAttempt_FailureStopsAttempt(t *testing.T) {
	meta := &config.CertMetadata{DeployAttemptCount: 3}
	capped, replaying, err := persistDeployAttempt(meta, func() error { return errors.New("disk full") })
	if err == nil {
		t.Fatal("持久化失败应返回错误")
	}
	if capped || replaying {
		t.Fatalf("持久化失败不应成为有效尝试: capped=%v replaying=%v", capped, replaying)
	}
	if meta.DeployAttemptCount != 3 || meta.DeployStartedAt != "" {
		t.Fatalf("持久化失败应恢复原元数据: %+v", meta)
	}
}

// TestShouldFinalizeDeployment 任一绑定成功即接纳证书；回调仍可按整体结果报 failure。
func TestShouldFinalizeDeployment(t *testing.T) {
	tests := []struct {
		name    string
		report  deployReport
		hasCert bool
		want    bool
	}{
		{"全部绑定成功", deployReport{report: true, success: true}, true, true},
		{"部分绑定成功", deployReport{
			report: true, success: false,
			successfulTargets: []config.BindingRetryTarget{{Host: "a.example.com", Port: 443}},
		}, true, true},
		{"没有证书内容", deployReport{report: true, success: true}, false, false},
		{"没有处理绑定", deployReport{}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldFinalizeDeployment(tt.report, tt.hasCert); got != tt.want {
				t.Fatalf("shouldFinalizeDeployment(%+v, %v) = %v, want %v", tt.report, tt.hasCert, got, tt.want)
			}
		})
	}
}

func TestPendingBindingTargetFilter(t *testing.T) {
	pending := []config.BindingRetryTarget{
		{Host: "WWW.Example.com", Port: 443},
		{Host: "192.0.2.10", Port: 8443, IPBinding: true},
	}
	if !isPendingBindingTarget(iis.EndpointKey{Host: "www.example.com", Port: 443}, pending) {
		t.Fatal("域名端点应忽略大小写匹配失败重试状态")
	}
	if !isPendingBindingTarget(iis.EndpointKey{Host: "192.0.2.10", Port: 8443, IPBinding: true}, pending) {
		t.Fatal("IP 绑定端点应匹配失败重试状态")
	}
	if isPendingBindingTarget(iis.EndpointKey{Host: "192.0.2.10", Port: 8443}, pending) {
		t.Fatal("IP 绑定与 SNI 绑定不得混淆")
	}
}

// TestSubmitNewCSR_PersistFailureStopsRequest 签发意图未持久化时不得提交 CSR。
func TestSubmitNewCSR_PersistFailureStopsRequest(t *testing.T) {
	d := NewMockDeployer()
	called := false
	client := NewMockClient()
	client.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
		called = true
		return nil, errors.New("不应调用")
	}
	certCfg := &config.CertConfig{
		CertName: "example.com-100",
		OrderID:  100,
		Domain:   "example.com",
		Metadata: config.CertMetadata{IssueRetryCount: 2},
	}

	if _, _, _, err := submitNewCSR(d, client, certCfg, func() error { return errors.New("disk full") }); err == nil {
		t.Fatal("持久化失败应阻止 CSR 提交")
	}
	if called {
		t.Fatal("签发意图未持久化时不得调用 SubmitCSR")
	}
	if certCfg.Metadata.IssueRetryCount != 2 || certCfg.Metadata.LastCSRHash != "" {
		t.Fatalf("持久化失败应恢复原元数据: %+v", certCfg.Metadata)
	}
}

// TestEvaluateAutoActionGate 自动动作准入门禁：触顶/过期/策略阻断/安全余量跳过且不回调
func TestEvaluateAutoActionGate(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	future := now.AddDate(0, 0, 30).Format("2006-01-02")
	within := now.Add(6 * time.Hour).Format(time.RFC3339)
	past := now.AddDate(0, 0, -1).Format("2006-01-02")

	tests := []struct {
		name          string
		meta          config.CertMetadata
		wantSkip      bool
		wantStateAfte string // 期望门禁后状态（空表示不校验）
	}{
		{"健康证书放行", config.CertMetadata{CertExpiresAt: future}, false, ""},
		{"策略阻断跳过", config.CertMetadata{LastIssueState: config.IssueStatePolicyBlocked, CertExpiresAt: future}, true, config.IssueStatePolicyBlocked},
		{"已触顶跳过", config.CertMetadata{LastIssueState: config.IssueStateCapped, CertExpiresAt: future}, true, config.IssueStateCapped},
		{"已过期状态跳过", config.CertMetadata{LastIssueState: config.IssueStateExpired, CertExpiresAt: future}, true, config.IssueStateExpired},
		{"到期转 EXPIRED", config.CertMetadata{CertExpiresAt: past}, true, config.IssueStateExpired},
		{"触顶后到期转 EXPIRED", config.CertMetadata{LastIssueState: config.IssueStateCapped, CapPhase: config.CapPhaseDeploy, CertExpiresAt: past}, true, config.IssueStateExpired},
		{"不足安全余量仍允许查询和部署", config.CertMetadata{CertExpiresAt: within}, false, ""},
		{"无到期信息放行", config.CertMetadata{}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &config.CertConfig{Metadata: tt.meta}
			skip, _ := evaluateAutoActionGate(cc, now)
			if skip != tt.wantSkip {
				t.Fatalf("skip = %v, want %v", skip, tt.wantSkip)
			}
			if tt.wantStateAfte != "" && cc.Metadata.LastIssueState != tt.wantStateAfte {
				t.Errorf("门禁后状态 = %q, want %q", cc.Metadata.LastIssueState, tt.wantStateAfte)
			}
		})
	}

	// 到期转 EXPIRED 时应清除触顶阶段
	t.Run("到期清除触顶阶段", func(t *testing.T) {
		cc := &config.CertConfig{Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateCapped, CapPhase: config.CapPhaseIssue, CertExpiresAt: past,
		}}
		evaluateAutoActionGate(cc, now)
		if cc.Metadata.CapPhase != "" {
			t.Errorf("过期后应清除 CapPhase，got %q", cc.Metadata.CapPhase)
		}
	})
}

// TestBeginDeployAttempt 部署意图计数：新尝试递增+落标记，在途重放不计数，触顶返回 capped
func TestBeginDeployAttempt(t *testing.T) {
	t.Run("新尝试递增并落在途标记", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: 3}
		capped, replaying := beginDeployAttempt(meta)
		if capped || replaying {
			t.Fatalf("首次尝试不应 capped/replaying: capped=%v replaying=%v", capped, replaying)
		}
		if meta.DeployAttemptCount != 4 {
			t.Errorf("计数应 3->4, got %d", meta.DeployAttemptCount)
		}
		if meta.DeployStartedAt == "" {
			t.Error("应写入在途标记 DeployStartedAt")
		}
	})

	t.Run("在途重放不重复计数", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: 4, DeployStartedAt: "2026-07-20T00:00:00Z"}
		capped, replaying := beginDeployAttempt(meta)
		if capped || !replaying {
			t.Fatalf("在途应判定为 replaying: capped=%v replaying=%v", capped, replaying)
		}
		if meta.DeployAttemptCount != 4 {
			t.Errorf("重放不应递增计数, got %d", meta.DeployAttemptCount)
		}
	})

	t.Run("触顶返回 capped 并标记 CAPPED", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: config.MaxDeployAttempts}
		capped, replaying := beginDeployAttempt(meta)
		if !capped || replaying {
			t.Fatalf("触顶应返回 capped: capped=%v replaying=%v", capped, replaying)
		}
		if meta.LastIssueState != config.IssueStateCapped || meta.CapPhase != config.CapPhaseDeploy {
			t.Errorf("应标记 CAPPED(deploy), got state=%q phase=%q", meta.LastIssueState, meta.CapPhase)
		}
		if meta.DeployAttemptCount != config.MaxDeployAttempts {
			t.Errorf("触顶不应再递增, got %d", meta.DeployAttemptCount)
		}
	})
}

// TestReconcileFailedDeploy 部署失败/无处理时的计数收敛
func TestReconcileFailedDeploy(t *testing.T) {
	t.Run("无绑定被处理撤销本轮意图", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: 5, DeployStartedAt: "t"}
		reconcileFailedDeploy(meta, false, false)
		if meta.DeployAttemptCount != 4 {
			t.Errorf("应回退计数 5->4, got %d", meta.DeployAttemptCount)
		}
		if meta.DeployStartedAt != "" {
			t.Error("应清除在途标记")
		}
	})

	t.Run("重放且无处理不回退计数", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: 5, DeployStartedAt: "t"}
		reconcileFailedDeploy(meta, false, true)
		if meta.DeployAttemptCount != 5 {
			t.Errorf("重放不应回退计数, got %d", meta.DeployAttemptCount)
		}
	})

	t.Run("明确失败保留计数清标记", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: 5, DeployStartedAt: "t"}
		reconcileFailedDeploy(meta, true, false)
		if meta.DeployAttemptCount != 5 || meta.DeployStartedAt != "" {
			t.Errorf("失败应保留计数清标记, got count=%d started=%q", meta.DeployAttemptCount, meta.DeployStartedAt)
		}
		if meta.IsCapped() {
			t.Error("未触顶不应 CAPPED")
		}
	})

	t.Run("第10次失败触顶 CAPPED", func(t *testing.T) {
		meta := &config.CertMetadata{DeployAttemptCount: config.MaxDeployAttempts, DeployStartedAt: "t"}
		reconcileFailedDeploy(meta, true, false)
		if !meta.IsCapped() || meta.CapPhase != config.CapPhaseDeploy {
			t.Errorf("第10次失败应 CAPPED(deploy), got state=%q phase=%q", meta.LastIssueState, meta.CapPhase)
		}
	})
}

// TestDeployAttemptLifecycle 连续失败每轮重启：最多 10 个持久尝试意图，重放不盲增计数
func TestDeployAttemptLifecycle(t *testing.T) {
	meta := &config.CertMetadata{}
	// 10 轮：每轮一次新尝试（begin 递增 + 失败 reconcile 清标记）
	for round := 1; round <= 10; round++ {
		capped, replaying := beginDeployAttempt(meta)
		if capped {
			t.Fatalf("第 %d 轮不应提前触顶", round)
		}
		if replaying {
			t.Fatalf("第 %d 轮新尝试不应为重放", round)
		}
		if meta.DeployAttemptCount != round {
			t.Fatalf("第 %d 轮计数应为 %d, got %d", round, round, meta.DeployAttemptCount)
		}
		reconcileFailedDeploy(meta, true, replaying) // 明确失败
	}
	if !meta.IsCapped() {
		t.Fatalf("10 次失败后应 CAPPED, state=%q count=%d", meta.LastIssueState, meta.DeployAttemptCount)
	}
	// 第 11 轮：begin 直接 capped，不产生第 11 次尝试
	capped, _ := beginDeployAttempt(meta)
	if !capped {
		t.Fatal("第 11 轮应被触顶拦截")
	}
	if meta.DeployAttemptCount != 10 {
		t.Errorf("绝不出现第 11 次部署尝试, got %d", meta.DeployAttemptCount)
	}
}

// TestDeployAttemptCrashReplay 崩溃恢复：意图已落盘但未完成，重启复用同一意图不重复计数
func TestDeployAttemptCrashReplay(t *testing.T) {
	// 模拟第 3 次尝试落盘后崩溃（DeployStartedAt 保留，计数=3）
	meta := &config.CertMetadata{DeployAttemptCount: 3, DeployStartedAt: "2026-07-20T00:00:00Z"}
	// 重启：begin 检测到在途标记 → 复用同一意图，不递增
	capped, replaying := beginDeployAttempt(meta)
	if capped || !replaying {
		t.Fatalf("崩溃后应复用同一意图: capped=%v replaying=%v", capped, replaying)
	}
	if meta.DeployAttemptCount != 3 {
		t.Errorf("崩溃恢复重放不应递增计数, got %d", meta.DeployAttemptCount)
	}
	// 本次成功：走 updateCertMetadata 清零（此处直接模拟成功清零）
	reconcileFailedDeploy(meta, true, replaying) // 若再失败仍不重复计数
	if meta.DeployAttemptCount != 3 {
		t.Errorf("同一意图失败后计数保持 3, got %d", meta.DeployAttemptCount)
	}
}

// TestSubmitNewCSR_IssueCountSeparation 签发计数：新 CSR 递增，已有 pending 只查询，触顶转 CAPPED。
func TestSubmitNewCSR_IssueCountSeparation(t *testing.T) {
	t.Run("生成新 CSR 递增签发计数", func(t *testing.T) {
		d := NewMockDeployer()
		client := NewMockClient()
		client.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			return &api.UpdateResponse{Data: api.UpdateResponseData{CertData: api.CertData{OrderID: 100, Status: "processing"}}}, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com",
			Metadata: config.CertMetadata{IssueRetryCount: 2}}
		if _, _, _, err := submitNewCSR(d, client, certCfg); err != nil {
			t.Fatalf("submitNewCSR error = %v", err)
		}
		if certCfg.Metadata.IssueRetryCount != 3 {
			t.Errorf("新 CSR 应 2->3, got %d", certCfg.Metadata.IssueRetryCount)
		}
	})

	t.Run("已有 pending CSR 只查询且不递增签发计数", func(t *testing.T) {
		d := NewMockDeployer()
		store := d.Store.(*MockOrderStore)
		keyPEM, csrPEM, err := cert.GenerateCSR("example.com")
		if err != nil {
			t.Fatalf("GenerateCSR error = %v", err)
		}
		store.HasPendingPrivateKeyFunc = func(string) bool { return true }
		store.LoadPendingCSRFunc = func(string) (string, error) { return csrPEM, nil }
		store.LoadPendingPrivateKeyFunc = func(string) (string, error) { return keyPEM, nil }
		client := NewMockClient()
		client.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			return &api.UpdateResponse{Data: api.UpdateResponseData{CertData: api.CertData{OrderID: 100, Status: "processing"}}}, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com",
			Metadata: config.CertMetadata{
				IssueRetryCount:  4,
				CSRSubmittedAt:   "2026-07-01T00:00:00Z",
				LastCSRHash:      mustCSRHash(t, csrPEM),
				ResubmitRequired: true,
			}}
		if _, _, _, err := submitNewCSR(d, client, certCfg); err != nil {
			t.Fatalf("submitNewCSR error = %v", err)
		}
		if certCfg.Metadata.IssueRetryCount != 4 {
			t.Errorf("query-first 不应递增签发计数, got %d", certCfg.Metadata.IssueRetryCount)
		}
	})

	t.Run("签发触顶转 CAPPED 不提交不报错", func(t *testing.T) {
		d := NewMockDeployer()
		client := NewMockClient()
		client.SubmitCSRFunc = func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
			t.Fatal("触顶后不应再提交 CSR")
			return nil, nil
		}
		certCfg := &config.CertConfig{CertName: "example.com-100", OrderID: 100, Domain: "example.com",
			Metadata: config.CertMetadata{IssueRetryCount: config.MaxIssueRetries}}
		_, _, reason, err := submitNewCSR(d, client, certCfg)
		if err != nil {
			t.Fatalf("触顶应静默跳过而非报错, got %v", err)
		}
		if !certCfg.Metadata.IsCapped() || certCfg.Metadata.CapPhase != config.CapPhaseIssue {
			t.Errorf("应标记 CAPPED(issue), got state=%q phase=%q", certCfg.Metadata.LastIssueState, certCfg.Metadata.CapPhase)
		}
		if reason == "" {
			t.Error("应返回触顶跳过原因")
		}
	})
}
