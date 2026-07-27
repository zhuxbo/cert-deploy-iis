package config

import (
	"encoding/json"
	"testing"
)

// rawFromConfig 将 Config 经 JSON 往返转为 raw map（数字为 float64，与真实 Load 一致）
func rawFromConfig(t *testing.T, cfg *Config) map[string]interface{} {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return raw
}

// firstCertMeta 取迁移后第一张证书的 metadata map
func firstCertMeta(t *testing.T, raw map[string]interface{}) map[string]interface{} {
	t.Helper()
	certs := getSlice(raw, "certificates")
	if len(certs) == 0 {
		t.Fatal("无证书")
	}
	node := certs[0].(map[string]interface{})
	meta, _ := getMap(node, "metadata")
	if meta == nil {
		return map[string]interface{}{}
	}
	return meta
}

func metaState(m map[string]interface{}) string {
	s, _ := m["last_issue_state"].(string)
	return s
}

// TestMigratePendingToProcessing pending/approving 中间态归一为 processing
func TestMigratePendingToProcessing(t *testing.T) {
	for _, state := range []string{"pending", "approving"} {
		cfg := &Config{
			Schedule: Schedule{RenewMode: "local"},
			Certificates: []CertConfig{{
				OrderID: 1, Domain: "example.com", Domains: []string{"example.com"},
				Metadata: CertMetadata{LastIssueState: state},
			}},
		}
		raw := rawFromConfig(t, cfg)
		migrateFields(raw)
		if got := metaState(firstCertMeta(t, raw)); got != IssueStateProcessing {
			t.Errorf("%s 应归一为 processing, got %q", state, got)
		}
	}
}

// TestMigratePolicyBlockedIP 旧非法 IP 配置迁移为 policy_blocked，合法 IP local/file 不动
func TestMigratePolicyBlockedIP(t *testing.T) {
	tests := []struct {
		name        string
		global      string
		cert        CertConfig
		wantState   string
		wantIllegal bool
	}{
		{
			name:      "IPv4+pull 非法",
			global:    "pull",
			cert:      CertConfig{OrderID: 1, Domain: "1.2.3.4", Domains: []string{"1.2.3.4"}},
			wantState: IssueStatePolicyBlocked, wantIllegal: true,
		},
		{
			name:      "IPv4+delegation 非法",
			global:    "local",
			cert:      CertConfig{OrderID: 1, Domain: "1.2.3.4", Domains: []string{"1.2.3.4"}, RenewMode: "local", ValidationMethod: ValidationMethodDelegation},
			wantState: IssueStatePolicyBlocked, wantIllegal: true,
		},
		{
			name:      "IPv6+继承全局 pull 非法",
			global:    "pull",
			cert:      CertConfig{OrderID: 1, Domain: "2001:db8::1", Domains: []string{"2001:db8::1"}},
			wantState: IssueStatePolicyBlocked, wantIllegal: true,
		},
		{
			name:      "IP+local+file 合法不动",
			global:    "pull",
			cert:      CertConfig{OrderID: 1, Domain: "1.2.3.4", Domains: []string{"1.2.3.4"}, RenewMode: "local", ValidationMethod: ValidationMethodFile},
			wantState: "", wantIllegal: false,
		},
		{
			name:      "域名证书 pull 不受影响",
			global:    "pull",
			cert:      CertConfig{OrderID: 1, Domain: "example.com", Domains: []string{"example.com"}},
			wantState: "", wantIllegal: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Schedule: Schedule{RenewMode: tt.global}, Certificates: []CertConfig{tt.cert}}
			raw := rawFromConfig(t, cfg)
			migrateFields(raw)
			meta := firstCertMeta(t, raw)
			if got := metaState(meta); got != tt.wantState {
				t.Errorf("状态 = %q, want %q", got, tt.wantState)
			}
			// 非法配置不得被改动 renew_mode/validation_method
			node := getSlice(raw, "certificates")[0].(map[string]interface{})
			if tt.wantIllegal {
				if _, changed := node["renew_mode"]; changed && tt.cert.RenewMode == "" {
					t.Error("policy_blocked 不应写入 renew_mode")
				}
			}
		})
	}
}

// TestMigrateLegacyCapped 旧计数 0/1/5/9/10/11 × 状态 表驱动
func TestMigrateLegacyCapped(t *testing.T) {
	tests := []struct {
		name      string
		count     int
		state     string
		wantState string
		wantPhase string
	}{
		{"count0 空", 0, "", "", ""},
		{"count1 空", 1, "", "", ""},
		{"count5 空", 5, "", "", ""},
		{"count9 空", 9, "", "", ""},
		{"count10 空 触顶", 10, "", IssueStateCapped, CapPhaseLegacy},
		{"count11 空 触顶", 11, "", IssueStateCapped, CapPhaseLegacy},
		{"count10 pending 触顶", 10, "pending", IssueStateCapped, CapPhaseLegacy},
		{"count10 processing 触顶", 10, "processing", IssueStateCapped, CapPhaseLegacy},
		{"count11 active 触顶", 11, "active", IssueStateCapped, CapPhaseLegacy},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Schedule: Schedule{RenewMode: "local"},
				Certificates: []CertConfig{{
					OrderID: 1, Domain: "example.com", Domains: []string{"example.com"},
					Metadata: CertMetadata{IssueRetryCount: tt.count, LastIssueState: tt.state},
				}},
			}
			raw := rawFromConfig(t, cfg)
			migrateFields(raw)
			meta := firstCertMeta(t, raw)
			if got := metaState(meta); got != tt.wantState {
				t.Errorf("状态 = %q, want %q", got, tt.wantState)
			}
			phase, _ := meta["capped_phase"].(string)
			if phase != tt.wantPhase {
				t.Errorf("capped_phase = %q, want %q", phase, tt.wantPhase)
			}
			// 部署计数从零开始，不从旧混合计数推断
			if _, has := meta["deploy_attempt_count"]; has {
				t.Errorf("部署计数不应由迁移写入, got %v", meta["deploy_attempt_count"])
			}
		})
	}
}

// TestLifecycleMigration_Ordering 非法 IP + 旧计数触顶：policy_blocked 优先（根因是配置错误）
func TestLifecycleMigration_Ordering(t *testing.T) {
	cfg := &Config{
		Schedule: Schedule{RenewMode: "pull"},
		Certificates: []CertConfig{{
			OrderID: 1, Domain: "1.2.3.4", Domains: []string{"1.2.3.4"},
			Metadata: CertMetadata{IssueRetryCount: 12, LastIssueState: "pending"},
		}},
	}
	raw := rawFromConfig(t, cfg)
	migrateFields(raw)
	meta := firstCertMeta(t, raw)
	if got := metaState(meta); got != IssueStatePolicyBlocked {
		t.Errorf("非法 IP 且触顶应优先 policy_blocked, got %q", got)
	}
	if _, has := meta["capped_phase"]; has {
		t.Error("policy_blocked 不应写 capped_phase")
	}
}

// TestMigrateLegacyCapped_Idempotent 迁移幂等：重复执行状态不变
func TestMigrateLegacyCapped_Idempotent(t *testing.T) {
	cfg := &Config{
		Schedule: Schedule{RenewMode: "local"},
		Certificates: []CertConfig{{
			OrderID: 1, Domain: "example.com", Domains: []string{"example.com"},
			Metadata: CertMetadata{IssueRetryCount: 10},
		}},
	}
	raw := rawFromConfig(t, cfg)
	migrateFields(raw)
	first := metaState(firstCertMeta(t, raw))
	changed := migrateFields(raw) // 再跑一次
	second := metaState(firstCertMeta(t, raw))
	if first != IssueStateCapped || second != IssueStateCapped {
		t.Errorf("状态应稳定为 CAPPED, first=%q second=%q", first, second)
	}
	if changed {
		t.Error("已迁移配置再次迁移不应报告变更（幂等）")
	}
}

func TestMigrateCapPhaseFieldName(t *testing.T) {
	raw := map[string]interface{}{
		"certificates": []interface{}{
			map[string]interface{}{
				"metadata": map[string]interface{}{
					"last_issue_state": IssueStateCapped,
					"cap_phase":        CapPhaseDeploy,
				},
			},
		},
	}
	if !migrateFields(raw) {
		t.Fatal("旧 cap_phase 应迁移")
	}
	meta := firstCertMeta(t, raw)
	if got := meta["capped_phase"]; got != CapPhaseDeploy {
		t.Fatalf("capped_phase = %v, want %q", got, CapPhaseDeploy)
	}
	if _, exists := meta["cap_phase"]; exists {
		t.Fatal("迁移后不应保留 cap_phase")
	}
}
