package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// === sslctlw 特有规则测试 ===

// TestMigrateConfig_MoveRenewDays renew_days 迁移到 schedule.renew_before_days
func TestMigrateConfig_MoveRenewDays(t *testing.T) {
	oldCfg := `{"certificates":[],"renew_days":20,"task_name":"SSLCtlW"}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("应检测到 renew_days 并触发迁移")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)

	// renew_days 应被删除
	if _, has := raw["renew_days"]; has {
		t.Error("迁移后不应保留 renew_days")
	}

	// schedule.renew_before_days 应为 20
	schedule, ok := raw["schedule"].(map[string]interface{})
	if !ok {
		t.Fatal("迁移后应创建 schedule 对象")
	}
	if schedule["renew_before_days"] != float64(20) {
		t.Errorf("schedule.renew_before_days = %v, 期望 20", schedule["renew_before_days"])
	}
}

// TestMigrateConfig_MoveRenewDays_NoOverwrite schedule 已有值时不覆盖
func TestMigrateConfig_MoveRenewDays_NoOverwrite(t *testing.T) {
	cfg := `{"certificates":[],"renew_days":10,"schedule":{"renew_before_days":25}}`

	data, changed, err := migrateConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if !changed {
		t.Fatal("renew_days 存在应触发迁移（删除源字段）")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)

	// 旧字段已删除
	if _, has := raw["renew_days"]; has {
		t.Error("迁移后不应保留 renew_days")
	}

	// 已有值保留
	schedule := raw["schedule"].(map[string]interface{})
	if schedule["renew_before_days"] != float64(25) {
		t.Errorf("schedule.renew_before_days = %v, 期望保留 25", schedule["renew_before_days"])
	}
}

// TestMigrateConfig_UseLocalKeyToRenewMode use_local_key 转换为 renew_mode
func TestMigrateConfig_UseLocalKeyToRenewMode(t *testing.T) {
	t.Run("true转local", func(t *testing.T) {
		cfg := `{"certificates":[{"order_id":1,"domain":"a.com","use_local_key":true}]}`
		data, changed, err := migrateConfig([]byte(cfg))
		if err != nil {
			t.Fatalf("error = %v", err)
		}
		if !changed {
			t.Fatal("应触发迁移")
		}
		var raw map[string]interface{}
		_ = json.Unmarshal(data, &raw)
		cert := raw["certificates"].([]interface{})[0].(map[string]interface{})
		if cert["renew_mode"] != "local" {
			t.Errorf("renew_mode = %v, 期望 local", cert["renew_mode"])
		}
		if _, has := cert["use_local_key"]; has {
			t.Error("use_local_key 应被删除")
		}
	})

	t.Run("false不设置renew_mode", func(t *testing.T) {
		cfg := `{"certificates":[{"order_id":1,"domain":"a.com","use_local_key":false}]}`
		data, _, _ := migrateConfig([]byte(cfg))
		var raw map[string]interface{}
		_ = json.Unmarshal(data, &raw)
		cert := raw["certificates"].([]interface{})[0].(map[string]interface{})
		if _, has := cert["renew_mode"]; has {
			t.Error("use_local_key=false 不应设置 renew_mode")
		}
	})

	t.Run("已有renew_mode不覆盖", func(t *testing.T) {
		cfg := `{"certificates":[{"order_id":1,"use_local_key":true,"renew_mode":"pull"}]}`
		data, _, _ := migrateConfig([]byte(cfg))
		var raw map[string]interface{}
		_ = json.Unmarshal(data, &raw)
		cert := raw["certificates"].([]interface{})[0].(map[string]interface{})
		if cert["renew_mode"] != "pull" {
			t.Errorf("已有 renew_mode 不应被覆盖, got %v", cert["renew_mode"])
		}
	})
}

// TestMigrateConfig_CertName 自动生成 cert_name
func TestMigrateConfig_CertName(t *testing.T) {
	cfg := `{"certificates":[{"order_id":123,"domain":"example.com"}]}`
	data, changed, err := migrateConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !changed {
		t.Fatal("应触发迁移")
	}
	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	cert := raw["certificates"].([]interface{})[0].(map[string]interface{})
	if cert["cert_name"] != "example.com-123" {
		t.Errorf("cert_name = %v, 期望 example.com-123", cert["cert_name"])
	}
}

// TestMigrateConfig_MoveExpiresAtToMetadata expires_at 移入 metadata
func TestMigrateConfig_MoveExpiresAtToMetadata(t *testing.T) {
	cfg := `{"certificates":[{"order_id":1,"expires_at":"2025-12-31","serial_number":"ABC"}]}`
	data, changed, err := migrateConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !changed {
		t.Fatal("应触发迁移")
	}
	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	cert := raw["certificates"].([]interface{})[0].(map[string]interface{})

	// 旧字段已删除
	if _, has := cert["expires_at"]; has {
		t.Error("expires_at 应被移除")
	}
	if _, has := cert["serial_number"]; has {
		t.Error("serial_number 应被移除")
	}

	// 新字段在 metadata 中
	meta, ok := cert["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("应创建 metadata 对象")
	}
	if meta["cert_expires_at"] != "2025-12-31" {
		t.Errorf("metadata.cert_expires_at = %v, 期望 2025-12-31", meta["cert_expires_at"])
	}
	if meta["cert_serial"] != "ABC" {
		t.Errorf("metadata.cert_serial = %v, 期望 ABC", meta["cert_serial"])
	}
}

// TestMigrateConfig_FullOldFormat 完整旧格式跨版本迁移
func TestMigrateConfig_FullOldFormat(t *testing.T) {
	oldCfg := `{
		"renew_days": 13,
		"certificates": [{
			"order_id": 100,
			"domain": "test.com",
			"expires_at": "2025-06-30",
			"serial_number": "XYZ",
			"use_local_key": true,
			"enabled": true
		}]
	}`

	data, changed, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if !changed {
		t.Fatal("旧格式应触发迁移")
	}

	// 二次迁移幂等
	_, changed2, _ := migrateConfig(data)
	if changed2 {
		t.Error("迁移后再次迁移不应有变化（幂等性）")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)

	// 顶层 renew_days 消失，schedule.renew_before_days 存在
	if _, has := raw["renew_days"]; has {
		t.Error("renew_days 应被移除")
	}
	schedule := raw["schedule"].(map[string]interface{})
	if schedule["renew_before_days"] != float64(13) {
		t.Errorf("schedule.renew_before_days = %v", schedule["renew_before_days"])
	}

	cert := raw["certificates"].([]interface{})[0].(map[string]interface{})
	if cert["cert_name"] != "test.com-100" {
		t.Errorf("cert_name = %v", cert["cert_name"])
	}
	if cert["renew_mode"] != "local" {
		t.Errorf("renew_mode = %v", cert["renew_mode"])
	}
	if _, has := cert["use_local_key"]; has {
		t.Error("use_local_key 应被删除")
	}
	meta := cert["metadata"].(map[string]interface{})
	if meta["cert_expires_at"] != "2025-06-30" {
		t.Errorf("cert_expires_at = %v", meta["cert_expires_at"])
	}
}

// TestMigrateConfig_NoChange 当前格式不触发迁移
func TestMigrateConfig_NoChange(t *testing.T) {
	cfg := `{
		"schedule": {"renew_before_days": 14, "renew_mode": "pull"},
		"certificates": [{"cert_name": "a.com-123", "order_id": 123, "domain": "a.com", "metadata": {"cert_expires_at": "2025-12-31"}}]
	}`
	_, changed, err := migrateConfig([]byte(cfg))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if changed {
		t.Error("当前格式不应触发迁移")
	}
}

// TestMigrateConfig_EmptyConfig 空配置不触发迁移
func TestMigrateConfig_EmptyConfig(t *testing.T) {
	_, changed, err := migrateConfig([]byte(`{}`))
	if err != nil {
		t.Fatalf("migrateConfig() error = %v", err)
	}
	if changed {
		t.Error("空配置不应触发迁移")
	}
}

// TestMigrateConfig_InvalidJSON 无效 JSON 返回错误
func TestMigrateConfig_InvalidJSON(t *testing.T) {
	_, _, err := migrateConfig([]byte("not json"))
	if err == nil {
		t.Error("无效 JSON 应返回错误")
	}
}

// TestMigrateConfig_Idempotent 迁移幂等性
func TestMigrateConfig_Idempotent(t *testing.T) {
	oldCfg := `{"certificates":[{"order_id":1,"domain":"a.com","renew_days":20,"use_local_key":true,"expires_at":"2025-01-01"}],"renew_days":20}`

	data1, changed1, err := migrateConfig([]byte(oldCfg))
	if err != nil {
		t.Fatalf("第一次迁移失败: %v", err)
	}
	if !changed1 {
		t.Fatal("第一次应触发迁移")
	}

	_, changed2, err := migrateConfig(data1)
	if err != nil {
		t.Fatalf("第二次迁移失败: %v", err)
	}
	if changed2 {
		t.Error("第二次迁移不应产生变化（幂等性）")
	}
}

// === Token 作用域迁移测试 ===

// tokenScopeRaw 构造带单个证书 encrypted_token 的 raw 配置
func tokenScopeRaw(encToken string) map[string]interface{} {
	return map[string]interface{}{
		"certificates": []interface{}{
			map[string]interface{}{
				"order_id": float64(1),
				"api":      map[string]interface{}{"encrypted_token": encToken},
			},
		},
	}
}

func tokenScopeValue(raw map[string]interface{}) string {
	api := raw["certificates"].([]interface{})[0].(map[string]interface{})["api"].(map[string]interface{})
	s, _ := api["encrypted_token"].(string)
	return s
}

// TestMigrateTokenScope_MachineScopeUnchanged 机器作用域 Token 不触发迁移
func TestMigrateTokenScope_MachineScopeUnchanged(t *testing.T) {
	raw := tokenScopeRaw(EncryptionPrefixMachine + "abc")
	if migrateTokenScope(raw) {
		t.Error("机器作用域 Token 不应触发迁移")
	}
}

// TestMigrateTokenScope_UndecryptableLegacyUnchanged 无法解密的旧作用域 Token 保留原值
func TestMigrateTokenScope_UndecryptableLegacyUnchanged(t *testing.T) {
	orig := EncryptionPrefix + "bm90LWEtcmVhbC1ibG9i" // base64("not-a-real-blob")，DPAPI 解密必失败
	raw := tokenScopeRaw(orig)
	if migrateTokenScope(raw) {
		t.Error("无法解密的 Token 不应产生变化")
	}
	if got := tokenScopeValue(raw); got != orig {
		t.Errorf("encrypted_token 被意外修改: %q", got)
	}
}

// TestMigrateTokenScope_ReencryptsLegacy 旧作用域可解密 Token 迁移为机器作用域
// 依赖 Windows DPAPI，仅在 Windows 上运行
func TestMigrateTokenScope_ReencryptsLegacy(t *testing.T) {
	const plaintext = "migrate-me-token"
	enc, err := EncryptToken(plaintext)
	if err != nil {
		t.Fatalf("EncryptToken() error = %v", err)
	}
	// 将标签换成旧用户作用域前缀模拟历史数据（底层密文不变，可解密）
	legacy := EncryptionPrefix + strings.TrimPrefix(enc, EncryptionPrefixMachine)
	raw := tokenScopeRaw(legacy)

	if !migrateTokenScope(raw) {
		t.Fatal("旧作用域可解密 Token 应触发迁移")
	}
	got := tokenScopeValue(raw)
	if !strings.HasPrefix(got, EncryptionPrefixMachine) {
		t.Errorf("迁移后应为机器作用域前缀, got %q", got)
	}
	if TokenNeedsMigration(got) {
		t.Error("迁移后不应再需要迁移（幂等）")
	}
	if dec, err := DecryptToken(got); err != nil || dec != plaintext {
		t.Errorf("迁移后解密 = %q, err = %v; want %q", dec, err, plaintext)
	}
}

// === 通用引擎测试 ===

// TestResolvePath 路径解析引擎
func TestResolvePath(t *testing.T) {
	raw := map[string]interface{}{
		"schedule": map[string]interface{}{"renew_before_days": float64(14)},
		"certificates": []interface{}{
			map[string]interface{}{
				"order_id": float64(1),
				"bind_rules": []interface{}{
					map[string]interface{}{"domain": "a.com"},
					map[string]interface{}{"domain": "b.com"},
				},
			},
			map[string]interface{}{
				"order_id": float64(2),
				"bind_rules": []interface{}{
					map[string]interface{}{"domain": "c.com"},
				},
			},
		},
	}

	tests := []struct {
		path      string
		wantCount int
	}{
		{".", 1},
		{"certificates[]", 2},
		{"certificates[].bind_rules[]", 3},
		{"schedule", 1},
		{"nonexistent[]", 0},
		{"certificates[].nonexistent[]", 0},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			nodes := resolvePath(raw, tt.path)
			if len(nodes) != tt.wantCount {
				t.Errorf("resolvePath(%q) 返回 %d 个节点, 期望 %d", tt.path, len(nodes), tt.wantCount)
			}
		})
	}
}

// TestSplitTargetPath 目标路径拆分
func TestSplitTargetPath(t *testing.T) {
	tests := []struct {
		target     string
		wantParent string
		wantField  string
	}{
		{"schedule.renew_before_days", "schedule", "renew_before_days"},
		{"certificates[].api", "certificates[]", "api"},
		{"field", ".", "field"},
		{"a[].b[].c", "a[].b[]", "c"},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			parent, field := splitTargetPath(tt.target)
			if parent != tt.wantParent || field != tt.wantField {
				t.Errorf("splitTargetPath(%q) = (%q, %q), 期望 (%q, %q)",
					tt.target, parent, field, tt.wantParent, tt.wantField)
			}
		})
	}
}

// TestEnsurePath 路径创建
func TestEnsurePath(t *testing.T) {
	t.Run("根路径", func(t *testing.T) {
		node := map[string]interface{}{"key": "val"}
		result := ensurePath(node, ".")
		if result == nil || result["key"] != "val" {
			t.Error("根路径应返回自身")
		}
	})

	t.Run("创建中间对象", func(t *testing.T) {
		node := map[string]interface{}{}
		result := ensurePath(node, "a.b")
		if result == nil {
			t.Fatal("应创建中间对象")
		}
		result["val"] = true
		// 验证路径正确创建
		a, ok := node["a"].(map[string]interface{})
		if !ok {
			t.Fatal("a 应为 map")
		}
		b, ok := a["b"].(map[string]interface{})
		if !ok {
			t.Fatal("a.b 应为 map")
		}
		if b["val"] != true {
			t.Error("值应被正确设置")
		}
	})

	t.Run("已存在的路径", func(t *testing.T) {
		existing := map[string]interface{}{"key": "existing"}
		node := map[string]interface{}{"child": existing}
		result := ensurePath(node, "child")
		if result == nil || result["key"] != "existing" {
			t.Error("已存在的路径应返回原对象")
		}
	})

	t.Run("路径冲突", func(t *testing.T) {
		node := map[string]interface{}{"child": "string-not-map"}
		result := ensurePath(node, "child.sub")
		if result != nil {
			t.Error("路径冲突应返回 nil")
		}
	})
}

// TestApplyRename_Generic 通用 rename 操作
func TestApplyRename_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"old_key": "v1", "keep": true},
			map[string]interface{}{"new_key": "v2"},
			map[string]interface{}{"old_key": "v3", "new_key": "existing"},
		},
	}

	changed := applyRename(raw, "items[]", "old_key", "new_key")
	if !changed {
		t.Fatal("应有变更")
	}

	items := raw["items"].([]interface{})
	if items[0].(map[string]interface{})["new_key"] != "v1" {
		t.Error("第一个元素应重命名")
	}
	if _, has := items[0].(map[string]interface{})["old_key"]; has {
		t.Error("旧键应删除")
	}
	if items[1].(map[string]interface{})["new_key"] != "v2" {
		t.Error("第二个元素不应变化")
	}
	if items[2].(map[string]interface{})["new_key"] != "existing" {
		t.Error("已有 new_key 不应被覆盖")
	}
}

// TestApplyDelete_Generic 通用 delete 操作
func TestApplyDelete_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{"keep": "v1", "remove": "x"},
			map[string]interface{}{"keep": "v2"},
		},
	}

	changed := applyDelete(raw, "items[]", "remove")
	if !changed {
		t.Fatal("应有变更")
	}
	item0 := raw["items"].([]interface{})[0].(map[string]interface{})
	if _, has := item0["remove"]; has {
		t.Error("字段应被删除")
	}
	if item0["keep"] != "v1" {
		t.Error("其他字段应保留")
	}
}

// TestApplyMove_Generic 通用 move 操作
func TestApplyMove_Generic(t *testing.T) {
	t.Run("基本移动", func(t *testing.T) {
		raw := map[string]interface{}{
			"old_field": float64(42),
		}
		changed := applyMove(raw, ".", "old_field", "parent.new_field")
		if !changed {
			t.Fatal("应有变更")
		}
		if _, has := raw["old_field"]; has {
			t.Error("源字段应被删除")
		}
		parent := raw["parent"].(map[string]interface{})
		if parent["new_field"] != float64(42) {
			t.Errorf("目标字段 = %v, 期望 42", parent["new_field"])
		}
	})

	t.Run("目标已存在不覆盖", func(t *testing.T) {
		raw := map[string]interface{}{
			"old_field": float64(10),
			"parent":    map[string]interface{}{"new_field": float64(99)},
		}
		changed := applyMove(raw, ".", "old_field", "parent.new_field")
		if !changed {
			t.Fatal("应有变更（源字段被删除）")
		}
		parent := raw["parent"].(map[string]interface{})
		if parent["new_field"] != float64(99) {
			t.Error("已有值不应被覆盖")
		}
	})

	t.Run("源字段不存在", func(t *testing.T) {
		raw := map[string]interface{}{"other": "val"}
		changed := applyMove(raw, ".", "nonexistent", "parent.field")
		if changed {
			t.Error("源字段不存在时不应有变更")
		}
	})

	t.Run("深层嵌套路径", func(t *testing.T) {
		raw := map[string]interface{}{
			"flat_val": "hello",
		}
		changed := applyMove(raw, ".", "flat_val", "a.b.c")
		if !changed {
			t.Fatal("应有变更")
		}
		a := raw["a"].(map[string]interface{})
		b := a["b"].(map[string]interface{})
		if b["c"] != "hello" {
			t.Error("深层路径应正确创建")
		}
	})
}

// TestApplySpread_Generic 通用 spread 操作
func TestApplySpread_Generic(t *testing.T) {
	raw := map[string]interface{}{
		"defaults": map[string]interface{}{"a": "1", "b": "2"},
		"items": []interface{}{
			map[string]interface{}{"name": "x"},
			map[string]interface{}{"name": "y", "cfg": map[string]interface{}{"a": "override"}},
			map[string]interface{}{"name": "z", "cfg": map[string]interface{}{"a": "1", "b": "2"}},
		},
	}

	changed := applySpread(raw, "defaults", "items[].cfg")
	if !changed {
		t.Fatal("应有变更")
	}
	if _, has := raw["defaults"]; has {
		t.Error("源字段应被删除")
	}

	items := raw["items"].([]interface{})
	cfg0 := items[0].(map[string]interface{})["cfg"].(map[string]interface{})
	if cfg0["a"] != "1" || cfg0["b"] != "2" {
		t.Errorf("x 应完整继承, got a=%v b=%v", cfg0["a"], cfg0["b"])
	}
	cfg1 := items[1].(map[string]interface{})["cfg"].(map[string]interface{})
	if cfg1["a"] != "override" {
		t.Errorf("y.a 应保留 override, got %v", cfg1["a"])
	}
	if cfg1["b"] != "2" {
		t.Errorf("y.b 应补全为 2, got %v", cfg1["b"])
	}
}

// TestApplySpread_EmptySource 空源字段直接删除
func TestApplySpread_EmptySource(t *testing.T) {
	raw := map[string]interface{}{
		"defaults": map[string]interface{}{},
		"items":    []interface{}{map[string]interface{}{"name": "x"}},
	}

	changed := applySpread(raw, "defaults", "items[].cfg")
	if !changed {
		t.Fatal("空源字段应被清理")
	}
	if _, has := raw["defaults"]; has {
		t.Error("空源字段应被删除")
	}
}

// === 默认值填充测试 ===

// TestApplyDefaults_FillMissing 补齐缺失字段
func TestApplyDefaults_FillMissing(t *testing.T) {
	raw := map[string]interface{}{
		"existing": "keep",
	}
	defaults := map[string]interface{}{
		"existing": "default",
		"missing":  "filled",
	}

	changed := applyDefaults(raw, defaults)
	if !changed {
		t.Fatal("应有变更")
	}
	if raw["existing"] != "keep" {
		t.Error("已有字段不应被覆盖")
	}
	if raw["missing"] != "filled" {
		t.Errorf("缺失字段应填充, got %v", raw["missing"])
	}
}

// TestApplyDefaults_RecursiveMap 嵌套 map 递归补齐
func TestApplyDefaults_RecursiveMap(t *testing.T) {
	raw := map[string]interface{}{
		"schedule": map[string]interface{}{
			"renew_before_days": float64(20),
		},
	}
	defaults := map[string]interface{}{
		"schedule": map[string]interface{}{
			"renew_mode":        "pull",
			"renew_before_days": float64(14),
		},
	}

	changed := applyDefaults(raw, defaults)
	if !changed {
		t.Fatal("应有变更（schedule 缺少 renew_mode）")
	}

	schedule := raw["schedule"].(map[string]interface{})
	if schedule["renew_mode"] != "pull" {
		t.Errorf("renew_mode = %v, 期望 pull", schedule["renew_mode"])
	}
	if schedule["renew_before_days"] != float64(20) {
		t.Error("已有值不应被覆盖")
	}
}

// TestApplyDefaults_CreateNestedObject 缺失的嵌套对象整体创建
func TestApplyDefaults_CreateNestedObject(t *testing.T) {
	raw := map[string]interface{}{}
	defaults := map[string]interface{}{
		"schedule": map[string]interface{}{
			"renew_mode":        "pull",
			"renew_before_days": float64(14),
		},
	}

	changed := applyDefaults(raw, defaults)
	if !changed {
		t.Fatal("应有变更")
	}

	schedule, ok := raw["schedule"].(map[string]interface{})
	if !ok {
		t.Fatal("应创建 schedule 对象")
	}
	if schedule["renew_mode"] != "pull" {
		t.Error("嵌套字段应填充")
	}
}

// TestApplyDefaults_NoChange 全部字段已存在时无变更
func TestApplyDefaults_NoChange(t *testing.T) {
	raw := map[string]interface{}{
		"a": "1",
		"b": map[string]interface{}{"c": "2"},
	}
	defaults := map[string]interface{}{
		"a": "default",
		"b": map[string]interface{}{"c": "default"},
	}

	changed := applyDefaults(raw, defaults)
	if changed {
		t.Error("全部字段已存在时不应有变更")
	}
}

// TestApplyDefaults_DeepCopyIsolation 填充的默认值与源隔离
func TestApplyDefaults_DeepCopyIsolation(t *testing.T) {
	defaults := map[string]interface{}{
		"nested": map[string]interface{}{"key": "val"},
	}
	raw := map[string]interface{}{}

	applyDefaults(raw, defaults)

	// 修改 raw 中的值不应影响 defaults
	raw["nested"].(map[string]interface{})["key"] = "modified"
	if defaults["nested"].(map[string]interface{})["key"] != "val" {
		t.Error("deepCopy 隔离失败")
	}
}

// TestDefaultConfigRaw 验证 DefaultConfig 序列化为 raw map
func TestDefaultConfigRaw(t *testing.T) {
	raw := defaultConfigRaw()

	// 关键默认值检查
	schedule, ok := raw["schedule"].(map[string]interface{})
	if !ok {
		t.Fatal("应包含 schedule 对象")
	}
	if schedule["renew_before_days"] != float64(14) {
		t.Errorf("renew_before_days = %v, 期望 14", schedule["renew_before_days"])
	}
	if schedule["renew_mode"] != "pull" {
		t.Errorf("renew_mode = %v, 期望 pull", schedule["renew_mode"])
	}
	if raw["task_name"] != "SSLCtlW" {
		t.Errorf("task_name = %v, 期望 SSLCtlW", raw["task_name"])
	}
	if raw["upgrade_interval"] != float64(24) {
		t.Errorf("upgrade_interval = %v, 期望 24", raw["upgrade_interval"])
	}
}

// === 旧文件合并测试 ===

// TestMergeInto_Basic 基本合并
func TestMergeInto_Basic(t *testing.T) {
	raw := map[string]interface{}{
		"existing": "keep",
	}
	source := map[string]interface{}{
		"existing": "ignore",
		"new_key":  "merged",
	}

	changed := mergeInto(raw, ".", source)
	if !changed {
		t.Fatal("应有变更")
	}
	if raw["existing"] != "keep" {
		t.Error("已有字段不应被覆盖")
	}
	if raw["new_key"] != "merged" {
		t.Error("新字段应合并")
	}
}

// TestMergeInto_NestedTarget 合并到子路径
func TestMergeInto_NestedTarget(t *testing.T) {
	raw := map[string]interface{}{}
	source := map[string]interface{}{"key": "val"}

	changed := mergeInto(raw, "parent", source)
	if !changed {
		t.Fatal("应有变更")
	}

	parent, ok := raw["parent"].(map[string]interface{})
	if !ok {
		t.Fatal("应创建 parent 对象")
	}
	if parent["key"] != "val" {
		t.Error("字段应合并到 parent")
	}
}

// TestMergeInto_NoChange 无新字段时无变更
func TestMergeInto_NoChange(t *testing.T) {
	raw := map[string]interface{}{"a": "1"}
	source := map[string]interface{}{"a": "2"}

	changed := mergeInto(raw, ".", source)
	if changed {
		t.Error("无新字段时不应有变更")
	}
}
