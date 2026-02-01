package deploy

import (
	"testing"
	"time"

	"cert-deploy/config"
)

func TestCheckDomainConflicts(t *testing.T) {
	tests := []struct {
		name       string
		certs      []config.CertConfig
		wantCount  int
		wantDomain string
	}{
		{
			"无冲突-单个证书",
			[]config.CertConfig{
				{OrderID: 1, Domain: "a.com", Enabled: true, BindRules: []config.BindRule{{Domain: "a.com"}}},
			},
			0,
			"",
		},
		{
			"无冲突-不同域名",
			[]config.CertConfig{
				{OrderID: 1, Domain: "a.com", Enabled: true, BindRules: []config.BindRule{{Domain: "a.com"}}},
				{OrderID: 2, Domain: "b.com", Enabled: true, BindRules: []config.BindRule{{Domain: "b.com"}}},
			},
			0,
			"",
		},
		{
			"有冲突-相同域名",
			[]config.CertConfig{
				{OrderID: 1, Domain: "a.com", Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
				{OrderID: 2, Domain: "b.com", Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
			},
			1,
			"shared.com",
		},
		{
			"禁用的证书不计入冲突",
			[]config.CertConfig{
				{OrderID: 1, Domain: "a.com", Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
				{OrderID: 2, Domain: "b.com", Enabled: false, BindRules: []config.BindRule{{Domain: "shared.com"}}},
			},
			0,
			"",
		},
		{
			"多个冲突域名",
			[]config.CertConfig{
				{OrderID: 1, Enabled: true, BindRules: []config.BindRule{{Domain: "a.com"}, {Domain: "b.com"}}},
				{OrderID: 2, Enabled: true, BindRules: []config.BindRule{{Domain: "a.com"}, {Domain: "b.com"}}},
			},
			2,
			"", // 有多个冲突
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDomainConflicts(tt.certs)

			if len(got) != tt.wantCount {
				t.Errorf("checkDomainConflicts() 返回 %d 个冲突，期望 %d 个", len(got), tt.wantCount)
			}

			if tt.wantDomain != "" {
				if _, ok := got[tt.wantDomain]; !ok {
					t.Errorf("期望域名 %q 存在冲突，但未找到", tt.wantDomain)
				}
			}
		})
	}
}

func TestSelectBestCertForDomainByIndexes(t *testing.T) {
	// 设置测试证书
	allCerts := []config.CertConfig{
		{OrderID: 100, Domain: "a.com", ExpiresAt: "2024-01-01", Enabled: true},
		{OrderID: 200, Domain: "b.com", ExpiresAt: "2024-06-01", Enabled: true},
		{OrderID: 300, Domain: "c.com", ExpiresAt: "2024-03-01", Enabled: true},
		{OrderID: 400, Domain: "d.com", ExpiresAt: "2024-06-01", Enabled: false}, // 禁用
	}

	tests := []struct {
		name        string
		indexes     []int
		wantOrderID int
	}{
		{
			"选择过期最晚的",
			[]int{0, 1, 2},
			200, // 2024-06-01 最晚
		},
		{
			"相同过期时间选 OrderID 大的",
			[]int{1, 3}, // 200 和 400 都是 2024-06-01
			200,         // 400 被禁用，只能选 200
		},
		{
			"单个索引",
			[]int{0},
			100,
		},
		{
			"空索引列表",
			[]int{},
			0, // nil
		},
		{
			"跳过禁用的证书",
			[]int{0, 3},
			100, // 400 被禁用
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectBestCertForDomainByIndexes(tt.indexes, allCerts)

			if tt.wantOrderID == 0 {
				if got != nil {
					t.Errorf("期望返回 nil，但得到 OrderID=%d", got.OrderID)
				}
			} else {
				if got == nil {
					t.Errorf("期望返回 OrderID=%d，但得到 nil", tt.wantOrderID)
				} else if got.OrderID != tt.wantOrderID {
					t.Errorf("期望 OrderID=%d，得到 OrderID=%d", tt.wantOrderID, got.OrderID)
				}
			}
		})
	}
}

func TestParseCertExpiry(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantTime  string
		wantValid bool
	}{
		{"有效日期", "2024-06-15", "2024-06-15", true},
		{"空字符串", "", "", false},
		{"无效格式", "2024/06/15", "", false},
		{"无效日期", "2024-13-01", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTime, gotValid := parseCertExpiry(tt.value)

			if gotValid != tt.wantValid {
				t.Errorf("parseCertExpiry(%q) valid = %v, want %v", tt.value, gotValid, tt.wantValid)
			}

			if tt.wantValid {
				wantTime, _ := time.Parse("2006-01-02", tt.wantTime)
				if !gotTime.Equal(wantTime) {
					t.Errorf("parseCertExpiry(%q) time = %v, want %v", tt.value, gotTime, wantTime)
				}
			}
		})
	}
}

func TestIsIPBinding(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         bool
	}{
		{"IP 绑定", "0.0.0.0:443", true},
		{"IP 绑定-指定", "192.168.1.1:443", true},
		{"域名绑定", "www.example.com:443", false},
		{"通配符绑定", "*.example.com:443", false},
		{"IPv6 类似", "[::1]:443", false}, // 包含冒号，不是纯数字
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("isIPBinding(%q) = %v, want %v", tt.hostnamePort, got, tt.want)
			}
		})
	}
}

func TestBindRule_Fields(t *testing.T) {
	rule := config.BindRule{
		Domain:   "www.example.com",
		SiteName: "Default Web Site",
		Port:     443,
	}

	if rule.Domain != "www.example.com" {
		t.Errorf("BindRule.Domain = %q", rule.Domain)
	}
	if rule.SiteName != "Default Web Site" {
		t.Errorf("BindRule.SiteName = %q", rule.SiteName)
	}
	if rule.Port != 443 {
		t.Errorf("BindRule.Port = %d", rule.Port)
	}
}

func TestCertConfig_Fields(t *testing.T) {
	certConfig := config.CertConfig{
		OrderID:      123,
		Domain:       "example.com",
		Domains:      []string{"example.com", "www.example.com"},
		ExpiresAt:    "2025-12-31",
		SerialNumber: "ABC123",
		Enabled:      true,
		BindRules: []config.BindRule{
			{Domain: "www.example.com", Port: 443},
		},
		UseLocalKey:      true,
		ValidationMethod: "file",
	}

	if certConfig.OrderID != 123 {
		t.Errorf("CertConfig.OrderID = %d", certConfig.OrderID)
	}
	if certConfig.Domain != "example.com" {
		t.Errorf("CertConfig.Domain = %q", certConfig.Domain)
	}
	if !certConfig.Enabled {
		t.Error("CertConfig.Enabled 应该为 true")
	}
	if len(certConfig.BindRules) != 1 {
		t.Errorf("CertConfig.BindRules 长度 = %d", len(certConfig.BindRules))
	}
	if !certConfig.UseLocalKey {
		t.Error("CertConfig.UseLocalKey 应该为 true")
	}
	if certConfig.ValidationMethod != "file" {
		t.Errorf("CertConfig.ValidationMethod = %q", certConfig.ValidationMethod)
	}
	if len(certConfig.Domains) != 2 {
		t.Errorf("CertConfig.Domains 长度 = %d", len(certConfig.Domains))
	}
}

func TestCheckDomainConflicts_EmptyList(t *testing.T) {
	conflicts := checkDomainConflicts([]config.CertConfig{})
	if len(conflicts) != 0 {
		t.Errorf("空列表应该返回 0 个冲突，实际得到 %d 个", len(conflicts))
	}
}

func TestCheckDomainConflicts_AllDisabled(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 1, Enabled: false, BindRules: []config.BindRule{{Domain: "a.com"}}},
		{OrderID: 2, Enabled: false, BindRules: []config.BindRule{{Domain: "a.com"}}},
	}
	conflicts := checkDomainConflicts(certs)
	if len(conflicts) != 0 {
		t.Errorf("全部禁用应该返回 0 个冲突，实际得到 %d 个", len(conflicts))
	}
}

func TestSelectBestCertForDomainByIndexes_AllDisabled(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 1, Enabled: false, ExpiresAt: "2025-01-01"},
		{OrderID: 2, Enabled: false, ExpiresAt: "2025-06-01"},
	}
	result := selectBestCertForDomainByIndexes([]int{0, 1}, certs)
	if result != nil {
		t.Error("全部禁用应该返回 nil")
	}
}

func TestParseCertExpiry_EdgeCases(t *testing.T) {
	// 边界日期
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"闰年", "2024-02-29", true},
		{"非闰年2月29", "2023-02-29", false},
		{"月末", "2024-12-31", true},
		{"最小日期", "2020-01-01", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid := parseCertExpiry(tt.value)
			if valid != tt.valid {
				t.Errorf("parseCertExpiry(%q) valid = %v, want %v", tt.value, valid, tt.valid)
			}
		})
	}
}

// TestSelectBestCertForDomainByIndexes_InvalidIndexes 测试索引越界
func TestSelectBestCertForDomainByIndexes_InvalidIndexes(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 100, Domain: "a.com", ExpiresAt: "2024-06-01", Enabled: true},
	}

	tests := []struct {
		name        string
		indexes     []int
		wantOrderID int
	}{
		{"负数索引", []int{-1}, 0},
		{"过大索引", []int{100}, 0},
		{"混合索引-有效无效", []int{-1, 0, 100}, 100},
		{"全部无效索引", []int{-1, -2, 100}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectBestCertForDomainByIndexes(tt.indexes, certs)
			if tt.wantOrderID == 0 {
				if got != nil {
					t.Errorf("期望返回 nil，但得到 OrderID=%d", got.OrderID)
				}
			} else {
				if got == nil {
					t.Errorf("期望返回 OrderID=%d，但得到 nil", tt.wantOrderID)
				} else if got.OrderID != tt.wantOrderID {
					t.Errorf("期望 OrderID=%d，得到 OrderID=%d", tt.wantOrderID, got.OrderID)
				}
			}
		})
	}
}

// TestSelectBestCertForDomainByIndexes_NoExpiry 测试没有过期时间的情况
func TestSelectBestCertForDomainByIndexes_NoExpiry(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 100, Domain: "a.com", ExpiresAt: "", Enabled: true},
		{OrderID: 200, Domain: "b.com", ExpiresAt: "", Enabled: true},
	}

	// 当两个都没有过期时间时，选择 OrderID 大的
	got := selectBestCertForDomainByIndexes([]int{0, 1}, certs)
	if got == nil {
		t.Error("期望返回非 nil")
	} else if got.OrderID != 200 {
		t.Errorf("期望 OrderID=200，得到 OrderID=%d", got.OrderID)
	}
}

// TestSelectBestCertForDomainByIndexes_MixedExpiry 测试混合过期时间
func TestSelectBestCertForDomainByIndexes_MixedExpiry(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 100, Domain: "a.com", ExpiresAt: "", Enabled: true},
		{OrderID: 200, Domain: "b.com", ExpiresAt: "2024-06-01", Enabled: true},
	}

	// 有过期时间的优先于没有过期时间的
	got := selectBestCertForDomainByIndexes([]int{0, 1}, certs)
	if got == nil {
		t.Error("期望返回非 nil")
	} else if got.OrderID != 200 {
		t.Errorf("期望 OrderID=200（有过期时间），得到 OrderID=%d", got.OrderID)
	}
}

// TestSelectBestCertForDomainByIndexes_SameExpiryDifferentOrderID 相同过期时间选 OrderID 大的
func TestSelectBestCertForDomainByIndexes_SameExpiryDifferentOrderID(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 100, Domain: "a.com", ExpiresAt: "2024-06-01", Enabled: true},
		{OrderID: 300, Domain: "b.com", ExpiresAt: "2024-06-01", Enabled: true},
		{OrderID: 200, Domain: "c.com", ExpiresAt: "2024-06-01", Enabled: true},
	}

	got := selectBestCertForDomainByIndexes([]int{0, 1, 2}, certs)
	if got == nil {
		t.Error("期望返回非 nil")
	} else if got.OrderID != 300 {
		t.Errorf("期望 OrderID=300（相同过期时间选 OrderID 大的），得到 OrderID=%d", got.OrderID)
	}
}

// TestCheckDomainConflicts_MultipleRulesPerCert 测试单个证书多条绑定规则
func TestCheckDomainConflicts_MultipleRulesPerCert(t *testing.T) {
	certs := []config.CertConfig{
		{
			OrderID: 1,
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "a.com"},
				{Domain: "b.com"},
				{Domain: "c.com"},
			},
		},
		{
			OrderID: 2,
			Enabled: true,
			BindRules: []config.BindRule{
				{Domain: "b.com"}, // 与证书1冲突
				{Domain: "d.com"},
			},
		},
	}

	conflicts := checkDomainConflicts(certs)
	if len(conflicts) != 1 {
		t.Errorf("期望 1 个冲突，得到 %d 个", len(conflicts))
	}
	if _, ok := conflicts["b.com"]; !ok {
		t.Error("期望 b.com 存在冲突")
	}
}

// TestCheckDomainConflicts_ThreeWayConflict 三方冲突
func TestCheckDomainConflicts_ThreeWayConflict(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 1, Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
		{OrderID: 2, Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
		{OrderID: 3, Enabled: true, BindRules: []config.BindRule{{Domain: "shared.com"}}},
	}

	conflicts := checkDomainConflicts(certs)
	if len(conflicts) != 1 {
		t.Errorf("期望 1 个冲突，得到 %d 个", len(conflicts))
	}
	if indexes, ok := conflicts["shared.com"]; ok {
		if len(indexes) != 3 {
			t.Errorf("期望 shared.com 有 3 个冲突索引，得到 %d 个", len(indexes))
		}
	} else {
		t.Error("期望 shared.com 存在冲突")
	}
}

// TestResult_Fields 测试 Result 结构体字段
func TestResult_Fields(t *testing.T) {
	result := Result{
		Domain:     "example.com",
		Success:    true,
		Message:    "部署成功",
		Thumbprint: "ABC123DEF456",
		OrderID:    12345,
	}

	if result.Domain != "example.com" {
		t.Errorf("Result.Domain = %q", result.Domain)
	}
	if !result.Success {
		t.Error("Result.Success 应该为 true")
	}
	if result.Message != "部署成功" {
		t.Errorf("Result.Message = %q", result.Message)
	}
	if result.Thumbprint != "ABC123DEF456" {
		t.Errorf("Result.Thumbprint = %q", result.Thumbprint)
	}
	if result.OrderID != 12345 {
		t.Errorf("Result.OrderID = %d", result.OrderID)
	}
}

// TestIsIPBinding_MoreCases 更多 IP 绑定测试用例
func TestIsIPBinding_MoreCases(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         bool
	}{
		{"空字符串", "", true}, // 空主机名被视为 IP
		{"只有端口", ":443", false}, // 冒号前为空，不是纯数字
		{"本地回环", "127.0.0.1:443", true},
		{"内网IP", "10.0.0.1:8443", true},
		{"带字母的IP格式", "192.168.1.a:443", false},
		{"域名带数字", "server1.example.com:443", false},
		{"纯数字域名", "123456.com:443", false}, // 包含 .com 不是纯数字
		{"多级子域名", "a.b.c.example.com:443", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isIPBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("isIPBinding(%q) = %v, want %v", tt.hostnamePort, got, tt.want)
			}
		})
	}
}

// TestParseCertExpiry_VariousFormats 测试各种日期格式
func TestParseCertExpiry_VariousFormats(t *testing.T) {
	tests := []struct {
		name  string
		value string
		valid bool
	}{
		{"标准格式", "2024-06-15", true},
		{"带时间", "2024-06-15 12:00:00", false}, // 只支持日期格式
		{"ISO 格式", "2024-06-15T12:00:00Z", false},
		{"美式格式", "06/15/2024", false},
		{"中式格式", "2024年06月15日", false},
		{"只有年月", "2024-06", false},
		{"带前导零", "2024-01-01", true},
		{"无前导零月份", "2024-6-15", false}, // 必须有前导零
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, valid := parseCertExpiry(tt.value)
			if valid != tt.valid {
				t.Errorf("parseCertExpiry(%q) valid = %v, want %v", tt.value, valid, tt.valid)
			}
		})
	}
}

// TestCheckDomainConflicts_EmptyBindRules 空绑定规则
func TestCheckDomainConflicts_EmptyBindRules(t *testing.T) {
	certs := []config.CertConfig{
		{OrderID: 1, Enabled: true, BindRules: []config.BindRule{}},
		{OrderID: 2, Enabled: true, BindRules: nil},
	}

	conflicts := checkDomainConflicts(certs)
	if len(conflicts) != 0 {
		t.Errorf("空绑定规则应该返回 0 个冲突，得到 %d 个", len(conflicts))
	}
}
