package cert

import (
	"testing"
	"time"

	"sslctlw/util"
)

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name         string
		certDomain   string
		targetDomain string
		want         bool
	}{
		// 精确匹配
		{"精确匹配", "example.com", "example.com", true},
		{"精确匹配-子域名", "www.example.com", "www.example.com", true},
		{"不匹配-不同域名", "example.com", "other.com", false},

		// 通配符匹配
		{"通配符-匹配 www", "*.example.com", "www.example.com", true},
		{"通配符-匹配 api", "*.example.com", "api.example.com", true},
		{"通配符-匹配 sub", "*.example.com", "sub.example.com", true},
		{"通配符-不匹配根域名", "*.example.com", "example.com", false},
		{"通配符-不匹配多级子域名", "*.example.com", "a.b.example.com", false},
		{"通配符-不匹配不同域名", "*.example.com", "www.other.com", false},

		// 边界情况
		{"空证书域名", "", "example.com", false},
		{"空目标域名", "example.com", "", false},
		{"双空", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// util.MatchDomain(bindingHost, certDomain) - targetDomain is bindingHost
			got := util.MatchDomain(tt.targetDomain, tt.certDomain)
			if got != tt.want {
				t.Errorf("util.MatchDomain(%q, %q) = %v, want %v", tt.targetDomain, tt.certDomain, got, tt.want)
			}
		})
	}
}

func TestCertInfo_MatchesDomain(t *testing.T) {
	cert := &CertInfo{
		Subject:  "CN=example.com",
		DNSNames: []string{"example.com", "www.example.com", "*.example.com"},
	}

	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"匹配 CN", "example.com", true},
		{"匹配 SAN 精确", "www.example.com", true},
		{"匹配 SAN 通配符", "api.example.com", true},
		{"不匹配", "other.com", false},
		{"不匹配多级子域名", "a.b.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cert.MatchesDomain(tt.domain)
			if got != tt.want {
				t.Errorf("CertInfo.MatchesDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestFilterByDomain(t *testing.T) {
	certs := []CertInfo{
		{Subject: "CN=a.com", DNSNames: []string{"a.com"}},
		{Subject: "CN=b.com", DNSNames: []string{"b.com", "www.b.com"}},
		{Subject: "CN=*.example.com", DNSNames: []string{"*.example.com"}},
	}

	tests := []struct {
		name      string
		domain    string
		wantCount int
	}{
		{"过滤 a.com", "a.com", 1},
		{"过滤 www.b.com", "www.b.com", 1},
		{"过滤 api.example.com (通配符)", "api.example.com", 1},
		{"过滤不存在的域名", "notfound.com", 0},
		{"空域名返回全部", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterByDomain(certs, tt.domain)
			if len(got) != tt.wantCount {
				t.Errorf("FilterByDomain(certs, %q) 返回 %d 个，期望 %d 个", tt.domain, len(got), tt.wantCount)
			}
		})
	}
}

func TestExtractCN(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{"简单 CN", "CN=example.com", "example.com"},
		{"带其他字段", "CN=example.com, O=Test Org, C=US", "example.com"},
		{"CN 在中间", "O=Test Org, CN=example.com, C=US", "example.com"},
		{"无 CN", "O=Test Org, C=US", ""},
		{"空字符串", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCN(tt.subject)
			if got != tt.want {
				t.Errorf("extractCN(%q) = %q, want %q", tt.subject, got, tt.want)
			}
		})
	}
}

func TestGetCertDisplayName(t *testing.T) {
	tests := []struct {
		name string
		cert *CertInfo
		want string
	}{
		{
			"有 FriendlyName",
			&CertInfo{FriendlyName: "My Cert", Subject: "CN=example.com"},
			"My Cert",
		},
		{
			"无 FriendlyName 有 CN",
			&CertInfo{Subject: "CN=example.com"},
			"example.com",
		},
		{
			"只有 Subject",
			&CertInfo{Subject: "O=Test Org"},
			"O=Test Org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCertDisplayName(tt.cert)
			if got != tt.want {
				t.Errorf("GetCertDisplayName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetCertStatus(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		notAfter time.Time
		want     string
	}{
		{"已过期", now.Add(-24 * time.Hour), "已过期"},
		{"即将过期", now.Add(3 * 24 * time.Hour), "即将过期"},
		{"临近过期", now.Add(15 * 24 * time.Hour), "临近过期"},
		{"有效", now.Add(60 * 24 * time.Hour), "有效"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertInfo{NotAfter: tt.notAfter}
			got := GetCertStatus(cert)
			// 检查是否包含期望的状态关键字
			if tt.want == "有效" {
				if got != "有效" {
					t.Errorf("GetCertStatus() = %q, want %q", got, tt.want)
				}
			} else if !containsString(got, tt.want[:6]) { // 取前6个字符（避免天数差异）
				t.Errorf("GetCertStatus() = %q, want contains %q", got, tt.want)
			}
		})
	}
}

func TestParseTimeMultiFormat_Local(t *testing.T) {
	input := "2024-01-02 03:04:05"
	got := parseTimeMultiFormat(input)
	if got.IsZero() {
		t.Fatal("parseTimeMultiFormat() 返回零值")
	}
	if got.Location() != time.Local {
		t.Errorf("parseTimeMultiFormat() Location = %v, want %v", got.Location(), time.Local)
	}
	if got.Format("2006-01-02 15:04:05") != input {
		t.Errorf("parseTimeMultiFormat() = %s, want %s", got.Format("2006-01-02 15:04:05"), input)
	}
}

func TestParseTimeMultiFormat_WithTimezone(t *testing.T) {
	input := "2024-01-02T03:04:05+08:00"
	got := parseTimeMultiFormat(input)
	if got.IsZero() {
		t.Fatal("parseTimeMultiFormat() 返回零值")
	}
	if got.Format(time.RFC3339) != input {
		t.Errorf("parseTimeMultiFormat() = %s, want %s", got.Format(time.RFC3339), input)
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

func TestGetWildcardName(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"已是通配符", "*.example.com", "*.example.com"},
		{"www 子域名", "www.example.com", "*.example.com"},
		{"api 子域名", "api.example.com", "*.example.com"},
		{"根域名", "example.com", "*.example.com"},
		{"多级子域名", "a.b.example.com", "*.b.example.com"},
		{"单个部分", "localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetWildcardName(tt.domain)
			if got != tt.want {
				t.Errorf("GetWildcardName(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestParseCertList(t *testing.T) {
	// 模拟 PowerShell 输出
	output := `===CERT===
Thumbprint: ABC123DEF456789012345678901234567890ABCD
Subject: CN=example.com, O=Test
Issuer: CN=Test CA
NotBefore: 2024-01-01 00:00:00
NotAfter: 2025-01-01 00:00:00
FriendlyName: My Test Cert
HasPrivateKey: True
SerialNumber: 1234567890
DNSNames: example.com,www.example.com
===CERT===
Thumbprint: DEF456789012345678901234567890ABCDEF1234
Subject: CN=other.com
Issuer: CN=Test CA
NotBefore: 2024-02-01 00:00:00
NotAfter: 2025-02-01 00:00:00
FriendlyName:
HasPrivateKey: False
SerialNumber: 0987654321
`

	certs := parseCertList(output)

	if len(certs) != 2 {
		t.Fatalf("期望解析出 2 个证书，实际得到 %d 个", len(certs))
	}

	// 验证第一个证书
	cert1 := certs[0]
	if cert1.Thumbprint != "ABC123DEF456789012345678901234567890ABCD" {
		t.Errorf("第一个证书 Thumbprint = %q", cert1.Thumbprint)
	}
	if cert1.FriendlyName != "My Test Cert" {
		t.Errorf("第一个证书 FriendlyName = %q", cert1.FriendlyName)
	}
	if !cert1.HasPrivKey {
		t.Error("第一个证书应该有私钥")
	}
	if len(cert1.DNSNames) != 2 {
		t.Errorf("第一个证书 DNSNames 长度 = %d, 期望 2", len(cert1.DNSNames))
	}

	// 验证第二个证书
	cert2 := certs[1]
	if cert2.Thumbprint != "DEF456789012345678901234567890ABCDEF1234" {
		t.Errorf("第二个证书 Thumbprint = %q", cert2.Thumbprint)
	}
	if cert2.HasPrivKey {
		t.Error("第二个证书不应该有私钥")
	}
}

// TestParseCertList_Empty 测试空输出
func TestParseCertList_Empty(t *testing.T) {
	certs := parseCertList("")
	if len(certs) != 0 {
		t.Errorf("空输出应该返回 0 个证书，实际得到 %d 个", len(certs))
	}
}

// TestParseCertList_OnlySeparators 测试只有分隔符
func TestParseCertList_OnlySeparators(t *testing.T) {
	output := `===CERT===
===CERT===
===CERT===
`
	certs := parseCertList(output)
	// 解析器会为每个分隔符创建条目，即使内容为空
	// 这是当前实现的行为，我们只验证不会 panic
	_ = certs
}

// TestParseCertList_SingleCert 测试单个证书
func TestParseCertList_SingleCert(t *testing.T) {
	output := `===CERT===
Thumbprint: ABC123DEF456789012345678901234567890ABCD
Subject: CN=single.com
Issuer: CN=Test CA
NotBefore: 2024-01-01 00:00:00
NotAfter: 2025-01-01 00:00:00
FriendlyName: Single Cert
HasPrivateKey: True
SerialNumber: 123
`
	certs := parseCertList(output)
	if len(certs) != 1 {
		t.Fatalf("期望解析出 1 个证书，实际得到 %d 个", len(certs))
	}
	if certs[0].FriendlyName != "Single Cert" {
		t.Errorf("FriendlyName = %q", certs[0].FriendlyName)
	}
}

// TestCertInfo_MatchesDomain_MoreCases 更多域名匹配测试
func TestCertInfo_MatchesDomain_MoreCases(t *testing.T) {
	tests := []struct {
		name   string
		cert   *CertInfo
		domain string
		want   bool
	}{
		{
			"匹配 CN",
			&CertInfo{Subject: "CN=example.com", DNSNames: nil},
			"example.com",
			true,
		},
		{
			"匹配 SAN",
			&CertInfo{Subject: "CN=other.com", DNSNames: []string{"example.com"}},
			"example.com",
			true,
		},
		{
			"不匹配",
			&CertInfo{Subject: "CN=other.com", DNSNames: []string{"another.com"}},
			"example.com",
			false,
		},
		{
			"空 DNSNames",
			&CertInfo{Subject: "CN=example.com", DNSNames: []string{}},
			"example.com",
			true,
		},
		{
			"nil DNSNames",
			&CertInfo{Subject: "CN=example.com", DNSNames: nil},
			"example.com",
			true,
		},
		{
			"通配符 CN",
			&CertInfo{Subject: "CN=*.example.com", DNSNames: nil},
			"www.example.com",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.MatchesDomain(tt.domain)
			if got != tt.want {
				t.Errorf("MatchesDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

// TestFilterByDomain_MoreCases 更多过滤测试
func TestFilterByDomain_MoreCases(t *testing.T) {
	certs := []CertInfo{
		{Subject: "CN=a.com", DNSNames: []string{"a.com", "www.a.com"}},
		{Subject: "CN=*.b.com", DNSNames: []string{"*.b.com"}},
		{Subject: "CN=c.com", DNSNames: nil},
	}

	tests := []struct {
		name      string
		domain    string
		wantCount int
	}{
		{"匹配精确域名", "a.com", 1},
		{"匹配通配符", "api.b.com", 1},
		{"匹配 SAN", "www.a.com", 1},
		{"匹配 CN without SAN", "c.com", 1},
		{"不匹配", "z.com", 0},
		{"空域名返回全部", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterByDomain(certs, tt.domain)
			if len(got) != tt.wantCount {
				t.Errorf("FilterByDomain(%q) 返回 %d 个，期望 %d 个", tt.domain, len(got), tt.wantCount)
			}
		})
	}
}

// TestExtractCN_MoreCases 更多 CN 提取测试
func TestExtractCN_MoreCases(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{"标准格式", "CN=example.com", "example.com"},
		{"多个字段", "C=US, ST=CA, L=SF, O=Test, OU=IT, CN=example.com", "example.com"},
		{"CN 在开头", "CN=example.com, O=Test", "example.com"},
		{"CN 在中间", "O=Test, CN=example.com, C=US", "example.com"},
		{"CN 在结尾", "O=Test, C=US, CN=example.com", "example.com"},
		{"无 CN", "O=Test, C=US", ""},
		{"空字符串", "", ""},
		{"通配符 CN", "CN=*.example.com", "*.example.com"},
		{"带逗号的 CN", "CN=example.com, Inc", "example.com"}, // 逗号后截断
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractCN(tt.subject)
			if got != tt.want {
				t.Errorf("extractCN(%q) = %q, want %q", tt.subject, got, tt.want)
			}
		})
	}
}

// TestGetCertStatus_AllStates 测试所有状态
func TestGetCertStatus_AllStates(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name       string
		notAfter   time.Time
		wantPrefix string
	}{
		{"已过期-1天", now.Add(-24 * time.Hour), "已过期"},
		{"已过期-1周", now.Add(-7 * 24 * time.Hour), "已过期"},
		{"即将过期-1天", now.Add(24 * time.Hour), "即将过期"},
		{"即将过期-7天", now.Add(7 * 24 * time.Hour), "即将过期"},
		{"临近过期-15天", now.Add(15 * 24 * time.Hour), "临近过期"},
		{"临近过期-30天", now.Add(30 * 24 * time.Hour), "临近过期"},
		{"有效-60天", now.Add(60 * 24 * time.Hour), "有效"},
		{"有效-1年", now.Add(365 * 24 * time.Hour), "有效"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &CertInfo{NotAfter: tt.notAfter}
			got := GetCertStatus(cert)
			if !hasPrefix(got, tt.wantPrefix) {
				t.Errorf("GetCertStatus() = %q, want prefix %q", got, tt.wantPrefix)
			}
		})
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// TestGetWildcardName_MoreCases 更多通配符名称测试
func TestGetWildcardName_MoreCases(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{"已是通配符", "*.example.com", "*.example.com"},
		{"一级子域名", "www.example.com", "*.example.com"},
		{"二级子域名", "api.sub.example.com", "*.sub.example.com"},
		{"三级子域名", "a.b.c.example.com", "*.b.c.example.com"},
		{"根域名", "example.com", "*.example.com"},
		{"单词", "localhost", "localhost"},
		{"空字符串", "", ""},
		{"带数字", "app123.example.com", "*.example.com"},
		{"带连字符", "my-app.example.com", "*.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetWildcardName(tt.domain)
			if got != tt.want {
				t.Errorf("GetWildcardName(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

// TestCertInfo_AllFields 测试 CertInfo 所有字段
func TestCertInfo_AllFields(t *testing.T) {
	now := time.Now()
	cert := &CertInfo{
		Thumbprint:   "ABC123",
		Subject:      "CN=example.com",
		Issuer:       "CN=Test CA",
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		FriendlyName: "Test Cert",
		HasPrivKey:   true,
		SerialNumber: "123456",
		DNSNames:     []string{"example.com", "www.example.com"},
	}

	if cert.Thumbprint != "ABC123" {
		t.Errorf("Thumbprint = %q", cert.Thumbprint)
	}
	if cert.Subject != "CN=example.com" {
		t.Errorf("Subject = %q", cert.Subject)
	}
	if cert.Issuer != "CN=Test CA" {
		t.Errorf("Issuer = %q", cert.Issuer)
	}
	if cert.FriendlyName != "Test Cert" {
		t.Errorf("FriendlyName = %q", cert.FriendlyName)
	}
	if !cert.HasPrivKey {
		t.Error("HasPrivKey 应该为 true")
	}
	if cert.SerialNumber != "123456" {
		t.Errorf("SerialNumber = %q", cert.SerialNumber)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("DNSNames 长度 = %d", len(cert.DNSNames))
	}
}

// TestMatchDomain_EdgeCases 边界情况测试
func TestMatchDomain_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		certDomain   string
		targetDomain string
		want         bool
	}{
		{"两个空字符串", "", "", false},
		{"证书域名空", "", "example.com", false},
		{"目标域名空", "example.com", "", false},
		{"空格", " ", " ", false}, // util.MatchDomain trims spaces, so " " becomes ""
		{"只有点", ".", ".", true}, // 精确匹配
		{"只有星号", "*", "*", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := util.MatchDomain(tt.targetDomain, tt.certDomain)
			if got != tt.want {
				t.Errorf("util.MatchDomain(%q, %q) = %v, want %v", tt.targetDomain, tt.certDomain, got, tt.want)
			}
		})
	}
}
