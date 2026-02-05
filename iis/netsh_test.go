package iis

import (
	"os"
	"strings"
	"testing"

	"sslctlw/util"
)

func TestParseSSLBindings_English(t *testing.T) {
	// 读取测试数据
	data, err := os.ReadFile("../testdata/netsh/english_output.txt")
	if err != nil {
		t.Skip("测试数据文件不存在:", err)
	}

	bindings := parseSSLBindings(string(data))

	if len(bindings) != 3 {
		t.Errorf("期望解析出 3 个绑定，实际得到 %d 个", len(bindings))
	}

	// 验证第一个绑定（IP:port）
	if len(bindings) > 0 {
		b := bindings[0]
		if b.HostnamePort != "0.0.0.0:443" {
			t.Errorf("第一个绑定 HostnamePort = %q, 期望 %q", b.HostnamePort, "0.0.0.0:443")
		}
		// 证书哈希应该转为小写
		if !strings.EqualFold(b.CertHash, "abc123def456789012345678901234567890abcd") {
			t.Errorf("第一个绑定 CertHash = %q", b.CertHash)
		}
	}

	// 验证第二个绑定（Hostname:port）
	if len(bindings) > 1 {
		b := bindings[1]
		if b.HostnamePort != "www.example.com:443" {
			t.Errorf("第二个绑定 HostnamePort = %q, 期望 %q", b.HostnamePort, "www.example.com:443")
		}
	}

	// 验证第三个绑定（通配符）
	if len(bindings) > 2 {
		b := bindings[2]
		if b.HostnamePort != "*.example.com:443" {
			t.Errorf("第三个绑定 HostnamePort = %q, 期望 %q", b.HostnamePort, "*.example.com:443")
		}
	}
}

func TestParseSSLBindings_Chinese(t *testing.T) {
	// 读取测试数据
	data, err := os.ReadFile("../testdata/netsh/chinese_output.txt")
	if err != nil {
		t.Skip("测试数据文件不存在:", err)
	}

	bindings := parseSSLBindings(string(data))

	if len(bindings) != 3 {
		t.Errorf("期望解析出 3 个绑定，实际得到 %d 个", len(bindings))
	}

	// 验证可以正确解析中文输出
	if len(bindings) > 1 {
		b := bindings[1]
		if b.HostnamePort != "www.example.com:443" {
			t.Errorf("中文输出解析失败: HostnamePort = %q", b.HostnamePort)
		}
	}
}

func TestParseHostFromBinding(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         string
	}{
		{"普通域名", "www.example.com:443", "www.example.com"},
		{"通配符域名", "*.example.com:443", "*.example.com"},
		{"IP 地址", "0.0.0.0:443", "0.0.0.0"},
		{"自定义端口", "www.example.com:8443", "www.example.com"},
		{"无端口", "www.example.com", "www.example.com"},
		{"IPv6", "[::1]:443", "[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseHostFromBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("ParseHostFromBinding(%q) = %q, want %q", tt.hostnamePort, got, tt.want)
			}
		})
	}
}

func TestParsePortFromBinding(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         int
	}{
		{"标准 443", "www.example.com:443", 443},
		{"自定义 8443", "www.example.com:8443", 8443},
		{"端口 80", "www.example.com:80", 80},
		{"无端口默认 443", "www.example.com", 443},
		{"空字符串", "", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePortFromBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("ParsePortFromBinding(%q) = %d, want %d", tt.hostnamePort, got, tt.want)
			}
		})
	}
}

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		name        string
		bindingHost string
		certDomain  string
		want        bool
	}{
		// 精确匹配
		{"精确匹配", "www.example.com", "www.example.com", true},
		{"精确匹配-大小写不敏感", "WWW.Example.COM", "www.example.com", true},
		{"不匹配-不同域名", "www.example.com", "www.other.com", false},

		// 通配符匹配
		{"通配符-一级子域名", "www.example.com", "*.example.com", true},
		{"通配符-另一个子域名", "api.example.com", "*.example.com", true},
		{"通配符-不匹配顶级域名", "example.com", "*.example.com", false},
		{"通配符-不匹配多级子域名", "a.b.example.com", "*.example.com", false},
		{"通配符-不匹配不同域名", "www.other.com", "*.example.com", false},

		// 边界情况
		{"空字符串", "", "*.example.com", false},
		{"绑定为空", "", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := util.MatchDomain(tt.bindingHost, tt.certDomain)
			if got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.bindingHost, tt.certDomain, got, tt.want)
			}
		})
	}
}

func TestParseSSLBindings_Inline(t *testing.T) {
	// 测试英文输出格式
	englishOutput := `
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : abc123def456789012345678901234567890abcd
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : MY

    Hostname:port                : www.example.com:443
    Certificate Hash             : def456abc789012345678901234567890abcdef1
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : MY
`
	bindings := parseSSLBindings(englishOutput)

	if len(bindings) != 2 {
		t.Errorf("期望解析出 2 个绑定，实际得到 %d 个", len(bindings))
	}

	if len(bindings) > 0 {
		if bindings[0].HostnamePort != "0.0.0.0:443" {
			t.Errorf("第一个绑定 HostnamePort = %q", bindings[0].HostnamePort)
		}
	}

	if len(bindings) > 1 {
		if bindings[1].HostnamePort != "www.example.com:443" {
			t.Errorf("第二个绑定 HostnamePort = %q", bindings[1].HostnamePort)
		}
	}
}

func TestParseSSLBindings_Chinese_Inline(t *testing.T) {
	// 测试中文输出格式
	chineseOutput := `
SSL 证书绑定:
-------------------------

    IP:端口                      : 0.0.0.0:443
    证书哈希                     : abc123def456789012345678901234567890abcd
    应用程序 ID                  : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    证书存储名称                 : MY

    主机名:端口                  : www.example.com:443
    证书哈希                     : def456abc789012345678901234567890abcdef1
    应用程序 ID                  : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    证书存储名称                 : MY
`
	bindings := parseSSLBindings(chineseOutput)

	if len(bindings) != 2 {
		t.Errorf("期望解析出 2 个绑定，实际得到 %d 个", len(bindings))
	}

	if len(bindings) > 1 {
		if bindings[1].HostnamePort != "www.example.com:443" {
			t.Errorf("中文输出解析失败: HostnamePort = %q", bindings[1].HostnamePort)
		}
	}
}

func TestParseSSLBindings_Empty(t *testing.T) {
	bindings := parseSSLBindings("")
	if len(bindings) != 0 {
		t.Errorf("空输出应该返回 0 个绑定，实际得到 %d 个", len(bindings))
	}
}

func TestSSLBinding_Fields(t *testing.T) {
	binding := SSLBinding{
		HostnamePort:    "www.example.com:443",
		CertHash:        "abc123",
		AppID:           "{00000000-0000-0000-0000-000000000000}",
		CertStoreName:   "MY",
		SslCtlStoreName: "",
	}

	if binding.HostnamePort != "www.example.com:443" {
		t.Errorf("SSLBinding.HostnamePort = %q", binding.HostnamePort)
	}
	if binding.CertHash != "abc123" {
		t.Errorf("SSLBinding.CertHash = %q", binding.CertHash)
	}
	if binding.AppID != "{00000000-0000-0000-0000-000000000000}" {
		t.Errorf("SSLBinding.AppID = %q", binding.AppID)
	}
	if binding.CertStoreName != "MY" {
		t.Errorf("SSLBinding.CertStoreName = %q", binding.CertStoreName)
	}
}

func TestDefaultAppID(t *testing.T) {
	if defaultAppID != "{00000000-0000-0000-0000-000000000000}" {
		t.Errorf("defaultAppID = %q", defaultAppID)
	}
}

// TestParseSSLBindings_AllFields 测试解析所有字段
func TestParseSSLBindings_AllFields(t *testing.T) {
	output := `
SSL Certificate bindings:
-------------------------

    Hostname:port                : www.example.com:443
    Certificate Hash             : ABC123DEF456789012345678901234567890ABCD
    Application ID               : {12345678-1234-1234-1234-123456789012}
    Certificate Store Name       : WebHosting
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 1 {
		t.Fatalf("期望解析出 1 个绑定，实际得到 %d 个", len(bindings))
	}

	b := bindings[0]
	if b.HostnamePort != "www.example.com:443" {
		t.Errorf("HostnamePort = %q", b.HostnamePort)
	}
	if b.CertHash != "abc123def456789012345678901234567890abcd" {
		t.Errorf("CertHash = %q（应该转小写）", b.CertHash)
	}
	if b.AppID != "{12345678-1234-1234-1234-123456789012}" {
		t.Errorf("AppID = %q", b.AppID)
	}
	if b.CertStoreName != "WebHosting" {
		t.Errorf("CertStoreName = %q", b.CertStoreName)
	}
}

// TestParseSSLBindings_MultipleBindings 测试解析多个绑定
func TestParseSSLBindings_MultipleBindings(t *testing.T) {
	output := `
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : 1111111111111111111111111111111111111111
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY

    Hostname:port                : www.example.com:443
    Certificate Hash             : 2222222222222222222222222222222222222222
    Application ID               : {11111111-1111-1111-1111-111111111111}
    Certificate Store Name       : MY

    Hostname:port                : api.example.com:8443
    Certificate Hash             : 3333333333333333333333333333333333333333
    Application ID               : {22222222-2222-2222-2222-222222222222}
    Certificate Store Name       : WebHosting
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 3 {
		t.Fatalf("期望解析出 3 个绑定，实际得到 %d 个", len(bindings))
	}

	// 验证第一个绑定
	if bindings[0].HostnamePort != "0.0.0.0:443" {
		t.Errorf("第一个绑定 HostnamePort = %q", bindings[0].HostnamePort)
	}

	// 验证第二个绑定
	if bindings[1].HostnamePort != "www.example.com:443" {
		t.Errorf("第二个绑定 HostnamePort = %q", bindings[1].HostnamePort)
	}

	// 验证第三个绑定
	if bindings[2].HostnamePort != "api.example.com:8443" {
		t.Errorf("第三个绑定 HostnamePort = %q", bindings[2].HostnamePort)
	}
	if bindings[2].CertStoreName != "WebHosting" {
		t.Errorf("第三个绑定 CertStoreName = %q", bindings[2].CertStoreName)
	}
}

// TestMatchDomain_MoreCases 更多域名匹配测试
func TestMatchDomain_MoreCases(t *testing.T) {
	tests := []struct {
		name        string
		bindingHost string
		certDomain  string
		want        bool
	}{
		// 精确匹配
		{"精确匹配-相同", "example.com", "example.com", true},
		{"精确匹配-子域名", "sub.example.com", "sub.example.com", true},

		// 通配符匹配
		{"通配符-单级子域名", "www.example.com", "*.example.com", true},
		{"通配符-不同子域名", "api.example.com", "*.example.com", true},
		{"通配符-不匹配根域名", "example.com", "*.example.com", false},
		{"通配符-不匹配多级子域名", "a.b.example.com", "*.example.com", false},
		{"通配符-空前缀", ".example.com", "*.example.com", false}, // .example.com 不是有效域名，不应匹配

		// 大小写
		{"大小写不敏感", "WWW.EXAMPLE.COM", "www.example.com", true},
		{"大小写混合", "Www.Example.Com", "*.example.com", true},

		// 边界情况
		{"空绑定域名", "", "*.example.com", false},
		{"空证书域名", "www.example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := util.MatchDomain(tt.bindingHost, tt.certDomain)
			if got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v",
					tt.bindingHost, tt.certDomain, got, tt.want)
			}
		})
	}
}

// TestParseHostFromBinding_MoreCases 更多主机名解析测试
func TestParseHostFromBinding_MoreCases(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         string
	}{
		{"标准格式", "www.example.com:443", "www.example.com"},
		{"IPv4 地址", "192.168.1.1:443", "192.168.1.1"},
		{"通配 IP", "0.0.0.0:443", "0.0.0.0"},
		{"通配符域名", "*.example.com:443", "*.example.com"},
		{"非标准端口", "www.example.com:8443", "www.example.com"},
		{"端口 80", "www.example.com:80", "www.example.com"},
		{"无端口", "www.example.com", "www.example.com"},
		{"空字符串", "", ""},
		{"只有冒号", ":", ":"}, // idx=0，不满足 idx>0，返回原始
		{"只有端口", ":443", ":443"}, // idx=0，不满足 idx>0，返回原始
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseHostFromBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("ParseHostFromBinding(%q) = %q, want %q",
					tt.hostnamePort, got, tt.want)
			}
		})
	}
}

// TestParsePortFromBinding_MoreCases 更多端口解析测试
func TestParsePortFromBinding_MoreCases(t *testing.T) {
	tests := []struct {
		name         string
		hostnamePort string
		want         int
	}{
		{"标准 443", "www.example.com:443", 443},
		{"端口 80", "www.example.com:80", 80},
		{"非标准端口", "www.example.com:8443", 8443},
		{"高端口", "www.example.com:65535", 65535},
		{"无端口", "www.example.com", 443},
		{"空字符串", "", 443},
		{"只有端口", ":443", 443},
		{"只有冒号", ":", 443},
		{"端口0", "www.example.com:0", 443}, // 0 无效，返回默认
		{"非数字端口", "www.example.com:abc", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParsePortFromBinding(tt.hostnamePort)
			if got != tt.want {
				t.Errorf("ParsePortFromBinding(%q) = %d, want %d",
					tt.hostnamePort, got, tt.want)
			}
		})
	}
}

// TestParseSSLBindings_ChineseFullWidth 测试中文全角冒号
func TestParseSSLBindings_ChineseFullWidth(t *testing.T) {
	// 测试全角冒号（：）的处理
	output := `
SSL 证书绑定:
-------------------------

    主机名：端口                  ： www.example.com:443
    证书哈希                     ： abc123def456789012345678901234567890abcd
    应用程序 ID                  ： {00000000-0000-0000-0000-000000000000}
    证书存储名称                 ： MY
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 1 {
		t.Fatalf("期望解析出 1 个绑定，实际得到 %d 个", len(bindings))
	}
}

// TestParseSSLBindings_MixedOutput 测试混合输出
func TestParseSSLBindings_MixedOutput(t *testing.T) {
	output := `
Some header text
SSL Certificate bindings:
-------------------------

Random text that should be ignored
    IP:port                      : 0.0.0.0:443
More random text
    Certificate Hash             : abc123def456789012345678901234567890abcd
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY
Footer text
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 1 {
		t.Fatalf("期望解析出 1 个绑定，实际得到 %d 个", len(bindings))
	}
	if bindings[0].HostnamePort != "0.0.0.0:443" {
		t.Errorf("HostnamePort = %q", bindings[0].HostnamePort)
	}
}

// TestParseSSLBindings_OnlyWhitespace 测试只有空白字符
func TestParseSSLBindings_OnlyWhitespace(t *testing.T) {
	output := `

   `
	bindings := parseSSLBindings(output)

	if len(bindings) != 0 {
		t.Errorf("只有空白字符应该返回 0 个绑定，实际得到 %d 个", len(bindings))
	}
}

// TestSSLBinding_AllFields 测试 SSLBinding 所有字段
func TestSSLBinding_AllFields(t *testing.T) {
	binding := SSLBinding{
		HostnamePort:    "www.example.com:443",
		CertHash:        "abc123",
		AppID:           "{00000000-0000-0000-0000-000000000000}",
		CertStoreName:   "MY",
		SslCtlStoreName: "CTL",
	}

	if binding.HostnamePort != "www.example.com:443" {
		t.Errorf("HostnamePort = %q", binding.HostnamePort)
	}
	if binding.CertHash != "abc123" {
		t.Errorf("CertHash = %q", binding.CertHash)
	}
	if binding.AppID != "{00000000-0000-0000-0000-000000000000}" {
		t.Errorf("AppID = %q", binding.AppID)
	}
	if binding.CertStoreName != "MY" {
		t.Errorf("CertStoreName = %q", binding.CertStoreName)
	}
	if binding.SslCtlStoreName != "CTL" {
		t.Errorf("SslCtlStoreName = %q", binding.SslCtlStoreName)
	}
}
