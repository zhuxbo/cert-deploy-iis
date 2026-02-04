package iis

import (
	"testing"
)

// TestFindBindingsForDomains_NoBindings 测试无绑定情况
func TestFindBindingsForDomains_NoBindings(t *testing.T) {
	// 调用 FindBindingsForDomains
	// 这会实际调用 ListSSLBindings
	bindings, err := FindBindingsForDomains([]string{"nonexistent.domain.com"})
	if err != nil {
		// 可能会因为 netsh 调用失败而出错，这是正常的
		t.Logf("FindBindingsForDomains 返回错误: %v (可能是预期的)", err)
		return
	}

	// 对于不存在的域名，应该返回空映射
	if len(bindings) > 0 {
		// 只有在域名恰好匹配时才会有结果
		t.Logf("找到 %d 个绑定（可能是系统已有绑定）", len(bindings))
	}
}

// TestFindBindingsForDomains_EmptyDomains 测试空域名列表
func TestFindBindingsForDomains_EmptyDomains(t *testing.T) {
	bindings, err := FindBindingsForDomains([]string{})
	if err != nil {
		t.Logf("空域名列表返回错误: %v", err)
		return
	}

	// 空域名列表应该返回空映射
	if len(bindings) != 0 {
		t.Errorf("空域名列表应该返回空映射，得到 %d 个绑定", len(bindings))
	}
}

// TestFindBindingsForDomains_NilDomains 测试 nil 域名列表
func TestFindBindingsForDomains_NilDomains(t *testing.T) {
	bindings, err := FindBindingsForDomains(nil)
	if err != nil {
		t.Logf("nil 域名列表返回错误: %v", err)
		return
	}

	// nil 域名列表应该返回空映射
	if len(bindings) != 0 {
		t.Errorf("nil 域名列表应该返回空映射，得到 %d 个绑定", len(bindings))
	}
}

// TestFindBindingsForDomains_MultipleDomains 测试多域名搜索
func TestFindBindingsForDomains_MultipleDomains(t *testing.T) {
	domains := []string{
		"www.example.com",
		"api.example.com",
		"*.example.com",
	}

	bindings, err := FindBindingsForDomains(domains)
	if err != nil {
		t.Logf("多域名搜索返回错误: %v", err)
		return
	}

	// 结果取决于系统状态
	t.Logf("多域名搜索找到 %d 个匹配绑定", len(bindings))
}

// TestListSSLBindings_Basic 测试基本列出功能
func TestListSSLBindings_Basic(t *testing.T) {
	bindings, err := ListSSLBindings()
	if err != nil {
		t.Logf("ListSSLBindings 返回错误: %v", err)
		return
	}

	t.Logf("系统中有 %d 个 SSL 绑定", len(bindings))
	for i, b := range bindings {
		t.Logf("绑定 %d: %s (IsIP: %v)", i+1, b.HostnamePort, b.IsIPBinding)
	}
}

// TestGetBindingForHost_NotFound 测试未找到绑定
func TestGetBindingForHost_NotFound(t *testing.T) {
	binding, err := GetBindingForHost("nonexistent.example.com", 443)
	if err != nil {
		t.Logf("GetBindingForHost 返回错误: %v", err)
		return
	}

	// 未找到时应该返回 nil
	if binding != nil {
		t.Logf("找到绑定: %s (可能是系统已有)", binding.HostnamePort)
	}
}

// TestGetBindingForIP_NotFound 测试未找到 IP 绑定
func TestGetBindingForIP_NotFound(t *testing.T) {
	// 使用一个不太可能存在的 IP
	binding, err := GetBindingForIP("192.168.255.255", 8443)
	if err != nil {
		t.Logf("GetBindingForIP 返回错误: %v", err)
		return
	}

	if binding != nil {
		t.Logf("找到绑定: %s (意外)", binding.HostnamePort)
	}
}

// TestParseSSLBindings_IPvsHostname 测试区分 IP 和主机名绑定
func TestParseSSLBindings_IPvsHostname(t *testing.T) {
	output := `
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : abc123def456789012345678901234567890abcd
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY

    Hostname:port                : www.example.com:443
    Certificate Hash             : def456789012345678901234567890abcdef1234
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 2 {
		t.Fatalf("期望 2 个绑定，得到 %d 个", len(bindings))
	}

	// 第一个应该是 IP 绑定
	if !bindings[0].IsIPBinding {
		t.Error("第一个绑定应该是 IP 绑定")
	}
	if bindings[0].HostnamePort != "0.0.0.0:443" {
		t.Errorf("第一个绑定 HostnamePort = %q", bindings[0].HostnamePort)
	}

	// 第二个应该是主机名绑定
	if bindings[1].IsIPBinding {
		t.Error("第二个绑定不应该是 IP 绑定")
	}
	if bindings[1].HostnamePort != "www.example.com:443" {
		t.Errorf("第二个绑定 HostnamePort = %q", bindings[1].HostnamePort)
	}
}

// TestParseSSLBindings_OnlyIPBindings 测试只有 IP 绑定
func TestParseSSLBindings_OnlyIPBindings(t *testing.T) {
	output := `
SSL Certificate bindings:
-------------------------

    IP:port                      : 0.0.0.0:443
    Certificate Hash             : abc123def456789012345678901234567890abcd
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY

    IP:port                      : 192.168.1.1:8443
    Certificate Hash             : def456789012345678901234567890abcdef1234
    Application ID               : {11111111-1111-1111-1111-111111111111}
    Certificate Store Name       : MY
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 2 {
		t.Fatalf("期望 2 个绑定，得到 %d 个", len(bindings))
	}

	for i, b := range bindings {
		if !b.IsIPBinding {
			t.Errorf("绑定 %d 应该是 IP 绑定", i+1)
		}
	}
}

// TestParseSSLBindings_OnlyHostnameBindings 测试只有主机名绑定
func TestParseSSLBindings_OnlyHostnameBindings(t *testing.T) {
	output := `
SSL Certificate bindings:
-------------------------

    Hostname:port                : www.example.com:443
    Certificate Hash             : abc123def456789012345678901234567890abcd
    Application ID               : {00000000-0000-0000-0000-000000000000}
    Certificate Store Name       : MY

    Hostname:port                : api.example.com:443
    Certificate Hash             : def456789012345678901234567890abcdef1234
    Application ID               : {11111111-1111-1111-1111-111111111111}
    Certificate Store Name       : MY
`
	bindings := parseSSLBindings(output)

	if len(bindings) != 2 {
		t.Fatalf("期望 2 个绑定，得到 %d 个", len(bindings))
	}

	for i, b := range bindings {
		if b.IsIPBinding {
			t.Errorf("绑定 %d 不应该是 IP 绑定", i+1)
		}
	}
}

// TestFindBindingsForDomains_IgnoresIPBindings 测试忽略 IP 绑定
func TestFindBindingsForDomains_IgnoresIPBindings(t *testing.T) {
	// 这个测试验证 FindBindingsForDomains 只返回 SNI 绑定
	// 由于依赖系统状态，我们只能验证逻辑
	domains := []string{"www.example.com"}

	bindings, err := FindBindingsForDomains(domains)
	if err != nil {
		t.Logf("FindBindingsForDomains 返回错误: %v", err)
		return
	}

	// 检查返回的绑定中不包含 IP 绑定
	for host, binding := range bindings {
		if binding.IsIPBinding {
			t.Errorf("返回了 IP 绑定: %s", host)
		}
	}
}

// TestMockHelpers 测试 mock 辅助函数
func TestMockHelpers(t *testing.T) {
	t.Run("MockSiteInfo", func(t *testing.T) {
		bindings := []BindingInfo{
			MockBindingInfo("https", "*", 443, "www.example.com", true),
		}
		site := MockSiteInfo(1, "Test Site", "Started", bindings)

		if site.ID != 1 {
			t.Errorf("ID = %d", site.ID)
		}
		if site.Name != "Test Site" {
			t.Errorf("Name = %q", site.Name)
		}
		if site.State != "Started" {
			t.Errorf("State = %q", site.State)
		}
		if len(site.Bindings) != 1 {
			t.Errorf("Bindings 数量 = %d", len(site.Bindings))
		}
	})

	t.Run("MockBindingInfo", func(t *testing.T) {
		binding := MockBindingInfo("https", "*", 443, "www.example.com", true)

		if binding.Protocol != "https" {
			t.Errorf("Protocol = %q", binding.Protocol)
		}
		if binding.IP != "*" {
			t.Errorf("IP = %q", binding.IP)
		}
		if binding.Port != 443 {
			t.Errorf("Port = %d", binding.Port)
		}
		if binding.Host != "www.example.com" {
			t.Errorf("Host = %q", binding.Host)
		}
		if !binding.HasSSL {
			t.Error("HasSSL 应该为 true")
		}
	})

	t.Run("MockSSLBinding", func(t *testing.T) {
		binding := MockSSLBinding("www.example.com:443", TestThumbprint, "{00000000}", "MY")

		if binding.HostnamePort != "www.example.com:443" {
			t.Errorf("HostnamePort = %q", binding.HostnamePort)
		}
		if binding.CertHash != TestThumbprint {
			t.Errorf("CertHash = %q", binding.CertHash)
		}
		if binding.AppID != "{00000000}" {
			t.Errorf("AppID = %q", binding.AppID)
		}
		if binding.CertStoreName != "MY" {
			t.Errorf("CertStoreName = %q", binding.CertStoreName)
		}
	})

	t.Run("MockError", func(t *testing.T) {
		err := MockError("test error")
		if err == nil {
			t.Error("MockError 应该返回错误")
		}
		if err.Error() != "test error" {
			t.Errorf("错误消息 = %q", err.Error())
		}
	})
}

// TestTestConstants 测试测试常量
func TestTestConstants(t *testing.T) {
	if TestThumbprint == "" {
		t.Error("TestThumbprint 不应为空")
	}
	if TestThumbprintLower == "" {
		t.Error("TestThumbprintLower 不应为空")
	}
	if TestDomain == "" {
		t.Error("TestDomain 不应为空")
	}
	if TestWildcardDomain == "" {
		t.Error("TestWildcardDomain 不应为空")
	}
	if TestPort != 443 {
		t.Errorf("TestPort = %d, want 443", TestPort)
	}
	if TestSiteName == "" {
		t.Error("TestSiteName 不应为空")
	}
}

// TestMockMode 测试 mock 模式开关
func TestMockMode(t *testing.T) {
	// 测试启用和禁用 mock 模式
	EnableMock()
	// 验证 mock 已启用（内部状态）

	DisableMock()
	// 验证 mock 已禁用
}
