package iis

import (
	"testing"
)

// TestFindBindingsFromList_Basic 测试基本域名匹配
func TestFindBindingsFromList_Basic(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "api.example.com:443", CertHash: "bbb", IsIPBinding: false},
		{HostnamePort: "other.com:443", CertHash: "ccc", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"*.example.com"})

	if len(result) != 2 {
		t.Fatalf("期望匹配 2 个绑定，得到 %d 个", len(result))
	}
	if result["www.example.com"] == nil {
		t.Error("应该匹配 www.example.com")
	}
	if result["api.example.com"] == nil {
		t.Error("应该匹配 api.example.com")
	}
	if result["other.com"] != nil {
		t.Error("不应匹配 other.com")
	}
}

// TestFindBindingsFromList_IgnoresIPBindings 测试忽略 IP 绑定
func TestFindBindingsFromList_IgnoresIPBindings(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "0.0.0.0:443", CertHash: "aaa", IsIPBinding: true},
		{HostnamePort: "www.example.com:443", CertHash: "bbb", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"*.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if result["www.example.com"] == nil {
		t.Error("应该匹配 www.example.com")
	}
}

// TestFindBindingsFromList_EmptyDomains 测试空域名列表
func TestFindBindingsFromList_EmptyDomains(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{})
	if len(result) != 0 {
		t.Errorf("空域名列表应该返回空映射，得到 %d 个", len(result))
	}

	result = findBindingsFromList(bindings, nil)
	if len(result) != 0 {
		t.Errorf("nil 域名列表应该返回空映射，得到 %d 个", len(result))
	}
}

// TestFindBindingsFromList_EmptyBindings 测试空绑定列表
func TestFindBindingsFromList_EmptyBindings(t *testing.T) {
	result := findBindingsFromList([]SSLBinding{}, []string{"*.example.com"})
	if len(result) != 0 {
		t.Errorf("空绑定列表应该返回空映射，得到 %d 个", len(result))
	}

	result = findBindingsFromList(nil, []string{"*.example.com"})
	if len(result) != 0 {
		t.Errorf("nil 绑定列表应该返回空映射，得到 %d 个", len(result))
	}
}

// TestFindBindingsFromList_ExactMatch 测试精确域名匹配
func TestFindBindingsFromList_ExactMatch(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "api.example.com:443", CertHash: "bbb", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"www.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if result["www.example.com"] == nil {
		t.Error("应该精确匹配 www.example.com")
	}
}

// TestFindBindingsFromList_MultipleDomains 测试多域名搜索
func TestFindBindingsFromList_MultipleDomains(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "api.other.com:443", CertHash: "bbb", IsIPBinding: false},
		{HostnamePort: "admin.third.com:443", CertHash: "ccc", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"www.example.com", "*.other.com"})

	if len(result) != 2 {
		t.Fatalf("期望匹配 2 个绑定，得到 %d 个", len(result))
	}
	if result["www.example.com"] == nil {
		t.Error("应该匹配 www.example.com")
	}
	if result["api.other.com"] == nil {
		t.Error("应该匹配 api.other.com")
	}
}

// TestFindBindingsFromList_WildcardNoMultiLevel 测试通配符不匹配多级子域名
func TestFindBindingsFromList_WildcardNoMultiLevel(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "a.b.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "example.com:443", CertHash: "bbb", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"*.example.com"})

	if len(result) != 0 {
		t.Errorf("通配符不应匹配多级子域名或根域名，得到 %d 个匹配", len(result))
	}
}

// TestFindBindingsFromList_NonStandardPort 测试非标准端口
func TestFindBindingsFromList_NonStandardPort(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:8443", CertHash: "aaa", IsIPBinding: false},
	}

	result := findBindingsFromList(bindings, []string{"*.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if result["www.example.com"] == nil {
		t.Error("应该匹配 www.example.com（不同端口）")
	}
}
