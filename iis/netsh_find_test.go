package iis

import (
	"reflect"
	"strings"
	"testing"
)

func mustFindBindings(t *testing.T, bindings []SSLBinding, domains []string) []SSLBinding {
	t.Helper()
	got, err := findBindingsFromList(bindings, domains)
	if err != nil {
		t.Fatalf("findBindingsFromList() error = %v", err)
	}
	return got
}

func findBindingByHost(bindings []SSLBinding, host string) *SSLBinding {
	for i := range bindings {
		if ParseHostFromBinding(bindings[i].HostnamePort) == host {
			return &bindings[i]
		}
	}
	return nil
}

func TestFindBindingsFromList_PreservesDistinctPortsAndSorts(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:8443", CertHash: "bbb"},
		{HostnamePort: "api.example.com:443", CertHash: "ccc"},
		{HostnamePort: "www.example.com:443", CertHash: "aaa"},
	}

	got, err := findBindingsFromList(bindings, []string{"*.example.com"})
	if err != nil {
		t.Fatalf("findBindingsFromList() error = %v", err)
	}

	gotKeys := make([]string, 0, len(got))
	for _, binding := range got {
		gotKeys = append(gotKeys, binding.HostnamePort)
	}
	want := []string{"api.example.com:443", "www.example.com:443", "www.example.com:8443"}
	if !reflect.DeepEqual(gotKeys, want) {
		t.Fatalf("绑定端点 = %v, want %v", gotKeys, want)
	}
}

func TestFindBindingsFromList_RejectsMalformedPort(t *testing.T) {
	_, err := findBindingsFromList(
		[]SSLBinding{{HostnamePort: "www.example.com:not-a-port", CertHash: "aaa"}},
		[]string{"www.example.com"},
	)
	if err == nil || !strings.Contains(err.Error(), "端口") {
		t.Fatalf("坏端口 error = %v, want 明确端口错误", err)
	}
}

func TestFindBindingsFromList_DeduplicatesIdenticalBinding(t *testing.T) {
	binding := SSLBinding{
		HostnamePort:    "www.example.com:443",
		CertHash:        "aaa",
		AppID:           "{app}",
		CertStoreName:   "MY",
		SslCtlStoreName: "CTL",
	}
	got, err := findBindingsFromList([]SSLBinding{binding, binding}, []string{"www.example.com"})
	if err != nil {
		t.Fatalf("findBindingsFromList() error = %v", err)
	}
	if len(got) != 1 || got[0] != binding {
		t.Fatalf("完全重复绑定未正确去重: %+v", got)
	}
}

func TestFindBindingsFromList_DeduplicatesEquivalentBindingFields(t *testing.T) {
	base := SSLBinding{
		HostnamePort:    "www.example.com:443",
		CertHash:        "AA11",
		AppID:           "{ABC-123}",
		CertStoreName:   "MY",
		SslCtlStoreName: "CTL",
	}
	tests := []struct {
		name   string
		change func(*SSLBinding)
	}{
		{name: "证书哈希", change: func(binding *SSLBinding) { binding.CertHash = " aa11 " }},
		{name: "AppID", change: func(binding *SSLBinding) { binding.AppID = " {abc-123} " }},
		{name: "证书存储", change: func(binding *SSLBinding) { binding.CertStoreName = " my " }},
		{name: "CTL 存储", change: func(binding *SSLBinding) { binding.SslCtlStoreName = " ctl " }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variant := base
			tt.change(&variant)
			got, err := findBindingsFromList([]SSLBinding{base, variant}, []string{"www.example.com"})
			if err != nil {
				t.Fatalf("等价绑定字段不应报歧义: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("等价绑定未去重: %+v", got)
			}
		})
	}
}

func TestFindBindingsFromList_RejectsAmbiguousEndpoint(t *testing.T) {
	_, err := findBindingsFromList(
		[]SSLBinding{
			{HostnamePort: "www.example.com:443", CertHash: "aaa"},
			{HostnamePort: "WWW.EXAMPLE.COM:443", CertHash: "bbb"},
		},
		[]string{"www.example.com"},
	)
	if err == nil || !strings.Contains(err.Error(), "歧义") {
		t.Fatalf("同端点不一致 error = %v, want 歧义错误", err)
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		ipBinding bool
		host      string
		port      int
		want      EndpointKey
	}{
		{
			name: "SNI 主机名大小写和默认端口",
			host: "WWW.Example.COM",
			want: EndpointKey{Host: "www.example.com", Port: 443},
		},
		{
			name:      "IP 规范表示",
			ipBinding: true,
			host:      "0:0:0:0:0:0:0:1",
			port:      8443,
			want:      EndpointKey{IPBinding: true, Host: "::1", Port: 8443},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tt.ipBinding, tt.host, tt.port)
			if err != nil {
				t.Fatalf("NormalizeEndpoint() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeEndpoint() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestFindBindingsFromList_Basic 测试基本域名匹配
func TestFindBindingsFromList_Basic(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "api.example.com:443", CertHash: "bbb", IsIPBinding: false},
		{HostnamePort: "other.com:443", CertHash: "ccc", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"*.example.com"})

	if len(result) != 2 {
		t.Fatalf("期望匹配 2 个绑定，得到 %d 个", len(result))
	}
	if findBindingByHost(result, "www.example.com") == nil {
		t.Error("应该匹配 www.example.com")
	}
	if findBindingByHost(result, "api.example.com") == nil {
		t.Error("应该匹配 api.example.com")
	}
	if findBindingByHost(result, "other.com") != nil {
		t.Error("不应匹配 other.com")
	}
}

// TestFindBindingsFromList_IgnoresIPBindings 测试忽略 IP 绑定
func TestFindBindingsFromList_IgnoresIPBindings(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "0.0.0.0:443", CertHash: "aaa", IsIPBinding: true},
		{HostnamePort: "www.example.com:443", CertHash: "bbb", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"*.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if findBindingByHost(result, "www.example.com") == nil {
		t.Error("应该匹配 www.example.com")
	}
}

// TestFindBindingsFromList_EmptyDomains 测试空域名列表
func TestFindBindingsFromList_EmptyDomains(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{})
	if len(result) != 0 {
		t.Errorf("空域名列表应该返回空映射，得到 %d 个", len(result))
	}

	result = mustFindBindings(t, bindings, nil)
	if len(result) != 0 {
		t.Errorf("nil 域名列表应该返回空映射，得到 %d 个", len(result))
	}
}

// TestFindBindingsFromList_EmptyBindings 测试空绑定列表
func TestFindBindingsFromList_EmptyBindings(t *testing.T) {
	result := mustFindBindings(t, []SSLBinding{}, []string{"*.example.com"})
	if len(result) != 0 {
		t.Errorf("空绑定列表应该返回空映射，得到 %d 个", len(result))
	}

	result = mustFindBindings(t, nil, []string{"*.example.com"})
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

	result := mustFindBindings(t, bindings, []string{"www.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if findBindingByHost(result, "www.example.com") == nil {
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

	result := mustFindBindings(t, bindings, []string{"www.example.com", "*.other.com"})

	if len(result) != 2 {
		t.Fatalf("期望匹配 2 个绑定，得到 %d 个", len(result))
	}
	if findBindingByHost(result, "www.example.com") == nil {
		t.Error("应该匹配 www.example.com")
	}
	if findBindingByHost(result, "api.other.com") == nil {
		t.Error("应该匹配 api.other.com")
	}
}

// TestFindBindingsFromList_WildcardNoMultiLevel 测试通配符不匹配多级子域名
func TestFindBindingsFromList_WildcardNoMultiLevel(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "a.b.example.com:443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "example.com:443", CertHash: "bbb", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"*.example.com"})

	if len(result) != 0 {
		t.Errorf("通配符不应匹配多级子域名或根域名，得到 %d 个匹配", len(result))
	}
}

// TestFindBindingsFromList_NonStandardPort 测试非标准端口
func TestFindBindingsFromList_NonStandardPort(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:8443", CertHash: "aaa", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"*.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定，得到 %d 个", len(result))
	}
	if findBindingByHost(result, "www.example.com") == nil {
		t.Error("应该匹配 www.example.com（不同端口）")
	}
}

// TestFindBindingsFromList_EmptyHost 测试空主机名
func TestFindBindingsFromList_EmptyHost(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: ":443", CertHash: "aaa", IsIPBinding: false},
		{HostnamePort: "", CertHash: "bbb", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"*.example.com"})

	if len(result) != 0 {
		t.Errorf("空主机名不应匹配，得到 %d 个匹配", len(result))
	}
}

// TestFindBindingsFromList_CaseInsensitive 测试大小写不敏感
func TestFindBindingsFromList_CaseInsensitive(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "WWW.EXAMPLE.COM:443", CertHash: "aaa", IsIPBinding: false},
	}

	result := mustFindBindings(t, bindings, []string{"www.example.com"})

	if len(result) != 1 {
		t.Fatalf("期望匹配 1 个绑定（大小写不敏感），得到 %d 个", len(result))
	}
}

// TestFindBindingsFromList_DuplicateDomain 测试重复域名只返回一次
func TestFindBindingsFromList_DuplicateDomain(t *testing.T) {
	bindings := []SSLBinding{
		{HostnamePort: "www.example.com:443", CertHash: "aaa", IsIPBinding: false},
	}

	// 域名列表中有重复
	result := mustFindBindings(t, bindings, []string{"www.example.com", "*.example.com"})

	if len(result) != 1 {
		t.Fatalf("同一绑定只应返回一次，得到 %d 个", len(result))
	}
}
