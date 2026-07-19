package iis

import "testing"

// TestParseHostFromBinding_IPv6 绑定键解析：兼容 IPv6 方括号形态与 IPv4/SNI
func TestParseHostFromBinding_IPv6(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"example.com:443", "example.com", 443},
		{"0.0.0.0:443", "0.0.0.0", 443},
		{"1.2.3.4:8443", "1.2.3.4", 8443},
		{"[::1]:443", "::1", 443},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443},
		{"[::]:443", "::", 443},
		{"host-no-port", "host-no-port", 443},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if h := ParseHostFromBinding(tt.in); h != tt.wantHost {
				t.Errorf("ParseHostFromBinding(%q) = %q, want %q", tt.in, h, tt.wantHost)
			}
			if p := ParsePortFromBinding(tt.in); p != tt.wantPort {
				t.Errorf("ParsePortFromBinding(%q) = %d, want %d", tt.in, p, tt.wantPort)
			}
		})
	}
}

// TestFormatIPPortKey netsh ipport 键构造：IPv6 加方括号，IPv4/通配直接拼接
func TestFormatIPPortKey(t *testing.T) {
	tests := []struct {
		ip   string
		port int
		want string
	}{
		{"0.0.0.0", 443, "0.0.0.0:443"},
		{"1.2.3.4", 8443, "1.2.3.4:8443"},
		{"::1", 443, "[::1]:443"},
		{"2001:db8::1", 443, "[2001:db8::1]:443"},
		{"[::1]", 443, "[::1]:443"}, // 已带括号不重复加
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := formatIPPortKey(tt.ip, tt.port); got != tt.want {
				t.Errorf("formatIPPortKey(%q,%d) = %q, want %q", tt.ip, tt.port, got, tt.want)
			}
		})
	}
}

// TestFormatIPPortKey_RoundTrip 构造的键能被 Parse 正确还原为裸 IP 与端口
func TestFormatIPPortKey_RoundTrip(t *testing.T) {
	cases := []struct {
		ip   string
		port int
	}{
		{"0.0.0.0", 443},
		{"1.2.3.4", 8443},
		{"::1", 443},
		{"2001:db8::1", 8443},
	}
	for _, c := range cases {
		key := formatIPPortKey(c.ip, c.port)
		if h := ParseHostFromBinding(key); h != c.ip {
			t.Errorf("round-trip host: key=%q got %q want %q", key, h, c.ip)
		}
		if p := ParsePortFromBinding(key); p != c.port {
			t.Errorf("round-trip port: key=%q got %d want %d", key, p, c.port)
		}
	}
}

// TestIPBindingInformation IIS 绑定信息构造：IPv6 加方括号，空主机名
func TestIPBindingInformation(t *testing.T) {
	tests := []struct {
		ip   string
		port int
		want string
	}{
		{"0.0.0.0", 443, "0.0.0.0:443:"},
		{"1.2.3.4", 443, "1.2.3.4:443:"},
		{"::1", 443, "[::1]:443:"},
	}
	for _, tt := range tests {
		if got := ipBindingInformation(tt.ip, tt.port); got != tt.want {
			t.Errorf("ipBindingInformation(%q,%d) = %q, want %q", tt.ip, tt.port, got, tt.want)
		}
	}
}

// TestIPMatchesBinding 通配 IP 承载任意 IP，具体 IP 精确匹配（忽略括号/大小写）
func TestIPMatchesBinding(t *testing.T) {
	tests := []struct {
		binding string
		target  string
		want    bool
	}{
		{"", "1.2.3.4", true},        // 空 = 通配
		{"*", "1.2.3.4", true},       // * = 通配
		{"0.0.0.0", "1.2.3.4", true}, // 0.0.0.0 = 通配
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4", "5.6.7.8", false},
		{"[::1]", "::1", true}, // 忽略括号
	}
	for _, tt := range tests {
		if got := ipMatchesBinding(tt.binding, tt.target); got != tt.want {
			t.Errorf("ipMatchesBinding(%q,%q) = %v, want %v", tt.binding, tt.target, got, tt.want)
		}
	}
}

// TestFindEmptyHostSiteForIP 空 Host 站点定位：优先 IP/端口匹配的空 Host 绑定，回退唯一空 Host http:80
func TestFindEmptyHostSiteForIP(t *testing.T) {
	t.Run("匹配已有空 Host 具体 IP 绑定", func(t *testing.T) {
		sites := []SiteInfo{
			{Name: "SNISite", Bindings: []BindingInfo{{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "a.com"}}},
			{Name: "IPSite", Bindings: []BindingInfo{{Protocol: "https", IP: "1.2.3.4", Port: 443, Host: ""}}},
		}
		if name, ok := FindEmptyHostSiteForIP(sites, "1.2.3.4", 443); !ok || name != "IPSite" {
			t.Errorf("应定位 IPSite, got %q ok=%v", name, ok)
		}
	})

	t.Run("匹配通配 IP 空 Host 绑定", func(t *testing.T) {
		sites := []SiteInfo{
			{Name: "Wild", Bindings: []BindingInfo{{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: ""}}},
		}
		if name, ok := FindEmptyHostSiteForIP(sites, "9.9.9.9", 443); !ok || name != "Wild" {
			t.Errorf("通配 IP 应承载任意 IP, got %q ok=%v", name, ok)
		}
	})

	t.Run("回退唯一空 Host http:80 站点", func(t *testing.T) {
		sites := []SiteInfo{
			{Name: "Only80", Bindings: []BindingInfo{{Protocol: "http", IP: "*", Port: 80, Host: ""}}},
		}
		if name, ok := FindEmptyHostSiteForIP(sites, "1.2.3.4", 443); !ok || name != "Only80" {
			t.Errorf("应回退到 Only80, got %q ok=%v", name, ok)
		}
	})

	t.Run("多个空 Host http:80 站点无法定位", func(t *testing.T) {
		sites := []SiteInfo{
			{Name: "A", Bindings: []BindingInfo{{Protocol: "http", Port: 80, Host: ""}}},
			{Name: "B", Bindings: []BindingInfo{{Protocol: "http", Port: 80, Host: ""}}},
		}
		if name, ok := FindEmptyHostSiteForIP(sites, "1.2.3.4", 443); ok {
			t.Errorf("多个候选应无法确定, got %q", name)
		}
	})

	t.Run("仅有主机名绑定无法定位", func(t *testing.T) {
		sites := []SiteInfo{
			{Name: "SNIOnly", Bindings: []BindingInfo{{Protocol: "https", Port: 443, Host: "a.com"}}},
		}
		if _, ok := FindEmptyHostSiteForIP(sites, "1.2.3.4", 443); ok {
			t.Error("纯 SNI 站点不应被定位为 IP 承载站点")
		}
	})
}
