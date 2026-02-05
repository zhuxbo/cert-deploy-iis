package iis

import (
	"testing"

	"sslctlw/util"
)

func TestParseBindings(t *testing.T) {
	tests := []struct {
		name        string
		bindingsStr string
		wantCount   int
		wantFirst   *BindingInfo
	}{
		{
			"单个 HTTP 绑定",
			"http/*:80:",
			1,
			&BindingInfo{Protocol: "http", IP: "0.0.0.0", Port: 80, Host: "", HasSSL: false},
		},
		{
			"单个 HTTPS 绑定带主机名",
			"https/*:443:www.example.com",
			1,
			&BindingInfo{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "www.example.com", HasSSL: true},
		},
		{
			"多个绑定",
			"http/*:80:,https/*:443:www.example.com",
			2,
			&BindingInfo{Protocol: "http", IP: "0.0.0.0", Port: 80, Host: "", HasSSL: false},
		},
		{
			"指定 IP",
			"http/192.168.1.1:80:localhost",
			1,
			&BindingInfo{Protocol: "http", IP: "192.168.1.1", Port: 80, Host: "localhost", HasSSL: false},
		},
		{
			"通配符域名",
			"https/*:443:*.example.com",
			1,
			&BindingInfo{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "*.example.com", HasSSL: true},
		},
		{
			"空字符串",
			"",
			0,
			nil,
		},
		{
			"复杂绑定",
			"http/*:80:,http/*:80:www.example.com,https/*:443:www.example.com,https/*:443:api.example.com",
			4,
			&BindingInfo{Protocol: "http", IP: "0.0.0.0", Port: 80, Host: "", HasSSL: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBindings(tt.bindingsStr)

			if len(got) != tt.wantCount {
				t.Errorf("parseBindings(%q) 返回 %d 个绑定，期望 %d 个", tt.bindingsStr, len(got), tt.wantCount)
			}

			if tt.wantFirst != nil && len(got) > 0 {
				first := got[0]
				if first.Protocol != tt.wantFirst.Protocol {
					t.Errorf("第一个绑定 Protocol = %q, 期望 %q", first.Protocol, tt.wantFirst.Protocol)
				}
				if first.IP != tt.wantFirst.IP {
					t.Errorf("第一个绑定 IP = %q, 期望 %q", first.IP, tt.wantFirst.IP)
				}
				if first.Port != tt.wantFirst.Port {
					t.Errorf("第一个绑定 Port = %d, 期望 %d", first.Port, tt.wantFirst.Port)
				}
				if first.Host != tt.wantFirst.Host {
					t.Errorf("第一个绑定 Host = %q, 期望 %q", first.Host, tt.wantFirst.Host)
				}
				if first.HasSSL != tt.wantFirst.HasSSL {
					t.Errorf("第一个绑定 HasSSL = %v, 期望 %v", first.HasSSL, tt.wantFirst.HasSSL)
				}
			}
		})
	}
}

func TestMatchDomainForBinding(t *testing.T) {
	tests := []struct {
		name        string
		bindingHost string
		certDomain  string
		want        bool
	}{
		{"精确匹配", "www.example.com", "www.example.com", true},
		{"通配符匹配", "api.example.com", "*.example.com", true},
		{"通配符不匹配多级", "a.b.example.com", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := util.MatchDomain(tt.bindingHost, tt.certDomain)
			if got != tt.want {
				t.Errorf("MatchDomain(%q, %q) = %v, want %v", tt.bindingHost, tt.certDomain, got, tt.want)
			}
		})
	}
}

func TestExpandIISPhysicalPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"无环境变量", "C:\\inetpub\\wwwroot", "C:\\inetpub\\wwwroot"},
		{"空字符串", "", ""},
		{"单个百分号", "C:\\test%path", "C:\\test%path"},
		{"双百分号", "C:\\test%%path", "C:\\test%path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandIISPhysicalPath(tt.path)
			if got != tt.want {
				t.Errorf("expandIISPhysicalPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetAppcmdPath(t *testing.T) {
	path := getAppcmdPath()
	if path == "" {
		t.Error("getAppcmdPath() 返回空字符串")
	}
	// 路径应该包含 appcmd.exe
	if !containsSubstring(path, "appcmd.exe") {
		t.Errorf("getAppcmdPath() = %q, 应该包含 appcmd.exe", path)
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstringHelper(s, substr))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestValidateBindingParams 测试绑定参数验证
func TestValidateBindingParams(t *testing.T) {
	tests := []struct {
		name     string
		siteName string
		host     string
		port     int
		wantErr  bool
	}{
		// 有效参数
		{"有效-基本", "Default Web Site", "www.example.com", 443, false},
		{"有效-空主机", "Default Web Site", "", 443, false},
		{"有效-端口0", "Default Web Site", "www.example.com", 0, false},
		{"有效-中文站点名", "中文站点", "www.example.com", 443, false},

		// 无效站点名
		{"无效-空站点名", "", "www.example.com", 443, true},
		{"无效-站点名含单引号", "site'name", "www.example.com", 443, true},
		{"无效-站点名含分号", "site;name", "www.example.com", 443, true},

		// 无效主机名
		{"无效-主机名格式", "Default Web Site", "-invalid.com", 443, true},
		{"无效-主机名下划线", "Default Web Site", "my_host.com", 443, true},

		// 无效端口
		{"无效-端口负数", "Default Web Site", "www.example.com", -1, true},
		{"无效-端口过大", "Default Web Site", "www.example.com", 70000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBindingParams(tt.siteName, tt.host, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBindingParams(%q, %q, %d) error = %v, wantErr %v",
					tt.siteName, tt.host, tt.port, err, tt.wantErr)
			}
		})
	}
}

// TestParseBindings_MoreCases 更多绑定解析测试
func TestParseBindings_MoreCases(t *testing.T) {
	tests := []struct {
		name        string
		bindingsStr string
		wantCount   int
		wantPorts   []int
	}{
		{
			"非标准端口",
			"https/*:8443:www.example.com",
			1,
			[]int{8443},
		},
		{
			"多个端口",
			"http/*:80:www.example.com,https/*:443:www.example.com,https/*:8443:www.example.com",
			3,
			[]int{80, 443, 8443},
		},
		{
			"带空格",
			"http/*:80:, https/*:443:",
			2,
			[]int{80, 443},
		},
		{
			"无效格式被忽略",
			"invalid,http/*:80:www.example.com",
			1,
			[]int{80},
		},
		{
			"格式特殊-单冒号",
			"http/192.168.1.1:80:www.example.com",
			1,
			[]int{80},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBindings(tt.bindingsStr)

			if len(got) != tt.wantCount {
				t.Errorf("parseBindings(%q) 返回 %d 个绑定，期望 %d 个", tt.bindingsStr, len(got), tt.wantCount)
			}

			for i, wantPort := range tt.wantPorts {
				if i < len(got) && got[i].Port != wantPort {
					t.Errorf("绑定 %d 端口 = %d, 期望 %d", i, got[i].Port, wantPort)
				}
			}
		})
	}
}

// TestExpandIISPhysicalPath_MoreCases 更多路径展开测试
func TestExpandIISPhysicalPath_MoreCases(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{"普通路径", "C:\\inetpub\\wwwroot", "C:\\inetpub\\wwwroot"},
		{"空字符串", "", ""},
		{"单个百分号开头", "%path", "%path"},
		{"单个百分号结尾", "path%", "path%"},
		{"双百分号", "%%", "%"},
		{"三个百分号", "%%%", "%%"},
		{"百分号中间", "C:\\%test%path", "C:\\%test%path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandIISPhysicalPath(tt.path)
			if got != tt.want {
				t.Errorf("expandIISPhysicalPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestParseBindings_Protocols 测试不同协议
func TestParseBindings_Protocols(t *testing.T) {
	tests := []struct {
		name        string
		bindingsStr string
		wantProto   string
		wantSSL     bool
	}{
		{"HTTP", "http/*:80:www.example.com", "http", false},
		{"HTTPS", "https/*:443:www.example.com", "https", true},
		{"大写 HTTP", "HTTP/*:80:www.example.com", "HTTP", false},
		{"大写 HTTPS", "HTTPS/*:443:www.example.com", "HTTPS", true},
		{"混合大小写", "HtTpS/*:443:www.example.com", "HtTpS", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bindings := parseBindings(tt.bindingsStr)
			if len(bindings) != 1 {
				t.Fatalf("期望 1 个绑定，得到 %d 个", len(bindings))
			}
			if bindings[0].Protocol != tt.wantProto {
				t.Errorf("Protocol = %q, want %q", bindings[0].Protocol, tt.wantProto)
			}
			if bindings[0].HasSSL != tt.wantSSL {
				t.Errorf("HasSSL = %v, want %v", bindings[0].HasSSL, tt.wantSSL)
			}
		})
	}
}
