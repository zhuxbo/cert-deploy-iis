package iis

import (
	"encoding/xml"
	"testing"
)

// TestParseScanSitesXML 测试站点 XML 解析逻辑
func TestParseScanSitesXML(t *testing.T) {
	tests := []struct {
		name       string
		xmlData    string
		wantCount  int
		wantFirst  *SiteInfo
		wantErr    bool
	}{
		{
			"正常站点列表",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
  <SITE SITE.NAME="Default Web Site" SITE.ID="1" bindings="http/*:80:,https/*:443:www.example.com" state="Started" />
  <SITE SITE.NAME="API Site" SITE.ID="2" bindings="https/*:443:api.example.com" state="Started" />
</appcmd>`,
			2,
			&SiteInfo{
				ID:    1,
				Name:  "Default Web Site",
				State: "Started",
			},
			false,
		},
		{
			"空站点列表",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
</appcmd>`,
			0,
			nil,
			false,
		},
		{
			"站点已停止",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
  <SITE SITE.NAME="Stopped Site" SITE.ID="3" bindings="http/*:80:" state="Stopped" />
</appcmd>`,
			1,
			&SiteInfo{
				ID:    3,
				Name:  "Stopped Site",
				State: "Stopped",
			},
			false,
		},
		{
			"复杂绑定",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
  <SITE SITE.NAME="Complex Site" SITE.ID="4" bindings="http/*:80:,http/*:80:www.example.com,https/*:443:www.example.com,https/*:443:api.example.com,https/*:8443:admin.example.com" state="Started" />
</appcmd>`,
			1,
			&SiteInfo{
				ID:    4,
				Name:  "Complex Site",
				State: "Started",
			},
			false,
		},
		{
			"无效 XML",
			`not valid xml`,
			0,
			nil,
			true,
		},
		{
			"中文站点名",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
  <SITE SITE.NAME="测试站点" SITE.ID="5" bindings="http/*:80:" state="Started" />
</appcmd>`,
			1,
			&SiteInfo{
				ID:    5,
				Name:  "测试站点",
				State: "Started",
			},
			false,
		},
		{
			"非数字站点 ID",
			`<?xml version="1.0" encoding="utf-8"?>
<appcmd>
  <SITE SITE.NAME="Invalid ID Site" SITE.ID="abc" bindings="http/*:80:" state="Started" />
</appcmd>`,
			1,
			&SiteInfo{
				ID:    0, // 解析失败时为 0
				Name:  "Invalid ID Site",
				State: "Started",
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result appcmdSiteList
			err := xml.Unmarshal([]byte(tt.xmlData), &result)

			if tt.wantErr {
				if err == nil {
					t.Error("期望解析错误，但没有返回错误")
				}
				return
			}

			if err != nil {
				t.Fatalf("解析 XML 失败: %v", err)
			}

			if len(result.Sites) != tt.wantCount {
				t.Errorf("站点数量 = %d, 期望 %d", len(result.Sites), tt.wantCount)
			}

			if tt.wantFirst != nil && len(result.Sites) > 0 {
				site := result.Sites[0]
				if site.Name != tt.wantFirst.Name {
					t.Errorf("第一个站点名称 = %q, 期望 %q", site.Name, tt.wantFirst.Name)
				}
				if site.State != tt.wantFirst.State {
					t.Errorf("第一个站点状态 = %q, 期望 %q", site.State, tt.wantFirst.State)
				}
			}
		})
	}
}

// TestFindMatchingBindingsLogic 测试匹配绑定逻辑（纯逻辑测试，不依赖 IIS）
func TestFindMatchingBindingsLogic(t *testing.T) {
	// 模拟站点数据
	sites := []SiteInfo{
		{
			ID:    1,
			Name:  "Default Web Site",
			State: "Started",
			Bindings: []BindingInfo{
				{Protocol: "http", IP: "0.0.0.0", Port: 80, Host: "", HasSSL: false},
				{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "www.example.com", HasSSL: true},
			},
		},
		{
			ID:    2,
			Name:  "API Site",
			State: "Started",
			Bindings: []BindingInfo{
				{Protocol: "http", IP: "0.0.0.0", Port: 80, Host: "api.example.com", HasSSL: false},
				{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "api.example.com", HasSSL: true},
			},
		},
		{
			ID:    3,
			Name:  "Wildcard Site",
			State: "Started",
			Bindings: []BindingInfo{
				{Protocol: "https", IP: "0.0.0.0", Port: 443, Host: "test.example.com", HasSSL: true},
			},
		},
	}

	tests := []struct {
		name            string
		certDomains     []string
		wantHttpsCount  int
		wantHttpCount   int
	}{
		{
			"精确匹配 HTTPS",
			[]string{"www.example.com"},
			1, // www.example.com
			0, // 已有 HTTPS，不需要添加
		},
		{
			"匹配多个域名",
			[]string{"www.example.com", "api.example.com"},
			2, // www + api
			0,
		},
		{
			"通配符匹配",
			[]string{"*.example.com"},
			3, // www + api + test
			0,
		},
		{
			"HTTP 绑定无对应 HTTPS",
			[]string{"api.example.com"},
			1, // api 已有 HTTPS
			0,
		},
		{
			"无匹配",
			[]string{"other.domain.com"},
			0,
			0,
		},
		{
			"空域名列表",
			[]string{},
			0,
			0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			httpsMatches, httpMatches := findMatchingBindingsFromSites(sites, tt.certDomains)

			if len(httpsMatches) != tt.wantHttpsCount {
				t.Errorf("HTTPS 匹配数 = %d, 期望 %d", len(httpsMatches), tt.wantHttpsCount)
			}
			if len(httpMatches) != tt.wantHttpCount {
				t.Errorf("HTTP 匹配数 = %d, 期望 %d", len(httpMatches), tt.wantHttpCount)
			}
		})
	}
}

// findMatchingBindingsFromSites 从站点列表中查找匹配的绑定（辅助测试函数）
func findMatchingBindingsFromSites(sites []SiteInfo, certDomains []string) ([]HttpBindingMatch, []HttpBindingMatch) {
	httpsMatches := make([]HttpBindingMatch, 0)
	httpMatches := make([]HttpBindingMatch, 0)

	httpsFound := make(map[string]bool)
	httpFound := make(map[string]bool)

	for _, site := range sites {
		for _, binding := range site.Bindings {
			if binding.Host == "" {
				continue
			}

			matchedDomain := ""
			for _, certDomain := range certDomains {
				if matchDomain(binding.Host, certDomain) {
					matchedDomain = certDomain
					break
				}
			}

			if matchedDomain == "" {
				continue
			}

			if binding.Protocol == "https" {
				key := binding.Host + ":" + string(rune(binding.Port))
				if !httpsFound[key] {
					httpsFound[key] = true
					httpsMatches = append(httpsMatches, HttpBindingMatch{
						SiteName:   site.Name,
						Host:       binding.Host,
						Port:       binding.Port,
						CertDomain: matchedDomain,
					})
				}
			} else if binding.Protocol == "http" {
				hasHttps := false
				for _, b := range site.Bindings {
					if b.Protocol == "https" && equalFoldDomain(b.Host, binding.Host) {
						hasHttps = true
						break
					}
				}

				if !hasHttps {
					key := site.Name + ":" + binding.Host
					if !httpFound[key] {
						httpFound[key] = true
						httpMatches = append(httpMatches, HttpBindingMatch{
							SiteName:   site.Name,
							Host:       binding.Host,
							Port:       443,
							CertDomain: matchedDomain,
						})
					}
				}
			}
		}
	}

	return httpsMatches, httpMatches
}

// matchDomain 域名匹配（简化版本用于测试）
func matchDomain(host, pattern string) bool {
	host = normalizeDomain(host)
	pattern = normalizeDomain(pattern)

	if host == pattern {
		return true
	}

	// 通配符匹配
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:] // .example.com
		if len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix {
			// 确保只匹配一级子域名
			prefix := host[:len(host)-len(suffix)]
			for _, c := range prefix {
				if c == '.' {
					return false
				}
			}
			return true
		}
	}

	return false
}

// normalizeDomain 规范化域名
func normalizeDomain(d string) string {
	result := make([]byte, len(d))
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// equalFoldDomain 不区分大小写比较域名
func equalFoldDomain(a, b string) bool {
	return normalizeDomain(a) == normalizeDomain(b)
}

// TestMatchDomainLogic 测试域名匹配逻辑
func TestMatchDomainLogic(t *testing.T) {
	tests := []struct {
		host    string
		pattern string
		want    bool
	}{
		{"www.example.com", "www.example.com", true},
		{"WWW.EXAMPLE.COM", "www.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"test.example.com", "*.example.com", true},
		{"a.b.example.com", "*.example.com", false}, // 通配符不匹配多级
		{"example.com", "*.example.com", false},     // 通配符不匹配顶级
		{"other.com", "*.example.com", false},
		{"", "*.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host+"_"+tt.pattern, func(t *testing.T) {
			got := matchDomain(tt.host, tt.pattern)
			if got != tt.want {
				t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}
