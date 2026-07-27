package setup

import (
	"testing"

	"sslctlw/api"
	"sslctlw/config"
)

// TestIPSANs 识别 IPv4/IPv6 SAN，忽略域名
func TestIPSANs(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    []string
	}{
		{"纯 IPv4", []string{"1.2.3.4"}, []string{"1.2.3.4"}},
		{"纯 IPv6", []string{"2001:db8::1"}, []string{"2001:db8::1"}},
		{"域名不算 IP", []string{"example.com"}, []string{}},
		{"混合取 IP", []string{"example.com", "1.2.3.4", "www.example.com"}, []string{"1.2.3.4"}},
		{"域名+IPv6", []string{"a.com", "::1"}, []string{"::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ipSANs(tt.domains)
			if len(got) != len(tt.want) {
				t.Fatalf("ipSANs(%v) = %v, want %v", tt.domains, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("ipSANs[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitBindingNames_MixedSAN(t *testing.T) {
	ips, dnsNames := splitBindingNames([]string{"example.com", " 1.2.3.4 ", "www.example.com", "2001:db8::1"})
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "2001:db8::1" {
		t.Fatalf("IP 分组错误: %v", ips)
	}
	if len(dnsNames) != 2 || dnsNames[0] != "example.com" || dnsNames[1] != "www.example.com" {
		t.Fatalf("DNS 分组错误: %v", dnsNames)
	}
}

// TestMakeCertConfig_IPDerivation IP 证书派生 local/file + IP 绑定规则；域名证书保持自动模式
func TestMakeCertConfig_IPDerivation(t *testing.T) {
	opts := Options{URL: "https://example.com/api/deploy", Token: "tok"}

	t.Run("IPv4 证书派生 local/file/规则", func(t *testing.T) {
		certData := api.CertData{OrderID: 100, Domains: "1.2.3.4"} // Certificate 空 → 回退 GetDomainList
		cfg := mustMakeCertConfig(t, certData, opts, "SERIAL")
		if cfg.RenewMode != "local" {
			t.Errorf("RenewMode = %q, want local", cfg.RenewMode)
		}
		if cfg.ValidationMethod != config.ValidationMethodFile {
			t.Errorf("ValidationMethod = %q, want file", cfg.ValidationMethod)
		}
		if cfg.AutoBindMode {
			t.Error("IP 证书应关闭自动绑定模式")
		}
		if len(cfg.BindRules) != 1 || cfg.BindRules[0].Domain != "1.2.3.4" || cfg.BindRules[0].Port != 443 {
			t.Errorf("应生成 IP 绑定规则, got %+v", cfg.BindRules)
		}
	})

	t.Run("多 IP SAN 各生成绑定规则", func(t *testing.T) {
		certData := api.CertData{OrderID: 101, Domains: "1.2.3.4,2001:db8::1"}
		cfg := mustMakeCertConfig(t, certData, opts, "")
		if len(cfg.BindRules) != 2 {
			t.Fatalf("应为每个 IP 生成规则, got %+v", cfg.BindRules)
		}
	})

	t.Run("混合 DNS 和 IP SAN 保留全部绑定规则", func(t *testing.T) {
		certData := api.CertData{OrderID: 103, Domains: "example.com,1.2.3.4,www.example.com"}
		cfg := mustMakeCertConfig(t, certData, opts, "")
		if cfg.AutoBindMode {
			t.Fatal("含 IP SAN 的证书应使用显式绑定规则")
		}
		if len(cfg.BindRules) != 3 {
			t.Fatalf("DNS 与 IP SAN 都应保留绑定规则, got %+v", cfg.BindRules)
		}
		for i, want := range []string{"example.com", "1.2.3.4", "www.example.com"} {
			if cfg.BindRules[i].Domain != want {
				t.Errorf("BindRules[%d].Domain = %q, want %q", i, cfg.BindRules[i].Domain, want)
			}
		}
	})

	t.Run("域名证书保持自动绑定不派生 local", func(t *testing.T) {
		certData := api.CertData{OrderID: 102, Domains: "example.com,www.example.com"}
		cfg := mustMakeCertConfig(t, certData, opts, "")
		if cfg.RenewMode != "" {
			t.Errorf("域名证书 RenewMode 应为空（继承全局）, got %q", cfg.RenewMode)
		}
		if !cfg.AutoBindMode {
			t.Error("域名证书应保持自动绑定模式")
		}
		if len(cfg.BindRules) != 0 {
			t.Errorf("域名证书不应生成 IP 绑定规则, got %+v", cfg.BindRules)
		}
	})
}

// TestDeriveSetupPolicy IP 证书强制 local（不受配置可读性限制），域名证书沿用现有配置判定
func TestDeriveSetupPolicy(t *testing.T) {
	t.Run("IP 证书强制 local 且通知", func(t *testing.T) {
		certData := api.CertData{OrderID: 1, Domains: "1.2.3.4"}
		notify, useLocal := deriveSetupPolicy(certData, nil, false) // 即使配置不可读
		if !notify || !useLocal {
			t.Errorf("IP 证书应 notify=true useLocal=true, got (%v,%v)", notify, useLocal)
		}
	})

	t.Run("域名证书沿用 decideReissueNotify", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Schedule.RenewMode = "pull"
		cfg.Certificates = []config.CertConfig{{OrderID: 5, RenewMode: "local"}}
		certData := api.CertData{OrderID: 5, Domains: "example.com"}
		notify, useLocal := deriveSetupPolicy(certData, cfg, true)
		if !notify || !useLocal {
			t.Errorf("既有 local 订单应 notify=true useLocal=true, got (%v,%v)", notify, useLocal)
		}
	})

	t.Run("域名证书配置不可读跳过通知", func(t *testing.T) {
		certData := api.CertData{OrderID: 9, Domains: "example.com"}
		notify, _ := deriveSetupPolicy(certData, nil, false)
		if notify {
			t.Error("域名证书配置不可读时应跳过通知")
		}
	})
}
