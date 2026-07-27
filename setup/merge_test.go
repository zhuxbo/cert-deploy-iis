package setup

import (
	"testing"

	"sslctlw/api"
	"sslctlw/config"
)

// TestMergeSetupCert_IPDerivationSurvivesRerun setup 重跑合并已有订单时，
// 必须保留 makeCertConfig 为 IP 证书派生的显式绑定模式。
// 若被写回 AutoBindMode=true，deployCertAutoMode 只认 SNI 绑定，
// 会把 IP 证书判成“未找到匹配的 IIS SSL 绑定”，每轮部署失败直到 CAPPED。
func TestMergeSetupCert_IPDerivationSurvivesRerun(t *testing.T) {
	opts := Options{URL: "https://example.com/api/deploy", Token: "tok"}

	t.Run("已配置的 IP 证书重跑保持显式规则", func(t *testing.T) {
		derived := mustMakeCertConfig(t, api.CertData{OrderID: 100, Domains: "1.2.3.4"}, opts, "S1")
		existing := derived // 首次 setup 已按派生结果落盘

		mergeSetupCert(&existing, mustMakeCertConfig(t, api.CertData{OrderID: 100, Domains: "1.2.3.4"}, opts, "S2"))

		if existing.AutoBindMode {
			t.Error("IP 证书重跑后不得回到自动绑定模式")
		}
		if existing.RenewMode != "local" || existing.ValidationMethod != config.ValidationMethodFile {
			t.Errorf("IP 证书应保持 local/file, got %q/%q", existing.RenewMode, existing.ValidationMethod)
		}
		if len(existing.BindRules) != 1 || existing.BindRules[0].Domain != "1.2.3.4" {
			t.Errorf("IP 绑定规则应保留, got %+v", existing.BindRules)
		}
	})

	t.Run("域名证书续期新增 IP SAN 后转为显式规则", func(t *testing.T) {
		existing := mustMakeCertConfig(t, api.CertData{OrderID: 200, Domains: "example.com"}, opts, "S1")
		if !existing.AutoBindMode {
			t.Fatal("前置条件：域名证书应为自动绑定模式")
		}

		mergeSetupCert(&existing, mustMakeCertConfig(t, api.CertData{OrderID: 200, Domains: "example.com,1.2.3.4"}, opts, "S2"))

		if existing.AutoBindMode {
			t.Error("证书新增 IP SAN 后必须转为显式绑定规则模式")
		}
		if existing.RenewMode != "local" {
			t.Errorf("RenewMode 应派生为 local（IP + pull 属非法配置）, got %q", existing.RenewMode)
		}
		if len(existing.BindRules) != 2 {
			t.Errorf("应为每个 SAN 生成绑定规则, got %+v", existing.BindRules)
		}
	})

	t.Run("域名证书不清空用户手工维护的绑定规则", func(t *testing.T) {
		existing := mustMakeCertConfig(t, api.CertData{OrderID: 300, Domains: "example.com"}, opts, "S1")
		existing.BindRules = []config.BindRule{{Domain: "example.com", Port: 8443}}
		existing.ValidationMethod = config.ValidationMethodFile

		mergeSetupCert(&existing, mustMakeCertConfig(t, api.CertData{OrderID: 300, Domains: "example.com"}, opts, "S2"))

		if len(existing.BindRules) != 1 || existing.BindRules[0].Port != 8443 {
			t.Errorf("setup 未派生规则时不得清空用户配置, got %+v", existing.BindRules)
		}
		if existing.ValidationMethod != config.ValidationMethodFile {
			t.Errorf("setup 未派生验证方式时不得清空用户配置, got %q", existing.ValidationMethod)
		}
	})

	t.Run("始终同步 API 与到期时间并启用", func(t *testing.T) {
		existing := config.CertConfig{OrderID: 400, Enabled: false}
		newCert := mustMakeCertConfig(t, api.CertData{OrderID: 400, Domains: "example.com", ExpiresAt: "2026-12-31"}, opts, "S")

		mergeSetupCert(&existing, newCert)

		if !existing.Enabled {
			t.Error("setup 处理过的证书应启用")
		}
		if existing.Metadata.CertExpiresAt != "2026-12-31" {
			t.Errorf("应同步到期时间, got %q", existing.Metadata.CertExpiresAt)
		}
		if existing.API.URL != newCert.API.URL {
			t.Errorf("应同步 API 配置, got %q", existing.API.URL)
		}
	})
}
