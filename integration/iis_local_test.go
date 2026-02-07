//go:build integration

package integration

import (
	"testing"

	"sslctlw/iis"
)

// TestIISLocalOperations 本地 IIS 操作测试（不需要 API Token）
// 运行方式: go test -tags=integration ./integration/... -run TestIISLocal -v
func TestIISLocalOperations(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	t.Run("ScanSites", func(t *testing.T) {
		sites, err := iis.ScanSites()
		if err != nil {
			t.Fatalf("ScanSites 失败: %v", err)
		}

		t.Logf("发现 %d 个站点:", len(sites))
		for _, site := range sites {
			t.Logf("  [%d] %s (状态: %s, 绑定: %d 个)",
				site.ID, site.Name, site.State, len(site.Bindings))
			for _, b := range site.Bindings {
				t.Logf("      - %s://%s:%d%s",
					b.Protocol, b.IP, b.Port, func() string {
						if b.Host != "" {
							return " (" + b.Host + ")"
						}
						return ""
					}())
			}
		}
	})

	t.Run("ListSSLBindings", func(t *testing.T) {
		bindings, err := iis.ListSSLBindings()
		if err != nil {
			t.Fatalf("ListSSLBindings 失败: %v", err)
		}

		t.Logf("发现 %d 个 SSL 绑定:", len(bindings))
		for _, b := range bindings {
			bindType := "SNI"
			if b.IsIPBinding {
				bindType = "IP"
			}
			t.Logf("  [%s] %s -> 证书: %s",
				bindType, b.HostnamePort, b.CertHash)
		}
	})

	t.Run("GetIISVersion", func(t *testing.T) {
		version, err := iis.GetIISMajorVersion()
		if err != nil {
			t.Fatalf("GetIISMajorVersion 失败: %v", err)
		}

		t.Logf("IIS 版本: %d", version)

		isIIS7 := iis.IsIIS7()
		t.Logf("IsIIS7 (版本 <= 7.5): %v", isIIS7)
	})

	t.Run("FindMatchingBindings", func(t *testing.T) {
		sites, err := iis.ScanSites()
		if err != nil {
			t.Fatalf("ScanSites 失败: %v", err)
		}

		// 收集所有绑定的域名
		var domains []string
		for _, site := range sites {
			for _, b := range site.Bindings {
				if b.Host != "" && b.Protocol == "https" {
					domains = append(domains, b.Host)
				}
			}
		}

		if len(domains) == 0 {
			t.Log("没有发现 HTTPS 绑定域名")
			return
		}

		t.Logf("测试域名: %v", domains)

		// 测试 FindMatchingBindings
		httpsMatches, httpMatches, err := iis.FindMatchingBindings(domains)
		if err != nil {
			t.Fatalf("FindMatchingBindings 失败: %v", err)
		}

		t.Logf("HTTPS 匹配: %d 个", len(httpsMatches))
		for _, m := range httpsMatches {
			t.Logf("  %s:%d (站点: %s, 匹配: %s)",
				m.Host, m.Port, m.SiteName, m.CertDomain)
		}

		t.Logf("HTTP 匹配 (需要添加 HTTPS): %d 个", len(httpMatches))
		for _, m := range httpMatches {
			t.Logf("  %s:%d (站点: %s)", m.Host, m.Port, m.SiteName)
		}
	})

	t.Run("GetSiteState", func(t *testing.T) {
		sites, err := iis.ScanSites()
		if err != nil || len(sites) == 0 {
			t.Skip("没有站点可测试")
		}

		site := sites[0]
		state, err := iis.GetSiteState(site.Name)
		if err != nil {
			t.Fatalf("GetSiteState 失败: %v", err)
		}

		t.Logf("站点 %q 状态: %s", site.Name, state)
	})
}

// TestIISBindingOperations 测试绑定操作（需要测试证书）
// 这个测试会创建和删除 SSL 绑定，需要谨慎运行
func TestIISBindingOperations(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	// 获取现有的 SSL 绑定，选择一个进行测试
	bindings, err := iis.ListSSLBindings()
	if err != nil {
		t.Fatalf("ListSSLBindings 失败: %v", err)
	}

	if len(bindings) == 0 {
		t.Skip("没有现有的 SSL 绑定，跳过绑定操作测试")
	}

	// 使用第一个绑定的证书进行测试
	existingBinding := bindings[0]
	testThumbprint := existingBinding.CertHash
	testHostname := "integration-test.local"
	testPort := 9443

	t.Logf("使用现有证书进行测试: %s", testThumbprint)

	// 清理可能存在的测试绑定
	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()
	cleanup.AddSNIBinding(testHostname, testPort)

	_ = iis.UnbindCertificate(testHostname, testPort)

	t.Run("BindCertificate", func(t *testing.T) {
		err := iis.BindCertificate(testHostname, testPort, testThumbprint)
		if err != nil {
			t.Fatalf("BindCertificate 失败: %v", err)
		}
		t.Logf("绑定成功: %s:%d", testHostname, testPort)
	})

	t.Run("GetBindingForHost", func(t *testing.T) {
		binding, err := iis.GetBindingForHost(testHostname, testPort)
		if err != nil {
			t.Fatalf("GetBindingForHost 失败: %v", err)
		}

		if binding == nil {
			t.Fatal("绑定不存在")
		}

		t.Logf("获取到绑定: %s -> %s", binding.HostnamePort, binding.CertHash)
	})

	t.Run("UnbindCertificate", func(t *testing.T) {
		err := iis.UnbindCertificate(testHostname, testPort)
		if err != nil {
			t.Fatalf("UnbindCertificate 失败: %v", err)
		}
		t.Log("解绑成功")

		// 验证已解绑
		binding, _ := iis.GetBindingForHost(testHostname, testPort)
		if binding != nil {
			t.Error("绑定应该已被删除")
		}
	})
}
