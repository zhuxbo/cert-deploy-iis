//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/iis"
)

// TestSSLBinding 测试 SSL 绑定
func TestSSLBinding(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取一个有效的证书
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var testCert *api.CertData
	var testHostname string
	for i := range certs {
		if certs[i].Status == "active" && certs[i].Certificate != "" && certs[i].PrivateKey != "" {
			testCert = &certs[i]
			// 使用证书的主域名作为测试主机名
			testHostname = certs[i].Domain
			// 通配符域名转换为测试域名
			if len(testHostname) > 0 && testHostname[0] == '*' {
				testHostname = "test" + testHostname[1:]
			}
			break
		}
	}

	if testCert == nil {
		t.Skip("没有可用的证书")
	}

	// 安装证书
	pfxPath, err := cert.PEMToPFX(testCert.Certificate, testCert.PrivateKey, testCert.CACert, "")
	if err != nil {
		t.Fatalf("PEM 转 PFX 失败: %v", err)
	}
	defer os.Remove(pfxPath)

	result, err := cert.InstallPFX(pfxPath, "")
	if err != nil || !result.Success {
		t.Fatalf("安装 PFX 失败")
	}
	cleanup.AddCertificate(result.Thumbprint)

	thumbprint := result.Thumbprint
	t.Logf("测试用证书已安装: %s", thumbprint)

	t.Run("ListSSLBindings", func(t *testing.T) {
		bindings, err := iis.ListSSLBindings()
		if err != nil {
			t.Fatalf("获取 SSL 绑定列表失败: %v", err)
		}

		t.Logf("当前 SSL 绑定数量: %d", len(bindings))
		for i, b := range bindings {
			t.Logf("绑定 %d: %s -> %s", i, b.HostnamePort, b.CertHash)
		}
	})

	t.Run("SNIBinding", func(t *testing.T) {
		testPort := 8443

		// 先清理可能存在的绑定
		_ = iis.UnbindCertificate(testHostname, testPort)
		cleanup.AddSNIBinding(testHostname, testPort)

		// 创建 SNI 绑定
		err := iis.BindCertificate(testHostname, testPort, thumbprint)
		if err != nil {
			t.Fatalf("SNI 绑定失败: %v", err)
		}
		t.Logf("SNI 绑定成功: %s:%d", testHostname, testPort)

		// 验证绑定
		binding, err := iis.GetBindingForHost(testHostname, testPort)
		if err != nil {
			t.Fatalf("获取绑定失败: %v", err)
		}

		if binding == nil {
			t.Fatal("绑定不存在")
		}

		if !strings.EqualFold(binding.CertHash, thumbprint) {
			t.Errorf("绑定证书不匹配: 期望 %s, 实际 %s", thumbprint, binding.CertHash)
		}

		t.Logf("绑定验证成功: %s -> %s", binding.HostnamePort, binding.CertHash)

		// 解除绑定
		err = iis.UnbindCertificate(testHostname, testPort)
		if err != nil {
			t.Errorf("解除 SNI 绑定失败: %v", err)
		} else {
			t.Log("解除 SNI 绑定成功")
		}
	})

	t.Run("IPBinding", func(t *testing.T) {
		testIP := "0.0.0.0"
		testPort := 8444

		// 先清理可能存在的绑定
		_ = iis.UnbindCertificateByIP(testIP, testPort)
		cleanup.AddIPBinding(testIP, testPort)

		// 创建 IP 绑定
		err := iis.BindCertificateByIP(testIP, testPort, thumbprint)
		if err != nil {
			t.Fatalf("IP 绑定失败: %v", err)
		}
		t.Logf("IP 绑定成功: %s:%d", testIP, testPort)

		// 验证绑定
		binding, err := iis.GetBindingForIP(testIP, testPort)
		if err != nil {
			t.Fatalf("获取绑定失败: %v", err)
		}

		if binding == nil {
			t.Fatal("绑定不存在")
		}

		if !strings.EqualFold(binding.CertHash, thumbprint) {
			t.Errorf("绑定证书不匹配: 期望 %s, 实际 %s", thumbprint, binding.CertHash)
		}

		t.Logf("绑定验证成功: %s -> %s", binding.HostnamePort, binding.CertHash)

		// 解除绑定
		err = iis.UnbindCertificateByIP(testIP, testPort)
		if err != nil {
			t.Errorf("解除 IP 绑定失败: %v", err)
		} else {
			t.Log("解除 IP 绑定成功")
		}
	})

	t.Run("FindBindingsForDomains", func(t *testing.T) {
		testPort := 8445

		// 创建一个测试绑定
		_ = iis.UnbindCertificate(testHostname, testPort)
		cleanup.AddSNIBinding(testHostname, testPort)

		err := iis.BindCertificate(testHostname, testPort, thumbprint)
		if err != nil {
			t.Fatalf("创建测试绑定失败: %v", err)
		}

		// 查找匹配的绑定
		domains := []string{testHostname}
		bindings, err := iis.FindBindingsForDomains(domains)
		if err != nil {
			t.Fatalf("查找绑定失败: %v", err)
		}

		t.Logf("找到 %d 个匹配的绑定", len(bindings))
		for domain, binding := range bindings {
			t.Logf("域名 %s: %s -> %s", domain, binding.HostnamePort, binding.CertHash)
		}

		// 清理
		_ = iis.UnbindCertificate(testHostname, testPort)
	})
}

// TestFindBindingsIgnoresIPBinding 测试 FindBindingsForDomains 忽略 IP 绑定
// IP 绑定（空主机名）用于泛匹配，需用户手工管理，自动绑定不处理
func TestFindBindingsIgnoresIPBinding(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取一个通配符证书
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var wildcardCert *api.CertData
	for i := range certs {
		if certs[i].Status == "active" &&
			certs[i].Certificate != "" &&
			certs[i].PrivateKey != "" &&
			len(certs[i].Domain) > 0 &&
			certs[i].Domain[0] == '*' {
			wildcardCert = &certs[i]
			break
		}
	}

	if wildcardCert == nil {
		t.Skip("没有可用的通配符证书")
	}

	// 安装证书
	pfxPath, err := cert.PEMToPFX(wildcardCert.Certificate, wildcardCert.PrivateKey, wildcardCert.CACert, "")
	if err != nil {
		t.Fatalf("PEM 转 PFX 失败: %v", err)
	}
	defer os.Remove(pfxPath)

	result, err := cert.InstallPFX(pfxPath, "")
	if err != nil || !result.Success {
		t.Fatalf("安装 PFX 失败")
	}
	cleanup.AddCertificate(result.Thumbprint)

	thumbprint := result.Thumbprint
	testIP := "0.0.0.0"
	testPort := 8446

	// 创建 IP 绑定（空主机名）
	_ = iis.UnbindCertificateByIP(testIP, testPort)
	cleanup.AddIPBinding(testIP, testPort)

	err = iis.BindCertificateByIP(testIP, testPort, thumbprint)
	if err != nil {
		t.Fatalf("IP 绑定失败: %v", err)
	}
	t.Logf("IP 绑定已创建: %s:%d", testIP, testPort)

	// 使用通配符域名查找绑定
	domains := []string{wildcardCert.Domain}
	bindings, err := iis.FindBindingsForDomains(domains)
	if err != nil {
		t.Fatalf("查找绑定失败: %v", err)
	}

	t.Logf("通配符域名 %s 查找到 %d 个 SNI 绑定", wildcardCert.Domain, len(bindings))

	// 验证 IP 绑定不会被返回（应该被忽略）
	for key, binding := range bindings {
		t.Logf("  SNI 绑定: %s -> %s", key, binding.CertHash)
		if binding.IsIPBinding {
			t.Errorf("IP 绑定不应该出现在结果中: %s", key)
		}
	}

	t.Log("验证通过: FindBindingsForDomains 正确忽略 IP 绑定")

	// 清理
	_ = iis.UnbindCertificateByIP(testIP, testPort)
}

// TestSSLBindingValidation 测试 SSL 绑定参数验证
func TestSSLBindingValidation(t *testing.T) {
	RequireAdmin(t)

	t.Run("InvalidHostname", func(t *testing.T) {
		err := iis.BindCertificate("", 443, "abc123")
		if err == nil {
			t.Error("期望返回错误")
		}
		t.Logf("正确返回错误: %v", err)
	})

	t.Run("InvalidPort", func(t *testing.T) {
		err := iis.BindCertificate("example.com", -1, "abc123")
		if err == nil {
			t.Error("期望返回错误")
		}
		t.Logf("正确返回错误: %v", err)
	})

	t.Run("InvalidThumbprint", func(t *testing.T) {
		err := iis.BindCertificate("example.com", 443, "invalid")
		if err == nil {
			t.Error("期望返回错误")
		}
		t.Logf("正确返回错误: %v", err)
	})
}
