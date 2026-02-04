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

// TestFullDeployFlow 测试完整的部署流程
func TestFullDeployFlow(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 1. 从 API 获取证书
	t.Log("步骤 1: 从 API 获取证书列表")
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var testCert *api.CertData
	for i := range certs {
		if certs[i].Status == "active" && certs[i].Certificate != "" && certs[i].PrivateKey != "" {
			testCert = &certs[i]
			break
		}
	}

	if testCert == nil {
		t.Skip("没有可用的证书（需要 active 状态且包含私钥）")
	}

	t.Logf("选择证书: OrderID=%d, Domain=%s", testCert.OrderID, testCert.Domain)

	// 检查是否是通配符域名
	testHostname := testCert.Domain
	if len(testHostname) > 0 && testHostname[0] == '*' {
		// 通配符域名不能直接用于 SNI 绑定，使用替代域名
		testHostname = "test" + testHostname[1:] // *.example.com -> test.example.com
		t.Logf("通配符域名转换为测试域名: %s", testHostname)
	}

	// 2. 转换为 PFX
	t.Log("步骤 2: PEM 转换为 PFX")
	pfxPath, err := cert.PEMToPFX(
		testCert.Certificate,
		testCert.PrivateKey,
		testCert.CACert,
		"",
	)
	if err != nil {
		t.Fatalf("PEM 转 PFX 失败: %v", err)
	}
	defer os.Remove(pfxPath)
	t.Logf("PFX 文件: %s", pfxPath)

	// 3. 安装证书到 Windows 证书存储
	t.Log("步骤 3: 安装证书到 Windows 证书存储")
	result, err := cert.InstallPFX(pfxPath, "")
	if err != nil {
		t.Fatalf("安装 PFX 失败: %v", err)
	}

	if !result.Success {
		t.Fatalf("安装失败: %s", result.ErrorMessage)
	}

	thumbprint := result.Thumbprint
	t.Logf("安装成功，Thumbprint: %s", thumbprint)
	cleanup.AddCertificate(thumbprint)

	// 4. 验证证书已安装
	t.Log("步骤 4: 验证证书安装")
	valid, status, err := cert.VerifyCertificate(thumbprint)
	if err != nil {
		t.Fatalf("验证证书失败: %v", err)
	}
	t.Logf("证书验证: valid=%v, status=%s", valid, status)

	// 5. 绑定到 IIS (SNI)
	testPort := 9443
	t.Logf("步骤 5: 绑定证书到 IIS (%s:%d)", testHostname, testPort)

	// 先清理
	_ = iis.UnbindCertificate(testHostname, testPort)
	cleanup.AddSNIBinding(testHostname, testPort)

	err = iis.BindCertificate(testHostname, testPort, thumbprint)
	if err != nil {
		t.Fatalf("绑定证书失败: %v", err)
	}
	t.Log("绑定成功")

	// 6. 验证绑定
	t.Log("步骤 6: 验证 SSL 绑定")
	binding, err := iis.GetBindingForHost(testHostname, testPort)
	if err != nil {
		t.Fatalf("获取绑定失败: %v", err)
	}
	if binding == nil {
		t.Fatal("绑定不存在")
	}
	t.Logf("绑定验证成功: %s -> %s", binding.HostnamePort, binding.CertHash)

	// 7. 尝试 HTTPS 访问（可选，取决于 IIS 站点配置）
	t.Log("步骤 7: 测试 HTTPS 访问（可选）")
	if err := verifyHTTPS(testHostname, testPort); err != nil {
		t.Logf("HTTPS 访问失败（可能是 IIS 站点未配置）: %v", err)
	} else {
		t.Log("HTTPS 访问成功")
	}

	// 8. 清理
	t.Log("步骤 8: 清理测试资源")
	if err := iis.UnbindCertificate(testHostname, testPort); err != nil {
		t.Logf("解除绑定失败: %v", err)
	} else {
		t.Log("解除绑定成功")
	}

	t.Log("完整部署流程测试通过")
}

// TestDeployWithIPBinding 测试 IP 绑定部署流程
func TestDeployWithIPBinding(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取证书
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var testCert *api.CertData
	for i := range certs {
		if certs[i].Status == "active" && certs[i].Certificate != "" && certs[i].PrivateKey != "" {
			testCert = &certs[i]
			break
		}
	}

	if testCert == nil {
		t.Skip("没有可用的证书")
	}

	// 转换并安装
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

	t.Logf("IP 绑定测试，证书: %s", thumbprint)

	testIP := "0.0.0.0"
	testPort := 9444

	// 绑定
	_ = iis.UnbindCertificateByIP(testIP, testPort)
	cleanup.AddIPBinding(testIP, testPort)

	err = iis.BindCertificateByIP(testIP, testPort, thumbprint)
	if err != nil {
		t.Fatalf("IP 绑定失败: %v", err)
	}

	// 验证
	binding, err := iis.GetBindingForIP(testIP, testPort)
	if err != nil {
		t.Fatalf("获取绑定失败: %v", err)
	}
	if binding == nil {
		t.Fatal("绑定不存在")
	}

	t.Logf("IP 绑定部署成功: %s -> %s", binding.HostnamePort, binding.CertHash)
}

// TestDeployMultipleDomains 测试多域名部署
func TestDeployMultipleDomains(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取证书
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var testCert *api.CertData
	for i := range certs {
		if certs[i].Status == "active" && certs[i].Certificate != "" && certs[i].PrivateKey != "" {
			testCert = &certs[i]
			break
		}
	}

	if testCert == nil {
		t.Skip("没有可用的证书")
	}

	// 转换并安装
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

	// 获取证书的所有域名
	domains := testCert.GetDomainList()
	if len(domains) == 0 {
		domains = []string{testCert.Domain}
	}

	t.Logf("证书域名: %v", domains)

	// 为每个域名创建绑定（使用不同端口避免冲突）
	basePort := 9500
	successCount := 0

	for i, domain := range domains {
		port := basePort + i

		// 跳过通配符域名
		if len(domain) > 0 && domain[0] == '*' {
			t.Logf("跳过通配符域名: %s", domain)
			continue
		}

		_ = iis.UnbindCertificate(domain, port)
		cleanup.AddSNIBinding(domain, port)

		err := iis.BindCertificate(domain, port, thumbprint)
		if err != nil {
			t.Logf("绑定 %s:%d 失败: %v", domain, port, err)
			continue
		}

		t.Logf("绑定 %s:%d 成功", domain, port)
		successCount++
	}

	t.Logf("多域名部署完成: 成功 %d 个", successCount)
}

// TestWildcardCertWithIPBinding 测试通配符证书使用 IP 绑定（空主机名泛匹配）
func TestWildcardCertWithIPBinding(t *testing.T) {
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

	t.Logf("使用通配符证书: %s (OrderID=%d)", wildcardCert.Domain, wildcardCert.OrderID)

	// 转换并安装证书
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
	t.Logf("证书已安装: %s", thumbprint)

	// 使用 IP 绑定实现通配符泛匹配（空主机名）
	// 这是 IIS7 或需要泛匹配时的典型做法
	testIP := "0.0.0.0"
	testPort := 9445

	_ = iis.UnbindCertificateByIP(testIP, testPort)
	cleanup.AddIPBinding(testIP, testPort)

	err = iis.BindCertificateByIP(testIP, testPort, thumbprint)
	if err != nil {
		t.Fatalf("IP 绑定失败: %v", err)
	}

	t.Logf("通配符证书已绑定到 %s:%d（泛匹配模式）", testIP, testPort)

	// 验证绑定
	binding, err := iis.GetBindingForIP(testIP, testPort)
	if err != nil {
		t.Fatalf("获取绑定失败: %v", err)
	}
	if binding == nil {
		t.Fatal("绑定不存在")
	}
	if !strings.EqualFold(binding.CertHash, thumbprint) {
		t.Errorf("证书不匹配: 期望 %s, 实际 %s", thumbprint, binding.CertHash)
	}

	t.Logf("验证成功: %s -> %s", binding.HostnamePort, binding.CertHash)

	// 说明：此绑定可以匹配任何到达 0.0.0.0:9445 的请求
	// 通配符证书 *.example.com 将为所有 *.example.com 子域名提供 HTTPS
	t.Log("通配符证书 IP 绑定测试通过（泛匹配模式）")
}

// TestCertificateReplacement 测试证书替换
func TestCertificateReplacement(t *testing.T) {
	RequireAdmin(t)
	RequireIIS(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取两个不同的证书
	certs, err := client.ListCertsByDomain(context.Background(), "")
	if err != nil {
		t.Fatalf("获取证书列表失败: %v", err)
	}

	var cert1, cert2 *api.CertData
	for i := range certs {
		if certs[i].Status == "active" && certs[i].Certificate != "" && certs[i].PrivateKey != "" {
			if cert1 == nil {
				cert1 = &certs[i]
			} else if cert2 == nil && certs[i].OrderID != cert1.OrderID {
				cert2 = &certs[i]
				break
			}
		}
	}

	if cert1 == nil {
		t.Skip("没有可用的证书")
	}

	// 安装第一个证书
	pfxPath1, err := cert.PEMToPFX(cert1.Certificate, cert1.PrivateKey, cert1.CACert, "")
	if err != nil {
		t.Fatalf("PEM 转 PFX 失败: %v", err)
	}
	defer os.Remove(pfxPath1)

	result1, err := cert.InstallPFX(pfxPath1, "")
	if err != nil || !result1.Success {
		t.Fatalf("安装第一个证书失败")
	}
	cleanup.AddCertificate(result1.Thumbprint)

	testHostname := cert1.Domain
	// 通配符域名转换为测试域名
	if len(testHostname) > 0 && testHostname[0] == '*' {
		testHostname = "test" + testHostname[1:]
	}
	testPort := 9600

	// 绑定第一个证书
	_ = iis.UnbindCertificate(testHostname, testPort)
	cleanup.AddSNIBinding(testHostname, testPort)

	err = iis.BindCertificate(testHostname, testPort, result1.Thumbprint)
	if err != nil {
		t.Fatalf("绑定第一个证书失败: %v", err)
	}

	t.Logf("第一个证书已绑定: %s", result1.Thumbprint)

	// 验证绑定
	binding, _ := iis.GetBindingForHost(testHostname, testPort)
	if binding == nil || !strings.EqualFold(binding.CertHash, result1.Thumbprint) {
		t.Fatal("第一个证书绑定验证失败")
	}

	// 如果有第二个证书，测试替换
	if cert2 != nil {
		pfxPath2, err := cert.PEMToPFX(cert2.Certificate, cert2.PrivateKey, cert2.CACert, "")
		if err != nil {
			t.Fatalf("PEM 转 PFX 失败: %v", err)
		}
		defer os.Remove(pfxPath2)

		result2, err := cert.InstallPFX(pfxPath2, "")
		if err != nil || !result2.Success {
			t.Fatalf("安装第二个证书失败")
		}
		cleanup.AddCertificate(result2.Thumbprint)

		// 替换绑定
		err = iis.BindCertificate(testHostname, testPort, result2.Thumbprint)
		if err != nil {
			t.Fatalf("替换证书失败: %v", err)
		}

		// 验证替换
		binding, _ = iis.GetBindingForHost(testHostname, testPort)
		if binding == nil || !strings.EqualFold(binding.CertHash, result2.Thumbprint) {
			t.Fatal("证书替换验证失败")
		}

		t.Logf("证书已替换: %s -> %s", result1.Thumbprint, result2.Thumbprint)
	} else {
		t.Log("只有一个证书，跳过替换测试")
	}
}
