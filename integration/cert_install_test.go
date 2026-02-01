//go:build integration

package integration

import (
	"os"
	"testing"

	"cert-deploy/api"
	"cert-deploy/cert"
)

// TestCertInstall 测试证书安装
func TestCertInstall(t *testing.T) {
	RequireAdmin(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取一个有效的证书
	certs, err := client.ListCertsByDomain("")
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

	t.Logf("使用证书: OrderID=%d, Domain=%s", testCert.OrderID, testCert.Domain)

	t.Run("PEMToPFX", func(t *testing.T) {
		// 测试 PEM 转 PFX
		pfxPath, err := cert.PEMToPFX(
			testCert.Certificate,
			testCert.PrivateKey,
			testCert.CACert,
			"test123",
		)
		if err != nil {
			t.Fatalf("PEM 转 PFX 失败: %v", err)
		}
		defer os.Remove(pfxPath)

		t.Logf("PFX 文件路径: %s", pfxPath)

		// 验证文件存在
		if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
			t.Fatal("PFX 文件不存在")
		}

		// 验证文件大小
		info, _ := os.Stat(pfxPath)
		if info.Size() == 0 {
			t.Fatal("PFX 文件为空")
		}
		t.Logf("PFX 文件大小: %d bytes", info.Size())
	})

	t.Run("InstallPFX", func(t *testing.T) {
		// 先转换为 PFX
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

		// 安装 PFX
		result, err := cert.InstallPFX(pfxPath, "")
		if err != nil {
			t.Fatalf("安装 PFX 失败: %v", err)
		}

		if !result.Success {
			t.Fatalf("安装失败: %s", result.ErrorMessage)
		}

		t.Logf("安装成功，Thumbprint: %s", result.Thumbprint)
		cleanup.AddCertificate(result.Thumbprint)

		// 验证证书已安装
		installed, err := cert.GetCertByThumbprint(result.Thumbprint)
		if err != nil {
			t.Fatalf("获取已安装证书失败: %v", err)
		}

		t.Logf("已安装证书: Subject=%s, NotAfter=%s",
			installed.Subject, installed.NotAfter.Format("2006-01-02"))
	})

	t.Run("VerifyThumbprint", func(t *testing.T) {
		// 计算 PEM 证书的 thumbprint
		thumbprint, err := cert.GetCertThumbprint(testCert.Certificate)
		if err != nil {
			t.Fatalf("计算 thumbprint 失败: %v", err)
		}

		t.Logf("计算得到的 Thumbprint: %s", thumbprint)

		if len(thumbprint) != 40 {
			t.Errorf("Thumbprint 长度不正确: %d (期望 40)", len(thumbprint))
		}
	})
}

// TestCertValidation 测试证书验证
func TestCertValidation(t *testing.T) {
	RequireAdmin(t)

	cleanup := NewTestCleanup(t)
	defer cleanup.Cleanup()

	client := api.NewClient(TestAPIBaseURL, TestToken)

	// 获取一个有效的证书并安装
	certs, err := client.ListCertsByDomain("")
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

	t.Run("VerifyCertificate", func(t *testing.T) {
		valid, status, err := cert.VerifyCertificate(result.Thumbprint)
		if err != nil {
			t.Fatalf("验证证书失败: %v", err)
		}

		t.Logf("证书验证结果: valid=%v, status=%s", valid, status)
	})

	t.Run("GetCertByThumbprint", func(t *testing.T) {
		certInfo, err := cert.GetCertByThumbprint(result.Thumbprint)
		if err != nil {
			t.Fatalf("获取证书失败: %v", err)
		}

		t.Logf("证书信息: Subject=%s", certInfo.Subject)
		t.Logf("证书信息: NotBefore=%s", certInfo.NotBefore.Format("2006-01-02"))
		t.Logf("证书信息: NotAfter=%s", certInfo.NotAfter.Format("2006-01-02"))
	})
}
