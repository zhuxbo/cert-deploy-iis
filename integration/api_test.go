//go:build integration

package integration

import (
	"testing"

	"cert-deploy/api"
)

// TestAPIConnection 测试 API 连接
func TestAPIConnection(t *testing.T) {
	client := api.NewClient(TestAPIBaseURL, TestToken)

	t.Run("ListCerts", func(t *testing.T) {
		certs, err := client.ListCertsByDomain("")
		if err != nil {
			t.Fatalf("获取证书列表失败: %v", err)
		}

		t.Logf("获取到 %d 个证书", len(certs))

		// 验证返回数据格式
		for i, cert := range certs {
			if cert.OrderID == 0 {
				t.Errorf("证书 %d: OrderID 为空", i)
			}
			if cert.Domain == "" {
				t.Errorf("证书 %d: Domain 为空", i)
			}
			t.Logf("证书 %d: OrderID=%d, Domain=%s, Status=%s, ExpiresAt=%s",
				i, cert.OrderID, cert.Domain, cert.Status, cert.ExpiresAt)
		}
	})

	t.Run("GetCertByDomain", func(t *testing.T) {
		// 先获取列表，找一个有效的域名
		certs, err := client.ListCertsByDomain("")
		if err != nil {
			t.Fatalf("获取证书列表失败: %v", err)
		}

		if len(certs) == 0 {
			t.Skip("没有可用的证书")
		}

		// 找一个 active 状态的证书
		var testDomain string
		for _, c := range certs {
			if c.Status == "active" && c.Domain != "" {
				testDomain = c.Domain
				break
			}
		}

		if testDomain == "" {
			t.Skip("没有 active 状态的证书")
		}

		cert, err := client.GetCertByDomain(testDomain)
		if err != nil {
			t.Fatalf("按域名获取证书失败: %v", err)
		}

		t.Logf("获取到证书: OrderID=%d, Domain=%s", cert.OrderID, cert.Domain)

		// 验证证书内容
		if cert.Certificate == "" {
			t.Error("证书内容为空")
		}
		if cert.PrivateKey == "" {
			t.Log("私钥为空（可能是本地私钥模式）")
		}
	})

	t.Run("GetCertByOrderID", func(t *testing.T) {
		// 先获取列表，找一个有效的订单 ID
		certs, err := client.ListCertsByDomain("")
		if err != nil {
			t.Fatalf("获取证书列表失败: %v", err)
		}

		if len(certs) == 0 {
			t.Skip("没有可用的证书")
		}

		testOrderID := certs[0].OrderID

		cert, err := client.GetCertByOrderID(testOrderID)
		if err != nil {
			t.Fatalf("按订单ID获取证书失败: %v", err)
		}

		t.Logf("获取到证书: OrderID=%d, Domain=%s, Status=%s",
			cert.OrderID, cert.Domain, cert.Status)

		if cert.OrderID != testOrderID {
			t.Errorf("订单ID不匹配: 期望 %d, 实际 %d", testOrderID, cert.OrderID)
		}
	})
}

// TestAPIValidation 测试 API 参数验证
func TestAPIValidation(t *testing.T) {
	t.Run("EmptyBaseURL", func(t *testing.T) {
		client := api.NewClient("", TestToken)
		_, err := client.ListCertsByDomain("")
		if err == nil {
			t.Error("期望返回错误，但没有")
		}
		t.Logf("正确返回错误: %v", err)
	})

	t.Run("EmptyToken", func(t *testing.T) {
		client := api.NewClient(TestAPIBaseURL, "")
		_, err := client.ListCertsByDomain("")
		if err == nil {
			t.Error("期望返回错误，但没有")
		}
		t.Logf("正确返回错误: %v", err)
	})

	t.Run("InvalidToken", func(t *testing.T) {
		client := api.NewClient(TestAPIBaseURL, "invalid-token")
		_, err := client.ListCertsByDomain("")
		if err == nil {
			t.Error("期望返回错误，但没有")
		}
		t.Logf("正确返回错误: %v", err)
	})
}
