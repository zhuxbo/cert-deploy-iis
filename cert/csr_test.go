package cert

import (
	"strings"
	"testing"
)

func TestGenerateCSR(t *testing.T) {
	// 测试基本的 CSR 生成
	keyPEM, csrPEM, err := GenerateCSR("example.com", nil)
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	// 验证私钥格式
	if !strings.Contains(keyPEM, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("生成的私钥应包含 RSA PRIVATE KEY 头")
	}
	if !strings.Contains(keyPEM, "-----END RSA PRIVATE KEY-----") {
		t.Error("生成的私钥应包含 RSA PRIVATE KEY 尾")
	}

	// 验证 CSR 格式
	if !strings.Contains(csrPEM, "-----BEGIN CERTIFICATE REQUEST-----") {
		t.Error("生成的 CSR 应包含 CERTIFICATE REQUEST 头")
	}
	if !strings.Contains(csrPEM, "-----END CERTIFICATE REQUEST-----") {
		t.Error("生成的 CSR 应包含 CERTIFICATE REQUEST 尾")
	}
}

func TestGenerateCSR_WithSANs(t *testing.T) {
	// 测试带 SANs 的 CSR 生成
	sans := []string{"www.example.com", "api.example.com"}
	keyPEM, csrPEM, err := GenerateCSR("example.com", sans)
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	if keyPEM == "" {
		t.Error("私钥不应为空")
	}
	if csrPEM == "" {
		t.Error("CSR 不应为空")
	}

	// 解析 CSR 验证域名
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}

	// 验证 Common Name
	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "example.com")
	}

	// 验证 DNSNames 包含所有域名
	expectedDomains := []string{"example.com", "www.example.com", "api.example.com"}
	if len(csr.DNSNames) != len(expectedDomains) {
		t.Errorf("DNSNames 数量 = %d, want %d", len(csr.DNSNames), len(expectedDomains))
	}

	for _, expected := range expectedDomains {
		found := false
		for _, dns := range csr.DNSNames {
			if dns == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DNSNames 中缺少 %q", expected)
		}
	}
}

func TestGenerateCSR_DuplicateSAN(t *testing.T) {
	// 测试重复的 SAN（主域名也在 SANs 中）
	sans := []string{"example.com", "www.example.com"}
	_, csrPEM, err := GenerateCSR("example.com", sans)
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}

	// 验证没有重复的域名
	domainCount := make(map[string]int)
	for _, dns := range csr.DNSNames {
		domainCount[dns]++
	}

	for domain, count := range domainCount {
		if count > 1 {
			t.Errorf("域名 %q 重复出现 %d 次", domain, count)
		}
	}
}

func TestParseCSR_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		csrPEM  string
		wantErr bool
	}{
		{"空字符串", "", true},
		{"无效 PEM", "not a pem", true},
		{"错误的 PEM 类型", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", true},
		{"无效的 CSR 数据", "-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCSR(tt.csrPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCSR() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseCSR_Valid(t *testing.T) {
	// 先生成一个有效的 CSR，然后解析
	_, csrPEM, err := GenerateCSR("test.example.com", []string{"www.test.example.com"})
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "test.example.com")
	}
}
