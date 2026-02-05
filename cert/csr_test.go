package cert

import (
	"strings"
	"testing"
)

func TestGenerateCSR(t *testing.T) {
	// 测试基本的 CSR 生成
	keyPEM, csrPEM, err := GenerateCSR("example.com")
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

	// 解析验证 CommonName
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}
	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, "example.com")
	}

	// CSR 不应包含 DNSNames（SAN 由服务端根据订单配置添加）
	if len(csr.DNSNames) != 0 {
		t.Errorf("DNSNames 应为空, 实际: %v", csr.DNSNames)
	}
}

func TestGenerateCSR_IDN(t *testing.T) {
	// 测试中文域名 CSR 生成（CommonName 应转为 Punycode）
	_, csrPEM, err := GenerateCSR("中文.com")
	if err != nil {
		t.Fatalf("GenerateCSR() error = %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseCSR() error = %v", err)
	}

	expectedCN := "xn--fiq228c.com"
	if csr.Subject.CommonName != expectedCN {
		t.Errorf("CommonName = %q, want %q", csr.Subject.CommonName, expectedCN)
	}

	if len(csr.DNSNames) != 0 {
		t.Errorf("DNSNames 应为空, 实际: %v", csr.DNSNames)
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
	_, csrPEM, err := GenerateCSR("test.example.com")
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
