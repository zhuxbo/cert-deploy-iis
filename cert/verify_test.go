package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"regexp"
	"testing"
	"time"
)

// generateTestCertAndKey 生成自签名测试证书和私钥 PEM
func generateTestCertAndKey() (certPEM, keyPEM string) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"test.example.com", "www.test.example.com"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	certBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certBlock), string(keyBlock)
}

func TestNormalizeSerialNumber(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"已规范化", "ABC123", "ABC123"},
		{"小写转大写", "abc123", "ABC123"},
		{"去除空格", "AB C1 23", "ABC123"},
		{"去除前导零", "00ABC123", "ABC123"},
		{"全零", "000", "0"},
		{"单个零", "0", "0"},
		{"空字符串", "", "0"},
		{"混合情况", "00 ab c1 23", "ABC123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSerialNumber(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSerialNumber(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// 测试证书需要实际的 PEM 数据，这里只测试基本的解析逻辑
func TestParseCertificate_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		certPEM string
		wantErr bool
	}{
		{"空字符串", "", true},
		{"无效 PEM", "not a pem", true},
		{"无效 PEM 头", "-----BEGIN INVALID-----\n-----END INVALID-----", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseCertificate(tt.certPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyKeyPair_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		certPEM string
		keyPEM  string
		wantErr bool
	}{
		{"空证书", "", "key", true},
		{"空私钥", "cert", "", true},
		{"无效证书", "invalid cert", "invalid key", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyKeyPair(tt.certPEM, tt.keyPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyKeyPair() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyKeyPair_Valid(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey()

	match, err := VerifyKeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("VerifyKeyPair() 返回错误: %v", err)
	}
	if !match {
		t.Error("VerifyKeyPair() 应该返回 true，匹配的证书和密钥对返回了 false")
	}
}

func TestGetCertThumbprint_Invalid(t *testing.T) {
	_, err := GetCertThumbprint("invalid pem")
	if err == nil {
		t.Error("GetCertThumbprint() 应该对无效 PEM 返回错误")
	}
}

func TestGetCertSerialNumber_Invalid(t *testing.T) {
	_, err := GetCertSerialNumber("invalid pem")
	if err == nil {
		t.Error("GetCertSerialNumber() 应该对无效 PEM 返回错误")
	}
}

func TestParseCertificate_Valid(t *testing.T) {
	certPEM, _ := generateTestCertAndKey()

	cert, err := ParseCertificate(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificate() 返回错误: %v", err)
	}
	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("ParseCertificate() CN = %q, want %q", cert.Subject.CommonName, "test.example.com")
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("ParseCertificate() DNSNames 数量 = %d, want 2", len(cert.DNSNames))
	}
}

func TestGetCertThumbprint_Valid(t *testing.T) {
	certPEM, _ := generateTestCertAndKey()

	thumbprint, err := GetCertThumbprint(certPEM)
	if err != nil {
		t.Fatalf("GetCertThumbprint() 返回错误: %v", err)
	}
	// SHA1 指纹应该是 40 个十六进制字符（大写）
	if len(thumbprint) != 40 {
		t.Errorf("GetCertThumbprint() 长度 = %d, want 40", len(thumbprint))
	}
	matched, _ := regexp.MatchString("^[0-9A-F]{40}$", thumbprint)
	if !matched {
		t.Errorf("GetCertThumbprint() = %q, 不是有效的大写十六进制字符串", thumbprint)
	}
}

func TestGetCertSerialNumber_Valid(t *testing.T) {
	certPEM, _ := generateTestCertAndKey()

	serial, err := GetCertSerialNumber(certPEM)
	if err != nil {
		t.Fatalf("GetCertSerialNumber() 返回错误: %v", err)
	}
	if serial == "" {
		t.Error("GetCertSerialNumber() 返回空字符串")
	}
	// 模板中设置的 SerialNumber 是 big.NewInt(1)，十六进制为 "1"
	if serial != "1" {
		t.Errorf("GetCertSerialNumber() = %q, want %q", serial, "1")
	}
}

func TestVerifyKeyPair_Mismatch(t *testing.T) {
	certPEM1, _ := generateTestCertAndKey()
	_, keyPEM2 := generateTestCertAndKey()

	match, err := VerifyKeyPair(certPEM1, keyPEM2)
	if err != nil {
		t.Fatalf("VerifyKeyPair() 返回错误: %v", err)
	}
	if match {
		t.Error("VerifyKeyPair() 应该返回 false，不匹配的证书和密钥对返回了 true")
	}
}

func TestNormalizeSerialNumber_MoreCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"纯大写", "ABCDEF", "ABCDEF"},
		{"纯小写", "abcdef", "ABCDEF"},
		{"混合大小写", "AbCdEf", "ABCDEF"},
		{"多个空格", "A B C D E F", "ABCDEF"},
		{"前后空格", " ABC ", "ABC"},
		{"前导零多个", "0000ABC", "ABC"},
		{"只有空格", "   ", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSerialNumber(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSerialNumber(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
