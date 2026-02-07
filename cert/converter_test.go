package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"长度 8", 8},
		{"长度 16", 16},
		{"长度 1", 1},
		{"长度 32", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := generateRandomString(tt.length)
			if err != nil {
				t.Fatalf("generateRandomString(%d) 返回错误: %v", tt.length, err)
			}
			if len(result) != tt.length {
				t.Errorf("generateRandomString(%d) 长度 = %d, want %d", tt.length, len(result), tt.length)
			}

			// 验证只包含允许的字符
			const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
			for _, c := range result {
				found := false
				for _, allowed := range charset {
					if c == allowed {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("generateRandomString() 包含非法字符: %c", c)
				}
			}
		})
	}
}

func TestGenerateRandomString_Unique(t *testing.T) {
	// 生成多个随机字符串，验证不重复
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s, err := generateRandomString(16)
		if err != nil {
			t.Fatalf("generateRandomString(16) 返回错误: %v", err)
		}
		if seen[s] {
			t.Errorf("generateRandomString() 生成了重复的字符串: %s", s)
		}
		seen[s] = true
	}
}

func TestPEMToPFX_InvalidCert(t *testing.T) {
	tests := []struct {
		name    string
		certPEM string
		keyPEM  string
		wantErr bool
	}{
		{
			"空证书",
			"",
			"-----BEGIN TEST KEY-----\ntest\n-----END TEST KEY-----",
			true,
		},
		{
			"无效证书 PEM",
			"not a pem",
			"-----BEGIN TEST KEY-----\ntest\n-----END TEST KEY-----",
			true,
		},
		{
			"空私钥",
			"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			"",
			true,
		},
		{
			"无效私钥 PEM",
			"-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			"not a pem",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PEMToPFX(tt.certPEM, tt.keyPEM, "", "password")
			if (err != nil) != tt.wantErr {
				t.Errorf("PEMToPFX() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPEMToPFX_Valid(t *testing.T) {
	certPEM, keyPEM := generateTestCertAndKey()

	pfxPath, err := PEMToPFX(certPEM, keyPEM, "", "testpassword")
	if err != nil {
		t.Fatalf("PEMToPFX() 返回错误: %v", err)
	}
	defer os.Remove(pfxPath)

	// 验证 PFX 文件存在且非空
	info, err := os.Stat(pfxPath)
	if err != nil {
		t.Fatalf("PFX 文件不存在: %v", err)
	}
	if info.Size() == 0 {
		t.Error("PFX 文件为空")
	}
}

func TestPEMToPFX_WithIntermediateChain(t *testing.T) {
	// 生成 CA 证书
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)
	caCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))

	// 生成终端实体证书，由 CA 签名
	eeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "ee.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"ee.example.com"},
	}
	eeCertDER, _ := x509.CreateCertificate(rand.Reader, eeTemplate, caCert, &eeKey.PublicKey, caKey)
	eeCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: eeCertDER}))

	eeKeyDER, _ := x509.MarshalECPrivateKey(eeKey)
	eeKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: eeKeyDER}))

	// 转换为 PFX，包含中间证书链
	pfxPath, err := PEMToPFX(eeCertPEM, eeKeyPEM, caCertPEM, "testpassword")
	if err != nil {
		t.Fatalf("PEMToPFX() 返回错误: %v", err)
	}
	defer os.Remove(pfxPath)

	info, err := os.Stat(pfxPath)
	if err != nil {
		t.Fatalf("PFX 文件不存在: %v", err)
	}
	if info.Size() == 0 {
		t.Error("PFX 文件为空")
	}
}

func TestPEMToPFX_InvalidKey(t *testing.T) {
	certPEM, _ := generateTestCertAndKey()

	// 使用损坏的密钥 PEM（有效的 PEM 头，但内容被篡改）
	corruptedKeyPEM := "-----BEGIN EC PRIVATE KEY-----\nYWJjZGVmZw==\n-----END EC PRIVATE KEY-----"

	_, err := PEMToPFX(certPEM, corruptedKeyPEM, "", "testpassword")
	if err == nil {
		t.Error("PEMToPFX() 应该对损坏的密钥返回错误")
	}
}
