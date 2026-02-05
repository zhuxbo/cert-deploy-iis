package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestIsPrivateKeyBlockType(t *testing.T) {
	tests := []struct {
		name      string
		blockType string
		want      bool
	}{
		{"RSA PRIVATE KEY", "RSA PRIVATE KEY", true},
		{"EC PRIVATE KEY", "EC PRIVATE KEY", true},
		{"PRIVATE KEY", "PRIVATE KEY", true},
		{"ENCRYPTED PRIVATE KEY", "ENCRYPTED PRIVATE KEY", true},
		{"CERTIFICATE", "CERTIFICATE", false},
		{"PUBLIC KEY", "PUBLIC KEY", false},
		{"CERTIFICATE REQUEST", "CERTIFICATE REQUEST", false},
		{"空字符串", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrivateKeyBlockType(tt.blockType)
			if got != tt.want {
				t.Errorf("isPrivateKeyBlockType(%q) = %v, want %v", tt.blockType, got, tt.want)
			}
		})
	}
}

func TestParsePrivateKeyFromPEM_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		pemData  string
		password string
		wantErr  bool
	}{
		{"空字符串", "", "", true},
		{"无效 PEM", "not a pem", "", true},
		{"证书而非私钥", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----", "", true},
		{"无效的私钥数据", "-----BEGIN TEST KEY-----\ninvalid\n-----END TEST KEY-----", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePrivateKeyFromPEM(tt.pemData, tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePrivateKeyFromPEM() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParsePrivateKeyBlock_NeedsPassword(t *testing.T) {
	// 测试加密私钥需要密码的情况
	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("dummy"),
	}

	_, err := parsePrivateKeyBlock(block, "")
	if err == nil {
		t.Error("parsePrivateKeyBlock() 应该对缺少密码的加密私钥返回错误")
	}
	if err.Error() != "私钥已加密，缺少密码" {
		t.Errorf("错误消息不匹配: %v", err)
	}
}

func TestParsePrivateKeyBlock_LegacyEncryptedRSA(t *testing.T) {
	// 生成 RSA 密钥
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	password := []byte("test-password")

	// 用旧式 PEM 加密（DEK-Info）加密 RSA 私钥
	//nolint:staticcheck // 测试旧式 PEM 加密解密路径
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(rsaKey), password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("加密 PEM 块失败: %v", err)
	}

	// 验证 DEK-Info header 存在
	if _, ok := encBlock.Headers["DEK-Info"]; !ok {
		t.Fatal("加密后的 PEM 块应该有 DEK-Info header")
	}

	// 解析应该成功
	key, err := parsePrivateKeyBlock(encBlock, string(password))
	if err != nil {
		t.Fatalf("parsePrivateKeyBlock() 旧式加密 RSA 解密失败: %v", err)
	}
	if key == nil {
		t.Fatal("parsePrivateKeyBlock() 返回 nil")
	}

	// 验证返回的是 RSA 密钥
	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("期望 *rsa.PrivateKey，得到 %T", key)
	}
}

func TestParsePrivateKeyBlock_LegacyEncryptedEC(t *testing.T) {
	// 生成 EC 密钥
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 密钥失败: %v", err)
	}

	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("序列化 EC 密钥失败: %v", err)
	}

	password := []byte("test-password")

	// 用旧式 PEM 加密
	//nolint:staticcheck // 测试旧式 PEM 加密解密路径
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY",
		ecDER, password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("加密 PEM 块失败: %v", err)
	}

	// 解析应该成功
	key, err := parsePrivateKeyBlock(encBlock, string(password))
	if err != nil {
		t.Fatalf("parsePrivateKeyBlock() 旧式加密 EC 解密失败: %v", err)
	}
	if key == nil {
		t.Fatal("parsePrivateKeyBlock() 返回 nil")
	}

	// 验证返回的是 EC 密钥
	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("期望 *ecdsa.PrivateKey，得到 %T", key)
	}
}

func TestParsePrivateKeyBlock_LegacyEncrypted_NoPassword(t *testing.T) {
	// 生成并加密一个 RSA 密钥
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	//nolint:staticcheck // 测试旧式 PEM 加密
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(rsaKey), []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("加密 PEM 块失败: %v", err)
	}

	// 不提供密码应该报错
	_, err = parsePrivateKeyBlock(encBlock, "")
	if err == nil {
		t.Error("缺少密码时应该返回错误")
	}
}

func TestParsePrivateKeyBlock_LegacyEncrypted_WrongPassword(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	//nolint:staticcheck // 测试旧式 PEM 加密
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY",
		x509.MarshalPKCS1PrivateKey(rsaKey), []byte("correct"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("加密 PEM 块失败: %v", err)
	}

	// 错误密码应该返回错误
	_, err = parsePrivateKeyBlock(encBlock, "wrong")
	if err == nil {
		t.Error("错误密码时应该返回错误")
	}
}

func TestParsePrivateKeyFromPEM_RSA(t *testing.T) {
	// 使用 Go 标准库生成一个 RSA 私钥用于测试
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
	})

	key, err := parsePrivateKeyFromPEM(string(pemBytes), "")
	if err != nil {
		t.Fatalf("parsePrivateKeyFromPEM() 错误: %v", err)
	}
	if key == nil {
		t.Fatal("parsePrivateKeyFromPEM() 返回 nil")
	}
}

func TestParsePrivateKeyFromPEM_EC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 EC 密钥失败: %v", err)
	}

	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("序列化 EC 密钥失败: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	})

	key, err := parsePrivateKeyFromPEM(string(pemBytes), "")
	if err != nil {
		t.Fatalf("parsePrivateKeyFromPEM() 错误: %v", err)
	}
	if key == nil {
		t.Fatal("parsePrivateKeyFromPEM() 返回 nil")
	}
}

func TestParsePrivateKeyFromPEM_PKCS8(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}

	derBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("序列化 PKCS8 密钥失败: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	})

	key, err := parsePrivateKeyFromPEM(string(pemBytes), "")
	if err != nil {
		t.Fatalf("parsePrivateKeyFromPEM() 错误: %v", err)
	}
	if key == nil {
		t.Fatal("parsePrivateKeyFromPEM() 返回 nil")
	}
}
