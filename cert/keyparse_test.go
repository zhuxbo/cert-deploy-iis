package cert

import (
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
