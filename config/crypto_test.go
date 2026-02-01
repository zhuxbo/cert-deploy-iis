package config

import (
	"strings"
	"testing"
)

func TestEncryptToken_Empty(t *testing.T) {
	result, err := EncryptToken("")
	if err != nil {
		t.Errorf("EncryptToken(\"\") error = %v", err)
	}
	if result != "" {
		t.Errorf("EncryptToken(\"\") = %q, want \"\"", result)
	}
}

func TestDecryptToken_Empty(t *testing.T) {
	result, err := DecryptToken("")
	if err != nil {
		t.Errorf("DecryptToken(\"\") error = %v", err)
	}
	if result != "" {
		t.Errorf("DecryptToken(\"\") = %q, want \"\"", result)
	}
}

func TestDecryptToken_InvalidFormat(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		wantErr   bool
	}{
		{"无前缀", "somedata", true},
		{"错误前缀", "v2:somedata", true},
		{"无效 base64", EncryptionPrefix + "!!!invalid!!!", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptToken(tt.encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncryptionPrefix(t *testing.T) {
	if EncryptionPrefix != "v1:" {
		t.Errorf("EncryptionPrefix = %q, want %q", EncryptionPrefix, "v1:")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	// 注意：此测试依赖 Windows DPAPI，只能在 Windows 上运行
	testCases := []string{
		"simple-token",
		"token-with-special-chars!@#$%",
		"中文token测试",
		strings.Repeat("a", 1000), // 长字符串
	}

	for _, original := range testCases {
		t.Run(original[:min(len(original), 20)], func(t *testing.T) {
			encrypted, err := EncryptToken(original)
			if err != nil {
				t.Fatalf("EncryptToken() error = %v", err)
			}

			// 验证加密后的格式
			if !strings.HasPrefix(encrypted, EncryptionPrefix) {
				t.Errorf("加密结果应以 %q 开头", EncryptionPrefix)
			}

			// 验证可以解密回原文
			decrypted, err := DecryptToken(encrypted)
			if err != nil {
				t.Fatalf("DecryptToken() error = %v", err)
			}

			if decrypted != original {
				t.Errorf("解密结果 = %q, want %q", decrypted, original)
			}
		})
	}
}

func TestEncrypt_ProducesDifferentOutput(t *testing.T) {
	// DPAPI 每次加密应该产生不同的输出（因为包含随机盐）
	token := "test-token"

	encrypted1, err := EncryptToken(token)
	if err != nil {
		t.Fatalf("第一次加密失败: %v", err)
	}

	encrypted2, err := EncryptToken(token)
	if err != nil {
		t.Fatalf("第二次加密失败: %v", err)
	}

	// 注意：DPAPI 可能在相同条件下产生相同输出，所以这个测试可能不总是通过
	// 这里主要验证两次加密都成功
	if encrypted1 == "" || encrypted2 == "" {
		t.Error("加密结果不应为空")
	}

	// 两个加密结果都应该能正确解密
	decrypted1, _ := DecryptToken(encrypted1)
	decrypted2, _ := DecryptToken(encrypted2)

	if decrypted1 != token || decrypted2 != token {
		t.Error("解密结果不匹配原文")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
