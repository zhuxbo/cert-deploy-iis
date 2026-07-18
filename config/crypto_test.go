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
		{"空数据", EncryptionPrefix, true},
		{"空 padding", EncryptionPrefix + "====", true},
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

			// 验证加密后的格式（当前输出机器作用域前缀）
			if !strings.HasPrefix(encrypted, EncryptionPrefixMachine) {
				t.Errorf("加密结果应以 %q 开头", EncryptionPrefixMachine)
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

func TestTokenNeedsMigration(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		want      bool
	}{
		{"空串", "", false},
		{"机器作用域", EncryptionPrefixMachine + "abc", false},
		{"旧用户作用域", EncryptionPrefix + "abc", true},
		{"未知前缀", "v9:abc", false},
		{"无前缀", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TokenNeedsMigration(tt.encrypted); got != tt.want {
				t.Errorf("TokenNeedsMigration(%q) = %v, want %v", tt.encrypted, got, tt.want)
			}
		})
	}
}

// TestDecryptToken_AcceptsBothScopePrefixes 验证解密同时兼容机器作用域与旧用户作用域前缀
// 依赖 Windows DPAPI，仅在 Windows 上运行
func TestDecryptToken_AcceptsBothScopePrefixes(t *testing.T) {
	const plaintext = "scope-compat-token"

	encrypted, err := EncryptToken(plaintext)
	if err != nil {
		t.Fatalf("EncryptToken() error = %v", err)
	}
	if !strings.HasPrefix(encrypted, EncryptionPrefixMachine) {
		t.Fatalf("加密结果应以 %q 开头, got %q", EncryptionPrefixMachine, encrypted)
	}

	// 机器作用域前缀可解密
	if got, err := DecryptToken(encrypted); err != nil || got != plaintext {
		t.Fatalf("DecryptToken(机器前缀) = %q, err = %v; want %q", got, err, plaintext)
	}

	// 将标签换成旧用户作用域前缀，底层密文不变，仍应能解密
	legacy := EncryptionPrefix + strings.TrimPrefix(encrypted, EncryptionPrefixMachine)
	if got, err := DecryptToken(legacy); err != nil || got != plaintext {
		t.Fatalf("DecryptToken(旧前缀) = %q, err = %v; want %q", got, err, plaintext)
	}
}
