package cert

import (
	"testing"
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
			result := generateRandomString(tt.length)
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
		s := generateRandomString(16)
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
			"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
			true,
		},
		{
			"无效证书 PEM",
			"not a pem",
			"-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
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

// TestPEMToPFX_Valid 需要有效的证书和私钥对
// 跳过：需要有效的测试证书
func TestPEMToPFX_Valid(t *testing.T) {
	t.Skip("跳过：需要有效的测试证书和私钥对")
}
