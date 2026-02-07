// +build windows

package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewAuthenticodeVerifier 测试创建验证器
func TestNewAuthenticodeVerifier(t *testing.T) {
	verifier := NewAuthenticodeVerifier()
	if verifier == nil {
		t.Fatal("NewAuthenticodeVerifier 返回 nil")
	}
}

// TestVerifyResult 测试验证结果结构
func TestVerifyResult(t *testing.T) {
	result := &VerifyResult{
		Valid:            true,
		Fingerprint:      "ABC123",
		Subject:          "Test Subject",
		Organization:     "Test Org",
		Country:          "CN",
		Issuer:           "Test CA",
		FingerprintMatch: true,
		FallbackUsed:     false,
		NeedsConfirm:     false,
		Message:          "验证成功",
	}

	if !result.Valid {
		t.Error("Valid 应该为 true")
	}

	if result.Message != "验证成功" {
		t.Errorf("Message = %q, want '验证成功'", result.Message)
	}
}

// TestFallbackVerifyConfig 测试回退验证配置
func TestFallbackVerifyConfig(t *testing.T) {
	cfg := &FallbackVerifyConfig{
		TrustedOrg:     "MyOrg",
		TrustedCountry: "CN",
		TrustedCAs:     []string{"DigiCert", "Sectigo"},
	}

	if cfg.TrustedOrg != "MyOrg" {
		t.Errorf("TrustedOrg = %q, want 'MyOrg'", cfg.TrustedOrg)
	}

	if len(cfg.TrustedCAs) != 2 {
		t.Errorf("TrustedCAs 长度 = %d, want 2", len(cfg.TrustedCAs))
	}
}

// TestVerifyUnsignedFile 测试验证未签名文件
func TestVerifyUnsignedFile(t *testing.T) {
	// 创建一个临时未签名的 exe 文件
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "unsigned.exe")

	// 写入一个最小的 PE 头（足以让 Windows 识别为 exe）
	// MZ 头 + 最小 PE 结构
	peData := []byte{
		'M', 'Z', // DOS 签名
		0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00,
		0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // PE 头偏移
		// PE 签名位置
	}
	// 填充到 PE 头位置
	for len(peData) < 0x80 {
		peData = append(peData, 0)
	}
	// 添加 PE 签名
	peData = append(peData, 'P', 'E', 0, 0)

	if err := os.WriteFile(tmpFile, peData, 0644); err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}

	verifier := NewAuthenticodeVerifier()
	result, err := verifier.Verify(tmpFile, nil, nil)

	// 未签名文件应该验证失败
	if err == nil && result != nil && result.Valid {
		t.Error("未签名文件不应该通过验证")
	}

	t.Logf("未签名文件验证结果: err=%v, result=%+v", err, result)
}

// TestVerifyNonExistentFile 测试验证不存在的文件
func TestVerifyNonExistentFile(t *testing.T) {
	verifier := NewAuthenticodeVerifier()
	result, err := verifier.Verify("/nonexistent/file.exe", nil, nil)

	// 验证不存在的文件应该返回错误或 Valid=false
	if err == nil && result != nil && result.Valid {
		t.Error("不存在的文件不应该通过验证")
	}

	t.Logf("验证不存在的文件: err=%v, result=%+v", err, result)
}

// TestVerifyCurrentExecutable 测试验证当前可执行文件（如果已签名）
func TestVerifyCurrentExecutable(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("无法获取当前可执行文件: %v", err)
	}

	// 解析符号链接
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Skipf("无法解析符号链接: %v", err)
	}

	verifier := NewAuthenticodeVerifier()
	result, err := verifier.Verify(exe, nil, nil)

	// 测试环境的 go test 二进制可能未签名，这是正常的
	if err != nil {
		t.Logf("验证当前可执行文件失败（可能未签名）: %v", err)
	} else if result != nil {
		t.Logf("验证结果: Valid=%v, Subject=%s, Issuer=%s",
			result.Valid, result.Subject, result.Issuer)
	}
}
