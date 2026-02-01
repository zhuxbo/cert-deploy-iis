package cert

import (
	"strings"
	"testing"
)

func TestSplitPEMCertChain(t *testing.T) {
	// 单个证书
	singleCert := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjECMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjbjAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjbjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+eKsiR4fZj4rCLes
-----END CERTIFICATE-----`

	// 带中间证书的证书链
	certChain := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjECMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjbjAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjbjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+eKsiR4fZj4rCLes
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjEDMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmlu
dGVybWVkaWF0ZTAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzAN
BgNVBAMMBmludGVybWVkaWF0ZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h
-----END CERTIFICATE-----`

	tests := []struct {
		name       string
		pemData    string
		wantLeaf   bool
		wantChain  bool
		chainCount int
	}{
		{"单个证书", singleCert, true, false, 0},
		{"证书链", certChain, true, true, 1},
		{"空字符串", "", false, false, 0},
		{"无效 PEM", "not a pem", false, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			leaf, chain := splitPEMCertChain(tt.pemData)

			hasLeaf := strings.Contains(leaf, "-----BEGIN CERTIFICATE-----")
			if hasLeaf != tt.wantLeaf {
				t.Errorf("splitPEMCertChain() hasLeaf = %v, want %v", hasLeaf, tt.wantLeaf)
			}

			hasChain := strings.Contains(chain, "-----BEGIN CERTIFICATE-----")
			if hasChain != tt.wantChain {
				t.Errorf("splitPEMCertChain() hasChain = %v, want %v", hasChain, tt.wantChain)
			}

			if tt.chainCount > 0 {
				count := strings.Count(chain, "-----BEGIN CERTIFICATE-----")
				if count != tt.chainCount {
					t.Errorf("splitPEMCertChain() chain count = %d, want %d", count, tt.chainCount)
				}
			}
		})
	}
}

func TestSimplifyPFXError(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"密码错误-英文", "The password is incorrect", "密码错误或证书文件损坏"},
		{"密码错误-中文", "密码错误", "密码错误或证书文件损坏"},
		{"访问被拒绝", "Access denied", "访问被拒绝，请以管理员权限运行"},
		{"文件不存在-英文", "file not found", "文件不存在"},
		{"文件不存在-中文", "找不到文件", "文件不存在"},
		{"格式无效-英文", "invalid format", "无效的证书文件格式"},
		{"格式无效-中文", "格式无效", "无效的证书文件格式"},
		{"短错误消息", "error", "导入失败: error"},
		{"长错误消息", strings.Repeat("x", 150), "导入失败: " + strings.Repeat("x", 100) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := simplifyPFXError(tt.output)
			if got != tt.want {
				t.Errorf("simplifyPFXError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInstallPFX_FileNotExists(t *testing.T) {
	_, err := InstallPFX("/nonexistent/file.pfx", "")
	if err == nil {
		t.Error("InstallPFX() 应该对不存在的文件返回错误")
	}
	if !strings.Contains(err.Error(), "不存在") {
		t.Errorf("错误消息应包含'不存在', got: %v", err)
	}
}

func TestInstallPEM_FileNotExists(t *testing.T) {
	// 测试证书文件不存在
	_, err := InstallPEM("/nonexistent/cert.pem", "/nonexistent/key.pem", "")
	if err == nil {
		t.Error("InstallPEM() 应该对不存在的证书文件返回错误")
	}
	if !strings.Contains(err.Error(), "不存在") {
		t.Errorf("错误消息应包含'不存在', got: %v", err)
	}
}

func TestInstallResult_Fields(t *testing.T) {
	result := InstallResult{
		Success:      true,
		Thumbprint:   "ABC123DEF456",
		ErrorMessage: "",
	}

	if !result.Success {
		t.Error("Success 应该为 true")
	}
	if result.Thumbprint != "ABC123DEF456" {
		t.Errorf("Thumbprint = %q", result.Thumbprint)
	}
	if result.ErrorMessage != "" {
		t.Errorf("ErrorMessage = %q", result.ErrorMessage)
	}

	// 测试失败结果
	failResult := InstallResult{
		Success:      false,
		Thumbprint:   "",
		ErrorMessage: "安装失败",
	}

	if failResult.Success {
		t.Error("Success 应该为 false")
	}
	if failResult.ErrorMessage != "安装失败" {
		t.Errorf("ErrorMessage = %q", failResult.ErrorMessage)
	}
}

func TestSplitPEMCertChain_MoreCases(t *testing.T) {
	// 测试多个中间证书
	multiChain := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjECMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjbjAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjbjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+eKsiR4fZj4rCLes
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjEDMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmlu
dGVybWVkaWF0ZTEwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjARMQ8w
DQYDVQQDDAZpbnRlcm1lZGlhdGUxMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALuj
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjEEMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmlu
dGVybWVkaWF0ZTIwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjARMQ8w
DQYDVQQDDAZpbnRlcm1lZGlhdGUyMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALuj
-----END CERTIFICATE-----`

	leaf, chain := splitPEMCertChain(multiChain)

	// 验证叶证书
	if !strings.Contains(leaf, "-----BEGIN CERTIFICATE-----") {
		t.Error("叶证书应该包含 PEM 头")
	}

	// 验证中间证书链
	chainCount := strings.Count(chain, "-----BEGIN CERTIFICATE-----")
	if chainCount != 2 {
		t.Errorf("中间证书数量 = %d, 期望 2", chainCount)
	}
}

func TestSplitPEMCertChain_WithPrivateKey(t *testing.T) {
	// 测试包含私钥的输入（私钥应该被忽略）
	mixedPEM := `-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpegPjECMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjbjAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjbjBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96h+eKsiR4fZj4rCLes
-----END CERTIFICATE-----
-----BEGIN TEST KEY-----
MIIEowIBAAKCAQEAu6OXu0b0v1bzjvuRyV9RY2eT/KecF8ReamC/3jySMXhjb8CV
-----END TEST KEY-----`

	leaf, chain := splitPEMCertChain(mixedPEM)

	// 验证叶证书存在
	if !strings.Contains(leaf, "-----BEGIN CERTIFICATE-----") {
		t.Error("叶证书应该包含 PEM 头")
	}

	// 验证私钥没有包含在输出中
	if strings.Contains(leaf, "PRIVATE KEY") {
		t.Error("叶证书不应包含私钥")
	}
	if strings.Contains(chain, "PRIVATE KEY") {
		t.Error("证书链不应包含私钥")
	}
}

func TestSimplifyPFXError_MoreCases(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		// 大小写变体
		{"密码大写", "PASSWORD INCORRECT", "密码错误或证书文件损坏"},
		{"访问大写", "ACCESS DENIED", "访问被拒绝，请以管理员权限运行"},
		{"不存在大写", "NOT FOUND", "文件不存在"},
		{"无效大写", "INVALID FORMAT", "无效的证书文件格式"},

		// 混合大小写
		{"密码混合", "Password incorrect", "密码错误或证书文件损坏"},
		{"访问混合", "Access Denied", "访问被拒绝，请以管理员权限运行"},

		// 空输入
		{"空字符串", "", "导入失败: "},

		// 100 字符边界
		{"正好100字符", strings.Repeat("a", 100), "导入失败: " + strings.Repeat("a", 100)},
		{"101字符", strings.Repeat("a", 101), "导入失败: " + strings.Repeat("a", 100) + "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := simplifyPFXError(tt.output)
			if got != tt.want {
				t.Errorf("simplifyPFXError(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}
