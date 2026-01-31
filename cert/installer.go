package cert

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cert-deploy/util"
)

// InstallResult 安装结果
type InstallResult struct {
	Success      bool
	Thumbprint   string
	ErrorMessage string
}

// InstallPFX 安装 PFX 证书到 LocalMachine\My
func InstallPFX(pfxPath, password string) (*InstallResult, error) {
	// 检查文件是否存在
	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("PFX 文件不存在: %s", pfxPath)
	}

	// 获取绝对路径
	absPath, err := filepath.Abs(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("获取绝对路径失败: %v", err)
	}

	// 使用 PowerShell 导入证书
	script := fmt.Sprintf(`
$password = ConvertTo-SecureString -String '%s' -Force -AsPlainText
$cert = Import-PfxCertificate -FilePath '%s' -CertStoreLocation Cert:\LocalMachine\My -Password $password -Exportable
if ($cert) {
    Write-Output "Thumbprint: $($cert.Thumbprint)"
} else {
    Write-Error "导入失败"
}
`, escapePassword(password), absPath)

	outputStr, err := util.RunPowerShellCombined(script)

	if err != nil {
		// 简化错误信息
		errMsg := simplifyPFXError(outputStr)
		return &InstallResult{
			Success:      false,
			ErrorMessage: errMsg,
		}, nil
	}

	// 解析指纹
	thumbprint := ""
	for _, line := range strings.Split(outputStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Thumbprint: ") {
			thumbprint = strings.TrimPrefix(line, "Thumbprint: ")
			thumbprint = strings.ToUpper(strings.TrimSpace(thumbprint))
			break
		}
	}

	if thumbprint == "" {
		return &InstallResult{
			Success:      false,
			ErrorMessage: "导入成功但未能获取证书指纹",
		}, nil
	}

	return &InstallResult{
		Success:    true,
		Thumbprint: thumbprint,
	}, nil
}

// InstallPEM 从 PEM 格式证书和私钥安装（先转换为 PFX）
func InstallPEM(certPath, keyPath, password string) (*InstallResult, error) {
	// 检查文件是否存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("证书文件不存在: %s", certPath)
	}
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("私钥文件不存在: %s", keyPath)
	}

	return installPEMWithGo(certPath, keyPath, password)
}

// installPEMWithGo 使用 Go 生成 PFX 并安装 PEM 证书
func installPEMWithGo(certPath, keyPath, password string) (*InstallResult, error) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert file failed: %w", err)
	}
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key file failed: %w", err)
	}

	leafPEM, chainPEM := splitPEMCertChain(string(certBytes))
	pfxPath, err := PEMToPFX(leafPEM, string(keyBytes), chainPEM, password)
	if err != nil {
		return &InstallResult{
			Success:      false,
			ErrorMessage: fmt.Sprintf("convert pem to pfx failed: %v", err),
		}, nil
	}
	defer os.Remove(pfxPath)

	return InstallPFX(pfxPath, password)
}

func splitPEMCertChain(pemData string) (string, string) {
	rest := []byte(pemData)
	leaf := ""
	var chain strings.Builder

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		encoded := pem.EncodeToMemory(block)
		if encoded == nil {
			continue
		}
		if leaf == "" {
			leaf = string(encoded)
		} else {
			chain.Write(encoded)
		}
	}

	if leaf == "" {
		return pemData, ""
	}
	return leaf, chain.String()
}

// escapePassword 转义密码中的特殊字符
func escapePassword(password string) string {
	// 转义 PowerShell 特殊字符
	password = strings.ReplaceAll(password, "'", "''")   // 单引号
	password = strings.ReplaceAll(password, "`", "``")   // 反引号
	password = strings.ReplaceAll(password, "$", "`$")   // 美元符号
	return password
}

// simplifyPFXError 简化 PFX 导入错误信息
func simplifyPFXError(output string) string {
	outputLower := strings.ToLower(output)

	// 检查常见错误
	if strings.Contains(outputLower, "password") || strings.Contains(outputLower, "密码") {
		return "密码错误或证书文件损坏"
	}
	if strings.Contains(outputLower, "access") || strings.Contains(outputLower, "denied") {
		return "访问被拒绝，请以管理员权限运行"
	}
	if strings.Contains(outputLower, "not found") || strings.Contains(outputLower, "找不到") {
		return "文件不存在"
	}
	if strings.Contains(outputLower, "invalid") || strings.Contains(outputLower, "无效") {
		return "无效的证书文件格式"
	}

	// 如果错误信息太长，截取前100个字符
	if len(output) > 100 {
		return "导入失败: " + output[:100] + "..."
	}
	return "导入失败: " + output
}

// VerifyCertificate 验证证书是否有效
func VerifyCertificate(thumbprint string) (bool, string, error) {
	cert, err := GetCertByThumbprint(thumbprint)
	if err != nil {
		return false, "", err
	}

	status := GetCertStatus(cert)
	valid := status == "有效" || strings.HasPrefix(status, "临近过期")

	return valid, status, nil
}
