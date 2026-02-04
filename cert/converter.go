package cert

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// PEMToPFX 将 PEM 格式的证书和私钥转换为 PFX 格式
// 返回 PFX 文件路径
func PEMToPFX(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
	// 解析私钥（支持加密 PEM / EC）
	privateKey, err := parsePrivateKeyFromPEM(keyPEM, password)
	if err != nil {
		return "", fmt.Errorf("解析私钥失败: %w", err)
	}

	// 解析证书
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return "", fmt.Errorf("无法解析证书 PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("解析证书失败: %w", err)
	}

	// 解析中间证书链
	var caCerts []*x509.Certificate
	if intermediatePEM != "" {
		remaining := []byte(intermediatePEM)
		certIndex := 0
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				certIndex++
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					// 记录警告但继续处理其他证书
					fmt.Printf("警告: 无法解析证书链中的第 %d 个证书: %v\n", certIndex, err)
				} else {
					caCerts = append(caCerts, caCert)
				}
			}
			remaining = rest
		}
	}

	// 生成 PFX
	pfxData, err := pkcs12.Modern.Encode(privateKey, cert, caCerts, password)
	if err != nil {
		return "", fmt.Errorf("生成 PFX 失败: %w", err)
	}

	// 写入临时文件
	tempDir := os.TempDir()
	pfxPath := filepath.Join(tempDir, fmt.Sprintf("cert_%s.pfx", generateRandomString(8)))

	if err := os.WriteFile(pfxPath, pfxData, 0600); err != nil {
		return "", fmt.Errorf("写入 PFX 文件失败: %w", err)
	}

	return pfxPath, nil
}

// generateRandomString 生成随机字符串
// 使用加密安全的随机数，失败时结合时间戳确保唯一性
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// rand.Read 失败极为罕见（仅当系统熵源不可用时）
		// 结合时间戳和进程 ID 确保唯一性，但安全性降低
		fmt.Printf("警告: 加密随机数生成失败: %v，使用降级方案\n", err)
		return fmt.Sprintf("%d_%d", time.Now().UnixNano(), os.Getpid())
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
