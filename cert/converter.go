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
		for {
			block, rest := pem.Decode(remaining)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
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
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		// 回退到时间戳
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
