package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateCSR 生成私钥和 CSR
// domain: 主域名（Common Name）
// sans: 额外的 Subject Alternative Names
// 返回：私钥 PEM、CSR PEM、错误
func GenerateCSR(domain string, sans []string) (keyPEM, csrPEM string, err error) {
	// 生成 RSA 私钥（2048 位）
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("生成私钥失败: %w", err)
	}

	// 构建 CSR 模板
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// 添加 SANs（包括主域名）
	allDomains := []string{domain}
	for _, san := range sans {
		if san != domain {
			allDomains = append(allDomains, san)
		}
	}
	template.DNSNames = allDomains

	// 创建 CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("创建 CSR 失败: %w", err)
	}

	// 编码私钥为 PEM
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	keyPEM = string(pem.EncodeToMemory(keyBlock))

	// 编码 CSR 为 PEM
	csrBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}
	csrPEM = string(pem.EncodeToMemory(csrBlock))

	return keyPEM, csrPEM, nil
}

// ParseCSR 解析 CSR PEM，提取域名信息
func ParseCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("无效的 CSR PEM")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析 CSR 失败: %w", err)
	}

	return csr, nil
}
