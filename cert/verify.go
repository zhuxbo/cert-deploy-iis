package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"sslctlw/util"
)

// VerifyKeyPair 检查证书和私钥是否匹配（比较公钥）
// 返回：是否匹配、错误
func VerifyKeyPair(certPEM, keyPEM string) (bool, error) {
	// 解析证书
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return false, fmt.Errorf("无法解析证书 PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("解析证书失败: %w", err)
	}

	privateKey, err := parsePrivateKeyFromPEM(keyPEM, "")
	if err != nil {
		return false, fmt.Errorf("解析私钥失败: %w", err)
	}

	return privateKeyMatchesPublicKey(privateKey, cert.PublicKey)
}

// VerifyCSRKeyPair 验证 CSR 自签名，并确认其公钥与私钥匹配。
func VerifyCSRKeyPair(csrPEM, keyPEM string) (bool, error) {
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return false, fmt.Errorf("无法解析 CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return false, fmt.Errorf("解析 CSR 失败: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("CSR 签名验证失败: %w", err)
	}
	privateKey, err := parsePrivateKeyFromPEM(keyPEM, "")
	if err != nil {
		return false, fmt.Errorf("解析私钥失败: %w", err)
	}
	return privateKeyMatchesPublicKey(privateKey, csr.PublicKey)
}

// CSRDERHash 解析并验证 CSR 签名，返回其 DER 的 SHA256。
// 使用 DER 而不是 PEM 原文，避免换行与包裹宽度差异破坏归属判断。
func CSRDERHash(csrPEM string) (string, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR 签名验证失败: %w", err)
	}
	sum := sha256.Sum256(csr.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyCSRIdentity 验证服务端 CSR 是否属于本机已持久化的签发意图。
// 解析或签名错误返回 error；合法但 hash、公钥或 CN 不匹配返回 (false, nil)。
func VerifyCSRIdentity(csrPEM, keyPEM, expectedHash, expectedCN string) (bool, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return false, err
	}
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("CSR 签名验证失败: %w", err)
	}
	sum := sha256.Sum256(csr.Raw)
	if expectedHash == "" || !strings.EqualFold(hex.EncodeToString(sum[:]), expectedHash) {
		return false, nil
	}
	privateKey, err := parsePrivateKeyFromPEM(keyPEM, "")
	if err != nil {
		return false, fmt.Errorf("解析私钥失败: %w", err)
	}
	matched, err := privateKeyMatchesPublicKey(privateKey, csr.PublicKey)
	if err != nil || !matched {
		return matched, err
	}
	return util.NormalizeDomain(csr.Subject.CommonName) == util.NormalizeDomain(expectedCN), nil
}

func privateKeyMatchesPublicKey(privateKey, publicKey any) (bool, error) {
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if rsaPub, ok := publicKey.(*rsa.PublicKey); ok {
			return priv.PublicKey.N.Cmp(rsaPub.N) == 0 && priv.PublicKey.E == rsaPub.E, nil
		}
		return false, nil
	case *ecdsa.PrivateKey:
		if ecdsaPub, ok := publicKey.(*ecdsa.PublicKey); ok {
			return priv.PublicKey.X.Cmp(ecdsaPub.X) == 0 && priv.PublicKey.Y.Cmp(ecdsaPub.Y) == 0, nil
		}
		return false, nil
	case ed25519.PrivateKey:
		if edPub, ok := publicKey.(ed25519.PublicKey); ok {
			pub := priv.Public().(ed25519.PublicKey)
			return bytes.Equal(pub, edPub), nil
		}
		return false, nil
	default:
		return false, fmt.Errorf("不支持的密钥类型")
	}
}

// ParseCertificate 解析证书 PEM
func ParseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解析证书 PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败: %w", err)
	}

	return cert, nil
}

// GetCertThumbprint 获取证书指纹（SHA1）
func GetCertThumbprint(certPEM string) (string, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return "", err
	}

	// 计算 SHA1 指纹
	fingerprint := sha1.Sum(cert.Raw)

	// 转换为十六进制字符串（大写）
	return strings.ToUpper(hex.EncodeToString(fingerprint[:])), nil
}

// GetCertSerialNumber 获取证书序列号
func GetCertSerialNumber(certPEM string) (string, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return "", err
	}

	// 序列号转换为十六进制字符串（大写）
	return fmt.Sprintf("%X", cert.SerialNumber), nil
}

// ExtractDomainsFromPEM 从证书 PEM 提取域名列表（CN + SAN 去重）
// 返回去重后的域名列表，CN 在首位
func ExtractDomainsFromPEM(certPEM string) ([]string, error) {
	cert, err := ParseCertificate(certPEM)
	if err != nil {
		return nil, err
	}

	// SAN (DNSNames) 必定包含 CN，直接使用 DNSNames
	seen := make(map[string]bool)
	var domains []string
	for _, d := range cert.DNSNames {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}

	return domains, nil
}

// normalizeSerialNumber 规范化序列号（去除空格、前导零，转大写）
func normalizeSerialNumber(sn string) string {
	// 去除空格
	sn = strings.ReplaceAll(sn, " ", "")
	// 转大写
	sn = strings.ToUpper(sn)
	// 去除前导零（但保留至少一个字符）
	sn = strings.TrimLeft(sn, "0")
	if sn == "" {
		sn = "0"
	}
	return sn
}

// IsCertExists 检查证书是否已存在（按序列号）
func IsCertExists(serialNumber string) (bool, *CertInfo, error) {
	certs, err := ListCertificates()
	if err != nil {
		return false, nil, err
	}

	normalizedInput := normalizeSerialNumber(serialNumber)
	for i := range certs {
		if normalizeSerialNumber(certs[i].SerialNumber) == normalizedInput {
			return true, &certs[i], nil
		}
	}

	return false, nil, nil
}
