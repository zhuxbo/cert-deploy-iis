package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
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

	// 比较公钥
	certPubKey := cert.PublicKey
	switch priv := privateKey.(type) {
	case *rsa.PrivateKey:
		if rsaPub, ok := certPubKey.(*rsa.PublicKey); ok {
			return priv.PublicKey.N.Cmp(rsaPub.N) == 0 && priv.PublicKey.E == rsaPub.E, nil
		}
		return false, nil
	case *ecdsa.PrivateKey:
		if ecdsaPub, ok := certPubKey.(*ecdsa.PublicKey); ok {
			return priv.PublicKey.X.Cmp(ecdsaPub.X) == 0 && priv.PublicKey.Y.Cmp(ecdsaPub.Y) == 0, nil
		}
		return false, nil
	case ed25519.PrivateKey:
		if edPub, ok := certPubKey.(ed25519.PublicKey); ok {
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
