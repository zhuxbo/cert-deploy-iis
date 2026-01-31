package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/youmark/pkcs8"
)

func parsePrivateKeyFromPEM(pemData string, password string) (interface{}, error) {
	data := []byte(pemData)
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if !isPrivateKeyBlockType(block.Type) {
			continue
		}
		return parsePrivateKeyBlock(block, password)
	}
	return nil, fmt.Errorf("无法解析私钥 PEM")
}

func isPrivateKeyBlockType(blockType string) bool {
	switch blockType {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		return true
	default:
		return false
	}
}

func parsePrivateKeyBlock(block *pem.Block, password string) (interface{}, error) {
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		if password == "" {
			return nil, fmt.Errorf("私钥已加密，缺少密码")
		}
		key, _, err := pkcs8.ParsePrivateKey(block.Bytes, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("解密 PKCS#8 私钥失败: %w", err)
		}
		return key, nil
	}

	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, fmt.Errorf("私钥已加密，缺少密码")
		}
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("私钥解密失败: %w", err)
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(der)
	default:
		if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
			return key, nil
		}
		if key, err := x509.ParseECPrivateKey(der); err == nil {
			return key, nil
		}
		return nil, fmt.Errorf("不支持的私钥类型: %s", block.Type)
	}
}
