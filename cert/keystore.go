package cert

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"encoding/pem"
	"sslctlw/config"
)

// KeyEncryptionPrefix 旧的用户作用域私钥前缀（仅用于兼容解密）
const KeyEncryptionPrefix = "v1:dpapi:"

// KeyEncryptionPrefixMachine 机器作用域私钥前缀（当前加密输出）
const KeyEncryptionPrefixMachine = "vm:dpapi:"

// 文件大小限制（spec 11）
const (
	MaxPrivateKeySize = 16 * 1024 // 16KB - 私钥 PEM 大小上限
	MaxCertChainSize  = 64 * 1024 // 64KB - 证书链（cert + intermediate）大小上限
)

// EncryptPrivateKey 使用 DPAPI（机器作用域）加密私钥
func EncryptPrivateKey(keyPEM string) (string, error) {
	if keyPEM == "" {
		return "", nil
	}
	encrypted, err := config.EncryptToken(keyPEM)
	if err != nil {
		return "", err
	}
	// config.EncryptToken 当前输出机器作用域前缀，替换为私钥专用机器前缀
	return KeyEncryptionPrefixMachine + strings.TrimPrefix(encrypted, config.EncryptionPrefixMachine), nil
}

// DecryptPrivateKey 使用 DPAPI 解密私钥，兼容机器作用域与旧用户作用域两种前缀
func DecryptPrivateKey(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	// 提取 base64 数据后交给底层 DecryptToken（解密作用域由密文自身决定）
	switch {
	case strings.HasPrefix(encrypted, KeyEncryptionPrefixMachine):
		base64Data := strings.TrimPrefix(encrypted, KeyEncryptionPrefixMachine)
		return config.DecryptToken(config.EncryptionPrefixMachine + base64Data)
	case strings.HasPrefix(encrypted, KeyEncryptionPrefix):
		base64Data := strings.TrimPrefix(encrypted, KeyEncryptionPrefix)
		return config.DecryptToken(config.EncryptionPrefix + base64Data)
	default:
		return "", errors.New("无效的私钥格式")
	}
}

// KeyNeedsMigration 判断私钥密文是否为旧用户作用域格式（需迁移到机器作用域）
// 纯字符串判定，不触发 DPAPI，便于测试
func KeyNeedsMigration(encrypted string) bool {
	if strings.HasPrefix(encrypted, KeyEncryptionPrefixMachine) {
		return false
	}
	return strings.HasPrefix(encrypted, KeyEncryptionPrefix)
}

// OrderMeta 订单元数据
type OrderMeta struct {
	OrderID         int      `json:"order_id"`
	Domain          string   `json:"domain"`
	Domains         []string `json:"domains"`
	Status          string   `json:"status"`
	ExpiresAt       string   `json:"expires_at"`
	CreatedAt       string   `json:"created_at"`
	LastDeployed    string   `json:"last_deployed,omitempty"`
	Thumbprint      string   `json:"thumbprint,omitempty"`
	IssueRetryCount int      `json:"issue_retry_count,omitempty"` // CSR 提交重试次数
	LastIssueState  string   `json:"last_issue_state,omitempty"`  // 上次签发状态
	CSRSubmittedAt  string   `json:"csr_submitted_at,omitempty"`  // CSR 提交时间
}

// OrderStore 本地订单存储
type OrderStore struct {
	BaseDir string // 默认 {程序目录}/sslctlw/orders/
}

// NewOrderStore 创建订单存储（使用 config.GetDataDir() 保持路径一致）
func NewOrderStore() *OrderStore {
	baseDir := filepath.Join(config.GetDataDir(), "orders")
	return &OrderStore{BaseDir: baseDir}
}

// GetOrderPath 获取订单目录路径
func (s *OrderStore) GetOrderPath(orderID int) string {
	return filepath.Join(s.BaseDir, strconv.Itoa(orderID))
}

// EnsureOrderDir 确保订单目录存在
func (s *OrderStore) EnsureOrderDir(orderID int) error {
	orderPath := s.GetOrderPath(orderID)
	return os.MkdirAll(orderPath, 0700)
}

// SavePrivateKey 保存私钥到订单目录（使用 DPAPI 加密）
func (s *OrderStore) SavePrivateKey(orderID int, keyPEM string) error {
	if len(keyPEM) > MaxPrivateKeySize {
		return fmt.Errorf("私钥大小 %d 超过上限 %d 字节", len(keyPEM), MaxPrivateKeySize)
	}
	if err := s.EnsureOrderDir(orderID); err != nil {
		return fmt.Errorf("创建订单目录失败: %w", err)
	}
	encrypted, err := EncryptPrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("加密私钥失败: %w", err)
	}
	keyPath := filepath.Join(s.GetOrderPath(orderID), "private.key")
	return atomicWriteKey(keyPath, []byte(encrypted))
}

// atomicWriteKey 原子写私钥密文（spec §10.3）：临时文件 + Rename 替换。
// Windows 上 os.Rename 即 MOVEFILE_REPLACE_EXISTING，原子替换已存在目标；
// 中途失败（临时文件写入或替换出错）时清理临时文件并保留已有密文，绝不截断唯一密文。
func atomicWriteKey(keyPath string, data []byte) error {
	tmpPath := keyPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("写入临时私钥失败: %w", err)
	}
	if err := os.Rename(tmpPath, keyPath); err != nil {
		_ = os.Remove(tmpPath) // 清理临时文件，保留旧密文
		return fmt.Errorf("原子替换私钥失败: %w", err)
	}
	return nil
}

// LoadPrivateKey 从订单目录加载私钥（使用 DPAPI 解密）
func (s *OrderStore) LoadPrivateKey(orderID int) (string, error) {
	keyPath := filepath.Join(s.GetOrderPath(orderID), "private.key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}
	stored := string(data)
	keyPEM, err := DecryptPrivateKey(stored)
	if err != nil {
		return "", err
	}
	// 验证解密后的数据是有效 PEM 格式
	if block, _ := pem.Decode([]byte(keyPEM)); block == nil {
		return "", errors.New("私钥文件可能已损坏")
	}
	// 透明迁移：旧用户作用域密文成功解密后，原子重写为机器作用域密文（spec §10.3）。
	// 迁移写失败保留旧密文并记警告、下次加载再试，绝不因迁移失败丢失唯一密文；
	// 迁移失败不影响本次读取（keyPEM 已在内存中）。
	if KeyNeedsMigration(stored) {
		reEncrypted, encErr := EncryptPrivateKey(keyPEM)
		if encErr != nil {
			log.Printf("警告: 私钥迁移重加密失败（订单 %d），保留旧密文下次再试: %v", orderID, encErr)
		} else if err := atomicWriteKey(keyPath, []byte(reEncrypted)); err != nil {
			log.Printf("警告: 私钥迁移写入失败（订单 %d），保留旧密文下次再试: %v", orderID, err)
		}
	}
	return keyPEM, nil
}

// HasPrivateKey 检查订单是否有本地私钥
func (s *OrderStore) HasPrivateKey(orderID int) bool {
	keyPath := filepath.Join(s.GetOrderPath(orderID), "private.key")
	_, err := os.Stat(keyPath)
	return err == nil
}

// SaveCertificate 保存证书到订单目录
func (s *OrderStore) SaveCertificate(orderID int, certPEM, chainPEM string) error {
	if err := s.EnsureOrderDir(orderID); err != nil {
		return fmt.Errorf("创建订单目录失败: %w", err)
	}
	orderPath := s.GetOrderPath(orderID)

	// 保存证书（权限 0600 - 仅所有者可读写）
	certPath := filepath.Join(orderPath, "cert.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0600); err != nil {
		return fmt.Errorf("保存证书失败: %w", err)
	}

	// 保存证书链（如果有）
	if chainPEM != "" {
		chainPath := filepath.Join(orderPath, "chain.pem")
		if err := os.WriteFile(chainPath, []byte(chainPEM), 0600); err != nil {
			return fmt.Errorf("保存证书链失败: %w", err)
		}
	}

	return nil
}

// LoadCertificate 从订单目录加载证书
func (s *OrderStore) LoadCertificate(orderID int) (certPEM, chainPEM string, err error) {
	orderPath := s.GetOrderPath(orderID)

	// 加载证书
	certData, err := os.ReadFile(filepath.Join(orderPath, "cert.pem"))
	if err != nil {
		return "", "", fmt.Errorf("读取证书失败: %w", err)
	}
	certPEM = string(certData)

	// 加载证书链（可选）
	chainData, err := os.ReadFile(filepath.Join(orderPath, "chain.pem"))
	if err == nil {
		chainPEM = string(chainData)
	}

	return certPEM, chainPEM, nil
}

// SaveMeta 保存订单元数据
func (s *OrderStore) SaveMeta(orderID int, meta *OrderMeta) error {
	if err := s.EnsureOrderDir(orderID); err != nil {
		return fmt.Errorf("创建订单目录失败: %w", err)
	}
	metaPath := filepath.Join(s.GetOrderPath(orderID), "meta.json")

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化元数据失败: %w", err)
	}

	return os.WriteFile(metaPath, data, 0600) // 权限 0600 - 仅所有者可读写
}

// LoadMeta 加载订单元数据
func (s *OrderStore) LoadMeta(orderID int) (*OrderMeta, error) {
	metaPath := filepath.Join(s.GetOrderPath(orderID), "meta.json")

	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta OrderMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("解析元数据失败: %w", err)
	}

	return &meta, nil
}

// ListOrders 列出所有订单 ID
func (s *OrderStore) ListOrders() ([]int, error) {
	entries, err := os.ReadDir(s.BaseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []int{}, nil
		}
		return nil, err
	}

	var orderIDs []int
	for _, entry := range entries {
		if entry.IsDir() {
			if id, err := strconv.Atoi(entry.Name()); err == nil {
				orderIDs = append(orderIDs, id)
			}
		}
	}
	return orderIDs, nil
}

// DeleteOrder 删除订单目录
func (s *OrderStore) DeleteOrder(orderID int) error {
	return os.RemoveAll(s.GetOrderPath(orderID))
}
