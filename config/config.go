package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// DataDirName 数据目录名称
const DataDirName = "CertDeploy"

// BindRule 绑定规则
type BindRule struct {
	Domain   string `json:"domain"`    // 要绑定的域名
	Port     int    `json:"port"`      // 端口，默认 443
	SiteName string `json:"site_name"` // IIS 站点名称（可选，空则自动匹配）
}

// CertConfig 证书配置（以证书为维度）
type CertConfig struct {
	OrderID      int        `json:"order_id"`               // 证书订单 ID
	Domain       string     `json:"domain"`                 // 主域名（显示用）
	Domains      []string   `json:"domains"`                // 证书包含的所有域名
	ExpiresAt    string     `json:"expires_at"`             // 过期时间
	SerialNumber string     `json:"serial_number"`          // 证书序列号
	Enabled      bool       `json:"enabled"`                // 是否启用自动部署
	BindRules    []BindRule `json:"bind_rules,omitempty"`   // 绑定规则
	UseLocalKey  bool       `json:"use_local_key"`          // 使用本地私钥模式
	AutoBindMode bool       `json:"auto_bind_mode"`         // 自动绑定模式（按已有绑定更换证书）
}

// Config 应用配置
type Config struct {
	APIBaseURL       string       `json:"api_base_url"`
	Token            string       `json:"token,omitempty"`            // 旧版明文 Token（兼容）
	EncryptedToken   string       `json:"encrypted_token,omitempty"` // 加密后的 Token
	Certificates     []CertConfig `json:"certificates"`               // 证书配置
	CheckDays        int          `json:"check_days"`                 // 提前多少天检查证书（默认10天）
	LastCheck        string       `json:"last_check"`                 // 上次检查时间
	AutoCheckEnabled bool         `json:"auto_check_enabled"`         // 是否启用自动部署（任务计划）
	CheckInterval    int          `json:"check_interval"`             // 检测间隔（小时），默认6
	TaskName         string       `json:"task_name"`                  // 任务计划名称
	IIS7Mode         bool         `json:"iis7_mode"`                  // IIS7 兼容模式（自动检测）
}

// GetToken 获取解密后的 Token
func (c *Config) GetToken() string {
	if c.EncryptedToken != "" {
		if decrypted, err := DecryptToken(c.EncryptedToken); err == nil {
			return decrypted
		}
	}
	return c.Token
}

// SetToken 加密并设置 Token
func (c *Config) SetToken(token string) error {
	encrypted, err := EncryptToken(token)
	if err != nil {
		// 加密失败，回退到明文
		c.Token = token
		c.EncryptedToken = ""
		return nil
	}
	c.EncryptedToken = encrypted
	c.Token = "" // 清除明文
	return nil
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		APIBaseURL:       "",
		Token:            "",
		Certificates:     []CertConfig{},
		CheckDays:        10,
		AutoCheckEnabled: false,
		CheckInterval:    6,
		TaskName:         "CertDeployIIS",
		IIS7Mode:         false,
	}
}

// GetDataDir 获取数据目录（程序同目录下的 CertDeploy 文件夹）
func GetDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		// 回退到当前目录
		return DataDirName
	}
	dataDir := filepath.Join(filepath.Dir(exe), DataDirName)

	// 确保目录存在
	os.MkdirAll(dataDir, 0755)

	return dataDir
}

// GetConfigPath 获取配置文件路径
func GetConfigPath() string {
	return filepath.Join(GetDataDir(), "config.json")
}

// GetLogDir 获取日志目录
func GetLogDir() string {
	logDir := filepath.Join(GetDataDir(), "logs")
	os.MkdirAll(logDir, 0755)
	return logDir
}

// Load 加载配置
func Load() (*Config, error) {
	path := GetConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// 设置默认值（不设置 APIBaseURL 和 Token 的默认值，由用户配置）
	if cfg.CheckDays == 0 {
		cfg.CheckDays = 10
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 6
	}
	if cfg.TaskName == "" {
		cfg.TaskName = "CertDeployIIS"
	}

	return &cfg, nil
}

// Save 保存配置
func (c *Config) Save() error {
	path := GetConfigPath()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// AddCertificate 添加证书配置
func (c *Config) AddCertificate(cert CertConfig) {
	c.Certificates = append(c.Certificates, cert)
}

// RemoveCertificateByIndex 按索引移除证书配置
func (c *Config) RemoveCertificateByIndex(index int) {
	if index >= 0 && index < len(c.Certificates) {
		c.Certificates = append(c.Certificates[:index], c.Certificates[index+1:]...)
	}
}

// GetCertificateByOrderID 按订单 ID 获取证书配置
func (c *Config) GetCertificateByOrderID(orderID int) *CertConfig {
	for i := range c.Certificates {
		if c.Certificates[i].OrderID == orderID {
			return &c.Certificates[i]
		}
	}
	return nil
}

// UpdateCertificate 更新证书配置
func (c *Config) UpdateCertificate(index int, cert CertConfig) {
	if index >= 0 && index < len(c.Certificates) {
		c.Certificates[index] = cert
	}
}

// GetDefaultBindRules 为证书生成默认绑定规则
func GetDefaultBindRules(domains []string) []BindRule {
	rules := make([]BindRule, 0, len(domains))
	for _, domain := range domains {
		rules = append(rules, BindRule{
			Domain: domain,
			Port:   443,
		})
	}
	return rules
}
