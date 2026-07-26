package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// configMu 保护配置文件读写的全局互斥锁
var configMu sync.RWMutex

// 配置常量
const (
	// DataDirName 数据目录名称
	DataDirName = "sslctlw"

	// DefaultRenewBeforeDays 提前续签天数（两种模式统一）
	DefaultRenewBeforeDays = 14

	// MaxRenewBeforeDays renew_before_days 的合理上限（deploy-spec 2.9）：
	// 无论续费还是重签，续签动作都应发生在到期前 30 天以内，服务端返回超限视为异常值拒绝
	MaxRenewBeforeDays = 30

	// DefaultTaskName 默认任务计划名称
	DefaultTaskName = "SSLCtlW"

	// DefaultUpgradeCheckInterval 默认升级检查间隔（小时）
	DefaultUpgradeCheckInterval = 24

	// MaxIssueRetries 签发尝试（CSR 提交）上限，`>= MaxIssueRetries` 触顶（deploy-spec §3.2）
	MaxIssueRetries = 10
	// MaxDeployAttempts 部署尝试上限，`>= MaxDeployAttempts` 触顶（deploy-spec §3.2）
	MaxDeployAttempts = 10
)

// 签发/生命周期状态常量（metadata.last_issue_state，deploy-spec §1.5）
const (
	// IssueStateProcessing 等待签发（服务端 pending 统一归一为此状态）
	IssueStateProcessing = "processing"
	// IssueStateCapped 触顶静默：签发或部署计数达上限，等待人工处理
	IssueStateCapped = "CAPPED"
	// IssueStateExpired 证书已过期，静默终止
	IssueStateExpired = "EXPIRED"
	// IssueStatePolicyBlocked 旧非法 IP 配置被策略阻断，等待重新 setup
	IssueStatePolicyBlocked = "policy_blocked_needs_setup"
)

// 触顶阶段常量（metadata.cap_phase）
const (
	CapPhaseIssue  = "issue"  // 签发计数触顶
	CapPhaseDeploy = "deploy" // 部署计数触顶
	CapPhaseLegacy = "legacy" // 旧版本混合计数升级即触顶
)

// BindRule 绑定规则
type BindRule struct {
	Domain   string `json:"domain"`    // 要绑定的域名
	Port     int    `json:"port"`      // 端口，默认 443
	SiteName string `json:"site_name"` // IIS 站点名称（可选，空则自动匹配）
}

// CertAPIConfig 证书级 API 配置
// 平台差异：spec §1.4 定义公共字段为 url + token（明文），
// Windows 平台使用 DPAPI 加密存储为 encrypted_token，属于 spec §1.6 允许的安全增强扩展。
type CertAPIConfig struct {
	URL            string `json:"url"`                       // 部署接口地址
	EncryptedToken string `json:"encrypted_token,omitempty"` // DPAPI 加密后的 Token（平台扩展，替代 spec 的明文 token）
}

// GetToken 获取解密后的 Token
// 未配置 Token 时返回 ("", nil)；配置存在但解密失败时返回明确错误，
// 不再静默返回空串（解密失败通常是配置由其他账户加密，如 SYSTEM 计划任务读取交互账户密文）
func (c *CertAPIConfig) GetToken() (string, error) {
	if c.EncryptedToken == "" {
		return "", nil
	}
	decrypted, err := DecryptToken(c.EncryptedToken)
	if err != nil {
		return "", fmt.Errorf("token 解密失败：配置可能由其他账户加密，请重新运行 setup 重录 Token: %w", err)
	}
	return decrypted, nil
}

// SetToken 加密并设置 Token
func (c *CertAPIConfig) SetToken(token string) error {
	encrypted, err := EncryptToken(token)
	if err != nil {
		return fmt.Errorf("Token 加密失败: %w", err)
	}
	c.EncryptedToken = encrypted
	return nil
}

// CertMetadata 证书元数据（spec 1.5）
type CertMetadata struct {
	LastDeployAt       string `json:"last_deploy_at,omitempty"`       // 最后部署时间
	CertExpiresAt      string `json:"cert_expires_at,omitempty"`      // 证书过期时间
	CertSerial         string `json:"cert_serial,omitempty"`          // 证书序列号
	CSRSubmittedAt     string `json:"csr_submitted_at,omitempty"`     // CSR 提交时间（仅 local 模式）
	LastCSRHash        string `json:"last_csr_hash,omitempty"`        // 上次 CSR 的 SHA256 哈希
	LastIssueState     string `json:"last_issue_state,omitempty"`     // 签发/生命周期状态（见 IssueState* 常量）
	IssueRetryCount    int    `json:"issue_retry_count,omitempty"`    // 签发尝试计数（CSR 提交），>= MaxIssueRetries 触顶
	DeployAttemptCount int    `json:"deploy_attempt_count,omitempty"` // 部署尝试计数，>= MaxDeployAttempts 触顶；与签发计数分离
	// 平台内部字段（不参与跨仓协议）
	CapPhase        string `json:"cap_phase,omitempty"`         // 触顶阶段（CapPhase* 常量），仅 last_issue_state=CAPPED 时有效
	DeployStartedAt string `json:"deploy_started_at,omitempty"` // 部署意图落盘标记：非空表示一次部署尝试在途，用于崩溃恢复重放判定不重复计数
	// 平台扩展（IIS）
	Thumbprint      string                 `json:"thumbprint,omitempty"`       // 证书指纹
	ValidationFiles []ValidationFileRecord `json:"validation_files,omitempty"` // 客户端实际创建并拥有的验证文件
}

// ValidationFileRecord 记录客户端拥有的验证文件；旧配置缺少该字段时自然为空。
type ValidationFileRecord struct {
	SiteName     string `json:"site_name"`
	RelativePath string `json:"relative_path"`
	SHA256       string `json:"sha256"`
}

// IsCapped 是否已触顶静默
func (m *CertMetadata) IsCapped() bool { return m.LastIssueState == IssueStateCapped }

// IsExpiredState 是否已标记过期静默
func (m *CertMetadata) IsExpiredState() bool { return m.LastIssueState == IssueStateExpired }

// IsPolicyBlocked 是否被策略阻断（旧非法 IP 配置）
func (m *CertMetadata) IsPolicyBlocked() bool { return m.LastIssueState == IssueStatePolicyBlocked }

// MarkCapped 标记触顶静默并记录触顶阶段；已处于 CAPPED 时保持首个阶段不变
func (m *CertMetadata) MarkCapped(phase string) {
	if m.LastIssueState == IssueStateCapped {
		if m.CapPhase == "" {
			m.CapPhase = phase
		}
		return
	}
	m.LastIssueState = IssueStateCapped
	m.CapPhase = phase
}

// CertConfig 证书配置（以证书为维度，spec 1.3）
type CertConfig struct {
	CertName         string        `json:"cert_name"`                   // 证书名称（如 example.com-12345）
	OrderID          int           `json:"order_id"`                    // 证书订单 ID
	Enabled          bool          `json:"enabled"`                     // 是否启用自动部署
	Domain           string        `json:"domain"`                      // 主域名（IIS 显示用，平台扩展）
	Domains          []string      `json:"domains"`                     // 证书包含的所有域名
	RenewMode        string        `json:"renew_mode,omitempty"`        // 证书级续签模式，空串继承全局
	ValidationMethod string        `json:"validation_method,omitempty"` // 验证方法: file 或 delegation
	API              CertAPIConfig `json:"api"`                         // 证书级 API 配置
	Metadata         CertMetadata  `json:"metadata"`                    // 证书元数据
	// 平台扩展（IIS）
	BindRules    []BindRule `json:"bind_rules,omitempty"` // 绑定规则
	AutoBindMode bool       `json:"auto_bind_mode"`       // 自动绑定模式（按已有绑定更换证书）
}

// IsLocalMode 判断证书是否使用 local 模式（检查证书级 renew_mode，回退到全局）
func (c *CertConfig) IsLocalMode(globalMode string) bool {
	mode := c.RenewMode
	if mode == "" {
		mode = globalMode
	}
	return mode == "local"
}

// Schedule 续签调度配置
type Schedule struct {
	RenewMode       string `json:"renew_mode"`        // 续签模式（默认 "pull"）
	RenewBeforeDays int    `json:"renew_before_days"` // 提前续签天数（默认 14）
}

// Config 应用配置
type Config struct {
	Certificates     []CertConfig `json:"certificates"`                  // 证书配置
	Schedule         Schedule     `json:"schedule"`                      // 续签调度配置
	LastCheck        string       `json:"last_check"`                    // 上次检查时间
	AutoCheckEnabled bool         `json:"auto_check_enabled"`            // 是否启用自动部署（任务计划）
	TaskName         string       `json:"task_name"`                     // 任务计划名称
	NextBatchOrderID int          `json:"next_batch_order_id,omitempty"` // 下一自动批次起点；零值从头
	// 升级配置
	UpgradeEnabled   bool   `json:"upgrade_enabled"`    // 启用自动检查更新，默认 true
	UpgradeChannel   string `json:"upgrade_channel"`    // 版本通道: main | dev，默认 main
	UpgradeInterval  int    `json:"upgrade_interval"`   // 升级检查间隔（小时），默认 24
	LastUpgradeCheck string `json:"last_upgrade_check"` // 上次升级检查时间
	SkippedVersion   string `json:"skipped_version"`    // 用户跳过的版本
	ReleaseURL       string `json:"release_url"`        // Release API 地址
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		Certificates: []CertConfig{},
		Schedule: Schedule{
			RenewMode:       "pull",
			RenewBeforeDays: DefaultRenewBeforeDays,
		},
		AutoCheckEnabled: false,
		TaskName:         DefaultTaskName,
		// 升级配置默认值
		UpgradeEnabled:  true,
		UpgradeChannel:  "main",
		UpgradeInterval: DefaultUpgradeCheckInterval,
		ReleaseURL:      "",
	}
}

// GetDataDir 获取数据目录（程序同目录下的 sslctlw 文件夹）
func GetDataDir() string {
	exe, err := os.Executable()
	if err != nil {
		return resolveDataDir("", os.Getenv("APPDATA"), os.MkdirAll)
	}
	return resolveDataDir(exe, os.Getenv("APPDATA"), os.MkdirAll)
}

func resolveDataDir(exePath, appData string, mkdir func(string, os.FileMode) error) string {
	if exePath != "" {
		dataDir := filepath.Join(filepath.Dir(exePath), DataDirName)
		if err := mkdir(dataDir, 0700); err == nil {
			return dataDir
		} else {
			fmt.Printf("警告: 创建数据目录失败 %s: %v\n", dataDir, err)
		}
	}

	if appData == "" {
		appData = "."
	}
	fallback := filepath.Join(appData, DataDirName)
	if err := mkdir(fallback, 0700); err != nil {
		fmt.Printf("警告: 创建数据目录失败 %s: %v\n", fallback, err)
	}
	return fallback
}

// GetConfigPath 获取配置文件路径
func GetConfigPath() string {
	return filepath.Join(GetDataDir(), "config.json")
}

// GetLogDir 获取日志目录
func GetLogDir() string {
	logDir := filepath.Join(GetDataDir(), "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		// 目录创建失败时记录日志，但不中断程序
		fmt.Printf("警告: 创建日志目录失败 %s: %v\n", logDir, err)
	}
	return logDir
}

// Load 加载配置（线程安全）
// 执行完整迁移流程：合并旧文件 → 规则迁移 → 递归补齐默认值 → 持久化
func Load() (*Config, error) {
	configMu.Lock()
	defer configMu.Unlock()

	path := GetConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// 一次性防御：正式文件缺失但存在旧版本两步写法遗留的 .bak 时用其恢复，
			// 不再误判为无配置返回空默认配置（会丢失既有证书配置）
			if recovered, ok := recoverFromBak(path); ok {
				data = recovered
			} else {
				return DefaultConfig(), nil
			}
		} else {
			return nil, err
		}
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	changed := false
	var toDelete []string

	// 步骤 2: 合并旧文件（如有）
	configDir := filepath.Dir(path)
	for _, mf := range mergeFiles {
		oldPath := filepath.Join(configDir, mf.name)
		oldData, readErr := os.ReadFile(oldPath)
		if readErr != nil {
			continue
		}
		var oldRaw map[string]interface{}
		if json.Unmarshal(oldData, &oldRaw) != nil {
			continue
		}
		if mergeInto(raw, mf.target, oldRaw) {
			changed = true
		}
		toDelete = append(toDelete, oldPath)
	}

	// 步骤 3: 遍历规则表执行字段迁移
	if migrateFields(raw) {
		changed = true
	}

	// 步骤 4: 递归补齐默认值
	if applyDefaults(raw, defaultConfigRaw()) {
		changed = true
	}

	// 步骤 5: 持久化写回（原子写，失败不影响本次加载）
	if changed {
		if newData, marshalErr := json.MarshalIndent(raw, "", "  "); marshalErr == nil {
			if writeErr := atomicWriteFile(path, newData); writeErr != nil {
				fmt.Printf("警告: 迁移后配置写回失败: %v\n", writeErr)
			}
		}
		for _, f := range toDelete {
			_ = os.Remove(f)
		}
	}

	// 从迁移后的 raw 反序列化为 Config
	cfgData, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Save 保存配置（线程安全，原子写入）
func (c *Config) Save() error {
	configMu.Lock()
	defer configMu.Unlock()

	path := GetConfigPath()

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(path, data)
}

// atomicWriteFile 原子写配置文件：临时文件 + 单次重命名替换。
// Windows 上 os.Rename 即 MOVEFILE_REPLACE_EXISTING，可直接原子替换已存在目标，
// 无需"先备份再替换"的两步 rename——后者在两次 rename 之间存在正式文件缺失窗口，
// 崩溃后 Load 遇 NotExist 会误判为无配置返回空默认配置。单步替换消除该窗口。
func atomicWriteFile(path string, data []byte) error {
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath) // 清理临时文件，保留旧配置
		return fmt.Errorf("重命名配置文件失败: %w", err)
	}
	return nil
}

// recoverFromBak 一次性防御：兼容旧版本"先备份再替换"两步写法在两次 rename 之间
// 崩溃后遗留的状态（正式文件缺失、path.bak 存在）。仅在正式文件缺失时调用：
// 将 .bak 恢复为正式文件并返回其内容，避免误判为无配置返回空默认配置。
func recoverFromBak(path string) ([]byte, bool) {
	bakPath := path + ".bak"
	data, err := os.ReadFile(bakPath)
	if err != nil {
		return nil, false
	}
	// 恢复为正式文件；恢复失败也返回已读到的数据供本次加载继续
	if renErr := os.Rename(bakPath, path); renErr != nil {
		fmt.Printf("警告: 从 .bak 恢复配置失败: %v\n", renErr)
	}
	return data, true
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

// GetUpgradeConfig 获取升级配置（用于 upgrade 包）
func (c *Config) GetUpgradeConfig() *UpgradeConfig {
	return &UpgradeConfig{
		Enabled:        c.UpgradeEnabled,
		Channel:        c.UpgradeChannel,
		CheckInterval:  c.UpgradeInterval,
		LastCheck:      c.LastUpgradeCheck,
		SkippedVersion: c.SkippedVersion,
		ReleaseURL:     c.ReleaseURL,
	}
}

// SetUpgradeConfig 设置升级配置
func (c *Config) SetUpgradeConfig(uc *UpgradeConfig) {
	c.UpgradeEnabled = uc.Enabled
	c.UpgradeChannel = uc.Channel
	c.UpgradeInterval = uc.CheckInterval
	c.LastUpgradeCheck = uc.LastCheck
	c.SkippedVersion = uc.SkippedVersion
	c.ReleaseURL = uc.ReleaseURL
}

// UpgradeConfig 升级配置（与 upgrade 包交互用）
type UpgradeConfig struct {
	Enabled        bool
	Channel        string
	CheckInterval  int
	LastCheck      string
	SkippedVersion string
	ReleaseURL     string
}

// ValidationMethod 验证方法常量
const (
	ValidationMethodFile       = "file"       // 文件验证 (HTTP-01)
	ValidationMethodDelegation = "delegation" // 委托验证 (DNS-01)
)

// ValidateValidationMethod 校验域名与验证方法的兼容性
// 返回错误信息，如果兼容则返回空字符串
func ValidateValidationMethod(domain string, method string) string {
	if method == "" {
		return ""
	}

	// 检查是否是 IP 地址（使用 net.ParseIP 准确判断）
	isIP := net.ParseIP(domain) != nil

	// 检查是否是通配符域名
	isWildcard := len(domain) > 2 && domain[0] == '*' && domain[1] == '.'

	if isIP && method == ValidationMethodDelegation {
		return "IP 地址不支持委托验证"
	}

	if isWildcard && method == ValidationMethodFile {
		return "通配符域名不支持文件验证"
	}

	return ""
}
