package util

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ===== PowerShell 转义 =====

// EscapePowerShellString 转义 PowerShell 单引号字符串
// 在 PowerShell 单引号字符串中，只需要将单引号转义为两个单引号
func EscapePowerShellString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// EscapePowerShellDoubleQuoteString 转义 PowerShell 双引号字符串
// 需要转义: $ ` " 和反引号
func EscapePowerShellDoubleQuoteString(s string) string {
	s = strings.ReplaceAll(s, "`", "``")
	s = strings.ReplaceAll(s, "$", "`$")
	s = strings.ReplaceAll(s, "\"", "`\"")
	return s
}

// ===== 验证函数 =====

// thumbprintRegex 证书指纹正则：40位十六进制字符
var thumbprintRegex = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)

// ValidateThumbprint 验证证书指纹格式
func ValidateThumbprint(thumbprint string) error {
	// 移除空格和连字符
	cleaned := strings.ReplaceAll(thumbprint, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")

	if !thumbprintRegex.MatchString(cleaned) {
		return fmt.Errorf("证书指纹必须是40位十六进制字符")
	}
	return nil
}

// NormalizeThumbprint 规范化并验证证书指纹
// 返回大写的40位十六进制字符串
func NormalizeThumbprint(thumbprint string) (string, error) {
	// 移除空格和连字符
	cleaned := strings.ReplaceAll(thumbprint, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ToUpper(cleaned)

	if !thumbprintRegex.MatchString(cleaned) {
		return "", fmt.Errorf("证书指纹必须是40位十六进制字符")
	}
	return cleaned, nil
}

// hostnameRegex 主机名正则
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateHostname 验证主机名格式
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("主机名不能为空")
	}
	if len(hostname) > 253 {
		return fmt.Errorf("主机名长度不能超过253个字符")
	}
	if !hostnameRegex.MatchString(hostname) {
		return fmt.Errorf("主机名格式无效")
	}
	return nil
}

// domainRegex 域名正则（支持通配符）
var domainRegex = regexp.MustCompile(`^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateDomain 验证域名格式（支持通配符如 *.example.com）
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("域名不能为空")
	}
	if len(domain) > 253 {
		return fmt.Errorf("域名长度不能超过253个字符")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("域名格式无效")
	}
	return nil
}

// ValidateSiteName 验证 IIS 站点名称
// 允许字母、数字、空格、连字符、下划线、点、中文
func ValidateSiteName(siteName string) error {
	if siteName == "" {
		return fmt.Errorf("站点名称不能为空")
	}
	if len(siteName) > 260 {
		return fmt.Errorf("站点名称长度不能超过260个字符")
	}

	// 检查危险字符
	dangerousChars := []string{"'", "\"", "`", "$", ";", "&", "|", "<", ">", "\n", "\r", "\t"}
	for _, char := range dangerousChars {
		if strings.Contains(siteName, char) {
			return fmt.Errorf("站点名称包含不允许的字符: %q", char)
		}
	}

	// 检查每个字符是否合法
	for _, r := range siteName {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' && r != '_' && r != '.' {
			return fmt.Errorf("站点名称包含不允许的字符: %q", r)
		}
	}

	return nil
}

// taskNameRegex 任务计划名称正则
var taskNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)

// ValidateTaskName 验证任务计划名称
func ValidateTaskName(taskName string) error {
	if taskName == "" {
		return fmt.Errorf("任务名称不能为空")
	}
	if len(taskName) > 260 {
		return fmt.Errorf("任务名称长度不能超过260个字符")
	}
	if !taskNameRegex.MatchString(taskName) {
		return fmt.Errorf("任务名称只能包含字母、数字、下划线、连字符和点")
	}
	return nil
}

// ValidatePort 验证端口号
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口号必须在 1-65535 之间")
	}
	return nil
}

// ValidateFriendlyName 验证证书友好名称
func ValidateFriendlyName(name string) error {
	if name == "" {
		return fmt.Errorf("友好名称不能为空")
	}
	if len(name) > 260 {
		return fmt.Errorf("友好名称长度不能超过260个字符")
	}

	// 检查危险字符（用于 PowerShell 注入）
	dangerousChars := []string{"'", "\"", "`", "$", ";", "&", "|", "<", ">", "\n", "\r"}
	for _, char := range dangerousChars {
		if strings.Contains(name, char) {
			return fmt.Errorf("友好名称包含不允许的字符: %q", char)
		}
	}

	return nil
}

// ValidateIPv4 验证 IPv4 地址
func ValidateIPv4(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP 地址不能为空")
	}
	if ip == "0.0.0.0" {
		return nil // 允许通配 IP
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("无效的 IP 地址格式")
	}
	if parsed.To4() == nil {
		return fmt.Errorf("必须是 IPv4 地址")
	}
	return nil
}

// ===== 路径安全 =====

// ValidateRelativePath 验证相对路径是否安全（防止路径遍历和符号链接攻击）
// basePath: 基础路径
// relativePath: 相对路径
// 返回: 清理后的完整路径
func ValidateRelativePath(basePath, relativePath string) (string, error) {
	if basePath == "" {
		return "", fmt.Errorf("基础路径不能为空")
	}
	if relativePath == "" {
		return "", fmt.Errorf("相对路径不能为空")
	}

	// 检查相对路径中的危险模式
	if strings.Contains(relativePath, "..") {
		return "", fmt.Errorf("路径包含非法的目录遍历序列 '..'")
	}

	// 清理并规范化路径
	cleanBase := filepath.Clean(basePath)
	cleanRel := filepath.Clean(relativePath)

	// 移除开头的路径分隔符
	cleanRel = strings.TrimPrefix(cleanRel, string(filepath.Separator))
	cleanRel = strings.TrimPrefix(cleanRel, "/")

	// 组合路径
	fullPath := filepath.Join(cleanBase, cleanRel)

	// 再次清理
	fullPath = filepath.Clean(fullPath)

	// 验证结果路径是否在基础路径内
	if !IsPathWithinBase(cleanBase, fullPath) {
		return "", fmt.Errorf("路径超出允许的目录范围")
	}

	// 解析符号链接
	realBasePath, err := filepath.EvalSymlinks(cleanBase)
	if err != nil {
		return "", fmt.Errorf("解析基础路径失败: %w", err)
	}

	realFullPath, err := evalSymlinksPartial(fullPath)
	if err != nil {
		return "", fmt.Errorf("解析目标路径失败: %w", err)
	}

	// 验证真实路径在基础路径内
	if !IsPathWithinBase(realBasePath, realFullPath) {
		return "", fmt.Errorf("路径超出允许范围（符号链接）")
	}

	return fullPath, nil
}

// evalSymlinksPartial 解析路径中已存在部分的符号链接
// 对于不存在的路径部分，保留原样拼接
func evalSymlinksPartial(path string) (string, error) {
	// 如果路径存在，直接解析
	if _, err := os.Stat(path); err == nil {
		return filepath.EvalSymlinks(path)
	}

	// 从路径末端向前找到存在的部分
	dir := path
	var remaining []string

	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		remaining = append([]string{filepath.Base(dir)}, remaining...)
		parent := filepath.Dir(dir)
		if parent == dir {
			// 到达根目录
			break
		}
		dir = parent
	}

	// 解析存在部分的符号链接
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}

	// 拼接剩余部分
	for _, part := range remaining {
		realDir = filepath.Join(realDir, part)
	}

	return realDir, nil
}

// IsPathWithinBase 检查目标路径是否在基础路径内
func IsPathWithinBase(basePath, targetPath string) bool {
	// 规范化路径
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return false
	}
	absTarget, err := filepath.Abs(targetPath)
	if err != nil {
		return false
	}

	// 确保基础路径以分隔符结尾（用于前缀匹配）
	if !strings.HasSuffix(absBase, string(filepath.Separator)) {
		absBase += string(filepath.Separator)
	}

	// 检查目标路径是否以基础路径为前缀
	return strings.HasPrefix(absTarget+string(filepath.Separator), absBase) ||
		strings.HasPrefix(absTarget, absBase)
}
