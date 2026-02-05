package util

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
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

// ===== 域名规范化 =====

// isASCII 检查字符串是否全部为 ASCII 字符
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// NormalizeDomain 将域名规范化为小写 ASCII (Punycode) 形式
// 纯 ASCII 直通；非 ASCII 尝试转 Punycode，失败则 fallback 到小写原串
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return domain
	}
	if isASCII(domain) {
		return strings.ToLower(domain)
	}

	prefix, rest := "", domain
	if strings.HasPrefix(domain, "*.") {
		prefix, rest = "*.", domain[2:]
	}
	ascii, err := idna.Lookup.ToASCII(rest)
	if err != nil {
		return strings.ToLower(domain)
	}
	return prefix + strings.ToLower(ascii)
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
	normalized := NormalizeDomain(hostname)
	if len(normalized) > 253 {
		return fmt.Errorf("主机名长度不能超过253个字符")
	}
	if !hostnameRegex.MatchString(normalized) {
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
	normalized := NormalizeDomain(domain)
	if len(normalized) > 253 {
		return fmt.Errorf("域名长度不能超过253个字符")
	}
	if !domainRegex.MatchString(normalized) {
		return fmt.Errorf("域名格式无效")
	}
	return nil
}

// ValidateSiteName 验证 IIS 站点名称（白名单模式）
// 只允许：字母、数字、空格、连字符、下划线、点、中文（CJK）
func ValidateSiteName(siteName string) error {
	if siteName == "" {
		return fmt.Errorf("站点名称不能为空")
	}
	if len(siteName) > 260 {
		return fmt.Errorf("站点名称长度不能超过260个字符")
	}

	// 白名单验证：只允许特定字符
	for _, r := range siteName {
		// 允许：字母、数字
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		// 允许：空格、连字符、下划线、点
		if r == ' ' || r == '-' || r == '_' || r == '.' {
			continue
		}
		// 允许：中文 CJK 基本区 (U+4E00-U+9FFF)
		if r >= 0x4E00 && r <= 0x9FFF {
			continue
		}
		// 允许：中文 CJK 扩展 A (U+3400-U+4DBF)
		if r >= 0x3400 && r <= 0x4DBF {
			continue
		}
		// 其他字符一律拒绝
		return fmt.Errorf("站点名称包含不允许的字符: %q", r)
	}

	return nil
}

// ValidateSiteNameStrict 严格验证 IIS 站点名称（仅 ASCII 和中文）
// 用于特别敏感的场景，不允许特殊字符
func ValidateSiteNameStrict(siteName string) error {
	if siteName == "" {
		return fmt.Errorf("站点名称不能为空")
	}
	if len(siteName) > 260 {
		return fmt.Errorf("站点名称长度不能超过260个字符")
	}

	for _, r := range siteName {
		// 允许：ASCII 字母
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			continue
		}
		// 允许：ASCII 数字
		if r >= '0' && r <= '9' {
			continue
		}
		// 允许：空格、连字符、下划线
		if r == ' ' || r == '-' || r == '_' {
			continue
		}
		// 允许：中文 CJK 基本区
		if r >= 0x4E00 && r <= 0x9FFF {
			continue
		}
		return fmt.Errorf("站点名称包含不允许的字符: %q", r)
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

// MatchDomain 检查绑定域名是否匹配证书域名（支持通配符）
// bindingHost: IIS 绑定的域名 (如 www.example.com)
// certDomain: 证书的域名 (如 *.example.com 或 www.example.com)
// 返回 true 表示匹配成功
//
// 匹配规则：
//   - 精确匹配: www.example.com 匹配 www.example.com
//   - 通配符匹配: *.example.com 匹配 www.example.com, api.example.com
//   - 通配符只匹配单级子域名: *.example.com 不匹配 a.b.example.com
func MatchDomain(bindingHost, certDomain string) bool {
	bindingHost = NormalizeDomain(bindingHost)
	certDomain = NormalizeDomain(certDomain)

	if bindingHost == "" || certDomain == "" {
		return false
	}

	// 精确匹配
	if bindingHost == certDomain {
		return true
	}

	// 通配符证书匹配: *.example.com 匹配 www.example.com
	if strings.HasPrefix(certDomain, "*.") {
		suffix := certDomain[1:] // ".example.com"
		// 校验通配符格式：后缀至少有 ".x" 且不含连续点
		if len(suffix) < 2 || strings.Contains(suffix[1:], "..") {
			return false
		}
		if strings.HasSuffix(bindingHost, suffix) {
			// 确保只有一级子域名 (www.example.com 匹配，但 a.b.example.com 不匹配)
			prefix := bindingHost[:len(bindingHost)-len(suffix)]
			if !strings.Contains(prefix, ".") && prefix != "" {
				return true
			}
		}
	}

	return false
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

	// Windows 路径大小写不敏感
	absBaseLower := strings.ToLower(absBase)
	absTargetLower := strings.ToLower(absTarget)

	// 检查目标路径是否以基础路径为前缀
	return strings.HasPrefix(absTargetLower+string(filepath.Separator), absBaseLower) ||
		strings.HasPrefix(absTargetLower, absBaseLower)
}
