package iis

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"

	"sslctlw/util"
)

// 默认 AppID (用于标识应用程序)
const defaultAppID = "{00000000-0000-0000-0000-000000000000}"

// SSLBinding SSL 证书绑定信息
type SSLBinding struct {
	HostnamePort    string
	CertHash        string
	AppID           string
	CertStoreName   string
	SslCtlStoreName string
	IsIPBinding     bool // true: IP:port 绑定（空主机名），false: Hostname:port 绑定（SNI）
}

// BindCertificate 绑定证书到指定的主机名和端口 (SNI 模式)
func BindCertificate(hostname string, port int, certHash string) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if err := util.ValidateHostname(hostname); err != nil {
		return fmt.Errorf("无效的主机名: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}
	if err := util.ValidateThumbprint(certHash); err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	// 清理证书哈希（移除空格和连字符）
	certHash = strings.ReplaceAll(certHash, " ", "")
	certHash = strings.ReplaceAll(certHash, "-", "")
	certHash = strings.ToLower(certHash)

	hostnamePort := fmt.Sprintf("%s:%d", hostname, port)

	// 先尝试删除已有绑定（忽略错误）
	_ = UnbindCertificate(hostname, port)

	// 添加新绑定
	output, err := util.RunCmdCombined("netsh", "http", "add", "sslcert",
		fmt.Sprintf("hostnameport=%s", hostnamePort),
		fmt.Sprintf("certhash=%s", certHash),
		fmt.Sprintf("appid=%s", defaultAppID),
		"certstorename=MY")

	// 检查输出是否包含成功信息
	outputLower := strings.ToLower(output)
	isSuccess := strings.Contains(outputLower, "success") ||
		strings.Contains(output, "成功")

	if err != nil && !isSuccess {
		return fmt.Errorf("绑定证书失败: %v, 输出: %s", err, output)
	}

	// 验证绑定是否真正成功
	binding, verifyErr := GetBindingForHost(hostname, port)
	if verifyErr != nil {
		if isSuccess {
			log.Printf("警告: SNI 绑定 %s:%d 命令成功但验证查询失败: %v", hostname, port, verifyErr)
			return fmt.Errorf("绑定命令成功但验证查询失败: %v", verifyErr)
		}
		return fmt.Errorf("绑定后验证失败: %v", verifyErr)
	}
	if binding == nil {
		if isSuccess {
			log.Printf("警告: SNI 绑定 %s:%d 命令成功但未找到绑定记录", hostname, port)
			return fmt.Errorf("绑定命令成功但未找到绑定记录（可能是解析问题）")
		}
		return fmt.Errorf("绑定未生效: 未找到绑定记录，输出: %s", output)
	}
	if !strings.EqualFold(binding.CertHash, certHash) {
		return fmt.Errorf("绑定证书不匹配: 期望 %s, 实际 %s", certHash, binding.CertHash)
	}

	return nil
}

// BindCertificateByIP 绑定证书到指定的 IP 和端口 (非 SNI 模式)
func BindCertificateByIP(ip string, port int, certHash string) error {
	if port == 0 {
		port = 443
	}
	if ip == "" || ip == "0.0.0.0" {
		ip = "0.0.0.0"
	}

	// 参数验证
	if err := util.ValidateIPv4(ip); err != nil {
		return fmt.Errorf("无效的 IP 地址: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}
	if err := util.ValidateThumbprint(certHash); err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	// 清理证书哈希
	certHash = strings.ReplaceAll(certHash, " ", "")
	certHash = strings.ReplaceAll(certHash, "-", "")
	certHash = strings.ToLower(certHash)

	ipPort := fmt.Sprintf("%s:%d", ip, port)

	// 先尝试删除已有绑定
	_ = UnbindCertificateByIP(ip, port)

	// 添加新绑定
	output, err := util.RunCmdCombined("netsh", "http", "add", "sslcert",
		fmt.Sprintf("ipport=%s", ipPort),
		fmt.Sprintf("certhash=%s", certHash),
		fmt.Sprintf("appid=%s", defaultAppID),
		"certstorename=MY")

	// 检查输出是否包含成功信息
	outputLower := strings.ToLower(output)
	isSuccess := strings.Contains(outputLower, "success") ||
		strings.Contains(output, "成功")

	if err != nil && !isSuccess {
		return fmt.Errorf("绑定证书失败: %v, 输出: %s", err, output)
	}

	// 验证绑定是否真正成功
	binding, verifyErr := GetBindingForIP(ip, port)
	if verifyErr != nil {
		if isSuccess {
			log.Printf("警告: IP 绑定 %s:%d 命令成功但验证查询失败: %v", ip, port, verifyErr)
			return fmt.Errorf("绑定命令成功但验证查询失败: %v", verifyErr)
		}
		return fmt.Errorf("绑定后验证失败: %v", verifyErr)
	}
	if binding == nil {
		if isSuccess {
			log.Printf("警告: IP 绑定 %s:%d 命令成功但未找到绑定记录", ip, port)
			return fmt.Errorf("绑定命令成功但未找到绑定记录（可能是解析问题）")
		}
		return fmt.Errorf("绑定未生效: 未找到绑定记录，输出: %s", output)
	}
	if !strings.EqualFold(binding.CertHash, certHash) {
		return fmt.Errorf("绑定证书不匹配: 期望 %s, 实际 %s", certHash, binding.CertHash)
	}

	return nil
}

// UnbindCertificate 解除主机名端口的证书绑定 (SNI)
func UnbindCertificate(hostname string, port int) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if err := util.ValidateHostname(hostname); err != nil {
		return fmt.Errorf("无效的主机名: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}

	hostnamePort := fmt.Sprintf("%s:%d", hostname, port)
	output, err := util.RunCmdCombined("netsh", "http", "delete", "sslcert",
		fmt.Sprintf("hostnameport=%s", hostnamePort))

	if err != nil {
		return fmt.Errorf("解除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// UnbindCertificateByIP 解除 IP 端口的证书绑定
func UnbindCertificateByIP(ip string, port int) error {
	if port == 0 {
		port = 443
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	// 参数验证
	if err := util.ValidateIPv4(ip); err != nil {
		return fmt.Errorf("无效的 IP 地址: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}

	ipPort := fmt.Sprintf("%s:%d", ip, port)
	output, err := util.RunCmdCombined("netsh", "http", "delete", "sslcert",
		fmt.Sprintf("ipport=%s", ipPort))

	if err != nil {
		return fmt.Errorf("解除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// ListSSLBindings 列出所有 SSL 证书绑定
func ListSSLBindings() ([]SSLBinding, error) {
	output, err := util.RunCmd("netsh", "http", "show", "sslcert")
	if err != nil {
		return nil, fmt.Errorf("获取 SSL 绑定列表失败: %v", err)
	}

	return parseSSLBindings(output), nil
}

// netsh 输出解析正则（支持中英文和全角/半角冒号）
var (
	// SNI 绑定: "Hostname:port", "主机名:端口"
	sniBindingRe = regexp.MustCompile(`(?i)(?:Hostname:port|主机名[:：]端口)\s*[:：]\s*(.+)`)
	// IP 绑定: "IP:port", "IP:端口"（空主机名，用于通配符泛匹配或 IP 证书）
	ipBindingRe = regexp.MustCompile(`(?i)(?:IP:port|IP[:：]端口)\s*[:：]\s*(.+)`)
	certHashRe  = regexp.MustCompile(`(?i)(?:Certificate Hash|证书哈希)\s*[:：]\s*([a-fA-F0-9]+)`)
	appIDRe     = regexp.MustCompile(`(?i)(?:Application ID|应用程序\s*ID)\s*[:：]\s*(\{[^}]+\})`)
	storeRe     = regexp.MustCompile(`(?i)(?:Certificate Store Name|证书存储名称)\s*[:：]\s*(.+)`)
)

// parseSSLBindings 解析 netsh 输出
func parseSSLBindings(output string) []SSLBinding {
	bindings := make([]SSLBinding, 0)

	var current *SSLBinding
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 检查是否是新的绑定条目（优先检查 SNI 绑定）
		if matches := sniBindingRe.FindStringSubmatch(line); matches != nil {
			if current != nil {
				bindings = append(bindings, *current)
			}
			current = &SSLBinding{
				HostnamePort: strings.TrimSpace(matches[1]),
				IsIPBinding:  false,
			}
			continue
		}
		// 检查 IP 绑定（空主机名）
		if matches := ipBindingRe.FindStringSubmatch(line); matches != nil {
			if current != nil {
				bindings = append(bindings, *current)
			}
			current = &SSLBinding{
				HostnamePort: strings.TrimSpace(matches[1]),
				IsIPBinding:  true,
			}
			continue
		}

		if current == nil {
			continue
		}

		// 解析其他字段
		if matches := certHashRe.FindStringSubmatch(line); matches != nil {
			current.CertHash = strings.ToLower(strings.TrimSpace(matches[1]))
		} else if matches := appIDRe.FindStringSubmatch(line); matches != nil {
			current.AppID = strings.TrimSpace(matches[1])
		} else if matches := storeRe.FindStringSubmatch(line); matches != nil {
			current.CertStoreName = strings.TrimSpace(matches[1])
		}
	}

	// 添加最后一个
	if current != nil {
		bindings = append(bindings, *current)
	}

	return bindings
}

// GetBindingForHost 获取指定主机的 SSL 绑定
func GetBindingForHost(hostname string, port int) (*SSLBinding, error) {
	if port == 0 {
		port = 443
	}

	bindings, err := ListSSLBindings()
	if err != nil {
		return nil, err
	}

	target := fmt.Sprintf("%s:%d", hostname, port)
	for _, b := range bindings {
		if strings.EqualFold(b.HostnamePort, target) {
			return &b, nil
		}
	}

	return nil, nil // 未找到
}

// GetBindingForIP 获取指定 IP 的 SSL 绑定
func GetBindingForIP(ip string, port int) (*SSLBinding, error) {
	if port == 0 {
		port = 443
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	bindings, err := ListSSLBindings()
	if err != nil {
		return nil, err
	}

	target := fmt.Sprintf("%s:%d", ip, port)
	for _, b := range bindings {
		if strings.EqualFold(b.HostnamePort, target) {
			return &b, nil
		}
	}

	return nil, nil // 未找到
}

// findBindingsFromList 从绑定列表中查找匹配指定域名的 SNI 绑定（纯函数，便于测试）
func findBindingsFromList(bindings []SSLBinding, domains []string) map[string]*SSLBinding {
	result := make(map[string]*SSLBinding)
	for i, b := range bindings {
		if b.IsIPBinding {
			continue
		}

		host := ParseHostFromBinding(b.HostnamePort)
		if host == "" {
			continue
		}
		for _, certDomain := range domains {
			if util.MatchDomain(host, certDomain) {
				result[host] = &bindings[i]
				break
			}
		}
	}
	return result
}

// FindBindingsForDomains 查找与指定域名匹配的 SNI 绑定
// 返回: 绑定域名 -> SSLBinding 映射
// 注意: 只匹配 SNI 绑定（Hostname:port），忽略 IP 绑定（空主机名）
// IP 绑定用于通配符泛匹配或 IP 证书，需用户手工管理
func FindBindingsForDomains(domains []string) (map[string]*SSLBinding, error) {
	bindings, err := ListSSLBindings()
	if err != nil {
		return nil, err
	}
	return findBindingsFromList(bindings, domains), nil
}

// ParseHostFromBinding 从 "hostname:port" 提取主机名
func ParseHostFromBinding(hostnamePort string) string {
	idx := strings.LastIndex(hostnamePort, ":")
	if idx > 0 {
		return hostnamePort[:idx]
	}
	return hostnamePort
}

// ParsePortFromBinding 从 "hostname:port" 提取端口
func ParsePortFromBinding(hostnamePort string) int {
	idx := strings.LastIndex(hostnamePort, ":")
	if idx > 0 && idx < len(hostnamePort)-1 {
		portStr := hostnamePort[idx+1:]
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		if port > 0 {
			return port
		}
	}
	return 443
}

