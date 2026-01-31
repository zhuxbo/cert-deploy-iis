package cert

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"time"

	"cert-deploy/util"
)

// CertInfo 证书信息
type CertInfo struct {
	Thumbprint   string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	FriendlyName string
	HasPrivKey   bool
	SerialNumber string
	DNSNames     []string // SAN 中的 DNS 名称
}

// ListCertificates 列出本机证书存储中的证书 (LocalMachine\My)
func ListCertificates() ([]CertInfo, error) {
	// 使用 PowerShell 获取证书列表
	script := `
Get-ChildItem -Path Cert:\LocalMachine\My | ForEach-Object {
    $cert = $_
    Write-Output "===CERT==="
    Write-Output "Thumbprint: $($cert.Thumbprint)"
    Write-Output "Subject: $($cert.Subject)"
    Write-Output "Issuer: $($cert.Issuer)"
    Write-Output "NotBefore: $($cert.NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "NotAfter: $($cert.NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Output "FriendlyName: $($cert.FriendlyName)"
    Write-Output "HasPrivateKey: $($cert.HasPrivateKey)"
    Write-Output "SerialNumber: $($cert.SerialNumber)"
    # 获取 SAN 中的 DNS 名称
    $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
    if ($san) {
        $sanStr = $san.Format($false)
        $dnsNames = [regex]::Matches($sanStr, 'DNS Name=([^\s,]+)') | ForEach-Object { $_.Groups[1].Value }
        if ($dnsNames) {
            Write-Output "DNSNames: $($dnsNames -join ',')"
        }
    }
}
`
	output, err := util.RunPowerShell(script)
	if err != nil {
		return nil, fmt.Errorf("获取证书列表失败: %v", err)
	}

	return parseCertList(output), nil
}

// parseCertList 解析 PowerShell 输出
func parseCertList(output string) []CertInfo {
	certs := make([]CertInfo, 0)
	var current *CertInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "===CERT===" {
			if current != nil {
				certs = append(certs, *current)
			}
			current = &CertInfo{}
			continue
		}

		if current == nil {
			continue
		}

		// 解析键值对
		if idx := strings.Index(line, ": "); idx > 0 {
			key := line[:idx]
			value := strings.TrimSpace(line[idx+2:])

			switch key {
			case "Thumbprint":
				current.Thumbprint = strings.ToUpper(value)
			case "Subject":
				current.Subject = value
			case "Issuer":
				current.Issuer = value
			case "NotBefore":
				current.NotBefore, _ = time.Parse("2006-01-02 15:04:05", value)
			case "NotAfter":
				current.NotAfter, _ = time.Parse("2006-01-02 15:04:05", value)
			case "FriendlyName":
				current.FriendlyName = value
			case "HasPrivateKey":
				current.HasPrivKey = strings.EqualFold(value, "True")
			case "SerialNumber":
				current.SerialNumber = value
			case "DNSNames":
				if value != "" {
					current.DNSNames = strings.Split(value, ",")
				}
			}
		}
	}

	// 添加最后一个
	if current != nil {
		certs = append(certs, *current)
	}

	return certs
}

// GetCertByThumbprint 根据指纹获取证书
func GetCertByThumbprint(thumbprint string) (*CertInfo, error) {
	thumbprint = strings.ToUpper(strings.ReplaceAll(thumbprint, " ", ""))

	certs, err := ListCertificates()
	if err != nil {
		return nil, err
	}

	for _, cert := range certs {
		if cert.Thumbprint == thumbprint {
			return &cert, nil
		}
	}

	return nil, fmt.Errorf("未找到证书: %s", thumbprint)
}

// GetCertDisplayName 获取证书显示名称
func GetCertDisplayName(cert *CertInfo) string {
	if cert.FriendlyName != "" {
		return cert.FriendlyName
	}

	// 从 Subject 中提取 CN
	cn := extractCN(cert.Subject)
	if cn != "" {
		return cn
	}

	return cert.Subject
}

// extractCN 从证书主题中提取 CN
func extractCN(subject string) string {
	re := regexp.MustCompile(`CN=([^,]+)`)
	matches := re.FindStringSubmatch(subject)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// GetCertStatus 获取证书状态描述
func GetCertStatus(cert *CertInfo) string {
	now := time.Now()

	if cert.NotAfter.Before(now) {
		return "已过期"
	}

	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
	if daysLeft <= 7 {
		return fmt.Sprintf("即将过期 (%d天)", daysLeft)
	}
	if daysLeft <= 30 {
		return fmt.Sprintf("临近过期 (%d天)", daysLeft)
	}

	return "有效"
}

// MatchesDomain 检查证书是否匹配指定域名
func (c *CertInfo) MatchesDomain(domain string) bool {
	domain = strings.ToLower(domain)

	// 检查 CN
	cn := strings.ToLower(extractCN(c.Subject))
	if matchDomain(cn, domain) {
		return true
	}

	// 检查 SAN DNS 名称
	for _, dns := range c.DNSNames {
		if matchDomain(strings.ToLower(dns), domain) {
			return true
		}
	}

	return false
}

// matchDomain 检查证书域名是否匹配目标域名（支持通配符）
func matchDomain(certDomain, targetDomain string) bool {
	if certDomain == "" || targetDomain == "" {
		return false
	}

	// 精确匹配
	if certDomain == targetDomain {
		return true
	}

	// 通配符匹配 (*.example.com)
	if strings.HasPrefix(certDomain, "*.") {
		suffix := certDomain[1:] // .example.com
		// 匹配 example.com 本身
		if targetDomain == certDomain[2:] {
			return true
		}
		// 匹配 sub.example.com
		if strings.HasSuffix(targetDomain, suffix) {
			// 确保只匹配一级子域名
			prefix := targetDomain[:len(targetDomain)-len(suffix)]
			if !strings.Contains(prefix, ".") {
				return true
			}
		}
	}

	return false
}

// FilterByDomain 根据域名过滤证书列表
func FilterByDomain(certs []CertInfo, domain string) []CertInfo {
	if domain == "" {
		return certs
	}

	result := make([]CertInfo, 0)
	for _, c := range certs {
		if c.MatchesDomain(domain) {
			result = append(result, c)
		}
	}
	return result
}

// DeleteCertificate 删除证书
func DeleteCertificate(thumbprint string) error {
	// 验证并规范化证书指纹
	cleanThumbprint, err := util.NormalizeThumbprint(thumbprint)
	if err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	// 转义 PowerShell 字符串
	escapedThumbprint := util.EscapePowerShellString(cleanThumbprint)

	script := fmt.Sprintf(`
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq '%s' }
if ($cert) {
    Remove-Item -Path $cert.PSPath -Force
    Write-Output "OK"
} else {
    Write-Error "证书不存在"
}
`, escapedThumbprint)

	output, err := util.RunPowerShellCombined(script)
	if err != nil {
		return fmt.Errorf("删除证书失败: %v, 输出: %s", err, output)
	}

	return nil
}

// SetFriendlyName 修改证书友好名称
func SetFriendlyName(thumbprint, friendlyName string) error {
	// 验证并规范化证书指纹
	cleanThumbprint, err := util.NormalizeThumbprint(thumbprint)
	if err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	// 验证友好名称
	if err := util.ValidateFriendlyName(friendlyName); err != nil {
		return fmt.Errorf("无效的友好名称: %w", err)
	}

	// 转义 PowerShell 字符串
	escapedThumbprint := util.EscapePowerShellString(cleanThumbprint)
	escapedFriendlyName := util.EscapePowerShellString(friendlyName)

	script := fmt.Sprintf(`
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq '%s' }
if ($cert) {
    $cert.FriendlyName = '%s'
    Write-Output "OK"
} else {
    throw "证书未找到"
}
`, escapedThumbprint, escapedFriendlyName)

	output, err := util.RunPowerShellCombined(script)
	if err != nil {
		return fmt.Errorf("设置友好名称失败: %v, 输出: %s", err, output)
	}

	return nil
}

// GetWildcardName 获取通配符格式的友好名称
// 用于 IIS7 兼容模式，同一 IP:Port 只能绑定一个证书
func GetWildcardName(domain string) string {
	// 如果已经是通配符格式，直接返回
	if strings.HasPrefix(domain, "*.") {
		return domain
	}

	// 提取根域名并转为通配符格式
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		// 取最后两部分作为根域名
		rootDomain := strings.Join(parts[len(parts)-2:], ".")
		return "*." + rootDomain
	}

	return domain
}
