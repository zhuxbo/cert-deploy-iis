package cert

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"sslctlw/util"
)

// parseTimeMultiFormat 尝试多种日期格式解析时间字符串
// 非英文 Windows 的 PowerShell 可能输出不同的日期格式
func parseTimeMultiFormat(value string) time.Time {
	type layout struct {
		format string
		local  bool
	}
	formats := []layout{
		{"2006-01-02 15:04:05", true},        // ISO 格式 (PowerShell ToString 指定)
		{"2006/01/02 15:04:05", true},        // 斜杠格式
		{"01/02/2006 15:04:05", true},        // US 格式 (MM/DD/YYYY)
		{"02/01/2006 15:04:05", true},        // GB 格式 (DD/MM/YYYY)
		{"1/2/2006 15:04:05", true},          // US 短格式
		{"2/1/2006 15:04:05", true},          // GB 短格式
		{"1/2/2006 3:04:05 PM", true},        // US 12小时格式
		{"2006-01-02T15:04:05", true},        // ISO 8601 (无时区，按本地时间)
		{"2006-01-02T15:04:05Z07:00", false}, // ISO 8601 with timezone
		{"2006-01-02", true},                 // 仅日期
	}
	for _, f := range formats {
		var (
			t   time.Time
			err error
		)
		if f.local {
			t, err = time.ParseInLocation(f.format, value, time.Local)
		} else {
			t, err = time.Parse(f.format, value)
		}
		if err == nil {
			return t
		}
	}
	log.Printf("警告: 无法解析日期 %q，所有格式均失败", value)
	return time.Time{}
}

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
    # 获取 SAN 中的 DNS 名称（支持多种格式：DNS Name=, DNS:, DNS 名称=）
    $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
    if ($san) {
        $sanStr = $san.Format($false)
        # 匹配多种格式：DNS Name=xxx, DNS:xxx, DNS 名称=xxx
        $dnsNames = [regex]::Matches($sanStr, '(?:DNS Name=|DNS:|DNS 名称=)([^\s,]+)') | ForEach-Object { $_.Groups[1].Value }
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
				current.NotBefore = parseTimeMultiFormat(value)
			case "NotAfter":
				current.NotAfter = parseTimeMultiFormat(value)
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

// cnRegex 用于从证书主题中提取 CN
var cnRegex = regexp.MustCompile(`CN=([^,]+)`)

// extractCN 从证书主题中提取 CN
func extractCN(subject string) string {
	matches := cnRegex.FindStringSubmatch(subject)
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
	// 检查 CN
	cn := extractCN(c.Subject)
	if util.MatchDomain(domain, cn) {
		return true
	}

	// 检查 SAN DNS 名称
	for _, dns := range c.DNSNames {
		if util.MatchDomain(domain, dns) {
			return true
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
    throw "证书不存在"
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

	// 去掉第一级子域名，替换为通配符
	// a.b.example.com → *.b.example.com
	// www.example.com → *.example.com
	// example.com     → *.example.com（根域名保持完整）
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) == 2 && parts[1] != "" {
		// 根域名（只有两部分如 example.com）→ *.example.com
		if !strings.Contains(parts[1], ".") {
			return "*." + domain
		}
		return "*." + parts[1]
	}

	return domain
}
