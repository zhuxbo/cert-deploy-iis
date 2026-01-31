package iis

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cert-deploy/util"
)

// validateBindingParams 验证绑定参数
func validateBindingParams(siteName, host string, port int) error {
	if err := util.ValidateSiteName(siteName); err != nil {
		return fmt.Errorf("无效的站点名称: %w", err)
	}
	if host != "" {
		if err := util.ValidateDomain(host); err != nil {
			return fmt.Errorf("无效的主机名: %w", err)
		}
	}
	if port != 0 {
		if err := util.ValidatePort(port); err != nil {
			return fmt.Errorf("无效的端口: %w", err)
		}
	}
	return nil
}

// GetIISMajorVersion 获取 IIS 主版本号
func GetIISMajorVersion() (int, error) {
	script := `
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue).MajorVersion
`
	output, err := util.RunPowerShell(script)
	if err != nil {
		return 0, fmt.Errorf("获取 IIS 版本失败: %v", err)
	}

	output = strings.TrimSpace(output)
	if output == "" {
		return 0, fmt.Errorf("无法获取 IIS 版本")
	}

	version, err := strconv.Atoi(output)
	if err != nil {
		return 0, fmt.Errorf("解析 IIS 版本失败: %v", err)
	}

	return version, nil
}

// IsIIS7 检查是否是 IIS7 (版本 < 8，不支持 SNI)
func IsIIS7() bool {
	version, err := GetIISMajorVersion()
	return err == nil && version < 8
}

// appcmd XML 输出结构
type appcmdSiteList struct {
	XMLName xml.Name     `xml:"appcmd"`
	Sites   []appcmdSite `xml:"SITE"`
}

type appcmdSite struct {
	Name     string `xml:"SITE.NAME,attr"`
	ID       string `xml:"SITE.ID,attr"`
	Bindings string `xml:"bindings,attr"`
	State    string `xml:"state,attr"`
}

// getAppcmdPath 获取 appcmd.exe 路径
func getAppcmdPath() string {
	windir := os.Getenv("windir")
	if windir == "" {
		windir = "C:\\Windows"
	}
	return filepath.Join(windir, "System32", "inetsrv", "appcmd.exe")
}

// CheckIISInstalled 检查 IIS 是否安装
func CheckIISInstalled() error {
	path := getAppcmdPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("IIS 未安装或 appcmd.exe 不存在: %s", path)
	}
	return nil
}

// ScanSites 扫描所有 IIS 站点
func ScanSites() ([]SiteInfo, error) {
	if err := CheckIISInstalled(); err != nil {
		return nil, err
	}

	output, err := util.RunCmd(getAppcmdPath(), "list", "site", "/xml")
	if err != nil {
		return nil, fmt.Errorf("执行 appcmd 失败: %v", err)
	}

	var result appcmdSiteList
	if err := xml.Unmarshal([]byte(output), &result); err != nil {
		return nil, fmt.Errorf("解析 XML 失败: %v", err)
	}

	sites := make([]SiteInfo, 0, len(result.Sites))
	for _, s := range result.Sites {
		id, _ := strconv.ParseInt(s.ID, 10, 64)
		site := SiteInfo{
			ID:       id,
			Name:     s.Name,
			State:    s.State,
			Bindings: parseBindings(s.Bindings),
		}
		sites = append(sites, site)
	}

	return sites, nil
}

// parseBindings 解析绑定字符串
// 格式: "http/*:80:,https/*:443:example.com"
func parseBindings(bindingsStr string) []BindingInfo {
	bindings := make([]BindingInfo, 0)
	if bindingsStr == "" {
		return bindings
	}

	parts := strings.Split(bindingsStr, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 格式: protocol/ip:port:host
		slashIdx := strings.Index(part, "/")
		if slashIdx < 0 {
			continue
		}

		protocol := part[:slashIdx]
		rest := part[slashIdx+1:]

		// 解析 ip:port:host
		colonParts := strings.SplitN(rest, ":", 3)
		if len(colonParts) < 2 {
			continue
		}

		ip := colonParts[0]
		if ip == "*" {
			ip = "0.0.0.0"
		}

		port, _ := strconv.Atoi(colonParts[1])

		host := ""
		if len(colonParts) > 2 {
			host = colonParts[2]
		}

		binding := BindingInfo{
			Protocol: protocol,
			IP:       ip,
			Port:     port,
			Host:     host,
			HasSSL:   strings.EqualFold(protocol, "https"),
		}
		bindings = append(bindings, binding)
	}

	return bindings
}

// AddHttpsBinding 添加 HTTPS 绑定（启用 SNI）
func AddHttpsBinding(siteName, host string, port int) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if err := validateBindingParams(siteName, host, port); err != nil {
		return err
	}

	bindingInfo := fmt.Sprintf("*:%d:%s", port, host)
	// sslFlags=1 表示启用 SNI（服务器名称指示）
	output, err := util.RunCmdCombined(getAppcmdPath(), "set", "site",
		fmt.Sprintf("/site.name:%s", siteName),
		fmt.Sprintf("/+bindings.[protocol='https',bindingInformation='%s',sslFlags='1']", bindingInfo))

	if err != nil {
		return fmt.Errorf("添加绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// AddHttpsBindingWithCert 添加 HTTPS 绑定并绑定证书（启用 SNI）
func AddHttpsBindingWithCert(siteName, host string, port int, certHash string) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if err := validateBindingParams(siteName, host, port); err != nil {
		return err
	}
	if err := util.ValidateThumbprint(certHash); err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	// 清理证书哈希
	certHash = strings.ReplaceAll(certHash, " ", "")
	certHash = strings.ReplaceAll(certHash, "-", "")

	bindingInfo := fmt.Sprintf("*:%d:%s", port, host)
	// sslFlags=1 表示启用 SNI
	output, err := util.RunCmdCombined(getAppcmdPath(), "set", "site",
		fmt.Sprintf("/site.name:%s", siteName),
		fmt.Sprintf("/+bindings.[protocol='https',bindingInformation='%s',sslFlags='1']", bindingInfo))

	if err != nil {
		// 如果绑定已存在，忽略错误继续
		if !strings.Contains(output, "already exists") && !strings.Contains(output, "已存在") {
			return fmt.Errorf("添加绑定失败: %v, 输出: %s", err, output)
		}
	}

	return nil
}

// RemoveHttpsBinding 移除 HTTPS 绑定
func RemoveHttpsBinding(siteName, host string, port int) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if err := validateBindingParams(siteName, host, port); err != nil {
		return err
	}

	bindingInfo := fmt.Sprintf("*:%d:%s", port, host)
	output, err := util.RunCmdCombined(getAppcmdPath(), "set", "site",
		fmt.Sprintf("/site.name:%s", siteName),
		fmt.Sprintf("/-bindings.[protocol='https',bindingInformation='%s']", bindingInfo))

	if err != nil {
		return fmt.Errorf("移除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// GetSiteState 获取站点状态
func GetSiteState(siteName string) (string, error) {
	// 参数验证
	if err := util.ValidateSiteName(siteName); err != nil {
		return "", fmt.Errorf("无效的站点名称: %w", err)
	}

	output, err := util.RunCmd(getAppcmdPath(), "list", "site", siteName, "/xml")
	if err != nil {
		return "", fmt.Errorf("获取站点状态失败: %v", err)
	}

	var result appcmdSiteList
	if err := xml.Unmarshal([]byte(output), &result); err != nil {
		return "", fmt.Errorf("解析 XML 失败: %v", err)
	}

	if len(result.Sites) == 0 {
		return "", fmt.Errorf("站点不存在: %s", siteName)
	}

	return result.Sites[0].State, nil
}

// StartSite 启动站点
func StartSite(siteName string) error {
	// 参数验证
	if err := util.ValidateSiteName(siteName); err != nil {
		return fmt.Errorf("无效的站点名称: %w", err)
	}

	output, err := util.RunCmdCombined(getAppcmdPath(), "start", "site", siteName)
	if err != nil {
		return fmt.Errorf("启动站点失败: %v, 输出: %s", err, output)
	}
	return nil
}

// StopSite 停止站点
func StopSite(siteName string) error {
	// 参数验证
	if err := util.ValidateSiteName(siteName); err != nil {
		return fmt.Errorf("无效的站点名称: %w", err)
	}

	output, err := util.RunCmdCombined(getAppcmdPath(), "stop", "site", siteName)
	if err != nil {
		return fmt.Errorf("停止站点失败: %v, 输出: %s", err, output)
	}
	return nil
}

// HttpBindingMatch HTTP 绑定匹配结果
type HttpBindingMatch struct {
	SiteName   string
	Host       string
	Port       int
	CertDomain string // 匹配的证书域名
}

// FindMatchingBindings 查找与证书域名匹配的 IIS 绑定
// 返回: httpsBindings (已有HTTPS绑定), httpBindings (可添加HTTPS的HTTP绑定)
func FindMatchingBindings(certDomains []string) (httpsMatches []HttpBindingMatch, httpMatches []HttpBindingMatch, err error) {
	sites, err := ScanSites()
	if err != nil {
		return nil, nil, err
	}

	httpsMatches = make([]HttpBindingMatch, 0)
	httpMatches = make([]HttpBindingMatch, 0)

	// 用于去重
	httpsFound := make(map[string]bool) // host:port -> true
	httpFound := make(map[string]bool)  // siteName:host -> true

	for _, site := range sites {
		for _, binding := range site.Bindings {
			if binding.Host == "" {
				continue
			}

			// 检查绑定的域名是否匹配证书的任意域名
			matchedDomain := ""
			for _, certDomain := range certDomains {
				if MatchDomainForBinding(binding.Host, certDomain) {
					matchedDomain = certDomain
					break
				}
			}

			if matchedDomain == "" {
				continue
			}

			if binding.Protocol == "https" {
				key := fmt.Sprintf("%s:%d", binding.Host, binding.Port)
				if !httpsFound[key] {
					httpsFound[key] = true
					httpsMatches = append(httpsMatches, HttpBindingMatch{
						SiteName:   site.Name,
						Host:       binding.Host,
						Port:       binding.Port,
						CertDomain: matchedDomain,
					})
				}
			} else if binding.Protocol == "http" {
				// HTTP 绑定：检查同站点是否已有对应的 HTTPS 绑定
				hasHttps := false
				for _, b := range site.Bindings {
					if b.Protocol == "https" && strings.EqualFold(b.Host, binding.Host) {
						hasHttps = true
						break
					}
				}

				if !hasHttps {
					key := fmt.Sprintf("%s:%s", site.Name, binding.Host)
					if !httpFound[key] {
						httpFound[key] = true
						httpMatches = append(httpMatches, HttpBindingMatch{
							SiteName:   site.Name,
							Host:       binding.Host,
							Port:       443, // 默认 HTTPS 端口
							CertDomain: matchedDomain,
						})
					}
				}
			}
		}
	}

	return httpsMatches, httpMatches, nil
}

// GetSitePhysicalPath 获取站点的物理路径
func GetSitePhysicalPath(siteName string) (string, error) {
	// 参数验证
	if err := util.ValidateSiteName(siteName); err != nil {
		return "", fmt.Errorf("无效的站点名称: %w", err)
	}

	// 转义 PowerShell 字符串
	escapedSiteName := util.EscapePowerShellString(siteName)

	// 使用 PowerShell 获取站点的物理路径
	script := fmt.Sprintf(`
Import-Module WebAdministration -ErrorAction SilentlyContinue
$site = Get-Item "IIS:\Sites\%s" -ErrorAction SilentlyContinue
if ($site) {
    $app = Get-WebApplication -Site '%s' -ErrorAction SilentlyContinue | Where-Object { $_.path -eq "/" }
    if ($app) {
        $app.PhysicalPath
    } else {
        $site.physicalPath
    }
}
`, escapedSiteName, escapedSiteName)

	output, err := util.RunPowerShell(script)
	if err != nil {
		return "", fmt.Errorf("获取站点路径失败: %v", err)
	}

	path := strings.TrimSpace(output)
	if path == "" {
		return "", fmt.Errorf("站点 %s 物理路径为空", siteName)
	}

	// 展开环境变量
	path = expandIISPhysicalPath(path)

	return path, nil
}

func expandIISPhysicalPath(path string) string {
	expanded := os.ExpandEnv(path)
	if !strings.Contains(expanded, "%") {
		return expanded
	}

	var builder strings.Builder
	builder.Grow(len(expanded))

	for i := 0; i < len(expanded); i++ {
		if expanded[i] != '%' {
			builder.WriteByte(expanded[i])
			continue
		}

		end := strings.IndexByte(expanded[i+1:], '%')
		if end < 0 {
			builder.WriteByte(expanded[i])
			continue
		}
		end = i + 1 + end

		if end == i+1 {
			builder.WriteByte('%')
			i = end
			continue
		}

		key := expanded[i+1 : end]
		if value, ok := os.LookupEnv(key); ok {
			builder.WriteString(value)
		} else {
			builder.WriteString(expanded[i : end+1])
		}
		i = end
	}

	return builder.String()
}

// GetSitePhysicalPathByDomain 根据域名查找站点并获取物理路径
func GetSitePhysicalPathByDomain(domain string) (string, string, error) {
	sites, err := ScanSites()
	if err != nil {
		return "", "", err
	}

	domain = strings.ToLower(strings.TrimSpace(domain))

	for _, site := range sites {
		for _, binding := range site.Bindings {
			if strings.EqualFold(binding.Host, domain) {
				path, err := GetSitePhysicalPath(site.Name)
				if err != nil {
					continue
				}
				return site.Name, path, nil
			}
		}
	}

	candidateSites := make([]string, 0)
	seen := make(map[string]bool)
	for _, site := range sites {
		for _, binding := range site.Bindings {
			if binding.Host != "" {
				continue
			}
			if !strings.EqualFold(binding.Protocol, "http") || binding.Port != 80 {
				continue
			}
			if !seen[site.Name] {
				seen[site.Name] = true
				candidateSites = append(candidateSites, site.Name)
			}
		}
	}

	if len(candidateSites) == 1 {
		path, err := GetSitePhysicalPath(candidateSites[0])
		if err != nil {
			return "", "", err
		}
		return candidateSites[0], path, nil
	}

	if len(candidateSites) > 1 {
		return "", "", fmt.Errorf("未找到域名 %s 对应的站点，存在多个无主机头 HTTP 绑定: %s", domain, strings.Join(candidateSites, ", "))
	}

	return "", "", fmt.Errorf("未找到域名 %s 对应的站点", domain)
}

// MatchDomainForBinding 检查绑定域名是否匹配证书域名
// bindingHost: IIS 绑定的域名 (如 www.example.com)
// certDomain: 证书的域名 (如 *.example.com 或 www.example.com)
func MatchDomainForBinding(bindingHost, certDomain string) bool {
	bindingHost = strings.ToLower(strings.TrimSpace(bindingHost))
	certDomain = strings.ToLower(strings.TrimSpace(certDomain))

	if bindingHost == "" || certDomain == "" {
		return false
	}

	// 精确匹配
	if bindingHost == certDomain {
		return true
	}

	// 通配符证书匹配: *.example.com 匹配 www.example.com, api.example.com 等
	if strings.HasPrefix(certDomain, "*.") {
		suffix := certDomain[1:] // ".example.com"
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
