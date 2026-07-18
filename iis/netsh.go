package iis

import (
	"bufio"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"sslctlw/util"
)

// bindVerifyRetryDelay verify 步瞬时未命中后的重查间隔（测试可置 0 加速）
var bindVerifyRetryDelay = 200 * time.Millisecond

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

// capturedBinding 回绑旧证书所需的绑定参数快照。
// 最小三字段（CertHash/AppID/CertStoreName）始终可用；
// full=true 时（经 httpapi 结构化查询）携带完整高级 SSL 参数，回绑可完整还原。
type capturedBinding struct {
	CertHash      string
	AppID         string
	CertStoreName string

	// 以下高级参数仅在 full=true 时有效（HttpQueryServiceConfiguration 结构化查询结果）
	full                    bool
	certCheckMode           uint32 // DefaultCertCheckMode 位掩码
	revocationFreshnessTime uint32 // DefaultRevocationFreshnessTime（秒）
	urlRetrievalTimeout     uint32 // DefaultRevocationUrlRetrievalTimeout（毫秒）
	sslCtlIdentifier        string // pDefaultSslCtlIdentifier
	sslCtlStoreName         string // pDefaultSslCtlStoreName
	defaultFlags            uint32 // DefaultFlags 位掩码
}

// DefaultCertCheckMode / DefaultFlags 位定义（MSDN HTTP_SERVICE_CONFIG_SSL_PARAM）。
// 仅解码可映射为 netsh add sslcert 布尔参数、且高置信度的位；其余位不回写（降级为 netsh 默认）。
const (
	// certCheckModeNoVerifyRevocation 不验证客户端证书吊销 → verifyclientcertrevocation=disable
	certCheckModeNoVerifyRevocation uint32 = 0x00000001
	// certCheckModeCachedRevocationOnly 仅用缓存吊销信息 → verifyrevocationwithcachedclientcertonly=enable
	certCheckModeCachedRevocationOnly uint32 = 0x00000002
	// certCheckModeNoUsageCheck 不做用途检查 → usagecheck=disable（位值文档标注 0x10000，best-effort，误判仅退回默认不劣于现状）
	certCheckModeNoUsageCheck uint32 = 0x00010000

	// sslFlagUseDSMapper DS 映射 → dsmapperusage=enable
	sslFlagUseDSMapper uint32 = 0x00000001
	// sslFlagNegotiateClientCert 协商客户端证书 → clientcertnegotiation=enable
	sslFlagNegotiateClientCert uint32 = 0x00000002
)

// appIDOrDefault AppID 为空时回退默认全零 GUID
func appIDOrDefault(appID string) string {
	if appID == "" {
		return defaultAppID
	}
	return appID
}

// storeOrDefault 证书存储名为空时回退默认 MY
func storeOrDefault(store string) string {
	if store == "" {
		return "MY"
	}
	return store
}

// sslParamNetshArgs 将捕获的高级 SSL 参数解码为 netsh add sslcert 参数串（纯函数）。
// 仅回写非默认值：布尔参数按位置位才发、数值参数非 0 才发、字符串参数非空才发，
// 使误判/未知位至多退回 netsh 默认（不劣于最小三字段回绑）。
func sslParamNetshArgs(b *capturedBinding) []string {
	var args []string
	// DefaultCertCheckMode 位 → netsh 布尔参数
	if b.certCheckMode&certCheckModeNoVerifyRevocation != 0 {
		args = append(args, "verifyclientcertrevocation=disable")
	}
	if b.certCheckMode&certCheckModeCachedRevocationOnly != 0 {
		args = append(args, "verifyrevocationwithcachedclientcertonly=enable")
	}
	if b.certCheckMode&certCheckModeNoUsageCheck != 0 {
		args = append(args, "usagecheck=disable")
	}
	// 吊销新鲜度/URL 超时（默认 0，非 0 才回写）
	if b.revocationFreshnessTime > 0 {
		args = append(args, fmt.Sprintf("revocationfreshnesstime=%d", b.revocationFreshnessTime))
	}
	if b.urlRetrievalTimeout > 0 {
		args = append(args, fmt.Sprintf("urlretrievaltimeout=%d", b.urlRetrievalTimeout))
	}
	// SSL CTL 标识/存储（默认空）
	if b.sslCtlIdentifier != "" {
		args = append(args, fmt.Sprintf("sslctlidentifier=%s", b.sslCtlIdentifier))
	}
	if b.sslCtlStoreName != "" {
		args = append(args, fmt.Sprintf("sslctlstorename=%s", b.sslCtlStoreName))
	}
	// DefaultFlags 位 → netsh 布尔参数（默认 disable，置位才 enable）
	if b.defaultFlags&sslFlagUseDSMapper != 0 {
		args = append(args, "dsmapperusage=enable")
	}
	if b.defaultFlags&sslFlagNegotiateClientCert != 0 {
		args = append(args, "clientcertnegotiation=enable")
	}
	return args
}

// buildRebindArgs 构造 netsh http add sslcert 参数串（纯函数）。
// 始终包含 keyParam=keyValue / certhash / appid / certstorename（最小三字段回绑）；
// full=true 时附加从结构化查询解码的高级参数，最大化回绑保真度。
func buildRebindArgs(keyParam, keyValue string, b *capturedBinding) []string {
	args := []string{
		fmt.Sprintf("%s=%s", keyParam, keyValue),
		fmt.Sprintf("certhash=%s", b.CertHash),
		fmt.Sprintf("appid=%s", appIDOrDefault(b.AppID)),
		fmt.Sprintf("certstorename=%s", storeOrDefault(b.CertStoreName)),
	}
	if b.full {
		args = append(args, sslParamNetshArgs(b)...)
	}
	return args
}

// 按值匹配的正则（locale 无关，不依赖 netsh 本地化字段名）
var (
	// certHashValueRe 证书哈希值：40 位（SHA-1）或 64 位（SHA-256）十六进制
	certHashValueRe = regexp.MustCompile(`\b(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40})\b`)
	// guidValueRe GUID 值（含大括号）
	guidValueRe = regexp.MustCompile(`\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}`)
)

// parseBindingByValue 从单条绑定的 show sslcert 输出中按值提取绑定信息（纯函数）
// 证书哈希与 AppID 直接按值形态匹配，任何显示语言下都能解析；
// 存储名尝试已知字段名解析（en/zh），失败回退 MY
func parseBindingByValue(output string) *capturedBinding {
	hash := certHashValueRe.FindString(output)
	if hash == "" {
		return nil
	}
	b := &capturedBinding{CertHash: strings.ToLower(hash)}

	b.AppID = guidValueRe.FindString(output)
	if b.AppID == "" {
		b.AppID = defaultAppID
	}

	if m := storeRe.FindStringSubmatch(output); m != nil {
		b.CertStoreName = strings.TrimSpace(m[1])
	}
	if b.CertStoreName == "" {
		b.CertStoreName = "MY"
	}
	return b
}

// queryBindingByKey 查询单条 SSL 绑定（keyParam: "hostnameport" 或 "ipport"）
// 返回 nil 表示未查到（绑定不存在或查询失败）。仅捕获最小三字段（netsh show 正则解析）。
func queryBindingByKey(keyParam, keyValue string) *capturedBinding {
	output, err := util.RunCmd(util.ResolveSystem32Exe("netsh.exe"), "http", "show", "sslcert",
		fmt.Sprintf("%s=%s", keyParam, keyValue))
	if err != nil {
		return nil
	}
	return parseBindingByValue(output)
}

// captureBinding 捕获旧绑定完整参数供回绑：
// 优先经 httpapi HttpQueryServiceConfiguration 结构化查询（locale 无关，含 flags/吊销/SSL CTL 等高级参数），
// 查询失败（API 不可用/未查到/结构解析异常）降级为 netsh show 最小三字段捕获，行为不劣于现状。
func captureBinding(keyParam, keyValue string) *capturedBinding {
	if full := queryFullBinding(keyParam, keyValue); full != nil {
		return full
	}
	return queryBindingByKey(keyParam, keyValue)
}

// bindAndVerify 通用绑定流程：捕获旧绑定 → 删除 → 添加 → 验证 → 失败回绑
// 成败判定以操作后 show sslcert 查到的 certhash 为准（locale 无关，不依赖输出关键词）；
// 新绑定未生效时用捕获的旧绑定回绑恢复，避免绑定丢失导致站点下线且自动模式永不自愈
func bindAndVerify(keyParam, keyValue, certHash string, unbind func() error) error {
	// 1. 删除前捕获旧绑定完整参数（供添加失败时回绑），优先结构化查询含高级 SSL 参数
	oldBinding := captureBinding(keyParam, keyValue)

	// 2. 删除已有绑定（绑定可能本就不存在，错误忽略）
	_ = unbind()

	// 3. 添加新绑定
	addOutput, addErr := util.RunCmdCombined(util.ResolveSystem32Exe("netsh.exe"), "http", "add", "sslcert",
		fmt.Sprintf("%s=%s", keyParam, keyValue),
		fmt.Sprintf("certhash=%s", certHash),
		fmt.Sprintf("appid=%s", defaultAppID),
		"certstorename=MY")

	// 4. 操作后验证目标绑定（verify 瞬时未命中重试一次，避免 netsh show 抖动/延迟误判回绑）
	if verifyBindingWithRetry(func() *capturedBinding { return queryBindingByKey(keyParam, keyValue) }, certHash, bindVerifyRetryDelay) {
		return nil
	}

	failErr := fmt.Errorf("绑定证书失败 (%s=%s): 命令错误=%v, 输出: %s",
		keyParam, keyValue, addErr, strings.TrimSpace(addOutput))

	// 5. 新绑定未生效：尽力回绑旧证书
	if oldBinding == nil {
		return failErr
	}
	if rbErr := rebindOldBinding(keyParam, keyValue, oldBinding); rbErr != nil {
		return fmt.Errorf("%v; 回绑旧证书 %s 失败: %v", failErr, oldBinding.CertHash, rbErr)
	}
	log.Printf("绑定新证书失败，已回绑旧证书 %s (%s=%s)", oldBinding.CertHash, keyParam, keyValue)
	return fmt.Errorf("%v; 已回绑旧证书 %s", failErr, oldBinding.CertHash)
}

// verifyBindingWithRetry 校验目标绑定是否为期望证书；首次未命中后延迟重查一次再判定。
// netsh add 成功但紧接的 show 偶发瞬时失败/延迟不应直接判失败触发回绑（回绑还会丢高级 SSL flag）。
// query 可注入便于单测；retryDelay<=0 时不休眠（测试加速）。
func verifyBindingWithRetry(query func() *capturedBinding, certHash string, retryDelay time.Duration) bool {
	if current := query(); current != nil && strings.EqualFold(current.CertHash, certHash) {
		return true
	}
	if retryDelay > 0 {
		time.Sleep(retryDelay)
	}
	current := query()
	return current != nil && strings.EqualFold(current.CertHash, certHash)
}

// rebindOldBinding 用捕获的旧绑定信息恢复绑定，结果同样按实际绑定验证。
// 参数串由 buildRebindArgs 生成：完整捕获时还原全部高级 SSL 参数，最小捕获时保持三字段回绑。
func rebindOldBinding(keyParam, keyValue string, old *capturedBinding) error {
	args := append([]string{"http", "add", "sslcert"}, buildRebindArgs(keyParam, keyValue, old)...)
	output, err := util.RunCmdCombined(util.ResolveSystem32Exe("netsh.exe"), args...)

	current := queryBindingByKey(keyParam, keyValue)
	if current != nil && strings.EqualFold(current.CertHash, old.CertHash) {
		return nil
	}
	return fmt.Errorf("回绑命令错误=%v, 输出: %s", err, strings.TrimSpace(output))
}

// normalizeCertHash 清理证书哈希（移除空格和连字符，统一小写）
func normalizeCertHash(certHash string) string {
	certHash = strings.ReplaceAll(certHash, " ", "")
	certHash = strings.ReplaceAll(certHash, "-", "")
	return strings.ToLower(certHash)
}

// BindCertificate 绑定证书到指定的主机名和端口 (SNI 模式)
func BindCertificate(hostname string, port int, certHash string) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if hostname == "" {
		return fmt.Errorf("主机名不能为空，IP 绑定请使用 BindCertificateByIP")
	}
	if err := util.ValidateDomain(hostname); err != nil {
		return fmt.Errorf("无效的主机名: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}
	if err := util.ValidateThumbprint(certHash); err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	certHash = normalizeCertHash(certHash)
	hostnamePort := fmt.Sprintf("%s:%d", hostname, port)

	return bindAndVerify("hostnameport", hostnamePort, certHash, func() error {
		return UnbindCertificate(hostname, port)
	})
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

	certHash = normalizeCertHash(certHash)
	ipPort := fmt.Sprintf("%s:%d", ip, port)

	return bindAndVerify("ipport", ipPort, certHash, func() error {
		return UnbindCertificateByIP(ip, port)
	})
}

// UnbindCertificate 解除主机名端口的证书绑定 (SNI)
func UnbindCertificate(hostname string, port int) error {
	if port == 0 {
		port = 443
	}

	// 参数验证
	if hostname == "" {
		return fmt.Errorf("主机名不能为空，IP 绑定请使用 UnbindCertificateByIP")
	}
	if err := util.ValidateDomain(hostname); err != nil {
		return fmt.Errorf("无效的主机名: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}

	hostnamePort := fmt.Sprintf("%s:%d", hostname, port)
	output, err := util.RunCmdCombined(util.ResolveSystem32Exe("netsh.exe"), "http", "delete", "sslcert",
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
	output, err := util.RunCmdCombined(util.ResolveSystem32Exe("netsh.exe"), "http", "delete", "sslcert",
		fmt.Sprintf("ipport=%s", ipPort))

	if err != nil {
		return fmt.Errorf("解除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// ListSSLBindings 列出所有 SSL 证书绑定
func ListSSLBindings() ([]SSLBinding, error) {
	output, err := util.RunCmd(util.ResolveSystem32Exe("netsh.exe"), "http", "show", "sslcert")
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
