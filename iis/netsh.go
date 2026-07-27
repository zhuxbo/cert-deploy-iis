package iis

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"sslctlw/util"
)

// bindVerifyRetryDelay verify 步瞬时未命中后的重查间隔（测试可置 0 加速）
var bindVerifyRetryDelay = 200 * time.Millisecond

// netsh 执行与 httpapi 查询入口（包级变量，供测试注入；生产值为真实实现）
var (
	// netshQuery 只读查询（stdout）
	netshQuery = func(args ...string) (string, error) {
		return util.RunCmd(util.ResolveSystem32Exe("netsh.exe"), args...)
	}
	// netshExec 变更类命令（stdout+stderr，失败信息需要回显）
	netshExec = func(args ...string) (string, error) {
		return util.RunCmdCombined(util.ResolveSystem32Exe("netsh.exe"), args...)
	}
	// queryFullBindingFn httpapi 结构化查询入口
	queryFullBindingFn = queryFullBinding
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
// 始终包含 keyParam=keyValue / certhash / appid / certstorename（最小三字段）；
// full=true 时附加从结构化查询解码的高级参数，供成功替换和失败回绑复用。
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

// netshCompleted 判断 netsh 是否真正执行完毕（而非根本没跑起来）。
// 精确查询下“执行完毕 + 非零退出”意味着该键无绑定；进程无法创建（PATH 损坏、
// ResolveSystem32Exe 未解析到绝对路径）则状态未知，不得据此执行破坏性操作。
// 残余不确定：命令超时被强制终止在 Windows 上同样表现为已退出，会被归入“不存在”；
// netsh show 属只读快查，超时概率远低于进程创建失败，故取此判定。
func netshCompleted(err error) bool {
	var exitErr *exec.ExitError
	// ProcessState 为空说明进程从未进入退出状态，Exited() 会解引用空指针
	if !errors.As(err, &exitErr) || exitErr.ProcessState == nil {
		return false
	}
	return exitErr.Exited()
}

// queryBindingByNetsh 经 netsh 查询单条 SSL 绑定，返回三态：
// (binding, nil) 确认存在；(nil, nil) 确认不存在（netsh 执行完毕且精确查询无结果）；
// (nil, err) 状态未知（netsh 无法执行或输出异常），调用方不得据此做破坏性操作。
func queryBindingByNetsh(keyParam, keyValue string) (*capturedBinding, error) {
	output, err := netshQuery("http", "show", "sslcert",
		fmt.Sprintf("%s=%s", keyParam, keyValue))
	if err != nil {
		if netshCompleted(err) {
			return nil, nil // netsh 已执行并以非零退出：该键无绑定
		}
		return nil, fmt.Errorf("netsh 查询失败: %w", err)
	}
	binding := parseBindingByValue(output)
	if binding == nil {
		// 退出码 0 却解析不出证书哈希属异常输出，宁可判未知也不误判为不存在
		return nil, errors.New("netsh 查询成功但输出无法解析")
	}
	return binding, nil
}

// queryBindingByKey 查询单条 SSL 绑定（keyParam: "hostnameport" 或 "ipport"）。
// 优先使用 httpapi 精确区分“不存在”和“查询失败”；结构化查询不可用时降级 netsh。
func queryBindingByKey(keyParam, keyValue string) (*capturedBinding, error) {
	binding, structuredErr := queryFullBindingFn(keyParam, keyValue)
	if structuredErr == nil {
		return binding, nil
	}
	binding, netshErr := queryBindingByNetsh(keyParam, keyValue)
	if netshErr == nil {
		return binding, nil
	}
	return nil, fmt.Errorf("结构化查询失败: %v; %w", structuredErr, netshErr)
}

// bindAndVerify 通用绑定流程：捕获旧绑定 → 删除 → 添加 → 验证 → 失败回绑
// 成败判定以操作后 show sslcert 查到的 certhash 为准（locale 无关，不依赖输出关键词）；
// 新绑定未生效时用捕获的旧绑定回绑恢复，避免绑定丢失导致站点下线且自动模式永不自愈
func bindAndVerify(keyParam, keyValue, certHash string, unbind func() error) error {
	// 1. 删除前捕获旧绑定完整参数（供添加失败时回绑），优先结构化查询含高级 SSL 参数。
	//    状态无法确认时必须在删除前中止：先删再发现没有快照可回绑，会让站点 HTTPS 下线且无法恢复。
	oldBinding, captureErr := queryBindingByKey(keyParam, keyValue)
	if captureErr != nil {
		return fmt.Errorf("无法确认 %s=%s 的现有绑定状态，已中止绑定以避免删除后无法恢复: %w",
			keyParam, keyValue, captureErr)
	}

	// 2. 删除已有绑定（绑定可能本就不存在，错误忽略）
	newBinding := &capturedBinding{CertHash: certHash}
	if oldBinding != nil {
		// 复制快照而不改写旧绑定；添加失败时仍需用旧哈希执行回绑。
		*newBinding = *oldBinding
		newBinding.CertHash = certHash
		newBinding.CertStoreName = "MY" // 新证书固定安装到 LocalMachine\My
		if !oldBinding.full {
			log.Printf("警告: %s=%s 仅通过 netsh 捕获到最小绑定信息，本次替换的高级 SSL 参数无法保真",
				keyParam, keyValue)
		}
	}
	_ = unbind()

	// 3. 添加新绑定：完整捕获时保留 AppID 与已确认的高级 SSL 参数；
	//    降级捕获时保留已确认的 AppID，不伪造未知高级参数。
	addArgs := append([]string{"http", "add", "sslcert"}, buildRebindArgs(keyParam, keyValue, newBinding)...)
	addOutput, addErr := netshExec(addArgs...)

	// 4. 操作后验证目标绑定；明确区分目标已生效、不存在、异常占用与查询失败。
	current, queryErr := queryBindingWithRetry(
		func() (*capturedBinding, error) { return queryBindingByKey(keyParam, keyValue) },
		certHash,
		bindVerifyRetryDelay,
	)
	state := classifyBindingState(current, queryErr, certHash)
	if state == bindingStateDesired {
		return nil
	}

	failErr := fmt.Errorf("绑定证书失败 (%s=%s): 命令错误=%v, 输出: %s",
		keyParam, keyValue, addErr, strings.TrimSpace(addOutput))

	// 查询失败时实际状态未知，禁止盲删一个可能已正确生效的新绑定。
	if !bindingStateAllowsRecovery(state) {
		return fmt.Errorf("%v; 操作后绑定状态无法确认，未执行破坏性回滚: %v", failErr, queryErr)
	}

	// 5. 已确认新绑定不存在或存在异常绑定：尽力恢复旧证书。
	if oldBinding == nil {
		return failErr
	}
	if rbErr := rebindOldBinding(keyParam, keyValue, current, oldBinding); rbErr != nil {
		return fmt.Errorf("%v; 回绑旧证书 %s 失败: %v", failErr, oldBinding.CertHash, rbErr)
	}
	log.Printf("绑定新证书失败，已回绑旧证书 %s (%s=%s)", oldBinding.CertHash, keyParam, keyValue)
	return fmt.Errorf("%v; 已回绑旧证书 %s", failErr, oldBinding.CertHash)
}

// rebindOldBinding 用捕获的旧绑定信息恢复绑定，结果同样按实际绑定验证。
// 参数串由 buildRebindArgs 生成：完整捕获时还原全部高级 SSL 参数，最小捕获时保持三字段回绑。
func rebindOldBinding(keyParam, keyValue string, current, old *capturedBinding) error {
	deleteCurrent := func() error {
		output, err := netshExec("http", "delete", "sslcert",
			fmt.Sprintf("%s=%s", keyParam, keyValue))
		if err != nil {
			return fmt.Errorf("命令错误=%v, 输出: %s", err, strings.TrimSpace(output))
		}
		return nil
	}
	addOld := func() error {
		args := append([]string{"http", "add", "sslcert"}, buildRebindArgs(keyParam, keyValue, old)...)
		output, err := netshExec(args...)
		if err != nil {
			return fmt.Errorf("命令错误=%v, 输出: %s", err, strings.TrimSpace(output))
		}
		return nil
	}
	return restoreBinding(
		current,
		old,
		deleteCurrent,
		addOld,
		func() (*capturedBinding, error) { return queryBindingByKey(keyParam, keyValue) },
	)
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

// BindCertificateByIP 绑定证书到指定的 IP 和端口 (非 SNI 模式)。
// 支持 IPv4/IPv6 与通配地址；IP 绑定每端口唯一，替换失败由 bindAndVerify 复验并回绑旧证书兜底，
// 状态未知时不执行破坏性回滚，避免误删同端口上可能已生效的其他证书绑定。
func BindCertificateByIP(ip string, port int, certHash string) error {
	if port == 0 {
		port = 443
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	// 参数验证（IPv4/IPv6 通用）
	if err := util.ValidateIP(ip); err != nil {
		return fmt.Errorf("无效的 IP 地址: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}
	if err := util.ValidateThumbprint(certHash); err != nil {
		return fmt.Errorf("无效的证书指纹: %w", err)
	}

	certHash = normalizeCertHash(certHash)
	ipPort := formatIPPortKey(ip, port)

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
	output, err := netshExec("http", "delete", "sslcert",
		fmt.Sprintf("hostnameport=%s", hostnamePort))

	if err != nil {
		return fmt.Errorf("解除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// UnbindCertificateByIP 解除 IP 端口的证书绑定（支持 IPv4/IPv6）
func UnbindCertificateByIP(ip string, port int) error {
	if port == 0 {
		port = 443
	}
	if ip == "" {
		ip = "0.0.0.0"
	}

	// 参数验证（IPv4/IPv6 通用）
	if err := util.ValidateIP(ip); err != nil {
		return fmt.Errorf("无效的 IP 地址: %w", err)
	}
	if err := util.ValidatePort(port); err != nil {
		return fmt.Errorf("无效的端口: %w", err)
	}

	ipPort := formatIPPortKey(ip, port)
	output, err := netshExec("http", "delete", "sslcert",
		fmt.Sprintf("ipport=%s", ipPort))

	if err != nil {
		return fmt.Errorf("解除绑定失败: %v, 输出: %s", err, output)
	}

	return nil
}

// ListSSLBindings 列出所有 SSL 证书绑定
func ListSSLBindings() ([]SSLBinding, error) {
	output, err := netshQuery("http", "show", "sslcert")
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

// GetBindingForIP 获取指定 IP 的 SSL 绑定（支持 IPv4/IPv6）
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

	target := formatIPPortKey(ip, port)
	for i := range bindings {
		if strings.EqualFold(bindings[i].HostnamePort, target) {
			return &bindings[i], nil
		}
	}

	return nil, nil // 未找到
}

// ParseBindingEndpoint 严格解析 netsh 返回的绑定端点；坏端口不得回退默认值。
func ParseBindingEndpoint(binding SSLBinding) (EndpointKey, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(binding.HostnamePort))
	if err != nil {
		return EndpointKey{}, fmt.Errorf("解析绑定端点 %q 失败: %w", binding.HostnamePort, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return EndpointKey{}, fmt.Errorf("绑定端点 %q 的端口无效", binding.HostnamePort)
	}
	return NormalizeEndpoint(binding.IsIPBinding, host, port)
}

func sameBindingAtEndpoint(a, b SSLBinding) bool {
	equalField := func(left, right string) bool {
		return strings.EqualFold(strings.TrimSpace(left), strings.TrimSpace(right))
	}
	return equalField(a.CertHash, b.CertHash) &&
		equalField(a.AppID, b.AppID) &&
		equalField(a.CertStoreName, b.CertStoreName) &&
		equalField(a.SslCtlStoreName, b.SslCtlStoreName) &&
		a.IsIPBinding == b.IsIPBinding
}

// findBindingsFromList 从绑定列表中查找匹配指定域名的 SNI 绑定（纯函数，便于测试）。
func findBindingsFromList(bindings []SSLBinding, domains []string) ([]SSLBinding, error) {
	byEndpoint := make(map[EndpointKey]SSLBinding)
	for _, b := range bindings {
		if b.IsIPBinding {
			continue
		}
		rawEndpoint := strings.TrimSpace(b.HostnamePort)
		rawHost, _, splitErr := net.SplitHostPort(rawEndpoint)
		if rawEndpoint == "" || (splitErr == nil && strings.TrimSpace(rawHost) == "") {
			continue
		}

		key, err := ParseBindingEndpoint(b)
		if err != nil {
			return nil, err
		}
		for _, certDomain := range domains {
			if util.MatchDomain(key.Host, certDomain) {
				if previous, exists := byEndpoint[key]; exists {
					if !sameBindingAtEndpoint(previous, b) {
						return nil, fmt.Errorf("IIS SSL 绑定端点 %s:%d 存在歧义", key.Host, key.Port)
					}
					break
				}
				byEndpoint[key] = b
				break
			}
		}
	}

	keys := make([]EndpointKey, 0, len(byEndpoint))
	for key := range byEndpoint {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].IPBinding != keys[j].IPBinding {
			return !keys[i].IPBinding
		}
		if keys[i].Host != keys[j].Host {
			return keys[i].Host < keys[j].Host
		}
		return keys[i].Port < keys[j].Port
	})

	result := make([]SSLBinding, 0, len(keys))
	for _, key := range keys {
		result = append(result, byEndpoint[key])
	}
	return result, nil
}

// FindBindingsForDomains 查找与指定域名匹配的 SNI 绑定
// 返回稳定排序的完整绑定端点切片。
// 注意: 只匹配 SNI 绑定（Hostname:port），忽略 IP 绑定（空主机名）
// IP 绑定用于通配符泛匹配或 IP 证书，需用户手工管理
func FindBindingsForDomains(domains []string) ([]SSLBinding, error) {
	bindings, err := ListSSLBindings()
	if err != nil {
		return nil, err
	}
	return findBindingsFromList(bindings, domains)
}

// ParseHostFromBinding 从 "host:port" 提取主机名。
// 兼容 IPv6 方括号形态：`[::1]:443` → `::1`（去括号返回裸 IP，便于 net.ParseIP 判定）；
// SNI 主机名与 IPv4 保持原样。
func ParseHostFromBinding(hostnamePort string) string {
	if strings.HasPrefix(hostnamePort, "[") {
		if end := strings.Index(hostnamePort, "]"); end > 1 {
			return hostnamePort[1:end]
		}
	}
	idx := strings.LastIndex(hostnamePort, ":")
	if idx > 0 {
		return hostnamePort[:idx]
	}
	return hostnamePort
}

// ParsePortFromBinding 从 "host:port" 提取端口。兼容 IPv6 方括号形态 `[::1]:443`。
func ParsePortFromBinding(hostnamePort string) int {
	rest := hostnamePort
	if strings.HasPrefix(hostnamePort, "[") {
		if end := strings.Index(hostnamePort, "]"); end > 0 {
			rest = hostnamePort[end+1:] // "]:443" 之后的 ":443"
		}
	}
	idx := strings.LastIndex(rest, ":")
	if idx >= 0 && idx < len(rest)-1 {
		portStr := rest[idx+1:]
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		if port > 0 {
			return port
		}
	}
	return 443
}

// formatIPPortKey 构造 netsh ipport 键：IPv6 地址加方括号（[::1]:443），
// IPv4 与通配地址直接拼接（0.0.0.0:443）。已带方括号的输入原样使用。
func formatIPPortKey(ip string, port int) string {
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}
