package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
	"sslctlw/util"
)

// ProgressFunc 进度回调
type ProgressFunc func(step, total int, message string)

// PromptKeyFunc 交互回调：请求用户提供私钥 PEM
// domain: 证书主域名（用于提示）
// certPEM: 证书内容（用于显示信息或验证）
// 返回私钥 PEM 内容，空字符串表示用户跳过
type PromptKeyFunc func(domain string, certPEM string) string

// RunResult 部署汇总结果
type RunResult struct {
	Installed int
	Skipped   int
	Failed    int
	NeedKey   int
}

// needKeyCert 需要私钥的证书信息（阶段 2 使用）
type needKeyCert struct {
	certData     api.CertData
	serialNumber string
}

// Run 执行一键部署
// promptKey 可选：提供时在需要私钥时交互提示用户，nil 则跳过交互
func Run(opts Options, progress ProgressFunc, promptKey PromptKeyFunc) (*RunResult, error) {
	totalSteps := 7
	step := 0

	report := func(msg string) {
		step++
		if progress != nil {
			progress(step, totalSteps, msg)
		}
		log.Printf("[setup %d/%d] %s", step, totalSteps, msg)
	}

	// 1. 校验参数
	report("校验参数...")
	allowed, reason := api.IsAllowedAPIURL(opts.URL)
	if !allowed {
		return nil, fmt.Errorf("API 地址不合法: %s", reason)
	}

	client := api.NewClient(opts.URL, opts.Token)

	// 2. 查询证书（独立超时：交互可能长时间阻塞，各 API 调用各自新建 context，
	// 不再共用一个贯穿全程的 ctx，避免交互后用已过期 ctx 通知服务端失败）
	report("查询证书...")
	var certs []api.CertData
	var err error

	queryCtx, queryCancel := context.WithTimeout(context.Background(), 60*api.APIQueryTimeout/30)
	if opts.Order != "" {
		certs, err = client.ListCertsByQuery(queryCtx, opts.Order)
	} else {
		certs, err = client.ListAllCerts(queryCtx)
	}
	queryCancel()
	if err != nil {
		return nil, fmt.Errorf("查询证书失败: %w", err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("未找到任何证书")
	}

	// 3. 过滤 active
	report("过滤有效证书...")
	var activeCerts []api.CertData
	for _, c := range certs {
		if c.Status == "active" {
			activeCerts = append(activeCerts, c)
		}
	}
	if len(activeCerts) == 0 {
		return nil, fmt.Errorf("没有 active 状态的证书（共查询到 %d 个）", len(certs))
	}
	log.Printf("[setup] 找到 %d 个有效证书", len(activeCerts))

	// 4. 阶段 1：批量安装（优先级 1-3，不交互）
	report(fmt.Sprintf("开始安装 %d 个证书...", len(activeCerts)))
	result := &RunResult{}
	var certConfigs []config.CertConfig
	var needKeys []needKeyCert

	// 现有配置：setup 重跑时按订单已配置的续签模式通知服务端（spec 5.2），
	// 避免把 local 模式订单的服务端自动重签误开为 pull 语义。
	// 配置存在但加载失败时无法确认既有模式，本次跳过续签模式通知（不通知优于错误通知）
	existingCfg, cfgErr := config.Load()
	cfgLoadOK := cfgErr == nil
	if cfgErr != nil {
		existingCfg = nil
		log.Printf("警告: 加载现有配置失败 (%v)，本次 setup 跳过服务端续签模式通知", cfgErr)
	}

	for _, certData := range activeCerts {
		// 优先级 3：检查是否已在 Windows 证书存储中
		serialNumber, _ := cert.GetCertSerialNumber(certData.Certificate)
		if serialNumber != "" {
			exists, certInfo, _ := cert.IsCertExists(serialNumber)
			if exists {
				log.Printf("证书 %s 已存在，跳过导入", certData.Domain())
				// 已存在证书仍需绑定生效才算部署成功：与新装路径共用 evalBindOutcome 判定，
				// 查找出错/全部失败/零匹配（含无法取指纹）同样计失败、发 failure 回调、不写入完成配置
				var br bindResult
				bindErr := errors.New("无法获取已存在证书的指纹")
				if certInfo != nil && certInfo.Thumbprint != "" {
					br, bindErr = bindCertToIIS(certData, certInfo.Thumbprint)
				}
				dec := decideExistingCert(br, bindErr)
				if !dec.Deployed {
					log.Printf("证书 %s 部署失败: %s", certData.Domain(), dec.Reason)
					sendSetupCallback(client, certData.OrderID, certData.Domain(), false, dec.Reason)
					result.Failed++
					continue
				}
				if dec.Reason != "" {
					log.Printf("证书 %s %s", certData.Domain(), dec.Reason)
				}
				result.Skipped++
				// 补通知服务端续签模式：installCert 是新装唯一通知点，首跑绑定失败不通知，
				// 重跑走本路径绑定生效后补通知，否则 pull 订单服务端 auto_reissue 永不开启（spec 5.2），到期续签停摆
				if notify, useLocal := decideReissueNotify(existingCfg, cfgLoadOK, certData.OrderID); notify {
					toggleAutoReissue(client, certData.OrderID, useLocal)
				}
				certConfigs = append(certConfigs, makeCertConfig(certData, opts, serialNumber))
				continue
			}
		}

		// 优先级 1-2：尝试获取私钥
		keyPEM, source := resolvePrivateKey(certData.Certificate, certData.PrivateKey, opts.KeyPath)
		if keyPEM == "" {
			// 需要私钥，归入阶段 2
			log.Printf("证书 %s 未找到可用私钥，等待用户提供", certData.Domain())
			needKeys = append(needKeys, needKeyCert{certData: certData, serialNumber: serialNumber})
			continue
		}

		log.Printf("证书 %s 使用 %s 私钥", certData.Domain(), source)
		notify, useLocal := decideReissueNotify(existingCfg, cfgLoadOK, certData.OrderID)
		if ok := installCert(client, certData, keyPEM, serialNumber, opts, &certConfigs, result, notify, useLocal); !ok {
			result.Failed++
		}
	}

	// 阶段 1 汇总
	result.NeedKey = len(needKeys)
	if len(needKeys) > 0 {
		var names []string
		for _, nk := range needKeys {
			names = append(names, nk.certData.Domain())
		}
		log.Printf("[setup] 需要私钥的证书: %s", strings.Join(names, ", "))
	}

	// 5. 阶段 2：交互获取私钥
	if len(needKeys) > 0 && promptKey != nil {
		report(fmt.Sprintf("等待用户提供私钥（%d 个证书）...", len(needKeys)))
		for i, nk := range needKeys {
			log.Printf("[setup] 请求私钥 (%d/%d): %s", i+1, len(needKeys), nk.certData.Domain())
			keyPEM := promptKey(nk.certData.Domain(), nk.certData.Certificate)
			if keyPEM == "" {
				log.Printf("证书 %s 用户跳过", nk.certData.Domain())
				continue
			}

			// 验证私钥与证书匹配
			matched, err := cert.VerifyKeyPair(nk.certData.Certificate, keyPEM)
			if err != nil {
				log.Printf("证书 %s 私钥验证失败: %v", nk.certData.Domain(), err)
				sendSetupCallback(client, nk.certData.OrderID, nk.certData.Domain(), false, fmt.Sprintf("私钥验证失败: %v", err))
				result.Failed++
				result.NeedKey--
				continue
			}
			if !matched {
				log.Printf("证书 %s 私钥与证书不匹配", nk.certData.Domain())
				sendSetupCallback(client, nk.certData.OrderID, nk.certData.Domain(), false, "私钥与证书不匹配")
				result.Failed++
				result.NeedKey--
				continue
			}

			notify, useLocal := decideReissueNotify(existingCfg, cfgLoadOK, nk.certData.OrderID)
			if ok := installCert(client, nk.certData, keyPEM, nk.serialNumber, opts, &certConfigs, result, notify, useLocal); !ok {
				result.Failed++
			}
			result.NeedKey--
		}
	}

	// 6. 保存配置
	report(fmt.Sprintf("保存配置（安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d）...",
		result.Installed, result.Skipped, result.Failed, result.NeedKey))
	if err := saveSetupConfig(certConfigs); err != nil {
		log.Printf("警告: 保存配置失败: %v", err)
	}

	// 7. 创建计划任务
	report("创建计划任务...")
	taskName := config.DefaultTaskName
	if err := util.CreateTask(taskName); err != nil {
		log.Printf("创建计划任务失败: %v", err)
	} else {
		log.Printf("计划任务已创建: %s", taskName)
	}

	// 完成
	report(fmt.Sprintf("完成: 安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d",
		result.Installed, result.Skipped, result.Failed, result.NeedKey))

	if result.Failed > 0 || result.NeedKey > 0 {
		return result, fmt.Errorf("部分证书部署未完成: 安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d",
			result.Installed, result.Skipped, result.Failed, result.NeedKey)
	}

	return result, nil
}

// installCert 安装单个证书（PEM→PFX→安装→绑定→通知→回调）
// notifyReissue：是否通知服务端续签模式（现有配置不可读时跳过）；
// useLocalKey：订单在现有配置中的生效续签模式（true=local）
// 成功返回 true 并更新 result.Installed 和 certConfigs
func installCert(client *api.Client, certData api.CertData, keyPEM string, serialNumber string, opts Options, certConfigs *[]config.CertConfig, result *RunResult, notifyReissue, useLocalKey bool) bool {
	pfxPath, err := cert.PEMToPFX(certData.Certificate, keyPEM, certData.CACert, "")
	if err != nil {
		log.Printf("证书 %s 转换失败: %v", certData.Domain(), err)
		sendSetupCallback(client, certData.OrderID, certData.Domain(), false, fmt.Sprintf("转换 PFX 失败: %v", err))
		return false
	}

	installResult, err := cert.InstallPFX(pfxPath, "")
	os.Remove(pfxPath)
	if err != nil || !installResult.Success {
		errMsg := "安装失败"
		if err != nil {
			errMsg = err.Error()
		} else if installResult.ErrorMessage != "" {
			errMsg = installResult.ErrorMessage
		}
		log.Printf("证书 %s 安装失败: %s", certData.Domain(), errMsg)
		sendSetupCallback(client, certData.OrderID, certData.Domain(), false, "安装证书失败: "+errMsg)
		return false
	}

	log.Printf("证书 %s 安装成功: %s", certData.Domain(), installResult.Thumbprint)

	// 安装后通过 thumbprint 获取准确的序列号
	if serialNumber == "" {
		if certInfo, err := cert.GetCertByThumbprint(installResult.Thumbprint); err == nil {
			serialNumber = certInfo.SerialNumber
		}
	}

	// IIS 绑定：按逐绑定结果如实判定部署成败，不再吞掉绑定错误
	br, bindErr := bindCertToIIS(certData, installResult.Thumbprint)
	bindOK, bindReason := evalBindOutcome(br, bindErr)
	if !bindOK {
		log.Printf("证书 %s 部署失败: %s", certData.Domain(), bindReason)
		sendSetupCallback(client, certData.OrderID, certData.Domain(), false, bindReason)
		return false
	}
	if bindReason != "" {
		log.Printf("证书 %s %s", certData.Domain(), bindReason)
	}

	result.Installed++

	// 通知服务端续签模式：按订单现有配置的生效模式（未配置的新订单默认 pull）
	if notifyReissue {
		toggleAutoReissue(client, certData.OrderID, useLocalKey)
	} else {
		log.Printf("跳过服务端续签模式通知 (订单 %d)：现有配置不可读，无法确认既有模式", certData.OrderID)
	}

	// 部署完成回调（spec 4.2 / 5.1，非关键路径）
	sendSetupCallback(client, certData.OrderID, certData.Domain(), true, "")

	*certConfigs = append(*certConfigs, makeCertConfig(certData, opts, serialNumber))
	return true
}

// sendSetupCallback 发送 setup 部署回调（同步，非关键路径，失败仅记日志）
// message 为失败原因摘要，仅 failure 携带；由 api.Client.Callback 统一脱敏 + 按 rune 截断
func sendSetupCallback(client *api.Client, orderID int, domain string, success bool, message string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status := "success"
	if !success {
		status = "failure"
	}
	req := &api.CallbackRequest{
		OrderID:    orderID,
		Status:     status,
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	// 仅 failure 携带失败原因（成功回调不含 message）
	if !success {
		req.Message = message
	}
	if err := client.Callback(ctx, req); err != nil {
		log.Printf("部署回调失败 (订单 %d, %s): %v", orderID, domain, err)
	}
}

// resolvePrivateKey 按优先级尝试获取私钥（不含交互）
// 返回：私钥 PEM, 来源描述
func resolvePrivateKey(certPEM string, apiKey string, keyPath string) (string, string) {
	// 优先级 1：API 返回的 private_key
	if apiKey != "" {
		if len(apiKey) > cert.MaxPrivateKeySize {
			log.Printf("API 私钥大小超限，跳过")
		} else if matched, err := cert.VerifyKeyPair(certPEM, apiKey); err != nil {
			log.Printf("API 私钥验证失败: %v", err)
		} else if !matched {
			log.Printf("API 私钥与证书不匹配")
		} else {
			return apiKey, "API"
		}
	}

	// 优先级 2：指定的私钥文件路径
	if keyPath != "" {
		keyPEM, err := readKeyFile(keyPath)
		if err != nil {
			log.Printf("读取私钥文件失败: %v", err)
		} else if matched, err := cert.VerifyKeyPair(certPEM, keyPEM); err != nil {
			log.Printf("文件私钥验证失败: %v", err)
		} else if !matched {
			log.Printf("文件私钥与证书不匹配")
		} else {
			return keyPEM, "文件"
		}
	}

	// 优先级 3（IsCertExists）在外层已处理
	return "", ""
}

// readKeyFile 读取私钥文件（带大小限制）
func readKeyFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("私钥文件不存在: %w", err)
	}
	if info.Size() > int64(cert.MaxPrivateKeySize) {
		return "", fmt.Errorf("私钥文件大小 %d 超过上限 %d", info.Size(), cert.MaxPrivateKeySize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("读取私钥文件失败: %w", err)
	}
	return string(data), nil
}

// bindResult IIS 绑定尝试结果计数
type bindResult struct {
	Succeeded int
	Failed    int
}

// bindCertToIIS 将证书绑定到 IIS 匹配的站点，返回逐绑定的成败计数
// 查找绑定本身失败时返回 error
func bindCertToIIS(certData api.CertData, thumbprint string) (bindResult, error) {
	var br bindResult

	allDomains := extractDomainsWithFallback(certData)
	if len(allDomains) == 0 && certData.Domain() != "" {
		allDomains = []string{certData.Domain()}
	}

	httpsMatches, httpMatches, err := iis.FindMatchingBindings(allDomains)
	if err != nil {
		log.Printf("查找 IIS 绑定失败: %v", err)
		return br, fmt.Errorf("查找 IIS 绑定失败: %w", err)
	}

	// 更新已有 HTTPS 绑定
	for _, match := range httpsMatches {
		if err := iis.BindCertificate(match.Host, match.Port, thumbprint); err != nil {
			log.Printf("更新绑定 %s:%d 失败: %v", match.Host, match.Port, err)
			br.Failed++
		} else {
			log.Printf("更新绑定: %s:%d", match.Host, match.Port)
			br.Succeeded++
		}
	}

	// 为 HTTP 绑定添加 HTTPS
	for _, match := range httpMatches {
		if err := iis.AddHttpsBinding(match.SiteName, match.Host, match.Port); err != nil {
			log.Printf("添加 HTTPS 绑定 %s 失败: %v", match.Host, err)
			br.Failed++
			continue
		}
		if err := iis.BindCertificate(match.Host, match.Port, thumbprint); err != nil {
			log.Printf("绑定证书 %s 失败: %v", match.Host, err)
			br.Failed++
		} else {
			log.Printf("添加绑定: %s:%d (站点: %s)", match.Host, match.Port, match.SiteName)
			br.Succeeded++
		}
	}

	return br, nil
}

// evalBindOutcome 根据绑定结果判定部署成败（纯函数）
// 语义与自动部署链路对齐：至少一个绑定成功即视为部署生效（success），
// 未找到可绑定站点、全部绑定失败或查找出错均为失败（failure）
func evalBindOutcome(br bindResult, bindErr error) (ok bool, reason string) {
	if bindErr != nil {
		return false, bindErr.Error()
	}
	if br.Succeeded == 0 && br.Failed == 0 {
		return false, "未找到可绑定的 IIS 站点"
	}
	if br.Succeeded == 0 {
		return false, fmt.Sprintf("全部 %d 个绑定失败", br.Failed)
	}
	if br.Failed > 0 {
		return true, fmt.Sprintf("部分绑定失败（成功 %d，失败 %d）", br.Succeeded, br.Failed)
	}
	return true, ""
}

// existingBindDecision 已存在证书（跳过导入）路径的绑定判定结果（纯函数产物）
// Deployed=true：绑定生效，计 Skipped、写入配置、补通知续签模式；
// Deployed=false：零成功（查找出错/全部失败/零匹配），计 Failed、发 failure 回调、不写入配置
type existingBindDecision struct {
	Deployed bool
	Reason   string
}

// decideExistingCert 已存在证书绑定结果 → 统计与回调动作（纯函数）
// 复用新装路径同一 evalBindOutcome，确保两路径零成功政策一致
func decideExistingCert(br bindResult, bindErr error) existingBindDecision {
	ok, reason := evalBindOutcome(br, bindErr)
	return existingBindDecision{Deployed: ok, Reason: reason}
}

// makeCertConfig 创建证书配置
func makeCertConfig(certData api.CertData, opts Options, serialNumber string) config.CertConfig {
	certAPI := config.CertAPIConfig{URL: opts.URL}
	certAPI.SetToken(opts.Token)

	// 优先从证书 PEM 提取域名（包含完整 SAN），API 数据作为回退
	domains := extractDomainsWithFallback(certData)

	return config.CertConfig{
		CertName:     fmt.Sprintf("%s-%d", certData.Domain(), certData.OrderID),
		OrderID:      certData.OrderID,
		Domain:       certData.Domain(),
		Domains:      domains,
		Enabled:      true,
		AutoBindMode: true,
		BindRules:    []config.BindRule{},
		API:          certAPI,
		Metadata: config.CertMetadata{
			CertExpiresAt: certData.ExpiresAt,
			CertSerial:    serialNumber,
		},
	}
}

// extractDomainsWithFallback 优先从证书 PEM 提取域名，失败则回退到 API 数据
func extractDomainsWithFallback(certData api.CertData) []string {
	if certData.Certificate != "" {
		domains, err := cert.ExtractDomainsFromPEM(certData.Certificate)
		if err == nil && len(domains) > 0 {
			return domains
		}
	}
	return certData.GetDomainList()
}

// saveSetupConfig 保存 setup 生成的证书配置
func saveSetupConfig(certConfigs []config.CertConfig) error {
	cfg, err := config.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	for _, newCert := range certConfigs {
		existing := cfg.GetCertificateByOrderID(newCert.OrderID)
		if existing != nil {
			existing.API = newCert.API
			existing.Domains = newCert.Domains
			existing.Metadata.CertExpiresAt = newCert.Metadata.CertExpiresAt
			existing.Enabled = true
			existing.AutoBindMode = true
		} else {
			cfg.AddCertificate(newCert)
		}
	}

	cfg.AutoCheckEnabled = true
	return cfg.Save()
}

// decideReissueNotify 决定是否及以何种模式通知服务端续签模式（纯函数）
// cfgLoadOK=false（配置存在但加载失败）时跳过通知：
// 无法确认订单既有模式，误通知 pull 会打开 local 订单的服务端自动重签
func decideReissueNotify(cfg *config.Config, cfgLoadOK bool, orderID int) (notify, useLocalKey bool) {
	if !cfgLoadOK {
		return false, false
	}
	return true, isOrderLocalMode(cfg, orderID)
}

// isOrderLocalMode 判断订单在现有配置中是否为 local 续签模式（纯函数）
// cfg 为 nil 或订单未配置时返回 false：setup 新增证书默认 pull 模式
func isOrderLocalMode(cfg *config.Config, orderID int) bool {
	if cfg == nil {
		return false
	}
	certCfg := cfg.GetCertificateByOrderID(orderID)
	if certCfg == nil {
		return false
	}
	return certCfg.IsLocalMode(cfg.Schedule.RenewMode)
}

// toggleAutoReissue 通知服务端切换自动续签模式，失败仅记日志
// 内部各自新建独立超时 context（不复用 Run 的贯穿 ctx），避免交互长时间阻塞后用过期 ctx 通知失败
// useLocalKey=false（pull 模式）→ autoReissue=true；useLocalKey=true（local 模式）→ autoReissue=false
func toggleAutoReissue(client *api.Client, orderID int, useLocalKey bool) {
	ctx, cancel := context.WithTimeout(context.Background(), api.APISubmitTimeout)
	defer cancel()

	autoReissue := !useLocalKey
	if err := client.ToggleAutoReissue(ctx, orderID, autoReissue); err != nil {
		log.Printf("警告: 通知服务端续签模式失败 (订单 %d): %v", orderID, err)
	} else {
		log.Printf("已通知服务端续签模式 (订单 %d, autoReissue=%v)", orderID, autoReissue)
	}
}

// RunCLI 从命令行参数执行 setup（CLI 入口）
func RunCLI(args []string) error {
	// 构造命令字符串
	cmdParts := []string{"setup"}
	cmdParts = append(cmdParts, args...)
	input := strings.Join(cmdParts, " ")

	opts, err := ParseCommand(input)
	if err != nil {
		return err
	}

	// CLI 交互回调：提示用户输入私钥文件路径
	promptKey := func(domain string, certPEM string) string {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("\n证书 %s 需要私钥。\n", domain)
		fmt.Print("请输入私钥文件路径（留空跳过）: ")
		path, _ := reader.ReadString('\n')
		path = strings.TrimSpace(path)
		if path == "" {
			return ""
		}
		keyPEM, err := readKeyFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取失败: %v\n", err)
			return ""
		}
		return keyPEM
	}

	result, err := Run(*opts, func(step, total int, message string) {
		fmt.Printf("[%d/%d] %s\n", step, total, message)
	}, promptKey)

	if result != nil && result.NeedKey > 0 {
		fmt.Printf("\n以下证书仍需要私钥，请使用 --key 指定私钥文件或在 GUI 中操作。\n")
	}

	return err
}
