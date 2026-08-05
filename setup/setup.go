package setup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
	"sslctlw/util"
)

// 证书安装与 IIS 绑定入口（包级变量，供测试注入；生产值为真实实现）
var (
	installPFXFn      = cert.InstallPFX
	bindCertToIISFn   = bindCertToIIS
	saveSetupConfigFn = saveSetupConfig
	createTaskFn      = util.CreateTask
	runTaskNowFn      = util.RunTaskNow
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

	existingCfg, cfgErr := config.Load()
	if cfgErr != nil {
		return nil, fmt.Errorf("加载现有配置失败，已停止 setup 以避免覆盖: %w", cfgErr)
	}

	client := api.NewClient(opts.URL, opts.Token)

	// 2. 查询证书（独立超时：交互可能长时间阻塞，各 API 调用各自新建 context，
	// 不再共用一个贯穿全程的 ctx，避免交互后用已过期 ctx 通知服务端失败）
	report("查询证书...")
	var certs []api.CertData
	var err error

	queryCtx, queryCancel := context.WithTimeout(context.Background(), 60*api.APIQueryTimeout/30)
	if err := validateSetupOrderQuery(opts.Order); err != nil {
		queryCancel()
		return nil, fmt.Errorf("查询证书失败: %w", err)
	}
	certs, err = client.ListCertsByQuery(queryCtx, opts.Order)
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
	var setupErrs []error

	// 现有配置：setup 重跑时按订单已配置的续签模式通知服务端（spec 5.2），
	// 避免把 local 模式订单的服务端自动重签误开为 pull 语义。
	for _, certData := range activeCerts {
		// 优先级 3：检查是否已在 Windows 证书存储中
		serialNumber, _ := cert.GetCertSerialNumber(certData.Certificate)
		if serialNumber != "" {
			exists, certInfo, _ := cert.IsCertExists(serialNumber)
			usableExisting := exists && certInfo != nil && certInfo.HasPrivKey
			if usableExisting && strings.TrimSpace(certData.CSR) != "" {
				matched, verifyErr := cert.VerifyCSRCertificateIdentity(
					certData.CSR, certData.Certificate, certData.Domain(),
				)
				if verifyErr != nil || !matched {
					usableExisting = false
					log.Printf("证书 %s 的本地证书与服务端 CSR 归属不一致，继续查找原私钥", certData.Domain())
				}
			}
			if usableExisting {
				log.Printf("证书 %s 已存在，跳过导入", certData.Domain())
				// 已存在证书仍需绑定生效才算部署成功：与新装路径共用 evalBindOutcome 判定，
				// 查找出错/全部失败/零匹配（含无法取指纹）同样计失败、发 failure 回调
				var br bindResult
				bindErr := errors.New("无法获取已存在证书的指纹")
				if certInfo != nil && certInfo.Thumbprint != "" {
					br, bindErr = bindCertToIISFn(certData, certInfo.Thumbprint)
				}
				dec := decideExistingCert(br, bindErr)
				// 证书已在存储中，无论绑定成败都写入配置交给计划任务续签接管（与新装路径一致）
				if !dec.Deployed {
					log.Printf("证书 %s 部署失败: %s", certData.Domain(), dec.Reason)
					sendSetupCallback(client, certData.OrderID, certData.Domain(), false, dec.Reason)
					result.Failed++
				} else {
					if dec.Reason != "" {
						log.Printf("证书 %s %s", certData.Domain(), dec.Reason)
					}
					result.Skipped++
				}
				certConfig, configErr := makeCertConfig(certData, opts, serialNumber)
				if configErr != nil {
					setupErrs = append(setupErrs, configErr)
					log.Printf("证书 %s 配置构造失败: %v", certData.Domain(), configErr)
					continue
				}
				if br.Succeeded > 0 && br.Failed > 0 {
					certConfig.Metadata.FailedBindings = append(
						[]config.BindingRetryTarget(nil), br.FailedTargets...,
					)
				}
				certConfigs = append(certConfigs, certConfig)
				if !dec.Deployed && br.Succeeded == 0 {
					continue
				}
				// 补通知服务端续签模式：installCert 是新装唯一通知点，首跑绑定失败不通知，
				// 重跑走本路径绑定生效后补通知，否则 pull 订单服务端 auto_reissue 永不开启（spec 5.2），到期续签停摆
				if notify, useLocal := deriveSetupPolicy(certData, existingCfg, true); notify {
					toggleAutoReissue(client, certData.OrderID, useLocal)
				}
				continue
			}
		}

		// 优先级 1-2：尝试获取私钥
		keyPEM, source := resolvePrivateKey(certData.Certificate, certData.PrivateKey, opts.KeyPath)
		if keyPEM != "" {
			if err := verifySetupCSRKey(certData, keyPEM); err != nil {
				log.Printf("证书 %s 的 %s 私钥未通过服务端 CSR 归属校验: %v", certData.Domain(), source, err)
				keyPEM = ""
			}
		}
		if keyPEM == "" {
			// 需要私钥，归入阶段 2
			log.Printf("证书 %s 未找到可用私钥，等待用户提供", certData.Domain())
			needKeys = append(needKeys, needKeyCert{certData: certData, serialNumber: serialNumber})
			continue
		}

		log.Printf("证书 %s 使用 %s 私钥", certData.Domain(), source)
		notify, useLocal := deriveSetupPolicy(certData, existingCfg, true)
		deployed, installErr := installCert(client, certData, keyPEM, serialNumber, opts, &certConfigs, result, notify, useLocal)
		if installErr != nil {
			setupErrs = append(setupErrs, installErr)
		}
		if !deployed {
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
			if err := verifySetupCSRKey(nk.certData, keyPEM); err != nil {
				log.Printf("证书 %s 私钥与服务端 CSR 不匹配: %v", nk.certData.Domain(), err)
				sendSetupCallback(client, nk.certData.OrderID, nk.certData.Domain(), false, "私钥与服务端 CSR 不匹配")
				result.Failed++
				result.NeedKey--
				continue
			}

			notify, useLocal := deriveSetupPolicy(nk.certData, existingCfg, true)
			deployed, installErr := installCert(client, nk.certData, keyPEM, nk.serialNumber, opts, &certConfigs, result, notify, useLocal)
			if installErr != nil {
				setupErrs = append(setupErrs, installErr)
			}
			if !deployed {
				result.Failed++
			}
			result.NeedKey--
		}
	}

	// 6. 保存配置
	report(fmt.Sprintf("保存配置（安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d）...",
		result.Installed, result.Skipped, result.Failed, result.NeedKey))
	mergeSetupConfigs(existingCfg, certConfigs, client.LastRenewBeforeDays)
	partialErr := errors.Join(setupErrs...)
	if result.Failed > 0 || result.NeedKey > 0 {
		partialErr = errors.Join(partialErr, fmt.Errorf("部分证书部署未完成: 安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d",
			result.Installed, result.Skipped, result.Failed, result.NeedKey))
	}
	if err := saveSetupConfigFn(existingCfg); err != nil {
		return result, errors.Join(partialErr, fmt.Errorf("保存配置失败: %w", err))
	}

	// 7. 创建计划任务并触发首次运行，避免新任务在随机日程到达前一直显示“从未运行”
	report("创建并启动计划任务...")
	taskName := config.DefaultTaskName
	taskErr := createTaskFn(taskName)
	var runTaskErr error
	if taskErr != nil {
		log.Printf("创建计划任务失败: %v", taskErr)
	} else {
		log.Printf("计划任务已创建: %s", taskName)
		runTaskErr = runTaskNowFn(taskName)
		if runTaskErr != nil {
			log.Printf("首次运行计划任务失败: %v", runTaskErr)
		} else {
			log.Printf("计划任务首次运行已启动: %s", taskName)
		}
	}

	finalErr := partialErr
	if taskErr != nil {
		finalErr = errors.Join(finalErr, fmt.Errorf("创建计划任务失败: %w", taskErr))
	}
	if runTaskErr != nil {
		finalErr = errors.Join(finalErr, fmt.Errorf("首次运行计划任务失败: %w", runTaskErr))
	}
	if finalErr != nil {
		return result, finalErr
	}

	// 完成
	report(fmt.Sprintf("完成: 安装 %d, 已存在 %d, 失败 %d, 需要私钥 %d",
		result.Installed, result.Skipped, result.Failed, result.NeedKey))

	return result, nil
}

// installCert 安装单个证书（PEM→PFX→安装→绑定→通知→回调）
// notifyReissue：是否通知服务端续签模式（现有配置不可读时跳过）；
// useLocalKey：订单在现有配置中的生效续签模式（true=local）
// 成功返回 true 并更新 result.Installed 和 certConfigs
func installCert(
	client *api.Client,
	certData api.CertData,
	keyPEM string,
	serialNumber string,
	opts Options,
	certConfigs *[]config.CertConfig,
	result *RunResult,
	notifyReissue, useLocalKey bool,
	configMakers ...func(api.CertData, Options, string) (config.CertConfig, error),
) (bool, error) {
	pfxPath, err := cert.PEMToPFX(certData.Certificate, keyPEM, certData.CACert, "")
	if err != nil {
		log.Printf("证书 %s 转换失败: %v", certData.Domain(), err)
		sendSetupCallback(client, certData.OrderID, certData.Domain(), false, fmt.Sprintf("转换 PFX 失败: %v", err))
		return false, nil
	}

	installResult, err := installPFXFn(pfxPath, "")
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
		return false, nil
	}

	log.Printf("证书 %s 安装成功: %s", certData.Domain(), installResult.Thumbprint)

	// 安装后通过 thumbprint 获取准确的序列号
	if serialNumber == "" {
		if certInfo, err := cert.GetCertByThumbprint(installResult.Thumbprint); err == nil {
			serialNumber = certInfo.SerialNumber
		}
	}

	// IIS 绑定：按逐绑定结果如实判定部署成败，不再吞掉绑定错误
	br, bindErr := bindCertToIISFn(certData, installResult.Thumbprint)
	bindOK, bindReason := evalBindOutcome(br, bindErr)
	if bindOK {
		result.Installed++
	}

	// 证书已装入 Windows 证书存储，无论绑定是否全部生效都要写入配置：
	// 部署成败（回调与 Installed/Failed 计数）和"该证书是否受管"是两件事，
	// 一次瞬时绑定失败不应让证书完全脱管——那样计划任务永远接管不了，只能人工重跑 setup。
	configMaker := makeCertConfig
	if len(configMakers) > 0 && configMakers[0] != nil {
		configMaker = configMakers[0]
	}
	certConfig, configErr := configMaker(certData, opts, serialNumber)
	if configErr != nil {
		if bindOK {
			sendSetupCallback(client, certData.OrderID, certData.Domain(), true, "")
		} else {
			sendSetupCallback(client, certData.OrderID, certData.Domain(), false, bindReason)
			return false, errors.Join(configErr, fmt.Errorf("部署失败: %s", bindReason))
		}
		return bindOK, configErr
	}
	if br.Succeeded > 0 && br.Failed > 0 {
		certConfig.Metadata.FailedBindings = append(
			[]config.BindingRetryTarget(nil), br.FailedTargets...,
		)
	}
	*certConfigs = append(*certConfigs, certConfig)

	// 任一绑定成功即已接纳并纳入管理；即使订单级回调为 failure，也要设置续签模式。
	if notifyReissue && (bindOK || br.Succeeded > 0) {
		toggleAutoReissue(client, certData.OrderID, useLocalKey)
	} else if !notifyReissue && (bindOK || br.Succeeded > 0) {
		log.Printf("跳过服务端续签模式通知 (订单 %d)：现有配置不可读，无法确认既有模式", certData.OrderID)
	}

	if !bindOK {
		log.Printf("证书 %s 部署失败: %s", certData.Domain(), bindReason)
		sendSetupCallback(client, certData.OrderID, certData.Domain(), false, bindReason)
		return false, nil
	}
	if bindReason != "" {
		log.Printf("证书 %s %s", certData.Domain(), bindReason)
	}

	// 部署完成回调（spec 4.2 / 5.1，非关键路径）
	sendSetupCallback(client, certData.OrderID, certData.Domain(), true, "")

	return true, nil
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

func verifySetupCSRKey(certData api.CertData, keyPEM string) error {
	if strings.TrimSpace(certData.CSR) == "" {
		return nil
	}
	hash, err := cert.CSRDERHash(certData.CSR)
	if err != nil {
		return err
	}
	matched, err := cert.VerifyCSRIdentity(certData.CSR, keyPEM, hash, certData.Domain())
	if err != nil {
		return err
	}
	if !matched {
		return errors.New("CSR 公钥或 Common Name 与私钥/订单不匹配")
	}
	return nil
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
	Succeeded     int
	Failed        int
	FailedTargets []config.BindingRetryTarget
}

// bindCertToIIS 将证书绑定到 IIS 匹配的站点，返回逐绑定的成败计数
// 查找绑定本身失败时返回 error
func bindCertToIIS(certData api.CertData, thumbprint string) (bindResult, error) {
	var br bindResult

	allDomains := extractDomainsWithFallback(certData)
	if len(allDomains) == 0 && certData.Domain() != "" {
		allDomains = []string{certData.Domain()}
	}

	ips, dnsNames := splitBindingNames(allDomains)
	var bindErrs []error
	if len(dnsNames) > 0 {
		dnsResult, err := bindDNSCertToIIS(dnsNames, thumbprint)
		br.Succeeded += dnsResult.Succeeded
		br.Failed += dnsResult.Failed
		br.FailedTargets = append(br.FailedTargets, dnsResult.FailedTargets...)
		if err != nil {
			bindErrs = append(bindErrs, err)
		}
	}
	if len(ips) > 0 {
		ipResult, err := bindIPCertToIIS(ips, thumbprint)
		br.Succeeded += ipResult.Succeeded
		br.Failed += ipResult.Failed
		br.FailedTargets = append(br.FailedTargets, ipResult.FailedTargets...)
		if err != nil {
			bindErrs = append(bindErrs, err)
		}
	}
	return br, errors.Join(bindErrs...)
}

// bindDNSCertToIIS 为 DNS SAN 查找并更新 SNI 绑定。
func bindDNSCertToIIS(domains []string, thumbprint string) (bindResult, error) {
	var br bindResult
	httpsMatches, httpMatches, err := iis.FindMatchingBindings(domains)
	if err != nil {
		log.Printf("查找 IIS 绑定失败: %v", err)
		return br, fmt.Errorf("查找 IIS 绑定失败: %w", err)
	}

	// 更新已有 HTTPS 绑定
	for _, match := range httpsMatches {
		if err := iis.BindCertificate(match.Host, match.Port, thumbprint); err != nil {
			log.Printf("更新绑定 %s:%d 失败: %v", match.Host, match.Port, err)
			br.Failed++
			br.FailedTargets = append(br.FailedTargets, config.BindingRetryTarget{
				Host: match.Host, Port: match.Port,
			})
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
			br.FailedTargets = append(br.FailedTargets, config.BindingRetryTarget{
				Host: match.Host, Port: match.Port,
			})
			continue
		}
		if err := iis.BindCertificate(match.Host, match.Port, thumbprint); err != nil {
			log.Printf("绑定证书 %s 失败: %v", match.Host, err)
			br.Failed++
			br.FailedTargets = append(br.FailedTargets, config.BindingRetryTarget{
				Host: match.Host, Port: match.Port,
			})
		} else {
			log.Printf("添加绑定: %s:%d (站点: %s)", match.Host, match.Port, match.SiteName)
			br.Succeeded++
		}
	}

	return br, nil
}

// bindIPCertToIIS 为 IP 证书执行 IP 绑定（ipport）。
// 先定位承载该 IP 的空 Host 站点并 best-effort 补齐 https 绑定，再经 netsh 绑定证书到具体 IP:端口；
// 绑定到具体 IP 而非通配 0.0.0.0，避免隐式覆盖同端口其他证书；netsh 层的复验/回滚在替换失败时
// 恢复旧绑定，状态未知时不做破坏性回滚（deploy-spec §5.2）。
func bindIPCertToIIS(ips []string, thumbprint string) (bindResult, error) {
	var br bindResult

	sites, scanErr := iis.ScanSites()
	if scanErr != nil {
		log.Printf("扫描 IIS 站点失败（仅执行 netsh 证书绑定）: %v", scanErr)
	}

	for _, ip := range ips {
		port := 443
		if scanErr == nil {
			if siteName, found := iis.FindEmptyHostSiteForIP(sites, ip, port); found {
				if err := iis.AddIPHttpsBindingIfNotExists(siteName, ip, port); err != nil {
					log.Printf("为站点 %s 补齐 IP HTTPS 绑定 %s:%d 失败: %v", siteName, ip, port, err)
				} else {
					log.Printf("IP 证书站点定位: %s -> %s:%d", siteName, ip, port)
				}
			} else {
				log.Printf("警告: 未定位到 IP %s:%d 的空 Host 站点，请确认已配置 IP 绑定站点", ip, port)
			}
		}

		if err := iis.BindCertificateByIP(ip, port, thumbprint); err != nil {
			log.Printf("IP 绑定 %s:%d 失败: %v", ip, port, err)
			br.Failed++
			br.FailedTargets = append(br.FailedTargets, config.BindingRetryTarget{
				Host: ip, Port: port, IPBinding: true,
			})
			continue
		}
		log.Printf("IP 绑定成功: %s:%d", ip, port)
		br.Succeeded++
	}

	return br, nil
}

// evalBindOutcome 根据绑定结果判定部署成败（纯函数）
// 语义与自动部署链路对齐：全部绑定成功才视为部署生效（success），
// 未找到可绑定站点、部分/全部绑定失败或查找出错均为失败（failure）
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
		return false, fmt.Sprintf("部分绑定失败（成功 %d，失败 %d）", br.Succeeded, br.Failed)
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

// makeCertConfig 创建证书配置。
// SAN 含 IP 的证书自动派生为 local + file，并为全部 DNS/IP SAN 生成显式绑定规则，
// 续签时分别走 SNI 与 ipport；不自动开启付费 auto_renew（deploy-spec §1.4 / §5.2）。
func makeCertConfig(certData api.CertData, opts Options, serialNumber string) (config.CertConfig, error) {
	return makeCertConfigWithTokenSetter(certData, opts, serialNumber,
		func(certAPI *config.CertAPIConfig, token string) error {
			return certAPI.SetToken(token)
		})
}

func makeCertConfigWithTokenSetter(
	certData api.CertData,
	opts Options,
	serialNumber string,
	setToken func(*config.CertAPIConfig, string) error,
) (config.CertConfig, error) {
	certAPI := config.CertAPIConfig{URL: opts.URL}
	if err := setToken(&certAPI, opts.Token); err != nil {
		return config.CertConfig{}, fmt.Errorf("证书 %s (订单 %d) Token 加密失败: %w",
			certData.Domain(), certData.OrderID, err)
	}

	// 优先从证书 PEM 提取域名（包含完整 SAN），API 数据作为回退
	domains := extractDomainsWithFallback(certData)

	cfg := config.CertConfig{
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

	// 含 IP SAN 的证书派生：强制 local/file，并为全部 DNS/IP SAN 生成显式规则。
	if ips := ipSANs(domains); len(ips) > 0 {
		cfg.RenewMode = "local"
		cfg.ValidationMethod = config.ValidationMethodFile
		cfg.AutoBindMode = false
		rules := make([]config.BindRule, 0, len(domains))
		for _, domain := range domains {
			rules = append(rules, config.BindRule{Domain: domain, Port: 443})
		}
		cfg.BindRules = rules
	}

	return cfg, nil
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

// ipSANs 返回域名列表中所有 IP 地址形式的 SAN（IPv4/IPv6）
func ipSANs(domains []string) []string {
	ips := make([]string, 0)
	for _, d := range domains {
		if net.ParseIP(strings.TrimSpace(d)) != nil {
			ips = append(ips, strings.TrimSpace(d))
		}
	}
	return ips
}

// splitBindingNames 将 SAN 分为 IP 与 DNS 两组，混合证书两类绑定都必须部署。
func splitBindingNames(domains []string) (ips, dnsNames []string) {
	for _, domain := range domains {
		name := strings.TrimSpace(domain)
		if net.ParseIP(name) != nil {
			ips = append(ips, name)
		} else if name != "" {
			dnsNames = append(dnsNames, name)
		}
	}
	return ips, dnsNames
}

// deriveSetupPolicy 决定 setup 的续签模式通知策略：
// SAN 含 IP 的证书强制 local（auto_reissue=false，通知安全无副作用，不受 cfgLoadOK 限制）；
// 其余证书沿用现有配置判定（decideReissueNotify）。
func deriveSetupPolicy(certData api.CertData, existingCfg *config.Config, cfgLoadOK bool) (notify, useLocalKey bool) {
	if len(ipSANs(extractDomainsWithFallback(certData))) > 0 {
		return true, true
	}
	return decideReissueNotify(existingCfg, cfgLoadOK, certData.OrderID)
}

// saveSetupConfig 保存 setup 生成的证书配置
func mergeSetupConfigs(cfg *config.Config, certConfigs []config.CertConfig, renewBeforeDays int) {
	for _, newCert := range certConfigs {
		existing := cfg.GetCertificateByOrderID(newCert.OrderID)
		if existing != nil {
			mergeSetupCert(existing, newCert)
		} else {
			cfg.AddCertificate(newCert)
		}
	}

	cfg.AutoCheckEnabled = true
	applySetupRenewBeforeDays(cfg, renewBeforeDays)
}

func saveSetupConfig(cfg *config.Config) error {
	return cfg.Save()
}

// mergeSetupCert 把本次 setup 观察到的证书形态合并进已有订单配置（纯函数）。
// AutoBindMode 随证书形态走：含 IP SAN 的证书由 makeCertConfig 派生为显式规则模式，
// 若在此被无条件写回自动绑定模式，deployCertAutoMode 只认 SNI 绑定会把 IP 证书判成
// “未找到匹配的 IIS SSL 绑定”，每轮部署失败直到 CAPPED。
// RenewMode/ValidationMethod/BindRules 仅在 setup 派生出值时覆盖，
// 避免清空用户为域名证书手工维护的配置。
func mergeSetupCert(existing *config.CertConfig, newCert config.CertConfig) {
	existing.API = newCert.API
	existing.Domains = newCert.Domains
	existing.Metadata.CertExpiresAt = newCert.Metadata.CertExpiresAt
	existing.Enabled = true
	existing.AutoBindMode = newCert.AutoBindMode
	if len(newCert.BindRules) > 0 {
		existing.BindRules = newCert.BindRules
	}
	if newCert.RenewMode != "" {
		existing.RenewMode = newCert.RenewMode
	}
	if newCert.ValidationMethod != "" {
		existing.ValidationMethod = newCert.ValidationMethod
	}
}

func applySetupRenewBeforeDays(cfg *config.Config, days int) {
	if days > 0 && days <= config.MaxRenewBeforeDays {
		cfg.Schedule.RenewBeforeDays = days
	}
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
