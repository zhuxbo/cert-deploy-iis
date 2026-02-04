package deploy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
	"sslctlw/util"
)

// 全局订单存储实例
var orderStore = cert.NewOrderStore()

// Result 部署结果
type Result struct {
	Domain     string
	Success    bool
	Message    string
	Thumbprint string
	OrderID    int
}

// AutoDeploy 自动部署证书（证书维度）
func AutoDeploy(cfg *config.Config) []Result {
	results := make([]Result, 0)

	if len(cfg.Certificates) == 0 {
		log.Println("没有配置任何证书")
		return results
	}

	if cfg.GetToken() == "" {
		log.Println("未配置 API Token")
		return results
	}

	client := api.NewClient(cfg.APIBaseURL, cfg.GetToken())

	// 检测 IIS 版本
	isIIS7 := iis.IsIIS7() || cfg.IIS7Mode
	if isIIS7 {
		log.Println("检测到 IIS7 兼容模式")
	}

	// 检查域名冲突
	conflicts := checkDomainConflicts(cfg.Certificates)
	if len(conflicts) > 0 {
		for domain, indexes := range conflicts {
			log.Printf("警告: 域名 %s 配置在多个证书中 (索引: %v)，将使用到期最晚的", domain, indexes)
		}
	}

	// 遍历证书配置
	for i, certCfg := range cfg.Certificates {
		if !certCfg.Enabled {
			continue
		}

		log.Printf("检查证书: %s (订单: %d, 本地私钥: %v)", certCfg.Domain, certCfg.OrderID, certCfg.UseLocalKey)

		var certData *api.CertData
		var privateKey string
		var err error

		if certCfg.UseLocalKey {
			// 本地私钥模式：到期前 > RenewDaysLocal 天发起续签
			// 目的：抢在服务端自动续签（14天）之前，由本地发起 CSR
			var reason string
			certData, privateKey, reason, err = handleLocalKeyMode(client, &cfg.Certificates[i], cfg.RenewDaysLocal)
			if err != nil {
				log.Printf("本地私钥模式处理失败: %v", err)
				results = append(results, Result{
					Domain:  certCfg.Domain,
					Success: false,
					Message: fmt.Sprintf("本地私钥模式失败: %v", err),
					OrderID: certCfg.OrderID,
				})
				continue
			}
			if certData == nil {
				if reason != "" {
					log.Printf("证书 %s 跳过: %s", certCfg.Domain, reason)
				}
				continue
			}
		} else {
			// 拉取模式：到期前 < RenewDaysFetch 天开始拉取
			// 目的：等服务端自动续签（14天）完成后再拉取
			certData, err = client.GetCertByOrderID(certCfg.OrderID)
			if err != nil {
				log.Printf("获取证书失败: %v", err)
				results = append(results, Result{
					Domain:  certCfg.Domain,
					Success: false,
					Message: fmt.Sprintf("获取证书失败: %v", err),
					OrderID: certCfg.OrderID,
				})
				continue
			}

			// 检查证书状态
			if certData.Status != "active" {
				log.Printf("证书状态非活跃: %s", certData.Status)
				results = append(results, Result{
					Domain:  certCfg.Domain,
					Success: false,
					Message: fmt.Sprintf("证书状态: %s", certData.Status),
					OrderID: certData.OrderID,
				})
				continue
			}

			// 拉取模式：检查是否到了拉取时间
			expiresAt, err := time.Parse("2006-01-02", certData.ExpiresAt)
			if err != nil {
				log.Printf("解析过期时间失败: %v", err)
				continue
			}

			daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)
			if daysUntilExpiry > cfg.RenewDaysFetch {
				log.Printf("证书 %s 还有 %d 天过期，等待服务端续签（<=%d天后拉取）", certData.Domain, daysUntilExpiry, cfg.RenewDaysFetch)
				continue
			}

			log.Printf("证书 %s 将在 %d 天后过期，开始拉取部署...", certData.Domain, daysUntilExpiry)
			privateKey = certData.PrivateKey
		}

		log.Printf("证书 %s 开始部署...", certData.Domain)

		// 根据模式选择部署方式
		var deployResults []Result
		if certCfg.AutoBindMode {
			// 自动绑定模式：按已有绑定更换证书
			deployResults = deployCertAutoMode(certData, privateKey, certCfg, client, isIIS7)
		} else {
			// 规则绑定模式：按配置的绑定规则部署
			deployResults = deployCertWithRules(certData, privateKey, certCfg, client, isIIS7, conflicts, cfg.Certificates)
		}
		results = append(results, deployResults...)

		// 更新配置中的订单 ID
		if certCfg.UseLocalKey && certCfg.OrderID != certData.OrderID {
			cfg.Certificates[i].OrderID = certData.OrderID
		}
	}

	// 更新检查时间
	cfg.LastCheck = time.Now().Format("2006-01-02 15:04:05")
	if err := cfg.Save(); err != nil {
		log.Printf("警告: 保存配置失败: %v", err)
	}

	return results
}

// deployCertWithRules 使用绑定规则部署证书
func deployCertWithRules(certData *api.CertData, privateKey string, certCfg config.CertConfig, client *api.Client, isIIS7 bool, conflicts map[string][]int, allCerts []config.CertConfig) []Result {
	results := make([]Result, 0)

	// 转换 PEM 到 PFX
	pfxPath, err := cert.PEMToPFX(
		certData.Certificate,
		privateKey,
		certData.CACert,
		"",
	)
	if err != nil {
		log.Printf("转换 PFX 失败: %v", err)
		for _, rule := range certCfg.BindRules {
			results = append(results, Result{
				Domain:  rule.Domain,
				Success: false,
				Message: fmt.Sprintf("转换 PFX 失败: %v", err),
				OrderID: certData.OrderID,
			})
		}
		return results
	}
	defer os.Remove(pfxPath)

	// 安装证书
	installResult, err := cert.InstallPFX(pfxPath, "")
	if err != nil || !installResult.Success {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else {
			errMsg = installResult.ErrorMessage
		}
		log.Printf("安装证书失败: %s", errMsg)
		for _, rule := range certCfg.BindRules {
			results = append(results, Result{
				Domain:  rule.Domain,
				Success: false,
				Message: fmt.Sprintf("安装证书失败: %s", errMsg),
				OrderID: certData.OrderID,
			})
		}
		return results
	}

	thumbprint := installResult.Thumbprint
	log.Printf("证书安装成功: %s", thumbprint)

	// IIS7 处理：修改友好名称
	if isIIS7 && len(certCfg.BindRules) > 0 {
		wildcardName := cert.GetWildcardName(certCfg.Domain)
		if err := cert.SetFriendlyName(thumbprint, wildcardName); err != nil {
			log.Printf("设置友好名称失败: %v", err)
		} else {
			log.Printf("已设置友好名称: %s", wildcardName)
		}
	}

	// 绑定到 IIS
	for _, rule := range certCfg.BindRules {
		// 检查是否有域名冲突，如果有则检查是否应该使用此证书
		if conflictIndexes, hasConflict := conflicts[rule.Domain]; hasConflict {
			bestCert := selectBestCertForDomainByIndexes(conflictIndexes, allCerts)
			if bestCert == nil || bestCert.OrderID != certCfg.OrderID {
				log.Printf("域名 %s 存在冲突，跳过（将由其他证书处理）", rule.Domain)
				continue
			}
		}

		port := rule.Port
		if port == 0 {
			port = 443
		}

		log.Printf("绑定证书到 %s:%d", rule.Domain, port)

		var bindErr error
		if isIIS7 {
			// IIS7 使用 IP:Port 绑定
			bindErr = iis.BindCertificateByIP("0.0.0.0", port, thumbprint)
		} else {
			// IIS8+ 使用 SNI 绑定
			bindErr = iis.BindCertificate(rule.Domain, port, thumbprint)
		}

		if bindErr != nil {
			log.Printf("绑定失败: %v", bindErr)
			results = append(results, Result{
				Domain:     rule.Domain,
				Success:    false,
				Message:    fmt.Sprintf("绑定失败: %v", bindErr),
				Thumbprint: thumbprint,
				OrderID:    certData.OrderID,
			})
			sendCallback(client, certData.OrderID, rule.Domain, false, "绑定失败: "+bindErr.Error())
		} else {
			log.Printf("绑定成功: %s", rule.Domain)
			results = append(results, Result{
				Domain:     rule.Domain,
				Success:    true,
				Message:    "部署成功",
				Thumbprint: thumbprint,
				OrderID:    certData.OrderID,
			})
			sendCallback(client, certData.OrderID, rule.Domain, true, "")
		}
	}

	return results
}

// handleLocalKeyMode 处理本地私钥模式
// renewDays: 到期前多少天发起续签（默认15天，需大于服务端自动续签的14天）
// 返回: 证书数据, 私钥, 跳过原因, 错误
// 当返回 certData=nil 且 error=nil 时，reason 说明跳过原因
func handleLocalKeyMode(client *api.Client, certCfg *config.CertConfig, renewDays int) (*api.CertData, string, string, error) {
	// 校验验证方法（校验证书的所有域名包括 SAN）
	if certCfg.ValidationMethod != "" {
		if errMsg := config.ValidateValidationMethod(certCfg.Domain, certCfg.ValidationMethod); errMsg != "" {
			return nil, "", "", fmt.Errorf("证书 [%s] 主域名校验失败: %s", certCfg.Domain, errMsg)
		}
		for _, d := range certCfg.Domains {
			if errMsg := config.ValidateValidationMethod(d, certCfg.ValidationMethod); errMsg != "" {
				return nil, "", "", fmt.Errorf("证书 [%s] SAN 域名 %s 校验失败: %s", certCfg.Domain, d, errMsg)
			}
		}
	}
	// 如果有订单 ID，先尝试获取该订单的证书
	if certCfg.OrderID > 0 {
		certData, err := client.GetCertByOrderID(certCfg.OrderID)
		if err != nil {
			log.Printf("获取订单 %d 证书失败: %v", certCfg.OrderID, err)
		} else if certData.Status == "processing" {
			// 处理中状态：检查是否需要文件验证
			if certData.File != nil && certData.File.Path != "" {
				log.Printf("订单 %d 需要文件验证", certCfg.OrderID)
				if err := handleFileValidation(certCfg.Domain, certData.File); err != nil {
					log.Printf("创建验证文件失败: %v", err)
				} else {
					log.Printf("验证文件已创建，等待 CA 验证")
				}
			} else {
				log.Printf("订单 %d 处理中，等待签发", certCfg.OrderID)
			}
			return nil, "", "CSR 已提交，等待签发", nil
		} else if certData.Status == "active" {
			// 检查证书是否需要续签
			expiresAt, err := time.Parse("2006-01-02", certData.ExpiresAt)
			if err != nil {
				log.Printf("解析过期时间失败: %v，继续检查私钥", err)
			} else {
				daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)
				if daysUntilExpiry > renewDays {
					log.Printf("证书 %s 还有 %d 天过期，未到续签时间（>%d天）", certData.Domain, daysUntilExpiry, renewDays)
					return nil, "", fmt.Sprintf("未到续签时间（还有 %d 天）", daysUntilExpiry), nil
				}
				log.Printf("证书 %s 还有 %d 天过期，需要续签（<=%d天）", certData.Domain, daysUntilExpiry, renewDays)
			}

			// 检查本地是否有私钥
			if orderStore.HasPrivateKey(certCfg.OrderID) {
				localKey, err := orderStore.LoadPrivateKey(certCfg.OrderID)
				if err != nil {
					return nil, "", "", fmt.Errorf("加载本地私钥失败: %w", err)
				}

				// 验证私钥是否匹配证书
				matched, err := cert.VerifyKeyPair(certData.Certificate, localKey)
				if err != nil {
					log.Printf("验证密钥匹配失败: %v", err)
				} else if matched {
					log.Printf("使用本地私钥（订单 %d）", certCfg.OrderID)
					if err := orderStore.SaveCertificate(certCfg.OrderID, certData.Certificate, certData.CACert); err != nil {
						log.Printf("警告: 保存证书失败: %v", err)
					}
					updateOrderMeta(certCfg.OrderID, certData)
					return certData, localKey, "", nil
				} else {
					log.Printf("本地私钥与证书不匹配，需要重新生成 CSR")
					orderStore.DeleteOrder(certCfg.OrderID)
				}
			}
			// 没有本地私钥，但证书已签发
			if certData.PrivateKey != "" {
				log.Printf("使用 API 返回的私钥")
				return certData, certData.PrivateKey, "", nil
			}
		}
	}

	// 需要生成新的 CSR 并提交
	log.Printf("生成新的 CSR")
	keyPEM, csrPEM, err := cert.GenerateCSR(certCfg.Domain, certCfg.Domains)
	if err != nil {
		return nil, "", "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// 提交 CSR
	csrReq := &api.CSRRequest{
		OrderID:          certCfg.OrderID,
		Domain:           certCfg.Domain,
		CSR:              csrPEM,
		ValidationMethod: certCfg.ValidationMethod,
	}

	csrResp, err := client.SubmitCSR(csrReq)
	if err != nil {
		return nil, "", "", fmt.Errorf("提交 CSR 失败: %w", err)
	}

	// 保存私钥到本地
	newOrderID := csrResp.Data.OrderID
	if err := orderStore.SavePrivateKey(newOrderID, keyPEM); err != nil {
		return nil, "", "", fmt.Errorf("保存私钥失败: %w", err)
	}

	// 更新配置中的订单 ID
	certCfg.OrderID = newOrderID

	log.Printf("CSR 已提交，订单 ID: %d，状态: %s", newOrderID, csrResp.Data.Status)

	// 如果证书立即签发了，获取并返回
	if csrResp.Data.Status == "active" {
		certData, err := client.GetCertByOrderID(newOrderID)
		if err == nil && certData.Status == "active" {
			if err := orderStore.SaveCertificate(newOrderID, certData.Certificate, certData.CACert); err != nil {
				log.Printf("警告: 保存证书失败: %v", err)
			}
			updateOrderMeta(newOrderID, certData)
			return certData, keyPEM, "", nil
		}
	}

	// 等待签发
	return nil, "", "CSR 已提交，等待签发", nil
}

// checkDomainConflicts 检查域名冲突（同一域名配置在多个证书中）
func checkDomainConflicts(certs []config.CertConfig) map[string][]int {
	conflicts := make(map[string][]int) // domain -> []certIndex

	for i, cert := range certs {
		if !cert.Enabled {
			continue
		}
		for _, rule := range cert.BindRules {
			conflicts[rule.Domain] = append(conflicts[rule.Domain], i)
		}
	}

	// 过滤只有一个证书的域名
	for domain, indexes := range conflicts {
		if len(indexes) <= 1 {
			delete(conflicts, domain)
		}
	}

	return conflicts
}

// selectBestCertForDomainByIndexes 根据索引列表选择最佳证书（到期最晚的）
func selectBestCertForDomainByIndexes(indexes []int, allCerts []config.CertConfig) *config.CertConfig {
	var best *config.CertConfig
	var bestExpiry time.Time
	bestHasExpiry := false

	for _, idx := range indexes {
		if idx < 0 || idx >= len(allCerts) {
			continue
		}
		cand := &allCerts[idx]
		if !cand.Enabled {
			continue
		}

		candExpiry, candHasExpiry := parseCertExpiry(cand.ExpiresAt)
		if best == nil {
			best = cand
			bestExpiry = candExpiry
			bestHasExpiry = candHasExpiry
			continue
		}

		if candHasExpiry && !bestHasExpiry {
			best = cand
			bestExpiry = candExpiry
			bestHasExpiry = true
			continue
		}
		if candHasExpiry && bestHasExpiry {
			if candExpiry.After(bestExpiry) || (candExpiry.Equal(bestExpiry) && cand.OrderID > best.OrderID) {
				best = cand
				bestExpiry = candExpiry
				bestHasExpiry = true
			}
			continue
		}
		if !candHasExpiry && !bestHasExpiry && cand.OrderID > best.OrderID {
			best = cand
		}
	}

	return best
}

func parseCertExpiry(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}
func updateOrderMeta(orderID int, certData *api.CertData) {
	meta := &cert.OrderMeta{
		OrderID:      orderID,
		Domain:       certData.Domain,
		Domains:      certData.GetDomainList(),
		Status:       certData.Status,
		ExpiresAt:    certData.ExpiresAt,
		CreatedAt:    certData.CreatedAt,
		LastDeployed: time.Now().Format("2006-01-02 15:04:05"),
	}
	if err := orderStore.SaveMeta(orderID, meta); err != nil {
		log.Printf("保存订单元数据失败: %v", err)
	}
}

// sendCallback 发送部署回调（异步，最多重试3次）
func sendCallback(client *api.Client, orderID int, domain string, success bool, message string) {
	go func() {
		status := "success"
		if !success {
			status = "failure"
		}

		req := &api.CallbackRequest{
			OrderID:    orderID,
			Domain:     domain,
			Status:     status,
			DeployedAt: time.Now().Format("2006-01-02 15:04:05"),
			ServerType: "IIS",
			Message:    message,
		}

		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				time.Sleep(time.Duration(attempt*10) * time.Second)
			}
			if err := client.Callback(req); err == nil {
				return
			}
		}
		log.Printf("回调最终失败: %s", domain)
	}()
}

// CheckAndDeploy 检查并部署（命令行模式入口）
func CheckAndDeploy() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("加载配置失败: %v", err)
	}

	if len(cfg.Certificates) == 0 {
		return fmt.Errorf("没有配置任何证书，请先运行 GUI 模式添加配置")
	}

	results := AutoDeploy(cfg)

	successCount := 0
	failCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
			log.Printf("[成功] %s: %s", r.Domain, r.Message)
		} else {
			failCount++
			log.Printf("[失败] %s: %s", r.Domain, r.Message)
		}
	}

	log.Printf("部署完成: 成功 %d, 失败 %d", successCount, failCount)

	if failCount > 0 {
		return fmt.Errorf("部分证书部署失败")
	}

	return nil
}

// deployCertAutoMode 自动绑定模式部署
// 查找 IIS 中已有的 SSL 绑定，更换证书
func deployCertAutoMode(certData *api.CertData, privateKey string, certCfg config.CertConfig, client *api.Client, isIIS7 bool) []Result {
	results := make([]Result, 0)

	// 1. 转换并安装证书
	pfxPath, err := cert.PEMToPFX(certData.Certificate, privateKey, certData.CACert, "")
	if err != nil {
		log.Printf("转换 PFX 失败: %v", err)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: fmt.Sprintf("转换 PFX 失败: %v", err), OrderID: certData.OrderID}}
	}
	defer os.Remove(pfxPath)

	installResult, err := cert.InstallPFX(pfxPath, "")
	if err != nil || !installResult.Success {
		errMsg := "安装失败"
		if err != nil {
			errMsg = err.Error()
		} else if installResult.ErrorMessage != "" {
			errMsg = installResult.ErrorMessage
		}
		return []Result{{Domain: certCfg.Domain, Success: false, Message: errMsg, OrderID: certData.OrderID}}
	}

	thumbprint := installResult.Thumbprint
	log.Printf("证书安装成功: %s", thumbprint)

	// 2. 查找 IIS 中匹配的绑定
	allDomains := certCfg.Domains
	if len(allDomains) == 0 && certCfg.Domain != "" {
		allDomains = []string{certCfg.Domain}
	}

	matchedBindings, err := iis.FindBindingsForDomains(allDomains)
	if err != nil {
		log.Printf("查找 IIS 绑定失败: %v", err)
	}

	if len(matchedBindings) == 0 {
		log.Printf("未找到 IIS 中的 SSL 绑定，跳过")
		return results
	}

	// 3. 更新匹配的绑定
	for domain, binding := range matchedBindings {
		host := iis.ParseHostFromBinding(binding.HostnamePort)
		port := iis.ParsePortFromBinding(binding.HostnamePort)

		log.Printf("更新绑定: %s:%d", host, port)

		var bindErr error
		if isIIS7 || isIPBinding(binding.HostnamePort) {
			bindErr = iis.BindCertificateByIP(host, port, thumbprint)
		} else {
			bindErr = iis.BindCertificate(host, port, thumbprint)
		}

		if bindErr != nil {
			log.Printf("绑定失败: %v", bindErr)
			results = append(results, Result{Domain: domain, Success: false, Message: bindErr.Error(), Thumbprint: thumbprint, OrderID: certData.OrderID})
			sendCallback(client, certData.OrderID, domain, false, bindErr.Error())
		} else {
			log.Printf("绑定成功: %s", domain)
			results = append(results, Result{Domain: domain, Success: true, Message: "部署成功", Thumbprint: thumbprint, OrderID: certData.OrderID})
			sendCallback(client, certData.OrderID, domain, true, "")
		}
	}

	return results
}

// handleFileValidation 处理文件验证
// 在 IIS 站点目录下创建验证文件
func handleFileValidation(domain string, file *api.FileValidation) error {
	if file == nil || file.Path == "" || file.Content == "" {
		return fmt.Errorf("验证文件信息不完整")
	}

	// 查找域名对应的站点物理路径
	siteName, sitePath, err := iis.GetSitePhysicalPathByDomain(domain)
	if err != nil {
		return fmt.Errorf("查找站点失败: %w", err)
	}

	log.Printf("找到站点: %s, 路径: %s", siteName, sitePath)

	// 构建验证文件的完整路径
	// file.Path 由接口返回，必须在 /.well-known/ 目录下
	relativePath := strings.TrimPrefix(file.Path, "/")
	relativePath = strings.ReplaceAll(relativePath, "/", string(os.PathSeparator))

	// 验证文件扩展名（禁止危险扩展名）
	ext := strings.ToLower(filepath.Ext(relativePath))
	dangerousExts := []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".asp", ".aspx", ".php"}
	for _, dext := range dangerousExts {
		if ext == dext {
			return fmt.Errorf("不允许创建 %s 扩展名的验证文件", ext)
		}
	}

	// 安全验证：防止路径遍历攻击
	fullPath, err := util.ValidateRelativePath(sitePath, relativePath)
	if err != nil {
		return fmt.Errorf("验证文件路径无效: %w", err)
	}

	// 额外限制：必须在 .well-known 目录下
	// 使用 filepath.Rel 获取相对路径，然后检查第一段是否为 .well-known
	// Windows 大小写不敏感，统一转小写比较
	relToSite, err := filepath.Rel(sitePath, fullPath)
	if err != nil {
		return fmt.Errorf("计算相对路径失败: %w", err)
	}
	pathParts := strings.Split(relToSite, string(os.PathSeparator))
	if len(pathParts) == 0 || !strings.EqualFold(pathParts[0], ".well-known") {
		return fmt.Errorf("验证文件路径必须在 .well-known 目录下")
	}

	// 创建目录（使用更严格的权限 0750）
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 写入验证文件
	if err := os.WriteFile(fullPath, []byte(file.Content), 0644); err != nil {
		return fmt.Errorf("写入验证文件失败: %w", err)
	}

	// 写入后验证文件位置（防止符号链接攻击）
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		// 如果解析失败，删除已写入的文件
		os.Remove(fullPath)
		return fmt.Errorf("验证文件路径失败: %w", err)
	}
	if !util.IsPathWithinBase(sitePath, realPath) {
		os.Remove(fullPath)
		return fmt.Errorf("文件写入位置超出站点目录范围")
	}

	log.Printf("验证文件已创建: %s", fullPath)

	// 创建 web.config 允许无扩展名文件访问（如果不存在）
	webConfigPath := filepath.Join(dir, "web.config")
	if _, err := os.Stat(webConfigPath); os.IsNotExist(err) {
		webConfigContent := `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
  </system.webServer>
</configuration>`
		if err := os.WriteFile(webConfigPath, []byte(webConfigContent), 0644); err != nil {
			log.Printf("警告: 创建 web.config 失败: %v", err)
		} else {
			log.Printf("已创建 web.config 允许无扩展名文件访问")
		}
	}

	return nil
}

// isIPBinding 判断是否是 IP 绑定（如 0.0.0.0:443）
func isIPBinding(hostnamePort string) bool {
	host := iis.ParseHostFromBinding(hostnamePort)
	// 简单判断：全数字和点则认为是 IP
	for _, c := range host {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

