package deploy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
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

// 分散延迟常量
const (
	spreadMin      = 5   // 最小延迟（秒）
	spreadMax      = 120 // 最大延迟（秒）
	spreadTotalMax = 600 // 总延迟上限（秒）
)

var errPendingKeyMismatch = errors.New("pending 私钥与目标证书不匹配")

// Local 模式健壮性常量
const (
	maxRenewBatch = 100          // 单次续签处理上限
	timeFormat    = time.RFC3339 // 时间格式（RFC3339）
	// retryCapNotice 第 10 次（最后一次）部署失败在回调 message 中的标注（deploy-spec §2.8）
	retryCapNotice = "已达重试上限"
)

// autoActionSafetyMargin 证书剩余有效期低于该值时不再发起新的自动动作（deploy-spec §3.2）
const autoActionSafetyMargin = 24 * time.Hour

// Result 部署结果
type Result struct {
	Domain     string
	Success    bool
	Message    string
	Thumbprint string
	OrderID    int
}

// AutoDeploy 自动部署证书（证书维度，per-cert client）
// scatterDelay: 是否在证书间插入分散延迟（CLI deploy --all 启用，GUI 不启用）
func AutoDeploy(cfg *config.Config, d *Deployer, scatterDelay bool) []Result {
	results := make([]Result, 0)

	if len(cfg.Certificates) == 0 {
		log.Println("没有配置任何证书")
		return results
	}

	// 并发保护：获取文件锁，防止多进程同时续签
	lockPath := filepath.Join(config.GetDataDir(), "deploy.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err == nil {
		locked, lockErr := tryLockFile(lockFile)
		if lockErr != nil {
			log.Printf("警告: 获取部署锁失败: %v", lockErr)
		} else if !locked {
			log.Println("另一个部署进程正在运行，跳过本次检查")
			lockFile.Close()
			return results
		}
		defer func() {
			lockFile.Close()
			os.Remove(lockPath)
		}()
	}

	// 检查域名冲突
	conflicts := checkDomainConflicts(cfg.Certificates)
	if len(conflicts) > 0 {
		for domain, indexes := range conflicts {
			log.Printf("警告: 域名 %s 配置在多个证书中 (索引: %v)，将使用到期最晚的", domain, indexes)
		}
	}

	// 统计启用证书数量，计算分散延迟
	var sleepMin, sleepMax int
	if scatterDelay {
		enabledCount := 0
		for _, c := range cfg.Certificates {
			if c.Enabled {
				enabledCount++
			}
		}
		sleepMin, sleepMax = calcSpreadDelay(enabledCount)
	}
	processedIndex := 0

	// 遍历证书配置
	processed := 0
	for i := range cfg.Certificates {
		if !cfg.Certificates[i].Enabled {
			continue
		}
		if processed >= maxRenewBatch {
			log.Printf("已达单次处理上限 %d，剩余证书下次处理", maxRenewBatch)
			break
		}

		// 分散延迟：第一个证书不延迟
		if scatterDelay && processedIndex > 0 && sleepMin > 0 {
			delay := sleepMin + rand.IntN(sleepMax-sleepMin+1)
			log.Printf("分散延迟 %d 秒...", delay)
			time.Sleep(time.Duration(delay) * time.Second)
		}
		processedIndex++

		certResults, attempted := processOneCert(cfg, d, i, conflicts)
		results = append(results, certResults...)

		// 逐证书持久化：状态变更（重试计数/CSR 哈希/订单号等）立即落盘，
		// 中途中断不丢失，避免重试上限被绕过、CSR 去重失效
		if err := cfg.Save(); err != nil {
			log.Printf("警告: 保存配置失败: %v", err)
		}

		if attempted {
			processed++
		}
	}

	// 回调响应同样携带 renew_before_days。等待非关键回调结束后统一应用，
	// 避免 goroutine 与证书循环并发修改配置，也覆盖 GUI 未显式 WaitCallbacks 的入口。
	d.WaitCallbacks()
	d.ApplyCallbackRenewBeforeDays(cfg)

	// 更新检查时间
	cfg.LastCheck = time.Now().Format("2006-01-02 15:04:05")
	if err := cfg.Save(); err != nil {
		log.Printf("警告: 保存配置失败: %v", err)
	}

	return results
}

// processOneCert 处理单个证书的续签检查与部署
// 返回该证书的部署结果与是否实际执行了部署尝试（用于单次批量上限统计）
func processOneCert(cfg *config.Config, d *Deployer, i int, conflicts map[string][]int) (certResults []Result, attempted bool) {
	results := make([]Result, 0)
	certCfg := cfg.Certificates[i]

	// 自动动作准入门禁：触顶(CAPPED)/过期(EXPIRED)/策略阻断/剩余不足安全余量时，
	// 本轮不发起任何动作、不发送任何回调（deploy-spec §3.2）。
	if skip, reason := evaluateAutoActionGate(&cfg.Certificates[i], time.Now()); skip {
		if reason != "" {
			log.Printf("证书 %s 跳过自动动作: %s", certCfg.Domain, reason)
		}
		return results, false
	}

	// per-cert client
	// 注意：client 创建失败时没有可用的 API 通道，只能记本地日志
	client, clientErr := NewClientForCert(&cfg.Certificates[i])
	if clientErr != nil {
		log.Printf("创建证书 %s 的 API 客户端失败: %v", certCfg.Domain, clientErr)
		results = append(results, Result{
			Domain:  certCfg.Domain,
			Success: false,
			Message: fmt.Sprintf("API 配置错误: %v", clientErr),
			OrderID: certCfg.OrderID,
		})
		return results, false
	}

	isLocal := certCfg.IsLocalMode(cfg.Schedule.RenewMode)
	log.Printf("检查证书: %s (订单: %d, 模式: %s)", certCfg.Domain, certCfg.OrderID, map[bool]string{true: "local", false: "pull"}[isLocal])

	var certData *api.CertData
	// 安全警告: privateKey 包含敏感的私钥数据，严禁在日志中打印
	var privateKey string
	var err error

	if isLocal {
		// 本机提交：签发阶段的失败只记本地日志与本地计数，一律不发送回调（deploy-spec §2.8）
		var reason string
		certData, privateKey, reason, err = handleLocalKeyMode(d, client, &cfg.Certificates[i], cfg.Schedule.RenewBeforeDays, cfg.Save)
		// API 调用完成后更新续签提前天数（无论成功或跳过）
		updateRenewBeforeDays(cfg, client)
		if err != nil {
			log.Printf("本机提交处理失败: %v", err)
			results = append(results, Result{
				Domain:  certCfg.Domain,
				Success: false,
				Message: fmt.Sprintf("本机提交失败: %v", err),
				OrderID: certCfg.OrderID,
			})
			return results, false
		}
		if certData == nil {
			if reason != "" {
				log.Printf("证书 %s 跳过: %s", certCfg.Domain, reason)
			}
			return results, false
		}
	} else {
		// 自动签发：拉取失败属签发/获取阶段，只记本地日志、不发送回调（deploy-spec §2.8）
		ctx, cancel := context.WithTimeout(context.Background(), api.APIQueryTimeout)
		certData, err = client.GetCertByOrderID(ctx, certCfg.OrderID)
		cancel()
		if err != nil {
			log.Printf("获取证书失败: %v", err)
			results = append(results, Result{
				Domain:  certCfg.Domain,
				Success: false,
				Message: fmt.Sprintf("获取证书失败: %v", err),
				OrderID: certCfg.OrderID,
			})
			return results, false
		}

		// API 调用成功，更新服务端返回的续签提前天数
		updateRenewBeforeDays(cfg, client)

		// 检查证书状态（pending/approving 归一为 processing，只等待不动作，deploy-spec §2.4）
		if certData.Status == "processing" || certData.Status == "pending" || certData.Status == "approving" {
			log.Printf("证书 %s 处理中，等待下次检查", certData.Domain())
			return results, false
		}
		if certData.Status != "active" {
			log.Printf("证书状态非活跃: %s", certData.Status)
			results = append(results, Result{
				Domain:  certCfg.Domain,
				Success: false,
				Message: fmt.Sprintf("证书状态: %s", certData.Status),
				OrderID: certData.OrderID,
			})
			return results, false
		}

		// 检查是否到了拉取时间
		expiresAt, err := time.Parse("2006-01-02", certData.ExpiresAt)
		if err != nil {
			log.Printf("解析证书 %s (订单 %d) 过期时间失败（值: %q）: %v", certData.Domain(), certData.OrderID, certData.ExpiresAt, err)
			return results, false
		}

		daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)
		if daysUntilExpiry < 0 {
			log.Printf("证书 %s 已过期 %d 天，跳过（需人工介入）", certData.Domain(), -daysUntilExpiry)
			return results, false
		}
		if daysUntilExpiry > cfg.Schedule.RenewBeforeDays {
			log.Printf("证书 %s 还有 %d 天过期，未到续签时间（<=%d天后拉取）", certData.Domain(), daysUntilExpiry, cfg.Schedule.RenewBeforeDays)
			return results, false
		}

		log.Printf("证书 %s 将在 %d 天后过期，开始拉取部署...", certData.Domain(), daysUntilExpiry)
		privateKey = certData.PrivateKey
	}

	// 安全校验：中间证书非空 + 证书链大小限制
	if certData.CACert == "" {
		log.Printf("证书 %s 中间证书为空，跳过部署", certData.Domain())
		results = append(results, Result{
			Domain:  certCfg.Domain,
			Success: false,
			Message: "中间证书为空，等待下次检查",
			OrderID: certData.OrderID,
		})
		return results, false
	}
	chainSize := len(certData.Certificate) + len(certData.CACert)
	if chainSize > cert.MaxCertChainSize {
		log.Printf("证书 %s 证书链大小 %d 超过上限 %d", certData.Domain(), chainSize, cert.MaxCertChainSize)
		return results, false
	}
	if certData.PrivateKey != "" && len(certData.PrivateKey) > cert.MaxPrivateKeySize {
		log.Printf("证书 %s 私钥大小 %d 超过上限 %d", certData.Domain(), len(certData.PrivateKey), cert.MaxPrivateKeySize)
		return results, false
	}

	log.Printf("证书 %s 开始部署...", certData.Domain())

	deployCertCfg := &cfg.Certificates[i]

	// 部署意图落盘（deploy-spec §5.1）：新尝试先递增部署计数并写入在途标记再落盘；
	// 崩溃恢复重放（标记已存在）复用同一意图不重复计数；触顶转 CAPPED 静默、不回调。
	capped, replaying, persistErr := persistDeployAttempt(&deployCertCfg.Metadata, cfg.Save)
	if persistErr != nil {
		msg := fmt.Sprintf("持久化部署意图失败，已停止部署: %v", persistErr)
		log.Printf("证书 %s %s", certData.Domain(), msg)
		results = append(results, Result{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID})
		return results, false
	}
	if capped {
		log.Printf("证书 %s 部署计数已触顶，进入 CAPPED 静默", certData.Domain())
		return results, false
	}

	// 底层部署函数只返回结构化结果，不自行发送回调（deploy-spec §2.8）
	var deployResults []Result
	var rep deployReport
	if certCfg.AutoBindMode {
		deployResults, rep = deployCertAutoMode(d, client, certData, privateKey, certCfg)
	} else {
		deployResults, rep = deployCertWithRules(d, client, certData, privateKey, certCfg, conflicts, cfg.Certificates)
	}
	results = append(results, deployResults...)

	// 更新配置中的订单 ID（续费后 API 返回新订单号）
	if deployCertCfg.OrderID != certData.OrderID {
		log.Printf("订单号更新: %d -> %d", deployCertCfg.OrderID, certData.OrderID)
		deployCertCfg.OrderID = certData.OrderID
	}

	// 部署结果原子落盘 + 部署计数收敛
	if shouldFinalizeDeployment(rep, certData.Certificate != "") {
		// 全部绑定成功：落盘证书、转正 pending 私钥、清零签发与部署状态
		if err := d.Store.SaveCertificate(certData.OrderID, certData.Certificate, certData.CACert); err != nil {
			log.Printf("警告: 保存已部署证书失败: %v", err)
		}
		finalizeSuccessfulDeployment(d, deployCertCfg, certData, privateKey, isLocal)
		updateCertDomains(deployCertCfg, certData.Certificate)
		updateCertSerial(deployCertCfg, certData.Certificate)
	} else {
		reconcileFailedDeploy(&deployCertCfg.Metadata, rep.report, replaying)
	}
	if err := cfg.Save(); err != nil {
		log.Printf("警告: 保存部署结果失败，不发送回调: %v", err)
		return results, true
	}

	// 编排层在结果落盘后统一发送一次回调（deploy-spec §2.8）：
	// 第 10 次（最后一次）部署失败在 message 标注"已达重试上限"。
	atRetryCap := !rep.success && deployCertCfg.Metadata.DeployAttemptCount >= config.MaxDeployAttempts
	emitDeployCallback(d, client, certData.OrderID, certCfg.Domain, rep, atRetryCap)

	return results, true
}

// deployReport 部署阶段的结构化结果，供编排层在结果落盘后统一发送一次回调。
// report=false 表示本轮无绑定被处理（全部因冲突跳过），不产生任何回调。
type deployReport struct {
	report  bool   // 是否需要回调
	success bool   // 是否全部绑定成功
	message string // 失败原因摘要（success 时为空）
}

// beginDeployAttempt 在发起一次部署前更新部署意图计数（deploy-spec §5.1）。
// capped=true 表示部署计数已触顶（调用方标记 CAPPED 后落盘并跳过、不回调）；
// replaying=true 表示复用已在途的部署意图（崩溃恢复重放），不重复计数。
func beginDeployAttempt(meta *config.CertMetadata) (capped, replaying bool) {
	if meta.DeployStartedAt != "" {
		return false, true // 在途重放：不计数
	}
	if meta.DeployAttemptCount >= config.MaxDeployAttempts {
		meta.MarkCapped(config.CapPhaseDeploy)
		return true, false
	}
	meta.DeployAttemptCount++
	meta.DeployStartedAt = time.Now().Format(timeFormat)
	return false, false
}

// persistDeployAttempt 将部署意图持久化后才允许执行外部部署动作。
// 保存失败时恢复调用前的内存状态，避免后续保存写入一个从未执行的虚假尝试。
func persistDeployAttempt(meta *config.CertMetadata, persist func() error) (capped, replaying bool, err error) {
	before := *meta
	capped, replaying = beginDeployAttempt(meta)
	if persist == nil {
		return capped, replaying, nil
	}
	if !replaying || capped {
		if err := persist(); err != nil {
			*meta = before
			return false, false, err
		}
	}
	return capped, replaying, nil
}

// shouldFinalizeDeployment 只有订单内全部绑定成功且证书内容非空时才完成生命周期。
func shouldFinalizeDeployment(rep deployReport, hasCertificate bool) bool {
	return rep.report && rep.success && hasCertificate
}

// reconcileFailedDeploy 处理未成功部署的计数收敛（deploy-spec §3.2）：
// 无绑定被处理（report=false）撤销本轮意图（非重放才回退计数）；
// 明确失败清在途标记并保留计数，触顶转 CAPPED。
func reconcileFailedDeploy(meta *config.CertMetadata, report, replaying bool) {
	if !report {
		if !replaying && meta.DeployAttemptCount > 0 {
			meta.DeployAttemptCount--
		}
		meta.DeployStartedAt = ""
		return
	}
	meta.DeployStartedAt = ""
	if meta.DeployAttemptCount >= config.MaxDeployAttempts {
		meta.MarkCapped(config.CapPhaseDeploy)
	}
}

// reportFromOutcome 由订单内各绑定聚合结果生成部署回调结构（纯函数）：
// 全成功→success；任一失败→failure（携带 "N/M 绑定失败: 首因"）；零处理→不回调。
func reportFromOutcome(o bindOutcome) deployReport {
	if o.success == 0 && o.failed == 0 {
		return deployReport{report: false}
	}
	if o.failed > 0 {
		return deployReport{report: true, success: false, message: aggregatedFailureMessage(o.success+o.failed, o.failed, o.firstFail)}
	}
	return deployReport{report: true, success: true}
}

// appendRetryCapNotice 在部署失败摘要末尾追加"已达重试上限"标注（deploy-spec §2.8）
func appendRetryCapNotice(msg string) string {
	if strings.Contains(msg, retryCapNotice) {
		return msg
	}
	if msg == "" {
		return retryCapNotice
	}
	return msg + "（" + retryCapNotice + "）"
}

// emitDeployCallback 由编排层在部署结果落盘后发送一次回调（deploy-spec §2.8）。
// 全成功发 success（不含 message）；明确失败发 failure（触顶时标注"已达重试上限"）；无处理不发。
func emitDeployCallback(d *Deployer, client APIClient, orderID int, domain string, rep deployReport, atRetryCap bool) {
	if !rep.report {
		return
	}
	if rep.success {
		sendCallback(d, client, orderID, domain, true, "")
		return
	}
	msg := rep.message
	if atRetryCap {
		msg = appendRetryCapNotice(msg)
	}
	sendCallback(d, client, orderID, domain, false, msg)
}

// evaluateAutoActionGate 在发起任何自动动作前基于本地元数据判定是否跳过本轮（deploy-spec §3.2）。
// skip=true 表示本轮不发起任何动作、不发送任何回调；可能就地把状态更新为 EXPIRED（由调用方落盘）。
func evaluateAutoActionGate(certCfg *config.CertConfig, now time.Time) (skip bool, reason string) {
	meta := &certCfg.Metadata

	var expiry time.Time
	haveExpiry := false
	if meta.CertExpiresAt != "" {
		if e, err := time.Parse("2006-01-02", meta.CertExpiresAt); err == nil {
			expiry, haveExpiry = e, true
		}
	}

	// 证书绝对到期是自动动作的准入截止点：已过期静默终止并转 EXPIRED（触顶后到期同样转 EXPIRED）。
	if haveExpiry && !expiry.After(now) {
		if !meta.IsExpiredState() {
			meta.LastIssueState = config.IssueStateExpired
			meta.CapPhase = ""
		}
		return true, "证书已过期，静默终止（EXPIRED）"
	}
	if meta.IsPolicyBlocked() {
		return true, "配置被策略阻断（policy_blocked），等待重新 setup"
	}
	if meta.IsExpiredState() {
		return true, "证书已过期（EXPIRED），等待人工处理"
	}
	if meta.IsCapped() {
		return true, "尝试计数已触顶（CAPPED），等待人工处理"
	}
	// 剩余有效期不足安全余量：不启动新动作（保持当前状态，不改状态、不回调）。
	if haveExpiry && expiry.Sub(now) < autoActionSafetyMargin {
		return true, "剩余有效期不足安全余量，本轮不发起新动作"
	}
	return false, ""
}

// verifyDeployKeyPair 部署前校验证书与私钥配对（spec 5.1 步骤 1）
// 通过返回 (true, "")；不通过返回 false 与失败原因，
// 防止服务端返回错配数据时安装绑定成功导致站点 TLS 握手全挂
func verifyDeployKeyPair(certPEM, keyPEM string) (bool, string) {
	matched, err := cert.VerifyKeyPair(certPEM, keyPEM)
	if err != nil {
		return false, fmt.Sprintf("证书私钥配对校验失败: %v", err)
	}
	if !matched {
		return false, "证书与私钥不匹配"
	}
	return true, ""
}

// deployCertWithRules 使用绑定规则部署证书。
// 只返回结构化结果与部署报告，不自行发送回调（回调由编排层统一发送，deploy-spec §2.8）。
func deployCertWithRules(d *Deployer, client APIClient, certData *api.CertData, privateKey string, certCfg config.CertConfig, conflicts map[string][]int, allCerts []config.CertConfig) ([]Result, deployReport) {
	results := make([]Result, 0)

	// 配对校验：转换/安装前确认证书与私钥匹配
	if ok, reason := verifyDeployKeyPair(certData.Certificate, privateKey); !ok {
		log.Printf("证书 %s %s", certData.Domain(), reason)
		for _, rule := range certCfg.BindRules {
			results = append(results, Result{
				Domain:  rule.Domain,
				Success: false,
				Message: reason,
				OrderID: certData.OrderID,
			})
		}
		return results, deployReport{report: true, success: false, message: reason}
	}

	// 转换 PEM 到 PFX
	pfxPath, err := d.Converter.PEMToPFX(
		certData.Certificate,
		privateKey,
		certData.CACert,
		"",
	)
	if err != nil {
		log.Printf("转换 PFX 失败: %v", err)
		msg := fmt.Sprintf("转换 PFX 失败: %v", err)
		for _, rule := range certCfg.BindRules {
			results = append(results, Result{
				Domain:  rule.Domain,
				Success: false,
				Message: msg,
				OrderID: certData.OrderID,
			})
		}
		return results, deployReport{report: true, success: false, message: msg}
	}
	defer removeTempFile(pfxPath)

	// 安装证书
	installResult, err := d.Installer.InstallPFX(pfxPath, "")
	if err != nil || !installResult.Success {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else {
			errMsg = installResult.ErrorMessage
		}
		log.Printf("安装证书失败: %s", errMsg)
		msg := "安装证书失败: " + errMsg
		for _, rule := range certCfg.BindRules {
			results = append(results, Result{
				Domain:  rule.Domain,
				Success: false,
				Message: msg,
				OrderID: certData.OrderID,
			})
		}
		return results, deployReport{report: true, success: false, message: msg}
	}

	thumbprint := installResult.Thumbprint
	log.Printf("证书安装成功: %s", thumbprint)

	// 绑定到 IIS（循环内只收集结果，报告按订单聚合到循环后返回，回调由编排层单发）
	var outcome bindOutcome
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

		// IP 证书走 IP 绑定（ipport），域名走 SNI 绑定；netsh 层的复验/回滚防止误覆盖同端口其他证书
		var bindErr error
		if net.ParseIP(rule.Domain) != nil {
			bindErr = d.Binder.BindCertificateByIP(rule.Domain, port, thumbprint)
		} else {
			bindErr = d.Binder.BindCertificate(rule.Domain, port, thumbprint)
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
			outcome.fail(fmt.Sprintf("%s: %v", rule.Domain, bindErr))
		} else {
			log.Printf("绑定成功: %s", rule.Domain)
			results = append(results, Result{
				Domain:     rule.Domain,
				Success:    true,
				Message:    "部署成功",
				Thumbprint: thumbprint,
				OrderID:    certData.OrderID,
			})
			outcome.ok()
		}
	}

	return results, reportFromOutcome(outcome)
}

// bindOutcome 聚合一个订单内各绑定的成败，用于生成订单级单条回调
type bindOutcome struct {
	success   int
	failed    int
	firstFail string // 首个失败绑定的原因（作为聚合 failure 回调的首因）
}

// ok 记一次绑定成功
func (o *bindOutcome) ok() { o.success++ }

// fail 记一次绑定失败，保留首个失败原因
func (o *bindOutcome) fail(reason string) {
	o.failed++
	if o.firstFail == "" {
		o.firstFail = reason
	}
}

// aggregatedFailureMessage 生成订单级 failure 回调的原因摘要（纯函数）：
// "<失败数>/<总数> 绑定失败: <首因>"，无首因时省略冒号后缀。
// 最终脱敏与截断由 api.Client.Callback 统一处理。
func aggregatedFailureMessage(total, failed int, firstReason string) string {
	base := fmt.Sprintf("%d/%d 绑定失败", failed, total)
	if firstReason == "" {
		return base
	}
	return base + ": " + firstReason
}

// validateCertConfig 校验证书配置的验证方法
func validateCertConfig(certCfg *config.CertConfig) error {
	if certCfg.ValidationMethod == "" {
		return nil
	}
	if errMsg := config.ValidateValidationMethod(certCfg.Domain, certCfg.ValidationMethod); errMsg != "" {
		return fmt.Errorf("证书 [%s] 主域名校验失败: %s", certCfg.Domain, errMsg)
	}
	for _, d := range certCfg.Domains {
		if errMsg := config.ValidateValidationMethod(d, certCfg.ValidationMethod); errMsg != "" {
			return fmt.Errorf("证书 [%s] SAN 域名 %s 校验失败: %s", certCfg.Domain, d, errMsg)
		}
	}
	return nil
}

// handleProcessingOrder 处理 processing 状态的订单
// 返回: reason, error
func handleProcessingOrder(d *Deployer, certCfg *config.CertConfig, certData *api.CertData) (reason string, err error) {
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
	return "CSR 已提交，等待签发", nil
}

// checkRenewalNeeded 检查证书是否需要续签
// 返回: 需要续签, 跳过原因
func checkRenewalNeeded(certData *api.CertData, renewDays int) (bool, string) {
	expiresAt, err := time.Parse("2006-01-02", certData.ExpiresAt)
	if err != nil {
		log.Printf("解析过期时间失败: %v，跳过", err)
		return false, "解析过期时间失败"
	}
	daysUntilExpiry := int(time.Until(expiresAt).Hours() / 24)
	if daysUntilExpiry < 0 {
		log.Printf("证书 %s 已过期 %d 天，跳过（需人工介入）", certData.Domain(), -daysUntilExpiry)
		return false, fmt.Sprintf("已过期 %d 天，需人工介入", -daysUntilExpiry)
	}
	if daysUntilExpiry > renewDays {
		log.Printf("证书 %s 还有 %d 天过期，未到续签时间（>%d天）", certData.Domain(), daysUntilExpiry, renewDays)
		return false, fmt.Sprintf("未到续签时间（还有 %d 天）", daysUntilExpiry)
	}
	log.Printf("证书 %s 还有 %d 天过期，需要续签（<=%d天）", certData.Domain(), daysUntilExpiry, renewDays)
	return true, ""
}

// tryUseLocalKey 尝试使用与目标证书配对的正式本地私钥。
// 配对失败只视为该来源不可用，不删除正式订单目录或任何私钥。
// 返回: 证书数据, 私钥, 是否成功
func tryUseLocalKey(d *Deployer, certData *api.CertData, certCfg *config.CertConfig) (*api.CertData, string, bool) {
	orderID := certData.OrderID
	if orderID == 0 {
		orderID = certCfg.OrderID
	}
	if !d.Store.HasPrivateKey(orderID) {
		return nil, "", false
	}
	localKey, err := d.Store.LoadPrivateKey(orderID)
	if err != nil {
		log.Printf("加载本地私钥失败: %v", err)
		return nil, "", false
	}
	matched, err := cert.VerifyKeyPair(certData.Certificate, localKey)
	if err != nil {
		log.Printf("验证密钥匹配失败: %v", err)
		return nil, "", false
	}
	if !matched {
		log.Printf("正式本地私钥与目标证书不匹配，保留原私钥并尝试 pending 私钥")
		return nil, "", false
	}
	log.Printf("使用本地私钥（订单 %d）", orderID)
	return certData, localKey, true
}

// selectIssuedPrivateKey 为 local 在途签发结果选择配对私钥。
// pending 是本次 CSR 的唯一权威私钥，存在时必须优先校验；只有 pending 已在崩溃窗口中转正/清理时，
// 才回退 API 或正式本地私钥完成恢复。
func selectIssuedPrivateKey(d *Deployer, certData *api.CertData, certCfg *config.CertConfig) (string, error) {
	if d.Store.HasPendingPrivateKey(certCfg.CertName) {
		pendingKey, err := d.Store.LoadPendingPrivateKey(certCfg.CertName)
		if err != nil {
			return "", fmt.Errorf("加载 pending 私钥失败: %w", err)
		}
		matched, err := cert.VerifyKeyPair(certData.Certificate, pendingKey)
		if err != nil {
			return "", fmt.Errorf("验证 pending 私钥配对失败: %w", err)
		}
		if matched {
			log.Printf("使用 pending 私钥（证书 %s，部署成功后转正）", certCfg.CertName)
			return pendingKey, nil
		}
		return "", fmt.Errorf("%w，已保留并等待重放同一 CSR", errPendingKeyMismatch)
	}
	if certData.PrivateKey != "" {
		matched, err := cert.VerifyKeyPair(certData.Certificate, certData.PrivateKey)
		if err == nil && matched {
			return certData.PrivateKey, nil
		}
		log.Printf("API 私钥与目标证书不匹配，尝试本地私钥来源")
	}
	if _, key, ok := tryUseLocalKey(d, certData, certCfg); ok {
		return key, nil
	}
	return "", errors.New("没有与目标证书配对的可用私钥")
}

// submitNewCSR 生成并提交新的 CSR
func submitNewCSR(d *Deployer, client APIClient, certCfg *config.CertConfig, persistConfig ...func() error) (*api.CertData, string, string, error) {
	if certCfg.CertName == "" {
		certCfg.CertName = fmt.Sprintf("%s-%d", certCfg.Domain, certCfg.OrderID)
	}
	// 已有 pending：重放同一 CSR（属同一签发尝试，不重复计数）
	if d.Store.HasPendingPrivateKey(certCfg.CertName) {
		return retryPendingCSR(d, client, certCfg, persistConfig...)
	}
	// 签发触顶：不再提交新 CSR，进入 CAPPED 静默，不发送任何回调（deploy-spec §3.2）
	retryCount := certCfg.Metadata.IssueRetryCount
	if retryCount >= config.MaxIssueRetries {
		certCfg.Metadata.MarkCapped(config.CapPhaseIssue)
		return nil, "", fmt.Sprintf("签发计数已达上限 %d，进入 CAPPED，等待人工处理", config.MaxIssueRetries), nil
	}

	log.Printf("生成新的 CSR (重试: %d/%d)", retryCount, config.MaxIssueRetries)
	keyPEM, csrPEM, err := cert.GenerateCSR(certCfg.Domain)
	if err != nil {
		return nil, "", "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// CSR 哈希去重（spec 5.8）
	csrHash := fmt.Sprintf("%x", sha256.Sum256([]byte(csrPEM)))
	if certCfg.Metadata.LastCSRHash == csrHash {
		log.Printf("CSR 与上次相同，跳过重复提交")
		return nil, "", "CSR 未变化，等待签发", nil
	}
	if err := d.Store.SavePendingCSR(certCfg.CertName, csrPEM); err != nil {
		return nil, "", "", fmt.Errorf("保存 pending CSR 失败: %w", err)
	}
	if err := d.Store.SavePendingPrivateKey(certCfg.CertName, keyPEM); err != nil {
		return nil, "", "", fmt.Errorf("保存 pending 私钥失败: %w", err)
	}
	return submitPendingCSR(d, client, certCfg, csrPEM, false, persistConfig...)
}

// retryPendingCSR 重放与现存 pending 私钥严格配对的原始 CSR。
// 网络结果不确定时绝不生成新密钥，避免覆盖服务端可能已经受理的唯一私钥。
func retryPendingCSR(d *Deployer, client APIClient, certCfg *config.CertConfig, persistConfig ...func() error) (*api.CertData, string, string, error) {
	csrPEM, err := d.Store.LoadPendingCSR(certCfg.CertName)
	if err != nil {
		return nil, "", "", fmt.Errorf("加载 pending CSR 失败，无法安全重试: %w", err)
	}
	keyPEM, err := d.Store.LoadPendingPrivateKey(certCfg.CertName)
	if err != nil {
		return nil, "", "", fmt.Errorf("加载 pending 私钥失败，无法安全重试: %w", err)
	}
	matched, err := cert.VerifyCSRKeyPair(csrPEM, keyPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("验证 pending CSR 失败，无法安全重试: %w", err)
	}
	if !matched {
		return nil, "", "", errors.New("pending CSR 与 pending 私钥不匹配，无法安全重试")
	}
	return submitPendingCSR(d, client, certCfg, csrPEM, true, persistConfig...)
}

func submitPendingCSR(d *Deployer, client APIClient, certCfg *config.CertConfig, csrPEM string, replaying bool, persistConfig ...func() error) (*api.CertData, string, string, error) {
	csrHash := fmt.Sprintf("%x", sha256.Sum256([]byte(csrPEM)))
	before := certCfg.Metadata
	var persist func() error
	if len(persistConfig) > 0 {
		persist = persistConfig[0]
	}

	// pending 文件已存在即视为同一签发意图的崩溃恢复重放；即使哈希尚未入配置，也只补齐元数据而不重复计数。
	if !replaying && certCfg.Metadata.LastCSRHash != csrHash {
		if certCfg.Metadata.IssueRetryCount >= config.MaxIssueRetries {
			certCfg.Metadata.MarkCapped(config.CapPhaseIssue)
			if persist != nil {
				if err := persist(); err != nil {
					certCfg.Metadata = before
					return nil, "", "", fmt.Errorf("持久化签发触顶状态失败: %w", err)
				}
			}
			return nil, "", fmt.Sprintf("签发计数已达上限 %d，进入 CAPPED，等待人工处理", config.MaxIssueRetries), nil
		}
		certCfg.Metadata.IssueRetryCount++
	}

	// 提交尝试的元数据必须在请求前持久化；重放同一 CSR 不重复计数（deploy-spec §3.2）。
	// 结果未确认时统一记为 processing 在途态：崩溃/失败后 pending 私钥留存供下轮重放。
	certCfg.Metadata.CSRSubmittedAt = time.Now().Format(timeFormat)
	certCfg.Metadata.LastCSRHash = csrHash
	certCfg.Metadata.LastIssueState = config.IssueStateProcessing
	if persist != nil {
		if err := persist(); err != nil {
			certCfg.Metadata = before
			return nil, "", "", fmt.Errorf("持久化签发意图失败: %w", err)
		}
	}

	csrReq := &api.UpdateRequest{
		OrderID:          certCfg.OrderID,
		Domains:          certCfg.Domain,
		CSR:              csrPEM,
		ValidationMethod: certCfg.ValidationMethod,
	}

	ctx, cancel := context.WithTimeout(context.Background(), api.APISubmitTimeout)
	defer cancel()
	csrResp, err := client.SubmitCSR(ctx, csrReq)
	if err != nil {
		return nil, "", "", fmt.Errorf("提交 CSR 失败: %w", err)
	}

	newOrderID := csrResp.Data.OrderID
	certCfg.OrderID = newOrderID
	log.Printf("CSR 已提交，订单 ID: %d，状态: %s", newOrderID, csrResp.Data.Status)

	// 归一化服务端状态：pending/approving 与 processing 统一按 processing 处理（deploy-spec §2.4/§2.6）
	if csrResp.Data.Status == "processing" || csrResp.Data.Status == "pending" || csrResp.Data.Status == "approving" {
		certCfg.Metadata.LastIssueState = config.IssueStateProcessing
		reason, err := handleProcessingOrder(d, certCfg, &csrResp.Data.CertData)
		return nil, "", reason, err
	}

	certCfg.Metadata.LastIssueState = csrResp.Data.Status
	return nil, "", fmt.Sprintf("CSR 已提交，等待后续查询（当前状态: %s）", csrResp.Data.Status), nil
}

// handleLocalKeyMode 处理本机提交模式
// renewDays: 到期前多少天发起续签（默认15天，需大于服务端自动续签的14天）
// 返回: 证书数据, 私钥, 跳过原因, 错误
// 当返回 certData=nil 且 error=nil 时，reason 说明跳过原因
func handleLocalKeyMode(d *Deployer, client APIClient, certCfg *config.CertConfig, renewDays int, persistConfig ...func() error) (*api.CertData, string, string, error) {
	// 1. 校验配置
	if err := validateCertConfig(certCfg); err != nil {
		return nil, "", "", err
	}

	// 2. 检查现有订单。LastIssueState 非空表示已有 CSR 在途，此时 active 是新签发完成，
	// 必须直接读取 pending 私钥部署，不能再按新证书的长期有效期判断是否需要续签。
	if certCfg.OrderID > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), api.APIQueryTimeout)
		certData, err := client.GetCertByOrderID(ctx, certCfg.OrderID)
		cancel()
		if err != nil {
			// API 请求失败时返回错误，不要静默提交新 CSR（防止重复生成订单）
			return nil, "", "", fmt.Errorf("获取订单 %d 证书失败: %w", certCfg.OrderID, err)
		}

		waitingForIssue := certCfg.Metadata.LastIssueState != "" || d.Store.HasPendingPrivateKey(certCfg.CertName)
		switch certData.Status {
		case "processing", "pending", "approving":
			// 服务端 pending/approving 归一为 processing：只等待/查询，不重复提交、不增计数（deploy-spec §2.4）
			certCfg.Metadata.LastIssueState = config.IssueStateProcessing
			// 证书已过期则停止，等待人工处理
			if certData.ExpiresAt != "" {
				if expiresAt, err := time.Parse("2006-01-02", certData.ExpiresAt); err == nil {
					if time.Now().After(expiresAt) {
						return nil, "", "", fmt.Errorf("证书已过期，processing 状态下停止续签，需人工处理")
					}
				}
			}
			reason, handleErr := handleProcessingOrder(d, certCfg, certData)
			if handleErr != nil {
				return nil, "", "", handleErr
			}
			return nil, "", reason, nil
		case "active":
			// 证书已签发，清理之前可能残留的验证文件
			cleanupValidationFiles(certCfg.Domain)
			if waitingForIssue {
				certCfg.Metadata.LastIssueState = certData.Status
				privateKey, err := selectIssuedPrivateKey(d, certData, certCfg)
				if err != nil {
					if errors.Is(err, errPendingKeyMismatch) {
						log.Printf("当前 active 证书尚未匹配 pending 私钥，重放同一 CSR 查询/推进签发")
						return retryPendingCSR(d, client, certCfg, persistConfig...)
					}
					return nil, "", "", err
				}
				return certData, privateKey, "", nil
			}

			// 检查是否需要续签
			needRenew, skipReason := checkRenewalNeeded(certData, renewDays)
			if !needRenew {
				return nil, "", skipReason, nil
			}

			// 当前 active 是旧证书；进入续签窗口后提交新 CSR，不重部署旧证书。
			certCfg.Metadata.LastIssueState = ""
			return submitNewCSR(d, client, certCfg, persistConfig...)
		default:
			// 非预期状态（pending/unpaid/cancelled 等），不提交新 CSR 防止重复下单
			certCfg.Metadata.LastIssueState = certData.Status
			log.Printf("订单 %d 状态为 %q，跳过", certCfg.OrderID, certData.Status)
			return nil, "", fmt.Sprintf("订单状态: %s", certData.Status), nil
		}
	}

	// 3. 提交新的 CSR
	return submitNewCSR(d, client, certCfg, persistConfig...)
}

// finalizeSuccessfulDeployment 在至少一个 IIS 绑定成功后转正 pending 私钥并清理签发状态。
// 转正失败时保留 LastIssueState 与 pending 文件，使下一轮仍能重试收敛。
func finalizeSuccessfulDeployment(d *Deployer, certCfg *config.CertConfig, certData *api.CertData, privateKey string, isLocal bool) bool {
	if isLocal && d.Store.HasPendingPrivateKey(certCfg.CertName) {
		if err := d.Store.PromotePendingPrivateKey(certCfg.CertName, certData.OrderID, privateKey); err != nil {
			log.Printf("警告: pending 私钥转正失败，保留签发状态供下次重试: %v", err)
			return false
		}
	}
	updateCertMetadata(certCfg, certData)
	return true
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

		candExpiry, candHasExpiry := parseCertExpiry(cand.Metadata.CertExpiresAt)
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

// updateCertMetadata 部署成功后更新证书元数据，清零签发与部署状态（deploy-spec §3.8）
func updateCertMetadata(certCfg *config.CertConfig, certData *api.CertData) {
	certCfg.Metadata.CertExpiresAt = certData.ExpiresAt
	certCfg.Metadata.LastDeployAt = time.Now().Format(timeFormat)
	certCfg.Metadata.CertSerial = "" // 部署成功后由 updateCertSerial 回填
	certCfg.Metadata.IssueRetryCount = 0
	certCfg.Metadata.DeployAttemptCount = 0
	certCfg.Metadata.LastIssueState = ""
	certCfg.Metadata.CapPhase = ""
	certCfg.Metadata.DeployStartedAt = ""
	certCfg.Metadata.CSRSubmittedAt = ""
	certCfg.Metadata.LastCSRHash = ""
}

// calcSpreadDelay 根据证书数量计算分散延迟区间（秒）
// spec: per-cert = clamp(600/N, 5, 120)
func calcSpreadDelay(count int) (sMin, sMax int) {
	if count <= 1 {
		return 0, 0
	}
	sMax = spreadTotalMax / count
	if sMax > spreadMax {
		sMax = spreadMax
	}
	if sMax < spreadMin {
		sMax = spreadMin
	}
	sMin = spreadMin
	return sMin, sMax
}

// updateCertSerial 从证书 PEM 提取序列号回填到配置
func updateCertSerial(certCfg *config.CertConfig, certPEM string) {
	serial, err := cert.GetCertSerialNumber(certPEM)
	if err != nil || serial == "" {
		return
	}
	certCfg.Metadata.CertSerial = serial
}

// updateCertDomains 从证书 PEM 提取域名更新配置
func updateCertDomains(certCfg *config.CertConfig, certPEM string) {
	domains, err := cert.ExtractDomainsFromPEM(certPEM)
	if err != nil || len(domains) == 0 {
		return // 提取失败，保持原值
	}
	certCfg.Domain = domains[0]
	certCfg.Domains = domains
	log.Printf("从证书提取域名: %v", domains)
}

// CallbackTimeout 回调超时时间
const CallbackTimeout = 60 * time.Second

// sendCallback 发送部署回调（异步，带超时控制）
// 回调请求含 order_id/status/deployed_at，失败时附带 message 原因摘要（spec 2.8）；
// message 由 Client.Callback 统一脱敏 + 按 rune 截断，本地同时记 Error 日志留全量；
// 注意：Client.Callback 内部已有重试机制（doWithRetry），此处不再额外重试
func sendCallback(d *Deployer, client APIClient, orderID int, domain string, success bool, message string) {
	message = api.SanitizeCallbackMessage(message)
	if !success && message != "" {
		log.Printf("上报失败回调 (订单 %d, %s): %s", orderID, domain, message)
	}
	seq := d.nextCallbackSequence()
	beforeRenewDays := clientRenewBeforeDays(client)
	d.callbackWg.Add(1)
	go func() {
		defer d.callbackWg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), CallbackTimeout)
		defer cancel()

		status := "success"
		if !success {
			status = "failure"
		}

		req := &api.CallbackRequest{
			OrderID:    orderID,
			Status:     status,
			DeployedAt: time.Now().Format(timeFormat),
		}
		// 仅 failure 携带失败原因（成功回调不含 message）
		if !success {
			req.Message = message
		}

		if err := client.Callback(ctx, req); err != nil {
			log.Printf("回调失败 (%s): %v", domain, err)
			return
		}
		if days := clientRenewBeforeDays(client); days != beforeRenewDays {
			d.recordCallbackRenewBeforeDays(seq, days)
		}
	}()
}

func clientRenewBeforeDays(client APIClient) int {
	if apiClient, ok := client.(*api.Client); ok {
		return apiClient.LastRenewBeforeDays
	}
	return 0
}

// CheckAndDeploy 检查并部署（命令行模式入口）
func CheckAndDeploy() error {
	// 守护启动时检查数据目录 ACL：机器作用域加密的 Token 与私钥机密性依赖此 ACL，
	// 弱 ACL 仅告警不阻断（避免存量安装无法续签）
	for _, w := range util.EvaluateDataDirACL(config.GetDataDir()) {
		log.Printf("[安全告警] %s", w)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("加载配置失败: %v", err)
	}

	if len(cfg.Certificates) == 0 {
		return fmt.Errorf("没有配置任何证书，请先运行 sslctlw setup 或 GUI 添加配置")
	}

	store := cert.NewOrderStore()
	deployer := DefaultDeployer(cfg, store)
	results := AutoDeploy(cfg, deployer, true)

	// 等待所有回调 goroutine 完成
	deployer.WaitCallbacks()

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

// deployCertAutoMode 自动绑定模式部署：查找 IIS 中已有的 SSL 绑定并更换证书。
// 只返回结构化结果与部署报告，不自行发送回调（回调由编排层统一发送，deploy-spec §2.8）。
func deployCertAutoMode(d *Deployer, client APIClient, certData *api.CertData, privateKey string, certCfg config.CertConfig) ([]Result, deployReport) {
	results := make([]Result, 0)

	// 配对校验：转换/安装前确认证书与私钥匹配
	if ok, reason := verifyDeployKeyPair(certData.Certificate, privateKey); !ok {
		log.Printf("证书 %s %s", certData.Domain(), reason)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: reason, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: reason}
	}

	// 1. 转换并安装证书
	pfxPath, err := d.Converter.PEMToPFX(certData.Certificate, privateKey, certData.CACert, "")
	if err != nil {
		log.Printf("转换 PFX 失败: %v", err)
		msg := fmt.Sprintf("转换 PFX 失败: %v", err)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: msg}
	}
	defer removeTempFile(pfxPath)

	installResult, err := d.Installer.InstallPFX(pfxPath, "")
	if err != nil || !installResult.Success {
		errMsg := "安装失败"
		if err != nil {
			errMsg = err.Error()
		} else if installResult.ErrorMessage != "" {
			errMsg = installResult.ErrorMessage
		}
		return []Result{{Domain: certCfg.Domain, Success: false, Message: errMsg, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: "安装证书失败: " + errMsg}
	}

	thumbprint := installResult.Thumbprint
	log.Printf("证书安装成功: %s", thumbprint)

	// 2. 查找 IIS 中匹配的绑定
	allDomains := certCfg.Domains
	if len(allDomains) == 0 && certCfg.Domain != "" {
		allDomains = []string{certCfg.Domain}
	}

	matchedBindings, err := d.Binder.FindBindingsForDomains(allDomains)
	if err != nil {
		log.Printf("查找 IIS 绑定失败: %v", err)
		msg := fmt.Sprintf("查找 IIS 绑定失败: %v", err)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: msg}
	}

	if len(matchedBindings) == 0 {
		// 自动模式依赖现存 SSL 绑定发现部署目标，找不到绑定说明部署无法进行
		// （常见于绑定曾丢失），上报失败让服务端与本地统计均可见，而非静默跳过
		msg := "自动绑定模式未找到匹配的 IIS SSL 绑定，无法部署"
		log.Printf("%s (域名: %v)", msg, allDomains)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: msg}
	}

	// 3. 更新匹配的绑定（循环内只收集结果，报告按订单聚合到循环后返回，回调由编排层单发）
	var outcome bindOutcome
	for domain, binding := range matchedBindings {
		host := iis.ParseHostFromBinding(binding.HostnamePort)
		port := iis.ParsePortFromBinding(binding.HostnamePort)

		log.Printf("更新绑定: %s:%d", host, port)

		var bindErr error
		if isIPBinding(binding.HostnamePort) {
			bindErr = d.Binder.BindCertificateByIP(host, port, thumbprint)
		} else {
			bindErr = d.Binder.BindCertificate(host, port, thumbprint)
		}

		if bindErr != nil {
			log.Printf("绑定失败: %v", bindErr)
			results = append(results, Result{Domain: domain, Success: false, Message: bindErr.Error(), Thumbprint: thumbprint, OrderID: certData.OrderID})
			outcome.fail(fmt.Sprintf("%s: %v", domain, bindErr))
		} else {
			log.Printf("绑定成功: %s", domain)
			results = append(results, Result{Domain: domain, Success: true, Message: "部署成功", Thumbprint: thumbprint, OrderID: certData.OrderID})
			outcome.ok()
		}
	}

	return results, reportFromOutcome(outcome)
}

// handleFileValidation 处理文件验证
// 在 IIS 站点目录下创建验证文件
func handleFileValidation(domain string, file *api.FileValidation) error {
	if file == nil || file.Path == "" || file.Content == "" {
		return fmt.Errorf("验证文件信息不完整")
	}

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

	// 输入本身通过安全校验后再访问 IIS，避免无效请求触发外部命令。
	siteName, sitePath, err := iis.GetSitePhysicalPathByDomain(domain)
	if err != nil {
		return fmt.Errorf("查找站点失败: %w", err)
	}

	log.Printf("找到站点: %s, 路径: %s", siteName, sitePath)

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
	if err := os.WriteFile(fullPath, []byte(file.Content), 0600); err != nil {
		return fmt.Errorf("写入验证文件失败: %w", err)
	}

	// 写入后验证文件位置（防止符号链接攻击）
	realPath, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		// 如果解析失败，删除已写入的文件
		if rmErr := os.Remove(fullPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("警告: 清理验证文件失败 %s: %v", fullPath, rmErr)
		}
		return fmt.Errorf("验证文件路径失败: %w", err)
	}
	if !util.IsPathWithinBase(sitePath, realPath) {
		if rmErr := os.Remove(fullPath); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("警告: 清理验证文件失败 %s: %v", fullPath, rmErr)
		}
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

// isIPBinding 判断是否是 IP 绑定（如 0.0.0.0:443，支持 IPv4 和 IPv6）
func isIPBinding(hostnamePort string) bool {
	host := iis.ParseHostFromBinding(hostnamePort)
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

// validationDirs 可能存在验证文件的子目录
var validationDirs = []string{
	filepath.Join(".well-known", "acme-challenge"),
	filepath.Join(".well-known", "pki-validation"),
}

// cleanupValidationFiles 清理验证文件
// 在证书签发成功后调用，清理 .well-known/acme-challenge/ 和 .well-known/pki-validation/ 下的验证文件
func cleanupValidationFiles(domain string) {
	_, sitePath, err := iis.GetSitePhysicalPathByDomain(domain)
	if err != nil {
		return
	}

	for _, subDir := range validationDirs {
		dir := filepath.Join(sitePath, subDir)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				os.Remove(filepath.Join(dir, entry.Name()))
			}
		}

		// 尝试删除空目录
		os.Remove(dir)
		log.Printf("已清理验证文件: %s", dir)
	}

	// 尝试删除空的 .well-known 目录
	os.Remove(filepath.Join(sitePath, ".well-known"))
}

// removeTempFile 清理临时文件（带重试）
func removeTempFile(path string) {
	util.CleanupTempFileSync(path)
}

// updateRenewBeforeDays 如果 API Client 返回了 renew_before_days，更新配置
func updateRenewBeforeDays(cfg *config.Config, client APIClient) {
	apiClient, ok := client.(*api.Client)
	if !ok {
		return
	}
	updateRenewBeforeDaysValue(cfg, apiClient.LastRenewBeforeDays)
}

func updateRenewBeforeDaysValue(cfg *config.Config, days int) {
	if days > config.MaxRenewBeforeDays {
		log.Printf("服务端返回的 renew_before_days=%d 超过上限 %d（续签应在到期前 30 天内），保留本地配置", days, config.MaxRenewBeforeDays)
		return
	}
	if days > 0 && days != cfg.Schedule.RenewBeforeDays {
		log.Printf("根据服务端配置更新续签提前天数: %d -> %d", cfg.Schedule.RenewBeforeDays, days)
		cfg.Schedule.RenewBeforeDays = days
	}
}
