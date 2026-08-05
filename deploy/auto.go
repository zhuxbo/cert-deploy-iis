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
	"sort"
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

var (
	errPendingKeyMismatch = errors.New("pending 私钥与目标证书不匹配")
	errNoUsableIssuedKey  = errors.New("没有与目标证书配对的可用私钥")
)

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

// runSupplemental 承载不应改变证书部署 Result/callback 的附加清理结果。
type runSupplemental struct {
	Errors   []error
	Warnings []string
}

// autoDeployLock 是自动部署锁的最小内部测试缝。
type autoDeployLock interface {
	Close() error
}

type autoDeployDependencies struct {
	openLock   func(path string) (autoDeployLock, error)
	tryLock    func(autoDeployLock) (bool, error)
	removeLock func(path string) error
	saveConfig func(*config.Config) error
}

func defaultAutoDeployDependencies() autoDeployDependencies {
	return autoDeployDependencies{
		openLock: func(path string) (autoDeployLock, error) {
			return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		},
		tryLock: func(lock autoDeployLock) (bool, error) {
			file, ok := lock.(*os.File)
			if !ok {
				return false, fmt.Errorf("无效的部署锁类型 %T", lock)
			}
			return tryLockFile(file)
		},
		removeLock: os.Remove,
		saveConfig: func(cfg *config.Config) error {
			return cfg.Save()
		},
	}
}

// AutoDeploy 自动部署证书（证书维度，per-cert client）。
// RunOptions 控制分散延迟，并为后续单证书与批次选择保留统一入口。
func AutoDeploy(cfg *config.Config, d *Deployer, opts RunOptions) RunReport {
	return runAutoDeploy(cfg, d, opts, defaultAutoDeployDependencies())
}

func selectBatch(certs []config.CertConfig, startOrderID, limit int) (indexes []int, nextOrderID int) {
	if limit <= 0 {
		return nil, 0
	}
	enabled := make([]int, 0, len(certs))
	for i := range certs {
		if certs[i].Enabled && certs[i].OrderID > 0 {
			enabled = append(enabled, i)
		}
	}
	start := 0
	if startOrderID != 0 {
		found := false
		for pos, index := range enabled {
			if certs[index].OrderID == startOrderID {
				start = pos
				found = true
				break
			}
		}
		if !found {
			start = 0
		}
	}
	end := start + limit
	if end > len(enabled) {
		end = len(enabled)
	}
	indexes = append(indexes, enabled[start:end]...)
	if end < len(enabled) {
		nextOrderID = certs[enabled[end]].OrderID
	}
	return indexes, nextOrderID
}

func runAutoDeploy(cfg *config.Config, d *Deployer, opts RunOptions, deps autoDeployDependencies) RunReport {
	report := RunReport{Results: make([]Result, 0)}

	if len(cfg.Certificates) == 0 {
		log.Println("没有配置任何证书")
		return report
	}

	// 并发保护：获取文件锁，防止多进程同时续签
	lockPath := filepath.Join(config.GetDataDir(), "deploy.lock")
	lockFile, err := deps.openLock(lockPath)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Errorf("打开部署锁失败: %w", err))
		return report
	}
	locked, lockErr := deps.tryLock(lockFile)
	if lockErr != nil {
		_ = lockFile.Close()
		report.Errors = append(report.Errors, fmt.Errorf("获取部署锁失败: %w", lockErr))
		return report
	}
	if !locked {
		log.Println("另一个部署进程正在运行，跳过本次检查")
		_ = lockFile.Close()
		report.AlreadyRunning = true
		return report
	}
	defer func() {
		_ = lockFile.Close()
		_ = deps.removeLock(lockPath)
	}()

	// 检查域名冲突
	conflicts := checkDomainConflicts(cfg.Certificates)
	if len(conflicts) > 0 {
		for endpoint, indexes := range conflicts {
			log.Printf("警告: 端点 %s:%d 配置在多个证书中 (索引: %v)，将使用到期最晚的", endpoint.Host, endpoint.Port, indexes)
		}
	}

	oldCursor := cfg.NextBatchOrderID
	nextCursor := oldCursor
	var batchIndexes []int
	var invalidIndexes []int
	if opts.OnlyOrderID != 0 {
		for i := range cfg.Certificates {
			if cfg.Certificates[i].Enabled && cfg.Certificates[i].OrderID == opts.OnlyOrderID {
				batchIndexes = append(batchIndexes, i)
			}
		}
	} else {
		for i := range cfg.Certificates {
			if cfg.Certificates[i].Enabled && cfg.Certificates[i].OrderID <= 0 {
				invalidIndexes = append(invalidIndexes, i)
			}
		}
		limit := opts.MaxCertificates
		if limit <= 0 || limit > maxRenewBatch {
			limit = maxRenewBatch
		}
		batchIndexes, nextCursor = selectBatch(cfg.Certificates, oldCursor, limit)
		enabledCount := 0
		for _, certCfg := range cfg.Certificates {
			if certCfg.Enabled && certCfg.OrderID > 0 {
				enabledCount++
			}
		}
		if enabledCount > limit {
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("启用证书 %d 张，本轮最多处理 %d 张", enabledCount, limit))
		}
	}

	// 按已选批次计算分散延迟
	var sleepMin, sleepMax int
	if opts.ScatterDelay {
		sleepMin, sleepMax = calcSpreadDelay(len(batchIndexes))
	}
	gate := &authGate{}
	apiRequestCertCount := 0
	beforeAPICall := func() {
		if opts.ScatterDelay && apiRequestCertCount > 0 && sleepMin > 0 {
			delay := sleepMin + rand.IntN(sleepMax-sleepMin+1)
			log.Printf("分散延迟 %d 秒...", delay)
			time.Sleep(time.Duration(delay) * time.Second)
		}
		apiRequestCertCount++
	}

	processIndexes := append(invalidIndexes, batchIndexes...)
	for _, i := range processIndexes {
		supplemental := &runSupplemental{}
		certResults, _ := processOneCertWithSaveAndGate(cfg, d, i, conflicts, func() error {
			return deps.saveConfig(cfg)
		}, gate, beforeAPICall, supplemental)
		report.Results = append(report.Results, certResults...)
		report.Errors = append(report.Errors, supplemental.Errors...)
		report.Warnings = append(report.Warnings, supplemental.Warnings...)
		if attention, ok := certAttention(&cfg.Certificates[i]); ok {
			report.Attention = append(report.Attention, attention)
		}

		// 逐证书持久化：状态变更（重试计数/CSR 哈希/订单号等）立即落盘，
		// 中途中断不丢失，避免重试上限被绕过、CSR 去重失效
		if err := deps.saveConfig(cfg); err != nil {
			report.Results = append(report.Results, Result{
				Domain:  cfg.Certificates[i].Domain,
				OrderID: cfg.Certificates[i].OrderID,
				Success: false,
				Message: fmt.Sprintf("保存证书状态失败: %v", err),
			})
			log.Printf("警告: 保存配置失败: %v", err)
		}

	}

	// 回调响应同样携带 renew_before_days。等待非关键回调结束后统一应用，
	// 避免 goroutine 与证书循环并发修改配置，也覆盖 GUI 未显式 WaitCallbacks 的入口。
	report.Warnings = append(report.Warnings, d.WaitCallbacks()...)
	d.ApplyCallbackRenewBeforeDays(cfg)
	if summary := gate.summary(); summary != "" {
		report.Warnings = append(report.Warnings, summary)
		log.Printf("警告: %s", summary)
	}

	// 更新检查时间
	cfg.LastCheck = time.Now().Format("2006-01-02 15:04:05")
	if opts.OnlyOrderID == 0 {
		cfg.NextBatchOrderID = nextCursor
	}
	if err := deps.saveConfig(cfg); err != nil {
		if opts.OnlyOrderID == 0 {
			cfg.NextBatchOrderID = oldCursor
		}
		report.Errors = append(report.Errors, fmt.Errorf("保存最终配置失败: %w", err))
		log.Printf("警告: 保存配置失败: %v", err)
	}

	return report
}

// processOneCert 处理单个证书的续签检查与部署
// 返回该证书的部署结果与是否实际执行了部署尝试（用于单次批量上限统计）
func certAttention(certCfg *config.CertConfig) (CertAttention, bool) {
	reason := ""
	switch {
	case certCfg.Metadata.IsPolicyBlocked():
		reason = "policy"
	case certCfg.Metadata.IsExpiredState():
		reason = "EXPIRED"
	case certCfg.Metadata.IsCapped():
		reason = "CAPPED"
	}
	if reason == "" {
		return CertAttention{}, false
	}
	return CertAttention{OrderID: certCfg.OrderID, Domain: certCfg.Domain, Reason: reason}, true
}

func processOneCert(cfg *config.Config, d *Deployer, i int, conflicts map[iis.EndpointKey][]int) (certResults []Result, attempted bool) {
	return processOneCertWithSave(cfg, d, i, conflicts, cfg.Save)
}

func processOneCertWithSave(
	cfg *config.Config,
	d *Deployer,
	i int,
	conflicts map[iis.EndpointKey][]int,
	save func() error,
	supplementals ...*runSupplemental,
) (certResults []Result, attempted bool) {
	return processOneCertWithSaveAndGate(cfg, d, i, conflicts, save, nil, nil, supplementals...)
}

func processOneCertWithSaveAndGate(
	cfg *config.Config,
	d *Deployer,
	i int,
	conflicts map[iis.EndpointKey][]int,
	save func() error,
	gate *authGate,
	beforeAPICall func(),
	supplementals ...*runSupplemental,
) (certResults []Result, attempted bool) {
	results := make([]Result, 0)
	certCfg := cfg.Certificates[i]
	var supplemental *runSupplemental
	if len(supplementals) > 0 {
		supplemental = supplementals[0]
	}

	// Deploy API 只操作既有订单。旧版、手工或损坏配置中的非正订单号保持可加载，
	// 但本轮不得创建客户端、请求 API、生成/清理 pending 或消耗尝试计数。
	if certCfg.OrderID <= 0 {
		results = append(results, Result{
			Domain:  certCfg.Domain,
			OrderID: certCfg.OrderID,
			Success: false,
			Message: "订单 ID 无效，请重新运行 setup 选择已有订单",
		})
		return results, false
	}

	// 上轮已可靠标记为待清理时，优先收敛本地产物；即使同时处于 CAPPED，
	// 也不能让前置终态门禁把清理恢复永久挡住。
	recoveredPending := false
	if handled, reason, err := recoverPendingCleanup(d, &cfg.Certificates[i], save); handled {
		if err != nil {
			results = append(results, Result{
				Domain: certCfg.Domain, OrderID: certCfg.OrderID, Success: false,
				Message: fmt.Sprintf("清理失效在途产物失败: %v", err),
			})
			return results, false
		}
		recoveredPending = true
		if reason != "" {
			log.Printf("证书 %s %s", certCfg.Domain, reason)
		}
	}
	// 停更清理还包含本客户端拥有的验证文件。记录本身就是可恢复标记：
	// 删除或保存失败时保留记录，下轮仍在 CAPPED 门禁前重试。
	if cfg.Certificates[i].Metadata.IsCapped() &&
		cfg.Certificates[i].Metadata.CapPhase == config.CapPhaseStalled &&
		len(cfg.Certificates[i].Metadata.ValidationFiles) > 0 {
		cleanupOwnedValidationFiles(d, &cfg.Certificates[i], save, supplemental)
		return results, false
	}
	if recoveredPending {
		return results, false
	}

	// 自动动作准入门禁：触顶(CAPPED)/过期(EXPIRED)/策略阻断时，
	// 本轮不发起任何动作、不发送任何回调（deploy-spec §3.2）。
	if skip, reason := evaluateAutoActionGate(&cfg.Certificates[i], time.Now()); skip {
		if reason != "" {
			log.Printf("证书 %s 跳过自动动作: %s", certCfg.Domain, reason)
		}
		return results, false
	}
	if stalledTooLong(&cfg.Certificates[i], time.Now()) {
		markStalled(d, &cfg.Certificates[i], save, supplementals...)
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
	if block, blocked := gate.blockedBy(client); blocked {
		gate.markSkipped()
		log.Printf("证书 %s 跳过本轮：该 API 凭据已被服务端拒绝（%s）", certCfg.Domain, block.description())
		return results, false
	}
	tracker := &apiCallTracker{trackNoProgress: true}
	trackedClient := &trackedAPIClient{
		APIClient:       client,
		concrete:        client,
		gate:            gate,
		tracker:         tracker,
		beforeFirstCall: beforeAPICall,
	}
	progressBefore := snapshotProgress(&cfg.Certificates[i])
	defer func() {
		settleNoProgress(&cfg.Certificates[i], progressBefore,
			tracker.madeCall && !tracker.authBlocked && tracker.trackNoProgress, time.Now())
	}()

	bindingRetry := len(cfg.Certificates[i].Metadata.FailedBindings) > 0
	if bindingRetry {
		if cfg.Certificates[i].Metadata.BindingRetryCount >= config.MaxDeployAttempts {
			results = append(results, Result{
				Domain: certCfg.Domain, OrderID: certCfg.OrderID, Success: false,
				Message: "失败绑定重试已达上限，需人工处理",
			})
			return results, false
		}
		cfg.Certificates[i].Metadata.BindingRetryCount++
		if err := save(); err != nil {
			cfg.Certificates[i].Metadata.BindingRetryCount--
			results = append(results, Result{
				Domain: certCfg.Domain, OrderID: certCfg.OrderID, Success: false,
				Message: fmt.Sprintf("持久化失败绑定重试状态失败: %v", err),
			})
			return results, false
		}
		certCfg = cfg.Certificates[i]
	}

	isLocal := certCfg.IsLocalMode(cfg.Schedule.RenewMode)
	log.Printf("检查证书: %s (订单: %d, 模式: %s)", certCfg.Domain, certCfg.OrderID, map[bool]string{true: "local", false: "pull"}[isLocal])

	var certData *api.CertData
	// 安全警告: privateKey 包含敏感的私钥数据，严禁在日志中打印
	var privateKey string
	var err error

	if isLocal {
		// 本机提交：签发阶段的失败只记本地日志与本地计数，一律不发送回调（deploy-spec §2.8）
		// 分散等待必须发生在 handleLocalKeyMode 创建 API context 之前，不能消耗请求超时预算。
		trackedClient.beforeCall()
		var reason string
		certData, privateKey, reason, err = handleLocalKeyMode(d, trackedClient, &cfg.Certificates[i], cfg.Schedule.RenewBeforeDays, save)
		// API 调用完成后更新续签提前天数（无论成功或跳过）
		updateRenewBeforeDays(cfg, client)
		if err != nil {
			trackAPIOrderError(&cfg.Certificates[i], err)
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
			if bindingRetry && isWaitingOrderStatus(cfg.Certificates[i].Metadata.LastOrderStatus) {
				rollbackBindingRetry(&cfg.Certificates[i], save)
			}
			if cfg.Certificates[i].Metadata.LastOrderStatus == config.OrderStatusActive &&
				cfg.Certificates[i].Metadata.LastIssueState == "" {
				// active 且不在续签窗口是健康跳过，不属于停更计时覆盖的无进展轮询。
				tracker.trackNoProgress = false
				cfg.Certificates[i].Metadata.NoProgressSince = ""
			}
			if reason != "" {
				log.Printf("证书 %s 跳过: %s", certCfg.Domain, reason)
			}
			return results, false
		}
	} else {
		// 自动签发：拉取失败属签发/获取阶段，只记本地日志、不发送回调（deploy-spec §2.8）
		ctx, cancel := beginTrackedAPIRequest(trackedClient, api.APIQueryTimeout)
		certData, err = trackedClient.GetCertByOrderID(ctx, certCfg.OrderID)
		cancel()
		if err != nil {
			trackAPIOrderError(&cfg.Certificates[i], err)
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
		changed := trackOrderStatus(&cfg.Certificates[i], certData.Status)
		switch classifyOrderStatus(certData.Status) {
		case orderClassWaiting, orderClassUnknown:
			if bindingRetry {
				rollbackBindingRetry(&cfg.Certificates[i], save)
			}
			log.Printf("证书 %s 订单状态 %s，继续等待", certData.Domain(), certData.Status)
			return results, false
		case orderClassTerminal, orderClassChainAnomaly:
			if changed {
				results = append(results, Result{
					Domain: certCfg.Domain, Success: false,
					Message: fmt.Sprintf("证书订单状态: %s", certData.Status), OrderID: certData.OrderID,
				})
			}
			return results, false
		case orderClassActive:
			// 继续部署判定
		}

		// 检查是否到了拉取时间
		expiresAt, ok := parseCertExpiry(certData.ExpiresAt)
		if !ok {
			results = append(results, Result{
				Domain:  certCfg.Domain,
				Success: false,
				Message: "解析证书过期时间失败",
				OrderID: certData.OrderID,
			})
			log.Printf("解析证书 %s (订单 %d) 过期时间失败（值: %q）", certData.Domain(), certData.OrderID, certData.ExpiresAt)
			return results, false
		}

		remaining := time.Until(expiresAt)
		if remaining <= 0 {
			deployCertCfg := &cfg.Certificates[i]
			deployCertCfg.Metadata.LastIssueState = config.IssueStateExpired
			deployCertCfg.Metadata.CapPhase = ""
			deployCertCfg.Metadata.ResubmitRequired = false
			log.Printf("证书 %s 已过期，跳过（需人工介入）", certData.Domain())
			return results, false
		}
		daysUntilExpiry := int(remaining.Hours() / 24)
		if !bindingRetry && daysUntilExpiry > cfg.Schedule.RenewBeforeDays {
			tracker.trackNoProgress = false
			cfg.Certificates[i].Metadata.NoProgressSince = ""
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
		results = append(results, Result{
			Domain:  certCfg.Domain,
			Success: false,
			Message: fmt.Sprintf("证书链大小 %d 超过上限 %d", chainSize, cert.MaxCertChainSize),
			OrderID: certData.OrderID,
		})
		log.Printf("证书 %s 证书链大小 %d 超过上限 %d", certData.Domain(), chainSize, cert.MaxCertChainSize)
		return results, false
	}
	if certData.PrivateKey != "" && len(certData.PrivateKey) > cert.MaxPrivateKeySize {
		results = append(results, Result{
			Domain:  certCfg.Domain,
			Success: false,
			Message: fmt.Sprintf("私钥大小 %d 超过上限 %d", len(certData.PrivateKey), cert.MaxPrivateKeySize),
			OrderID: certData.OrderID,
		})
		log.Printf("证书 %s 私钥大小 %d 超过上限 %d", certData.Domain(), len(certData.PrivateKey), cert.MaxPrivateKeySize)
		return results, false
	}

	log.Printf("证书 %s 开始部署...", certData.Domain())

	deployCertCfg := &cfg.Certificates[i]
	prevSerial := deployCertCfg.Metadata.CertSerial
	prevExpiry := deployCertCfg.Metadata.CertExpiresAt

	// 部署意图落盘（deploy-spec §5.1）：新尝试先递增部署计数并写入在途标记再落盘；
	// 崩溃恢复重放（标记已存在）复用同一意图不重复计数；触顶转 CAPPED 静默、不回调。
	capped, replaying, persistErr := false, false, error(nil)
	if !bindingRetry {
		capped, replaying, persistErr = persistDeployAttempt(&deployCertCfg.Metadata, save)
	}
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
	persistedCertCfg := *deployCertCfg

	// 底层部署函数只返回结构化结果，不自行发送回调（deploy-spec §2.8）
	var deployResults []Result
	var rep deployReport
	if certCfg.AutoBindMode {
		deployResults, rep = deployCertAutoMode(d, client, certData, privateKey, certCfg)
	} else {
		deployResults, rep = deployCertWithRules(d, client, certData, privateKey, certCfg, i, conflicts, cfg.Certificates)
	}
	results = append(results, deployResults...)

	// 更新配置中的订单 ID（续费后 API 返回新订单号）
	if deployCertCfg.OrderID != certData.OrderID {
		log.Printf("订单号更新: %d -> %d", deployCertCfg.OrderID, certData.OrderID)
		deployCertCfg.OrderID = certData.OrderID
	}

	// 部署结果原子落盘 + 部署计数收敛。任一绑定成功即接纳证书；
	// 部分失败只把失败端点留给独立重试状态。
	accepted := rep.report && certData.Certificate != "" &&
		(rep.success || len(rep.successfulTargets) > 0)
	if accepted {
		if err := d.Store.SaveCertificate(certData.OrderID, certData.Certificate, certData.CACert); err != nil {
			log.Printf("警告: 保存已部署证书失败: %v", err)
			msg := fmt.Sprintf("保存已部署证书失败: %v", err)
			results = append(results, Result{
				Domain: certCfg.Domain, OrderID: certData.OrderID, Success: false, Message: msg,
			})
			accepted = false
			rep = deployReport{report: true, success: false, message: msg}
		} else if finalizeSuccessfulDeployment(d, deployCertCfg, certData, privateKey, isLocal) {
			// 转正失败说明生命周期未收敛（本地正式私钥仍是旧的），本轮按失败处理：
			// 必须清掉在途标记让部署计数继续推进，否则 DeployStartedAt 永久残留会使后续每轮
			// 都被判为崩溃恢复重放而不计数，绕过 CAPPED 兜底并每轮重复上报一次 success 回调。
			updateCertDomains(deployCertCfg, certData.Certificate)
			updateCertSerial(deployCertCfg, certData.Certificate)
			if rep.success {
				if unchanged := trackCertUnchanged(deployCertCfg, prevSerial, prevExpiry); unchanged != "" {
					// 物理写入成功但证书没有更替，契约上属于部署失败：恢复成功路径刚清掉的
					// 部署计数与进展字段，让后续轮次继续累积并最终受 CAPPED 约束。
					preserveUnchangedFailureState(&deployCertCfg.Metadata, persistedCertCfg.Metadata)
					accepted = false
					rep = deployReport{report: true, success: false, message: unchanged}
					results = append(results, Result{
						Domain: certCfg.Domain, OrderID: certData.OrderID, Success: false, Message: unchanged,
					})
				}
			}
			if accepted && len(rep.failedTargets) > 0 {
				deployCertCfg.Metadata.FailedBindings = append(
					[]config.BindingRetryTarget(nil), rep.failedTargets...,
				)
				if bindingRetry {
					deployCertCfg.Metadata.BindingRetryCount = persistedCertCfg.Metadata.BindingRetryCount
				}
			}
		} else {
			accepted = false
			msg := "pending 私钥转正失败，部署生命周期未收敛"
			results = append(results, Result{
				Domain: certCfg.Domain, OrderID: certData.OrderID, Success: false, Message: msg,
			})
			rep = deployReport{report: true, success: false, message: msg}
		}
	}
	if !accepted {
		reconcileFailedDeploy(&deployCertCfg.Metadata, rep.report, replaying)
	}
	if err := save(); err != nil {
		log.Printf("警告: 保存部署结果失败，不发送回调: %v", err)
		*deployCertCfg = persistedCertCfg
		results = append(results, Result{
			Domain: certCfg.Domain, OrderID: certData.OrderID, Success: false,
			Message: fmt.Sprintf("保存部署结果失败: %v", err),
		})
		return results, true
	}
	if accepted && len(deployCertCfg.Metadata.ValidationFiles) > 0 {
		var supplemental *runSupplemental
		if len(supplementals) > 0 {
			supplemental = supplementals[0]
		}
		cleanupOwnedValidationFiles(d, deployCertCfg, save, supplemental)
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
	report            bool                        // 是否需要回调
	success           bool                        // 是否全部绑定成功
	message           string                      // 失败原因摘要（success 时为空）
	successfulTargets []config.BindingRetryTarget // 本轮成功端点
	failedTargets     []config.BindingRetryTarget // 本轮失败端点
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

// shouldFinalizeDeployment 任一绑定成功且证书内容非空时即接纳证书。
func shouldFinalizeDeployment(rep deployReport, hasCertificate bool) bool {
	return rep.report && hasCertificate && (rep.success || len(rep.successfulTargets) > 0)
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

func retryTarget(key iis.EndpointKey) config.BindingRetryTarget {
	return config.BindingRetryTarget{Host: key.Host, Port: key.Port, IPBinding: key.IPBinding}
}

func isPendingBindingTarget(key iis.EndpointKey, pending []config.BindingRetryTarget) bool {
	if len(pending) == 0 {
		return true
	}
	for _, target := range pending {
		if target.Port == key.Port && target.IPBinding == key.IPBinding &&
			strings.EqualFold(target.Host, key.Host) {
			return true
		}
	}
	return false
}

func isWaitingOrderStatus(status string) bool {
	class := classifyOrderStatus(status)
	return class == orderClassWaiting || class == orderClassUnknown
}

func rollbackBindingRetry(certCfg *config.CertConfig, persist func() error) {
	if certCfg.Metadata.BindingRetryCount <= 0 {
		return
	}
	certCfg.Metadata.BindingRetryCount--
	if persist != nil {
		if err := persist(); err != nil {
			certCfg.Metadata.BindingRetryCount++
			log.Printf("回滚失败绑定查询轮次失败: %v", err)
		}
	}
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
		if e, ok := parseCertExpiry(meta.CertExpiresAt); ok {
			expiry, haveExpiry = e, true
		}
	}

	// 证书绝对到期是自动动作的准入截止点：已过期静默终止并转 EXPIRED（触顶后到期同样转 EXPIRED）。
	if haveExpiry && !expiry.After(now) {
		if !meta.IsExpiredState() {
			meta.LastIssueState = config.IssueStateExpired
			meta.CapPhase = ""
			meta.ResubmitRequired = false
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
func deployCertWithRules(d *Deployer, client APIClient, certData *api.CertData, privateKey string, certCfg config.CertConfig, currentCertIndex int, conflicts map[iis.EndpointKey][]int, allCerts []config.CertConfig) ([]Result, deployReport) {
	results := make([]Result, 0)

	targets, err := executableRuleTargets(certCfg, currentCertIndex, conflicts, allCerts)
	if err != nil {
		msg := fmt.Sprintf("绑定目标无效: %v", err)
		return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
			deployReport{report: true, success: false, message: msg}
	}
	if len(targets) == 0 {
		if len(certCfg.BindRules) == 0 {
			msg := "未配置 IIS 绑定规则，无法部署"
			return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
				deployReport{report: true, success: false, message: msg}
		}
		return nil, deployReport{}
	}

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
	var successfulTargets, failedTargets []config.BindingRetryTarget
	for _, target := range targets {
		rule := target.rule
		port := target.key.Port

		log.Printf("绑定证书到 %s:%d", rule.Domain, port)

		// IP 证书走 IP 绑定（ipport），域名走 SNI 绑定；netsh 层的复验/回滚防止误覆盖同端口其他证书
		var bindErr error
		if target.key.IPBinding {
			bindErr = d.Binder.BindCertificateByIP(target.key.Host, port, thumbprint)
		} else {
			bindErr = d.Binder.BindCertificate(target.key.Host, port, thumbprint)
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
			failedTargets = append(failedTargets, retryTarget(target.key))
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
			successfulTargets = append(successfulTargets, retryTarget(target.key))
		}
	}

	rep := reportFromOutcome(outcome)
	rep.successfulTargets = successfulTargets
	rep.failedTargets = failedTargets
	return results, rep
}

type executableRuleTarget struct {
	rule config.BindRule
	key  iis.EndpointKey
}

func endpointKeyForRule(rule config.BindRule) (iis.EndpointKey, error) {
	host := strings.TrimSpace(rule.Domain)
	return iis.NormalizeEndpoint(net.ParseIP(strings.Trim(host, "[]")) != nil, host, rule.Port)
}

func executableRuleTargets(certCfg config.CertConfig, currentCertIndex int, conflicts map[iis.EndpointKey][]int, allCerts []config.CertConfig) ([]executableRuleTarget, error) {
	targets := make([]executableRuleTarget, 0, len(certCfg.BindRules))
	seen := make(map[iis.EndpointKey]struct{}, len(certCfg.BindRules))
	for _, rule := range certCfg.BindRules {
		key, err := endpointKeyForRule(rule)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}

		if conflictIndexes, hasConflict := conflicts[key]; hasConflict {
			bestIndex := selectBestCertIndexForDomainByIndexes(conflictIndexes, allCerts)
			if bestIndex != currentCertIndex {
				log.Printf("端点 %s:%d 存在冲突，跳过（将由其他证书处理）", key.Host, key.Port)
				continue
			}
		}
		if !isPendingBindingTarget(key, certCfg.Metadata.FailedBindings) {
			continue
		}
		targets = append(targets, executableRuleTarget{rule: rule, key: key})
	}
	return targets, nil
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
func handleProcessingOrder(
	d *Deployer,
	certCfg *config.CertConfig,
	certData *api.CertData,
	persistConfig ...func() error,
) (reason string, err error) {
	if certData.File == nil || certData.File.Path == "" {
		log.Printf("订单 %d 处理中，等待签发", certCfg.OrderID)
		return "CSR 已提交，等待签发", nil
	}
	if certData.File.Content == "" {
		return "", fmt.Errorf("验证文件信息不完整")
	}
	if d.ValidationRoots == nil || d.ValidationFiles == nil {
		return "", fmt.Errorf("文件验证依赖未配置")
	}
	log.Printf("订单 %d 需要文件验证", certCfg.OrderID)

	roots, err := resolveValidationRoots(d.ValidationRoots, certCfg)
	if err != nil {
		return "", fmt.Errorf("解析验证站点失败: %w", err)
	}
	relativePath, err := normalizeValidationRelativePath(certData.File.Path)
	if err != nil {
		return "", err
	}
	var persist func() error
	if len(persistConfig) > 0 {
		persist = persistConfig[0]
	}
	for _, root := range roots {
		recordIndex := validationRecordIndex(certCfg.Metadata.ValidationFiles, root.SiteName, relativePath)
		placed, err := d.ValidationFiles.PlaceToken(root, certData.File.Path, certData.File.Content)
		if err != nil {
			return "", fmt.Errorf("站点 %s 创建验证文件失败: %w", root.SiteName, err)
		}
		if !placed.Created {
			continue // 同内容预存可复用，但客户端不取得所有权。
		}
		record := config.ValidationFileRecord{
			SiteName:     root.SiteName,
			RelativePath: placed.RelativePath,
			SHA256:       placed.SHA256,
		}
		var previous config.ValidationFileRecord
		if recordIndex >= 0 {
			previous = certCfg.Metadata.ValidationFiles[recordIndex]
			certCfg.Metadata.ValidationFiles[recordIndex] = record
		} else {
			certCfg.Metadata.ValidationFiles = append(certCfg.Metadata.ValidationFiles, record)
		}
		restoreRecord := func() {
			if recordIndex >= 0 {
				certCfg.Metadata.ValidationFiles[recordIndex] = previous
			} else {
				certCfg.Metadata.ValidationFiles = certCfg.Metadata.ValidationFiles[:len(certCfg.Metadata.ValidationFiles)-1]
			}
		}
		if persist == nil {
			restoreRecord()
			rollbackErr := rollbackValidationToken(d.ValidationFiles, root, record)
			return "", errors.Join(errors.New("新增验证文件后缺少完整配置持久化函数"), rollbackErr)
		}
		if err := persist(); err != nil {
			restoreRecord()
			rollbackErr := rollbackValidationToken(d.ValidationFiles, root, record)
			return "", errors.Join(fmt.Errorf("持久化验证文件所有权失败: %w", err), rollbackErr)
		}
	}
	log.Printf("验证文件已创建，等待 CA 验证")
	return "CSR 已提交，等待签发", nil
}

type pendingOwnership int

const (
	pendingOwnershipNone pendingOwnership = iota
	pendingOwnershipConfirmed
	pendingOwnershipMismatch
	pendingOwnershipOrphan
	pendingOwnershipUnknown
)

// checkPendingOwnership 用服务端当前动作的 CSR 判断本地 pending 是否属于该动作。
// 缺失或非法 CSR 无法形成安全结论，必须保留 pending；合法但不匹配时才清理。
func checkPendingOwnership(
	d *Deployer,
	certCfg *config.CertConfig,
	certData *api.CertData,
	persistConfig ...func() error,
) (pendingOwnership, string, error) {
	if !d.Store.HasPendingPrivateKey(certCfg.CertName) {
		return pendingOwnershipNone, "", nil
	}
	if certCfg.Metadata.LastCSRHash == "" || certCfg.Metadata.CSRSubmittedAt == "" {
		nextState := config.IssueStateProcessing
		if classifyOrderStatus(certData.Status) == orderClassActive {
			nextState = ""
		}
		if err := discardPendingIntent(d, certCfg, nextState, persistConfig...); err != nil {
			return pendingOwnershipUnknown, "", err
		}
		return pendingOwnershipOrphan, "", nil
	}
	if strings.TrimSpace(certData.CSR) == "" {
		return pendingOwnershipUnknown, "服务端当前动作缺少 CSR，已保留 pending 并停止本轮", nil
	}
	pendingKey, err := d.Store.LoadPendingPrivateKey(certCfg.CertName)
	if err != nil {
		return pendingOwnershipUnknown, "", fmt.Errorf("加载 pending 私钥失败: %w", err)
	}

	expectedHash := certCfg.Metadata.LastCSRHash
	serverHash, hashErr := cert.CSRDERHash(certData.CSR)
	if hashErr != nil {
		return pendingOwnershipUnknown, "服务端 CSR 无法解析或签名无效，已保留 pending 并停止本轮", nil
	}
	// 兼容本版落地前按 PEM 原文保存的 hash：只在本地 pending CSR 可解析且
	// 原文 hash 与旧 metadata 相符时迁移为 DER hash。
	if pendingCSR, loadErr := d.Store.LoadPendingCSR(certCfg.CertName); loadErr == nil {
		legacyHash := fmt.Sprintf("%x", sha256.Sum256([]byte(pendingCSR)))
		if strings.EqualFold(expectedHash, legacyHash) {
			if pendingDERHash, derErr := cert.CSRDERHash(pendingCSR); derErr == nil {
				expectedHash = pendingDERHash
			}
		}
	}
	matched, verifyErr := cert.VerifyCSRIdentity(
		certData.CSR,
		pendingKey,
		expectedHash,
		certCfg.Domain,
	)
	if verifyErr != nil {
		return pendingOwnershipUnknown, "服务端 CSR 无法验证，已保留 pending 并停止本轮", nil
	}
	if matched {
		changed := certCfg.Metadata.ResubmitRequired ||
			!strings.EqualFold(certCfg.Metadata.LastCSRHash, serverHash)
		certCfg.Metadata.ResubmitRequired = false
		certCfg.Metadata.LastCSRHash = serverHash
		if changed && len(persistConfig) > 0 && persistConfig[0] != nil {
			if err := persistConfig[0](); err != nil {
				return pendingOwnershipUnknown, "", fmt.Errorf("持久化 CSR 归属确认失败: %w", err)
			}
		}
		return pendingOwnershipConfirmed, "", nil
	}

	nextState := config.IssueStateProcessing
	if classifyOrderStatus(certData.Status) == orderClassActive {
		nextState = ""
	}
	if err := discardPendingIntent(d, certCfg, nextState, persistConfig...); err != nil {
		return pendingOwnershipUnknown, "", err
	}
	return pendingOwnershipMismatch, "", nil
}

// discardPendingIntent 先落盘“待清理”状态，再删除本地敏感产物，保证崩溃后可恢复。
func discardPendingIntent(
	d *Deployer,
	certCfg *config.CertConfig,
	nextState string,
	persistConfig ...func() error,
) error {
	if len(persistConfig) == 0 || persistConfig[0] == nil {
		return errors.New("清理不匹配 pending 前缺少完整配置持久化函数")
	}
	persist := persistConfig[0]
	certCfg.Metadata.LastIssueState = nextState
	certCfg.Metadata.CSRSubmittedAt = ""
	certCfg.Metadata.LastCSRHash = ""
	certCfg.Metadata.ResubmitRequired = false
	certCfg.Metadata.PendingCleanup = true
	if err := persist(); err != nil {
		return fmt.Errorf("持久化 pending 清理意图失败: %w", err)
	}
	if err := d.Store.RemovePendingArtifacts(certCfg.CertName); err != nil {
		return fmt.Errorf("清理不匹配 pending 产物失败: %w", err)
	}
	certCfg.Metadata.PendingCleanup = false
	if err := persist(); err != nil {
		certCfg.Metadata.PendingCleanup = true
		return fmt.Errorf("持久化 pending 清理结果失败: %w", err)
	}
	return nil
}

func resolveValidationRoots(resolver ValidationWebRootResolver, certCfg *config.CertConfig) ([]iis.ValidationWebRoot, error) {
	domains := append([]string(nil), certCfg.Domains...)
	if len(domains) == 0 && certCfg.Domain != "" {
		domains = []string{certCfg.Domain}
	}
	explicitSites := make([]string, 0)
	seenSites := make(map[string]struct{})
	autoRequested := len(certCfg.BindRules) == 0
	for _, rule := range certCfg.BindRules {
		if rule.SiteName == "" {
			autoRequested = true
			continue
		}
		key := strings.ToLower(rule.SiteName)
		if _, exists := seenSites[key]; exists {
			continue
		}
		seenSites[key] = struct{}{}
		explicitSites = append(explicitSites, rule.SiteName)
	}
	if autoRequested {
		explicitSites = append(explicitSites, "")
	}
	sort.Slice(explicitSites, func(i, j int) bool {
		return strings.ToLower(explicitSites[i]) < strings.ToLower(explicitSites[j])
	})
	all := make([]iis.ValidationWebRoot, 0)
	for _, siteName := range explicitSites {
		roots, err := resolver.ResolveValidationWebRoots(domains, siteName)
		if err != nil {
			return nil, err
		}
		all = append(all, roots...)
	}
	sort.Slice(all, func(i, j int) bool {
		return strings.ToLower(all[i].SiteName) < strings.ToLower(all[j].SiteName)
	})
	deduped := make([]iis.ValidationWebRoot, 0, len(all))
	seenPaths := make(map[string]struct{})
	for _, root := range all {
		key := strings.ToLower(filepath.Clean(root.PhysicalPath))
		if _, exists := seenPaths[key]; exists {
			continue
		}
		seenPaths[key] = struct{}{}
		deduped = append(deduped, root)
	}
	if len(deduped) == 0 {
		return nil, fmt.Errorf("未找到可用于文件验证的 IIS 站点")
	}
	return deduped, nil
}

func validationRecordIndex(records []config.ValidationFileRecord, siteName, relativePath string) int {
	for i, record := range records {
		if strings.EqualFold(record.SiteName, siteName) &&
			strings.EqualFold(filepath.Clean(record.RelativePath), filepath.Clean(relativePath)) {
			return i
		}
	}
	return -1
}

func rollbackValidationToken(store validationFileStore, root iis.ValidationWebRoot, record config.ValidationFileRecord) error {
	status, err := store.RemoveToken(root, record)
	if err != nil {
		return fmt.Errorf("回滚新建验证文件失败: %w", err)
	}
	if status != validationTokenRemoved && status != validationTokenMissing {
		return fmt.Errorf("回滚新建验证文件失败: 文件所有权已变化")
	}
	return nil
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
		return "", fmt.Errorf("%w，已保留并等待服务端签发推进", errPendingKeyMismatch)
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
	return "", errNoUsableIssuedKey
}

// resetIssueStateForResubmit 在服务端订单已 active、但本地已无对应 pending 私钥且其他私钥
// 也无法配对时，先持久化清除失效的在途标记。调用方随后同轮创建新的逻辑签发尝试，
// 避免按服务端新证书的长有效期健康跳过，导致本地旧证书静默过期。
func resetIssueStateForResubmit(certCfg *config.CertConfig, cause error, persistConfig ...func() error) error {
	before := certCfg.Metadata
	certCfg.Metadata.LastIssueState = ""
	certCfg.Metadata.CSRSubmittedAt = ""
	certCfg.Metadata.LastCSRHash = ""
	certCfg.Metadata.ResubmitRequired = true
	var persist func() error
	if len(persistConfig) > 0 {
		persist = persistConfig[0]
	}
	if persist != nil {
		if err := persist(); err != nil {
			certCfg.Metadata = before
			return errors.Join(cause, fmt.Errorf("重置失效签发状态失败: %w", err))
		}
	}
	return nil
}

// submitNewCSR 生成并提交新的 CSR
func submitNewCSR(d *Deployer, client APIClient, certCfg *config.CertConfig, persistConfig ...func() error) (*api.CertData, string, string, error) {
	if certCfg.OrderID <= 0 {
		return nil, "", "", fmt.Errorf("订单 ID 必须为正整数，请重新运行 setup 配置已有订单")
	}
	if certCfg.CertName == "" {
		certCfg.CertName = fmt.Sprintf("%s-%d", certCfg.Domain, certCfg.OrderID)
	}
	if handled, reason, err := recoverPendingCleanup(d, certCfg, persistConfig...); handled {
		return nil, "", reason, err
	}
	// 已有已落盘意图时只等待 GET 证明归属，绝不重放 CSR POST。
	if d.Store.HasPendingPrivateKey(certCfg.CertName) {
		if certCfg.Metadata.LastCSRHash != "" && certCfg.Metadata.CSRSubmittedAt != "" {
			certCfg.Metadata.LastIssueState = config.IssueStateProcessing
			return nil, "", "已有 CSR 结果待确认，后续仅查询订单", nil
		}
		// pending 已写入但意图元数据尚未落盘，按规范视为未提交孤儿，先清理再建新尝试。
		if err := d.Store.RemovePendingArtifacts(certCfg.CertName); err != nil {
			return nil, "", "", fmt.Errorf("清理未提交的 pending 孤儿失败: %w", err)
		}
	}
	// 安全余量只禁止建立新 CSR；既有 pending 的 query-first 判断与孤儿清理先于此门禁。
	if expiresAt, ok := parseCertExpiry(certCfg.Metadata.CertExpiresAt); ok &&
		time.Until(expiresAt) < autoActionSafetyMargin {
		return nil, "", "剩余有效期不足安全余量，不建立新的 CSR 尝试", nil
	}
	// 签发触顶：不再提交新 CSR，进入 CAPPED 静默，不发送任何回调（deploy-spec §3.2）
	retryCount := certCfg.Metadata.IssueRetryCount
	if retryCount >= config.MaxIssueRetries {
		certCfg.Metadata.ResubmitRequired = false
		certCfg.Metadata.MarkCapped(config.CapPhaseIssue)
		return nil, "", fmt.Sprintf("签发计数已达上限 %d，进入 CAPPED，等待人工处理", config.MaxIssueRetries), nil
	}

	// 先单独落盘恢复标记，再生成/写入 pending。否则 pending 已写成但新意图保存失败时，
	// metadata 会回滚到无标记状态，重启后把旧 active 与新 pending 的错配误当成“继续等签发”。
	if !certCfg.Metadata.ResubmitRequired {
		before := certCfg.Metadata
		certCfg.Metadata.ResubmitRequired = true
		if len(persistConfig) > 0 && persistConfig[0] != nil {
			if err := persistConfig[0](); err != nil {
				certCfg.Metadata = before
				return nil, "", "", fmt.Errorf("持久化 CSR 恢复标记失败: %w", err)
			}
		}
	}

	log.Printf("生成新的 CSR (重试: %d/%d)", retryCount, config.MaxIssueRetries)
	keyPEM, csrPEM, err := cert.GenerateCSR(certCfg.Domain)
	if err != nil {
		return nil, "", "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// CSR 哈希去重使用解析后的 DER，避免 PEM 换行差异影响归属判断（spec 5.8）。
	csrHash, err := cert.CSRDERHash(csrPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("计算 CSR 标识失败: %w", err)
	}
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
	return submitPendingCSR(d, client, certCfg, csrPEM, persistConfig...)
}

// recoverPendingCleanup 收敛“拒绝状态已落盘、pending 删除尚未完成”的崩溃/IO 失败窗口。
// 标记存在时只做本地清理，绝不把残留文件误当成可重放的签发意图。
func recoverPendingCleanup(
	d *Deployer,
	certCfg *config.CertConfig,
	persistConfig ...func() error,
) (handled bool, reason string, err error) {
	if !certCfg.Metadata.PendingCleanup {
		return false, "", nil
	}
	var persist func() error
	if len(persistConfig) > 0 {
		persist = persistConfig[0]
	}
	if persist == nil {
		return true, "", errors.New("清理已失效的 pending 产物前缺少配置持久化函数")
	}
	if err := d.Store.RemovePendingArtifacts(certCfg.CertName); err != nil {
		return true, "", fmt.Errorf("清理已失效的 pending 产物失败: %w", err)
	}
	certCfg.Metadata.PendingCleanup = false
	if err := persist(); err != nil {
		certCfg.Metadata.PendingCleanup = true
		return true, "", fmt.Errorf("保存 pending 清理结果失败: %w", err)
	}
	return true, "已清理失效的在途产物，下轮重新检查", nil
}

func submitPendingCSR(d *Deployer, client APIClient, certCfg *config.CertConfig, csrPEM string, persistConfig ...func() error) (*api.CertData, string, string, error) {
	csrHash, err := cert.CSRDERHash(csrPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("计算 CSR 标识失败: %w", err)
	}
	before := certCfg.Metadata
	var persist func() error
	if len(persistConfig) > 0 {
		persist = persistConfig[0]
	}

	// 每次进入本函数都建立新的逻辑尝试；结果不确定后的恢复只走 GET。
	if certCfg.Metadata.LastCSRHash != csrHash {
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

	// 提交尝试的元数据必须在请求前持久化。结果未确认时保留 pending，
	// 下轮通过 GET 返回的服务端 CSR 判断归属。
	certCfg.Metadata.CSRSubmittedAt = time.Now().Format(timeFormat)
	certCfg.Metadata.LastCSRHash = csrHash
	certCfg.Metadata.LastIssueState = config.IssueStateProcessing
	// 从“新意图已落盘”到“服务端确定响应”之间无法原子提交。标记保持到
	// 后续 GET 通过服务端 CSR 证明归属；任何情况下都不重放这个 POST。
	certCfg.Metadata.ResubmitRequired = true
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
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 200 {
			cleanupPending := false
			if api.IsAuthBlockErrorCode(apiErr.ErrorCode) {
				// 整批共通失败未接收本次提交：回滚计数与在途状态，修复凭据后可自动恢复。
				certCfg.Metadata = before
				certCfg.Metadata.PendingCleanup = true
				cleanupPending = true
			} else if apiErr.ErrorCode == api.ErrorCodeOrderInProgress {
				// 唯一过渡态：服务端已有在途订单，下轮只 GET 等待，不重复 POST、不升级为永久阻断。
				certCfg.Metadata.LastIssueState = config.IssueStateProcessing
				certCfg.Metadata.ResubmitRequired = false
				certCfg.Metadata.LastCSRHash = ""
				certCfg.Metadata.CSRSubmittedAt = ""
				certCfg.Metadata.PendingCleanup = true
				cleanupPending = true
			} else {
				// 单条目或未分类业务拒绝已确定未接收：保留本次计数，清理本轮意图。
				certCfg.Metadata.LastIssueState = ""
				certCfg.Metadata.CSRSubmittedAt = ""
				certCfg.Metadata.LastCSRHash = ""
				certCfg.Metadata.ResubmitRequired = false
				certCfg.Metadata.PendingCleanup = true
				cleanupPending = true
			}
			if persist != nil {
				if persistErr := persist(); persistErr != nil {
					return nil, "", "", errors.Join(err,
						fmt.Errorf("保存 CSR 拒绝状态失败，已保留在途产物: %w", persistErr))
				}
			}
			if cleanupPending {
				if removeErr := d.Store.RemovePendingArtifacts(certCfg.CertName); removeErr != nil {
					return nil, "", "", errors.Join(err,
						fmt.Errorf("清理未被服务端接收的 pending 产物失败: %w", removeErr))
				}
				certCfg.Metadata.PendingCleanup = false
				if persist != nil {
					if persistErr := persist(); persistErr != nil {
						certCfg.Metadata.PendingCleanup = true
						return nil, "", "", errors.Join(err,
							fmt.Errorf("保存 pending 清理结果失败: %w", persistErr))
					}
				}
			}
			if apiErr.ErrorCode == api.ErrorCodeOrderInProgress {
				return nil, "", "订单已在途，等待签发", nil
			}
		}
		return nil, "", "", fmt.Errorf("提交 CSR 失败: %w", err)
	}

	newOrderID := csrResp.Data.OrderID
	certCfg.OrderID = newOrderID
	log.Printf("CSR 已提交，订单 ID: %d，状态: %s", newOrderID, csrResp.Data.Status)

	trackOrderStatus(certCfg, csrResp.Data.Status)
	// 已收到服务端确定响应，新的 CSR 已进入服务端状态机；此后只需按订单状态查询恢复。
	certCfg.Metadata.ResubmitRequired = false
	// 提交成功按契约只应返回 pending/processing。即使服务端异常返回 active，
	// 本轮也不得直接消费响应证书；统一进入 query-first，下一轮 GET 再验证 CSR 归属。
	certCfg.Metadata.LastIssueState = config.IssueStateProcessing
	if persist != nil {
		if err := persist(); err != nil {
			return nil, "", "", fmt.Errorf("持久化新订单 %d processing 状态失败: %w", newOrderID, err)
		}
	} else if csrResp.Data.CertData.File != nil && csrResp.Data.CertData.File.Path != "" {
		return nil, "", "", fmt.Errorf("新订单 %d 文件验证前缺少完整配置持久化函数", newOrderID)
	}
	reason, err := handleProcessingOrder(d, certCfg, &csrResp.Data.CertData, persist)
	return nil, "", reason, err
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
	if handled, reason, err := recoverPendingCleanup(d, certCfg, persistConfig...); handled {
		return nil, "", reason, err
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
		statusChanged := trackOrderStatus(certCfg, certData.Status)

		ownership, ownershipReason, ownershipErr := checkPendingOwnership(
			d, certCfg, certData, persistConfig...,
		)
		if ownershipErr != nil {
			return nil, "", "", ownershipErr
		}
		if ownership == pendingOwnershipUnknown {
			return nil, "", ownershipReason, nil
		}

		// 只有真正在途的签发（processing 或残留 pending 私钥）才跳过续签窗口直接部署。
		// 不能用 LastIssueState != ""：default 分支会把 unpaid/cancelled 等非预期状态写进来，
		// 那样订单一旦转 active 就会绕过续签窗口，把远未到期的证书重新部署一遍。
		waitingForIssue := certCfg.Metadata.LastIssueState == config.IssueStateProcessing ||
			certCfg.Metadata.LastIssueState == config.IssueStateActive ||
			d.Store.HasPendingPrivateKey(certCfg.CertName)
		switch classifyOrderStatus(certData.Status) {
		case orderClassWaiting, orderClassUnknown:
			// 在途、可自愈和未知状态都保守等待：只 GET，不重复提交、不增计数。
			certCfg.Metadata.LastIssueState = config.IssueStateProcessing
			// 证书已过期则停止，等待人工处理
			if certData.ExpiresAt != "" {
				if expiresAt, ok := parseCertExpiry(certData.ExpiresAt); ok {
					if time.Now().After(expiresAt) {
						return nil, "", "", fmt.Errorf("证书已过期，processing 状态下停止续签，需人工处理")
					}
				}
			}
			reason, handleErr := handleProcessingOrder(d, certCfg, certData, persistConfig...)
			if handleErr != nil {
				return nil, "", "", handleErr
			}
			return nil, "", reason, nil
		case orderClassActive:
			if ownership == pendingOwnershipMismatch ||
				ownership == pendingOwnershipOrphan ||
				(certCfg.Metadata.ResubmitRequired && ownership == pendingOwnershipNone) {
				// 当前 active 不是本机提交结果。先利用服务端或正式本地私钥部署；
				// 全部不可用时按 §3.2 门禁建立新的 CSR 尝试，不受普通续签窗口限制。
				if certData.PrivateKey != "" {
					if matched, keyErr := cert.VerifyKeyPair(certData.Certificate, certData.PrivateKey); keyErr == nil && matched {
						return certData, certData.PrivateKey, "", nil
					}
				}
				if _, localKey, ok := tryUseLocalKey(d, certData, certCfg); ok {
					return certData, localKey, "", nil
				}
				return submitNewCSR(d, client, certCfg, persistConfig...)
			}
			if waitingForIssue {
				certCfg.Metadata.LastIssueState = config.IssueStateActive
				privateKey, err := selectIssuedPrivateKey(d, certData, certCfg)
				if err != nil {
					if errors.Is(err, errPendingKeyMismatch) {
						log.Printf("当前 active 证书尚未匹配 pending 私钥，继续只查询等待服务端签发推进")
						return nil, "", "当前证书尚未匹配在途私钥，等待签发", nil
					}
					if errors.Is(err, errNoUsableIssuedKey) {
						if resetErr := resetIssueStateForResubmit(certCfg, err, persistConfig...); resetErr != nil {
							return nil, "", "", resetErr
						}
						log.Printf("当前 active 证书无可用配对私钥，已重置失效状态并重新提交 CSR")
						return submitNewCSR(d, client, certCfg, persistConfig...)
					}
					return nil, "", "", err
				}
				return certData, privateKey, "", nil
			}

			if len(certCfg.Metadata.FailedBindings) > 0 {
				privateKey, err := selectIssuedPrivateKey(d, certData, certCfg)
				if err != nil {
					return nil, "", "", fmt.Errorf("失败绑定重试无法取得已接纳证书私钥: %w", err)
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
		case orderClassTerminal, orderClassChainAnomaly:
			// 订单状态只写展示字段，不污染 last_issue_state；继续每日 GET 以允许服务端自愈。
			log.Printf("订单 %d 状态为 %q，停止本轮", certCfg.OrderID, certData.Status)
			if statusChanged {
				return nil, "", "", fmt.Errorf("订单状态: %s", certData.Status)
			}
			return nil, "", fmt.Sprintf("订单状态未变化: %s", certData.Status), nil
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

// checkDomainConflicts 检查端点冲突（同一绑定类型、规范主机和端口配置在多个证书中）。
func checkDomainConflicts(certs []config.CertConfig) map[iis.EndpointKey][]int {
	conflicts := make(map[iis.EndpointKey][]int)

	for i, cert := range certs {
		if !cert.Enabled {
			continue
		}
		seen := make(map[iis.EndpointKey]struct{}, len(cert.BindRules))
		for _, rule := range cert.BindRules {
			key, err := endpointKeyForRule(rule)
			if err != nil {
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			conflicts[key] = append(conflicts[key], i)
		}
	}

	// 过滤只有一个证书的域名
	for endpoint, indexes := range conflicts {
		if len(indexes) <= 1 {
			delete(conflicts, endpoint)
		}
	}

	return conflicts
}

// selectBestCertForDomainByIndexes 根据索引列表选择最佳证书（到期最晚的）
func selectBestCertForDomainByIndexes(indexes []int, allCerts []config.CertConfig) *config.CertConfig {
	bestIndex := selectBestCertIndexForDomainByIndexes(indexes, allCerts)
	if bestIndex < 0 {
		return nil
	}
	return &allCerts[bestIndex]
}

func selectBestCertIndexForDomainByIndexes(indexes []int, allCerts []config.CertConfig) int {
	bestIndex := -1
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
		if bestIndex < 0 {
			bestIndex = idx
			bestExpiry = candExpiry
			bestHasExpiry = candHasExpiry
			continue
		}
		best := &allCerts[bestIndex]

		if candHasExpiry && !bestHasExpiry {
			bestIndex = idx
			bestExpiry = candExpiry
			bestHasExpiry = true
			continue
		}
		if candHasExpiry && bestHasExpiry {
			if candExpiry.After(bestExpiry) || (candExpiry.Equal(bestExpiry) && cand.OrderID > best.OrderID) {
				bestIndex = idx
				bestExpiry = candExpiry
				bestHasExpiry = true
			}
			continue
		}
		if !candHasExpiry && !bestHasExpiry && cand.OrderID > best.OrderID {
			bestIndex = idx
		}
	}

	return bestIndex
}

func parseCertExpiry(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
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
	certCfg.Metadata.NoProgressSince = ""
	certCfg.Metadata.BlockReportCount = 0
	certCfg.Metadata.LastDeployBlockReason = ""
	certCfg.Metadata.FailedBindings = nil
	certCfg.Metadata.BindingRetryCount = 0
	certCfg.Metadata.PendingCleanup = false
	certCfg.Metadata.ResubmitRequired = false
}

// trackCertUnchanged 在自动部署全部成功后判断服务端是否真的换了证书。
// 序列号可用时只看序列号；仅在序列号缺失时才用到期时间未前移作降级判据。
func trackCertUnchanged(certCfg *config.CertConfig, prevSerial, prevExpiry string) string {
	newSerial := certCfg.Metadata.CertSerial
	newExpiry := certCfg.Metadata.CertExpiresAt
	same := false
	identity := ""
	switch {
	case prevSerial != "" && newSerial != "":
		same = prevSerial == newSerial
		identity = fmt.Sprintf("序列号 %s 未变", newSerial)
	case prevExpiry != "" && newExpiry != "":
		same = prevExpiry == newExpiry
		identity = fmt.Sprintf("到期时间 %s 未前移", newExpiry)
	}
	if !same {
		certCfg.Metadata.UnchangedCertRounds = 0
		return ""
	}
	certCfg.Metadata.UnchangedCertRounds++
	rounds := certCfg.Metadata.UnchangedCertRounds
	log.Printf("证书 %s 服务端返回的证书未更替（第 %d 轮，%s）", certCfg.Domain, rounds, identity)
	if rounds < config.CertUnchangedRounds {
		return ""
	}
	return fmt.Sprintf("服务端连续 %d 轮返回同一张证书（%s），证书未实际更新", rounds, identity)
}

func preserveUnchangedFailureState(meta *config.CertMetadata, before config.CertMetadata) {
	meta.DeployAttemptCount = before.DeployAttemptCount
	meta.DeployStartedAt = before.DeployStartedAt
	meta.LastDeployAt = before.LastDeployAt
	meta.CertExpiresAt = before.CertExpiresAt
	meta.CertSerial = before.CertSerial
	meta.NoProgressSince = before.NoProgressSince
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
			d.recordCallbackWarning(fmt.Sprintf("回调失败 (%s): %v", domain, err))
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
func CheckAndDeploy() RunReport {
	report := RunReport{}
	// 守护启动时检查数据目录 ACL：机器作用域加密的 Token 与私钥机密性依赖此 ACL，
	// 弱 ACL 仅告警不阻断（避免存量安装无法续签）
	for _, w := range util.EvaluateDataDirACL(config.GetDataDir()) {
		log.Printf("[安全告警] %s", w)
	}

	cfg, err := config.Load()
	if err != nil {
		report.Errors = append(report.Errors, fmt.Errorf("加载配置失败: %v", err))
		return report
	}

	if len(cfg.Certificates) == 0 {
		report.Errors = append(report.Errors, fmt.Errorf("没有配置任何证书，请先运行 sslctlw setup 或 GUI 添加配置"))
		return report
	}

	store := cert.NewOrderStore()
	deployer := DefaultDeployer(cfg, store)
	return AutoDeploy(cfg, deployer, RunOptions{ScatterDelay: true})
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

	// 1. 安装前发现并严格校验所有可执行端点。
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

	endpoints := make([]iis.EndpointKey, 0, len(matchedBindings))
	for _, binding := range matchedBindings {
		endpoint, parseErr := iis.ParseBindingEndpoint(binding)
		if parseErr != nil {
			msg := fmt.Sprintf("IIS 绑定端点无效: %v", parseErr)
			return []Result{{Domain: certCfg.Domain, Success: false, Message: msg, OrderID: certData.OrderID}},
				deployReport{report: true, success: false, message: msg}
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(certCfg.Metadata.FailedBindings) > 0 {
		filtered := endpoints[:0]
		for _, endpoint := range endpoints {
			if isPendingBindingTarget(endpoint, certCfg.Metadata.FailedBindings) {
				filtered = append(filtered, endpoint)
			}
		}
		endpoints = filtered
		if len(endpoints) == 0 {
			return nil, deployReport{}
		}
	}

	// 2. 确认存在可执行端点后才转换并安装证书。
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

	// 3. 更新匹配的绑定（循环内只收集结果，报告按订单聚合到循环后返回，回调由编排层单发）
	var outcome bindOutcome
	var successfulTargets, failedTargets []config.BindingRetryTarget
	for _, endpoint := range endpoints {
		domain := endpoint.Host

		log.Printf("更新绑定: %s:%d", endpoint.Host, endpoint.Port)

		var bindErr error
		if endpoint.IPBinding {
			bindErr = d.Binder.BindCertificateByIP(endpoint.Host, endpoint.Port, thumbprint)
		} else {
			bindErr = d.Binder.BindCertificate(endpoint.Host, endpoint.Port, thumbprint)
		}

		if bindErr != nil {
			log.Printf("绑定失败: %v", bindErr)
			results = append(results, Result{Domain: domain, Success: false, Message: bindErr.Error(), Thumbprint: thumbprint, OrderID: certData.OrderID})
			outcome.fail(fmt.Sprintf("%s: %v", domain, bindErr))
			failedTargets = append(failedTargets, retryTarget(endpoint))
		} else {
			log.Printf("绑定成功: %s", domain)
			results = append(results, Result{Domain: domain, Success: true, Message: "部署成功", Thumbprint: thumbprint, OrderID: certData.OrderID})
			outcome.ok()
			successfulTargets = append(successfulTargets, retryTarget(endpoint))
		}
	}

	rep := reportFromOutcome(outcome)
	rep.successfulTargets = successfulTargets
	rep.failedTargets = failedTargets
	return results, rep
}

// isIPBinding 判断是否是 IP 绑定（如 0.0.0.0:443，支持 IPv4 和 IPv6）
func isIPBinding(hostnamePort string) bool {
	host := iis.ParseHostFromBinding(hostnamePort)
	if host == "" {
		return false
	}
	return net.ParseIP(host) != nil
}

// cleanupOwnedValidationFiles 只按 metadata 中的所有权记录清理；不扫描目录。
// 不确定的站点、路径、文件类型或哈希只告警并保留记录。
func cleanupOwnedValidationFiles(
	d *Deployer,
	certCfg *config.CertConfig,
	persist func() error,
	supplemental *runSupplemental,
) {
	if len(certCfg.Metadata.ValidationFiles) == 0 {
		return
	}
	if supplemental == nil {
		supplemental = &runSupplemental{}
	}
	if d.ValidationRoots == nil || d.ValidationFiles == nil {
		supplemental.Warnings = append(supplemental.Warnings, "验证文件清理依赖未配置，已保留所有权记录")
		return
	}

	before := append([]config.ValidationFileRecord(nil), certCfg.Metadata.ValidationFiles...)
	remaining := make([]config.ValidationFileRecord, 0, len(before))
	changed := false
	domains := certCfg.Domains
	if len(domains) == 0 && certCfg.Domain != "" {
		domains = []string{certCfg.Domain}
	}
	for _, record := range before {
		roots, err := d.ValidationRoots.ResolveValidationWebRoots(domains, record.SiteName)
		if err != nil || len(roots) != 1 || !strings.EqualFold(roots[0].SiteName, record.SiteName) {
			supplemental.Warnings = append(supplemental.Warnings,
				fmt.Sprintf("验证文件站点 %s 无法安全解析，已保留记录", record.SiteName))
			remaining = append(remaining, record)
			continue
		}
		status, err := d.ValidationFiles.RemoveToken(roots[0], record)
		if err != nil {
			supplemental.Errors = append(supplemental.Errors,
				fmt.Errorf("清理站点 %s 验证文件失败: %w", record.SiteName, err))
			remaining = append(remaining, record)
			continue
		}
		switch status {
		case validationTokenRemoved, validationTokenMissing:
			changed = true
		case validationTokenOwnershipChanged:
			supplemental.Warnings = append(supplemental.Warnings,
				fmt.Sprintf("站点 %s 验证文件所有权已变化，已保留文件和记录", record.SiteName))
			remaining = append(remaining, record)
		default:
			supplemental.Warnings = append(supplemental.Warnings,
				fmt.Sprintf("站点 %s 验证文件状态未知，已保留记录", record.SiteName))
			remaining = append(remaining, record)
		}
	}
	if !changed {
		return
	}
	certCfg.Metadata.ValidationFiles = remaining
	if persist == nil {
		certCfg.Metadata.ValidationFiles = before
		supplemental.Errors = append(supplemental.Errors, errors.New("清理验证文件后缺少完整配置持久化函数"))
		return
	}
	if err := persist(); err != nil {
		certCfg.Metadata.ValidationFiles = before
		supplemental.Errors = append(supplemental.Errors, fmt.Errorf("保存验证文件清理结果失败: %w", err))
	}
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
