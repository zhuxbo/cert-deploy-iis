package ui

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/deploy"
	"sslctlw/iis"
	"sslctlw/util"
)

// TaskStatus 任务状态
type TaskStatus int

const (
	TaskStatusIdle TaskStatus = iota
	TaskStatusRunning
	TaskStatusSuccess
	TaskStatusFailed
)

// BackgroundTask 后台任务（仅支持手动触发，不做定时轮询）
type BackgroundTask struct {
	mu       sync.Mutex
	status   TaskStatus
	message  string
	lastRun  time.Time
	checkMu  sync.Mutex
	checking bool
	onUpdate func()
	results  []deploy.Result
	report   deploy.RunReport

	loadConfig func() (*config.Config, error)
	runDeploy  func(*config.Config) deploy.RunReport
	now        func() time.Time
}

// NewBackgroundTask 创建后台任务
func NewBackgroundTask() *BackgroundTask {
	return newBackgroundTask(
		config.Load,
		func(cfg *config.Config) deploy.RunReport {
			store := cert.NewOrderStore()
			return deploy.AutoDeploy(cfg, deploy.DefaultDeployer(cfg, store), deploy.RunOptions{})
		},
		time.Now,
	)
}

func newBackgroundTask(
	loadConfig func() (*config.Config, error),
	runDeploy func(*config.Config) deploy.RunReport,
	now func() time.Time,
) *BackgroundTask {
	return &BackgroundTask{
		status:     TaskStatusIdle,
		message:    "未启动",
		loadConfig: loadConfig,
		runDeploy:  runDeploy,
		now:        now,
	}
}

// SetOnUpdate 设置更新回调
func (t *BackgroundTask) SetOnUpdate(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onUpdate = fn
}

// GetStatus 获取状态信息
func (t *BackgroundTask) GetStatus() (TaskStatus, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.message
}

// GetLastRun 获取上次运行时间
func (t *BackgroundTask) GetLastRun() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastRun
}

// GetResults 获取最近的结果
func (t *BackgroundTask) GetResults() []deploy.Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]deploy.Result(nil), t.results...)
}

// GetReport 获取最近一次完整运行报告。
func (t *BackgroundTask) GetReport() deploy.RunReport {
	t.mu.Lock()
	defer t.mu.Unlock()
	return cloneRunReport(t.report)
}

// RunOnce 立即执行一次检测（异步）
func (t *BackgroundTask) RunOnce() {
	go t.doCheck()
}

// RunOnceSync 同步执行一次检测（阻塞直到完成）
func (t *BackgroundTask) RunOnceSync() {
	t.doCheck()
}

// doCheck 执行检查
func (t *BackgroundTask) doCheck() {
	if !t.tryStartCheck() {
		return
	}
	defer t.endCheck()

	// 防止底层调用链中的 panic 导致整个程序崩溃
	defer func() {
		if r := recover(); r != nil {
			t.updateStatus(TaskStatusFailed, fmt.Sprintf("内部错误: %v", r))
		}
	}()

	t.mu.Lock()
	t.results = nil
	t.report = deploy.RunReport{}
	t.mu.Unlock()

	t.updateStatus(TaskStatusRunning, "正在检测证书...")

	cfg, err := t.loadConfig()
	if err != nil {
		t.updateStatus(TaskStatusFailed, fmt.Sprintf("加载配置失败: %v", err))
		return
	}

	if len(cfg.Certificates) == 0 {
		t.updateStatus(TaskStatusIdle, "没有配置自动部署证书")
		return
	}

	t.updateStatus(TaskStatusRunning, fmt.Sprintf("正在检查 %d 个证书...", len(cfg.Certificates)))

	report := t.runDeploy(cfg)

	t.mu.Lock()
	t.lastRun = t.now()
	t.results = append([]deploy.Result(nil), report.Results...)
	t.report = cloneRunReport(report)
	lastRun := t.lastRun
	t.mu.Unlock()

	status, message := backgroundStatusFromReport(report, lastRun)
	t.updateStatus(status, message)
}

func backgroundStatusFromReport(report deploy.RunReport, lastRun time.Time) (TaskStatus, string) {
	suffix := fmt.Sprintf(" (上次: %s)", lastRun.Format("15:04:05"))
	if err := report.Err(); err != nil {
		return TaskStatusFailed, fmt.Sprintf("检测失败: %v%s", err, suffix)
	}
	if len(report.Attention) > 0 {
		return TaskStatusFailed, fmt.Sprintf("需人工处理 %d 个证书%s", len(report.Attention), suffix)
	}
	if report.AlreadyRunning {
		return TaskStatusRunning, "已有部署正在运行"
	}
	if len(report.Warnings) > 0 && len(report.Results) == 0 {
		return TaskStatusSuccess, fmt.Sprintf("检测完成，警告 %d 条%s", len(report.Warnings), suffix)
	}

	successCount := 0
	for _, result := range report.Results {
		if result.Success {
			successCount++
		}
	}
	if len(report.Results) == 0 {
		return TaskStatusSuccess, "检测完成，无需更新" + suffix
	}
	if len(report.Warnings) > 0 {
		return TaskStatusSuccess, fmt.Sprintf("部署成功 %d 个，警告 %d 条%s", successCount, len(report.Warnings), suffix)
	}
	return TaskStatusSuccess, fmt.Sprintf("部署成功 %d 个%s", successCount, suffix)
}

func cloneRunReport(report deploy.RunReport) deploy.RunReport {
	report.Results = append([]deploy.Result(nil), report.Results...)
	report.Errors = append([]error(nil), report.Errors...)
	report.Warnings = append([]string(nil), report.Warnings...)
	report.Attention = append([]deploy.CertAttention(nil), report.Attention...)
	return report
}

func queryTaskHealthPresentation(
	enabled bool,
	taskName string,
	now time.Time,
	query func(string) (*util.TaskHealth, error),
) (bool, string) {
	if !enabled {
		return false, "自动部署已停止"
	}
	health, err := query(taskName)
	if err != nil {
		return false, fmt.Sprintf("任务计划不健康: %v", err)
	}
	warnings := util.EvaluateTaskHealth(health, now)
	if len(warnings) > 0 {
		return false, "任务计划不健康: " + strings.Join(warnings, "；")
	}
	return true, "任务计划健康"
}

func observeWorker(
	done <-chan struct{},
	timeout <-chan time.Time,
	cancelled <-chan struct{},
	onTimeout func(),
) bool {
	select {
	case <-done:
		return true
	case <-timeout:
		if onTimeout != nil {
			onTimeout()
		}
	case <-cancelled:
		return false
	}

	select {
	case <-done:
		return true
	case <-cancelled:
		return false
	}
}

// updateStatus 更新状态（带防抖动：相同状态和消息时跳过更新）
func (t *BackgroundTask) updateStatus(status TaskStatus, message string) {
	t.mu.Lock()
	if t.status == status && t.message == message {
		t.mu.Unlock()
		return
	}
	t.status = status
	t.message = message
	onUpdate := t.onUpdate
	t.mu.Unlock()

	if onUpdate != nil {
		onUpdate()
	}
}

func (t *BackgroundTask) tryStartCheck() bool {
	t.checkMu.Lock()
	defer t.checkMu.Unlock()
	if t.checking {
		return false
	}
	t.checking = true
	return true
}

func (t *BackgroundTask) endCheck() {
	t.checkMu.Lock()
	t.checking = false
	t.checkMu.Unlock()
}

// CheckCertExpiry 检查证书过期情况（不自动部署，仅检查）
func CheckCertExpiry(cfg *config.Config) []CertExpiryInfo {
	results := make([]CertExpiryInfo, 0)

	for _, certCfg := range cfg.Certificates {
		if !certCfg.Enabled {
			continue
		}

		token, tokenErr := certCfg.API.GetToken()
		if tokenErr != nil {
			results = append(results, CertExpiryInfo{
				Domain: certCfg.Domain,
				Error:  tokenErr.Error(),
			})
			continue
		}
		if token == "" || certCfg.API.URL == "" {
			results = append(results, CertExpiryInfo{
				Domain: certCfg.Domain,
				Error:  "未配置 API",
			})
			continue
		}

		client := api.NewClient(certCfg.API.URL, token)
		ctx, cancel := context.WithTimeout(context.Background(), api.APIQueryTimeout)
		certData, err := client.GetCertByOrderID(ctx, certCfg.OrderID)
		cancel()
		if err != nil {
			results = append(results, CertExpiryInfo{
				Domain: certCfg.Domain,
				Error:  err.Error(),
			})
			continue
		}

		expiresAt, _ := time.Parse("2006-01-02", certData.ExpiresAt)
		daysLeft := int(time.Until(expiresAt).Hours() / 24)

		results = append(results, CertExpiryInfo{
			Domain:    certCfg.Domain,
			CertName:  certData.Domain(),
			ExpiresAt: expiresAt,
			DaysLeft:  daysLeft,
			Status:    certData.Status,
		})
	}

	return results
}

// CertExpiryInfo 证书过期信息
type CertExpiryInfo struct {
	Domain    string
	CertName  string
	ExpiresAt time.Time
	DaysLeft  int
	Status    string
	Error     string
}

// CheckLocalCerts 检查本地证书过期情况
func CheckLocalCerts() []LocalCertInfo {
	results := make([]LocalCertInfo, 0)

	certs, err := cert.ListCertificates()
	if err != nil {
		return results
	}

	sslBindings, sslErr := iis.ListSSLBindings()
	if sslErr != nil {
		log.Printf("警告: 加载 SSL 绑定列表失败: %v", sslErr)
	}
	boundCerts := make(map[string]bool)
	for _, b := range sslBindings {
		boundCerts[strings.ToUpper(b.CertHash)] = true
	}

	for _, c := range certs {
		if !c.HasPrivKey {
			continue
		}

		daysLeft := int(time.Until(c.NotAfter).Hours() / 24)
		info := LocalCertInfo{
			Thumbprint: c.Thumbprint,
			Subject:    c.Subject,
			ExpiresAt:  c.NotAfter,
			DaysLeft:   daysLeft,
			IsBound:    boundCerts[c.Thumbprint],
		}

		if daysLeft < 0 {
			info.Status = "已过期"
		} else if daysLeft < 7 {
			info.Status = "即将过期"
		} else if daysLeft < 30 {
			info.Status = "注意"
		} else {
			info.Status = "正常"
		}

		results = append(results, info)
	}

	return results
}

// LocalCertInfo 本地证书信息
type LocalCertInfo struct {
	Thumbprint string
	Subject    string
	ExpiresAt  time.Time
	DaysLeft   int
	Status     string
	IsBound    bool
}
