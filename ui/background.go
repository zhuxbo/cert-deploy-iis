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
}

// NewBackgroundTask 创建后台任务
func NewBackgroundTask() *BackgroundTask {
	return &BackgroundTask{
		status:  TaskStatusIdle,
		message: "未启动",
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
	return t.results
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

	t.updateStatus(TaskStatusRunning, "正在检测证书...")

	cfg, err := config.Load()
	if err != nil {
		t.updateStatus(TaskStatusFailed, fmt.Sprintf("加载配置失败: %v", err))
		return
	}

	if len(cfg.Certificates) == 0 {
		t.updateStatus(TaskStatusIdle, "没有配置自动部署证书")
		return
	}

	t.updateStatus(TaskStatusRunning, fmt.Sprintf("正在检查 %d 个证书...", len(cfg.Certificates)))

	store := cert.NewOrderStore()
	results := deploy.AutoDeploy(cfg, deploy.DefaultDeployer(cfg, store), false)

	t.mu.Lock()
	t.lastRun = time.Now()
	t.results = results
	t.mu.Unlock()

	// 统计结果
	successCount := 0
	failCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		} else {
			failCount++
		}
	}

	if len(results) == 0 {
		t.updateStatus(TaskStatusSuccess, fmt.Sprintf("检测完成，无需更新 (上次: %s)", t.lastRun.Format("15:04:05")))
	} else if failCount == 0 {
		t.updateStatus(TaskStatusSuccess, fmt.Sprintf("部署成功 %d 个 (上次: %s)", successCount, t.lastRun.Format("15:04:05")))
	} else {
		t.updateStatus(TaskStatusFailed, fmt.Sprintf("成功 %d, 失败 %d (上次: %s)", successCount, failCount, t.lastRun.Format("15:04:05")))
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
