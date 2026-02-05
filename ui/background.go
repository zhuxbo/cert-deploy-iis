package ui

import (
	"context"
	"fmt"
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

// BackgroundTask 后台任务
type BackgroundTask struct {
	mu           sync.Mutex
	status       TaskStatus
	message      string
	lastRun      time.Time
	nextRun      time.Time
	interval     time.Duration
	running      bool
	stopChan     chan struct{}
	resetChan    chan struct{} // 通知 runLoop 重建 ticker
	onUpdate     func()
	results      []deploy.Result
	checkEnabled bool
}

// NewBackgroundTask 创建后台任务
func NewBackgroundTask() *BackgroundTask {
	return &BackgroundTask{
		status:       TaskStatusIdle,
		message:      "未启动",
		interval:     1 * time.Hour, // 默认每小时检查一次
		stopChan:     make(chan struct{}),
		resetChan:    make(chan struct{}, 1),
		checkEnabled: false,
	}
}

// SetInterval 设置检查间隔
func (t *BackgroundTask) SetInterval(d time.Duration) {
	t.mu.Lock()
	t.interval = d
	running := t.running
	if running {
		t.nextRun = time.Now().Add(d)
	}
	t.mu.Unlock()
	// 通知 runLoop 重建 ticker
	if running {
		select {
		case t.resetChan <- struct{}{}:
		default:
		}
	}
}

// SetOnUpdate 设置更新回调
func (t *BackgroundTask) SetOnUpdate(fn func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onUpdate = fn
}

// Start 启动定时任务
func (t *BackgroundTask) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.checkEnabled = true
	t.stopChan = make(chan struct{})
	t.resetChan = make(chan struct{}, 1)
	t.mu.Unlock()

	go t.runLoop()
}

// Stop 停止定时任务
func (t *BackgroundTask) Stop() {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	t.running = false
	t.checkEnabled = false
	close(t.stopChan)
	t.mu.Unlock()

	t.updateStatus(TaskStatusIdle, "已停止")
}

// IsRunning 是否正在运行
func (t *BackgroundTask) IsRunning() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// IsCheckEnabled 是否启用定时检测
func (t *BackgroundTask) IsCheckEnabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.checkEnabled
}

// GetStatus 获取状态信息
func (t *BackgroundTask) GetStatus() (TaskStatus, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.message
}

// GetNextRun 获取下次运行时间
func (t *BackgroundTask) GetNextRun() time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nextRun
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

// runLoop 主循环
func (t *BackgroundTask) runLoop() {
	t.updateStatus(TaskStatusIdle, "定时检测已启动")

	// 启动时立即检查一次
	t.doCheck()

	t.mu.Lock()
	interval := t.interval
	t.nextRun = time.Now().Add(interval)
	t.mu.Unlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopChan:
			return
		case <-t.resetChan:
			// 间隔已变更，重建 ticker
			ticker.Stop()
			t.mu.Lock()
			interval = t.interval
			t.mu.Unlock()
			ticker = time.NewTicker(interval)
		case <-ticker.C:
			t.doCheck()
			t.mu.Lock()
			t.nextRun = time.Now().Add(t.interval)
			t.mu.Unlock()
		}
	}
}

// doCheck 执行检查
func (t *BackgroundTask) doCheck() {
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
	results := deploy.AutoDeploy(cfg, deploy.DefaultDeployer(cfg, store))

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
	// 如果状态和消息都没变化，跳过更新
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

// CheckCertExpiry 检查证书过期情况（不自动部署，仅检查）
func CheckCertExpiry(cfg *config.Config) []CertExpiryInfo {
	results := make([]CertExpiryInfo, 0)

	token := cfg.GetToken()
	if token == "" {
		return results
	}

	client := api.NewClient(cfg.APIBaseURL, token)

	for _, certCfg := range cfg.Certificates {
		if !certCfg.Enabled {
			continue
		}

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
			CertName:  certData.Domain,
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

	sslBindings, _ := iis.ListSSLBindings()
	boundCerts := make(map[string]bool)
	for _, b := range sslBindings {
		boundCerts[b.CertHash] = true
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
