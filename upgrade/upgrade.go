package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Upgrader 升级器，聚合所有依赖
type Upgrader struct {
	Checker    ReleaseChecker
	Downloader FileDownloader
	Verifier   SignatureVerifier
	Updater    SelfUpdater
	Config     *Config

	mu          sync.RWMutex
	progress    UpdateProgress
	onProgress  func(UpdateProgress)
	latestInfo  *ReleaseInfo
	currentPlan *UpdatePlan
}

// NewUpgrader 创建升级器
func NewUpgrader(cfg *Config) *Upgrader {
	return &Upgrader{
		Checker:    NewGitHubChecker(cfg.ReleaseURL),
		Downloader: NewHTTPDownloader(),
		Verifier:   NewAuthenticodeVerifier(),
		Updater:    NewWindowsUpdater(),
		Config:     cfg,
		progress:   UpdateProgress{Status: StatusIdle},
	}
}

// SetOnProgress 设置进度回调
func (u *Upgrader) SetOnProgress(fn func(UpdateProgress)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.onProgress = fn
}

// GetProgress 获取当前进度
func (u *Upgrader) GetProgress() UpdateProgress {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.progress
}

// GetLatestInfo 获取最新版本信息
func (u *Upgrader) GetLatestInfo() *ReleaseInfo {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.latestInfo
}

// ErrNeedChainUpgrade 需要链式升级的错误
type ErrNeedChainUpgrade struct {
	CurrentVersion string
	TargetVersion  string
	MinVersion     string
}

func (e *ErrNeedChainUpgrade) Error() string {
	return fmt.Sprintf("当前版本 %s 低于最低要求 %s，需要链式升级到 %s", e.CurrentVersion, e.MinVersion, e.TargetVersion)
}

// CheckForUpdate 检查更新
// 如果需要链式升级，返回 ErrNeedChainUpgrade 错误
func (u *Upgrader) CheckForUpdate(ctx context.Context, currentVersion string) (*ReleaseInfo, error) {
	u.updateProgress(StatusChecking, "正在检查更新...", 0, 0, 0)

	info, err := u.Checker.CheckUpdate(ctx, string(u.Config.Channel), currentVersion)
	if err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("检查更新失败: %v", err), 0, 0, 0)
		return nil, err
	}

	u.mu.Lock()
	u.latestInfo = info
	u.mu.Unlock()

	if info == nil {
		u.updateProgress(StatusIdle, "已是最新版本", 0, 0, 0)
		return nil, nil
	}

	// 检查是否被用户跳过
	if u.Config.SkippedVersion == info.Version {
		u.updateProgress(StatusIdle, "用户已跳过此版本", 0, 0, 0)
		return nil, nil
	}

	// 检查最低版本要求（不可跳过版本）
	if info.MinVersion != "" && CompareVersion(currentVersion, info.MinVersion) < 0 {
		u.updateProgress(StatusAvailable,
			fmt.Sprintf("发现新版本 %s（需要链式升级）", info.Version), 0, 0, 0)
		return info, &ErrNeedChainUpgrade{
			CurrentVersion: currentVersion,
			TargetVersion:  info.Version,
			MinVersion:     info.MinVersion,
		}
	}

	u.mu.Lock()
	u.progress.NewVersion = info.Version
	u.mu.Unlock()
	u.updateProgress(StatusAvailable, fmt.Sprintf("发现新版本 %s", info.Version), 0, 0, 0)

	return info, nil
}

// GetUpgradePath 获取升级路径
func (u *Upgrader) GetUpgradePath(ctx context.Context, currentVersion, targetVersion string) (*UpgradePath, error) {
	u.updateProgress(StatusChecking, "正在获取升级路径...", 0, 0, 0)

	path, err := u.Checker.GetUpgradePath(ctx, currentVersion, targetVersion)
	if err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("获取升级路径失败: %v", err), 0, 0, 0)
		return nil, err
	}

	if path == nil || len(path.Steps) == 0 {
		u.updateProgress(StatusFailed, "服务端未返回升级路径", 0, 0, 0)
		return nil, fmt.Errorf("服务端未返回升级路径，请访问官网手动下载")
	}

	u.updateProgress(StatusAvailable, fmt.Sprintf("需要经过 %d 个版本升级", len(path.Steps)), 0, 0, 0)
	return path, nil
}

// ChainUpgrade 执行链式升级
// confirmFn: 每个步骤前的确认回调，返回 false 取消升级
// 返回最终版本号
func (u *Upgrader) ChainUpgrade(ctx context.Context, path *UpgradePath, confirmFn func(step UpgradeStep, index, total int) bool) (string, error) {
	if path == nil || len(path.Steps) == 0 {
		return "", fmt.Errorf("升级路径为空")
	}

	total := len(path.Steps)
	var lastVersion string

	for i, step := range path.Steps {
		// 确认回调
		if confirmFn != nil && !confirmFn(step, i+1, total) {
			u.updateProgress(StatusIdle, "用户取消升级", 0, 0, 0)
			return lastVersion, fmt.Errorf("用户取消升级")
		}

		u.updateProgress(StatusDownloading,
			fmt.Sprintf("正在升级到 %s (%d/%d)...", step.Version, i+1, total), 0, 0, 0)

		// 下载
		tempPath, err := u.downloadStep(ctx, step)
		if err != nil {
			return lastVersion, fmt.Errorf("下载版本 %s 失败: %w", step.Version, err)
		}

		// 验证
		u.updateProgress(StatusVerifying,
			fmt.Sprintf("正在验证 %s (%d/%d)...", step.Version, i+1, total), 0, 0, 0)

		fingerprints := u.Config.Fingerprints
		if len(step.Fingerprints) > 0 && len(fingerprints) == 0 {
			fingerprints = step.Fingerprints
		}

		verifyResult, err := u.Verifier.Verify(tempPath, fingerprints, u.Config.GetFallbackConfig())
		if err != nil {
			os.Remove(tempPath)
			return lastVersion, fmt.Errorf("验证版本 %s 失败: %w", step.Version, err)
		}

		if !verifyResult.Valid {
			os.Remove(tempPath)
			return lastVersion, fmt.Errorf("版本 %s 签名无效: %s", step.Version, verifyResult.Message)
		}

		// 如果需要用户确认新证书，在链式升级中自动拒绝（安全考虑）
		if verifyResult.NeedsConfirm {
			os.Remove(tempPath)
			return lastVersion, fmt.Errorf("版本 %s 使用了新证书，链式升级不支持自动确认，请手动升级", step.Version)
		}

		// 应用
		u.updateProgress(StatusApplying,
			fmt.Sprintf("正在应用 %s (%d/%d)...", step.Version, i+1, total), 0, 0, 0)

		if err := u.ApplyUpdate(ctx, tempPath, step.Version); err != nil {
			return lastVersion, fmt.Errorf("应用版本 %s 失败: %w", step.Version, err)
		}

		lastVersion = step.Version

		// 如果不是最后一步，需要重启后继续
		if i < total-1 {
			u.updateProgress(StatusSuccess,
				fmt.Sprintf("已升级到 %s，重启后将继续升级到下一版本", step.Version), 0, 0, 0)
			// 链式升级每一步都需要重启，返回当前版本让调用方处理
			return lastVersion, nil
		}
	}

	u.updateProgress(StatusSuccess, fmt.Sprintf("链式升级完成，已升级到 %s", lastVersion), 0, 0, 0)
	return lastVersion, nil
}

// downloadStep 下载单个升级步骤
func (u *Upgrader) downloadStep(ctx context.Context, step UpgradeStep) (string, error) {
	tempDir := filepath.Join(os.TempDir(), "sslctlw-upgrade")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return "", fmt.Errorf("创建临时目录失败: %w", err)
	}

	tempPath := filepath.Join(tempDir, fmt.Sprintf("sslctlw-%s.exe", step.Version))

	err := u.Downloader.Download(ctx, step.DownloadURL, tempPath, func(downloaded, total int64, speed float64) {
		percent := float64(0)
		if total > 0 {
			percent = float64(downloaded) / float64(total) * 100
		}
		u.updateProgress(StatusDownloading,
			fmt.Sprintf("正在下载 %s... %.1f%%", step.Version, percent),
			downloaded, total, speed)
	})

	if err != nil {
		return "", err
	}

	return tempPath, nil
}

// DownloadAndVerify 下载并验证更新
func (u *Upgrader) DownloadAndVerify(ctx context.Context, info *ReleaseInfo) (string, *VerifyResult, error) {
	// 创建临时目录
	tempDir := filepath.Join(os.TempDir(), "sslctlw-upgrade")
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("创建临时目录失败: %v", err), 0, 0, 0)
		return "", nil, fmt.Errorf("创建临时目录失败: %w", err)
	}

	tempPath := filepath.Join(tempDir, fmt.Sprintf("sslctlw-%s.exe", info.Version))

	// 下载文件
	u.updateProgress(StatusDownloading, "正在下载更新...", 0, info.FileSize, 0)

	err := u.Downloader.Download(ctx, info.DownloadURL, tempPath, func(downloaded, total int64, speed float64) {
		percent := float64(0)
		if total > 0 {
			percent = float64(downloaded) / float64(total) * 100
		}
		u.updateProgress(StatusDownloading,
			fmt.Sprintf("正在下载... %.1f%%", percent),
			downloaded, total, speed)
	})

	if err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("下载失败: %v", err), 0, 0, 0)
		return "", nil, err
	}

	// 验证签名
	u.updateProgress(StatusVerifying, "正在验证签名...", 0, 0, 0)

	// 合并预埋指纹和服务端下发的指纹
	fingerprints := u.Config.Fingerprints
	if len(info.Fingerprints) > 0 {
		// 服务端下发的指纹必须与预埋指纹有交集（如果预埋了的话）
		// 这里简单处理：如果预埋了指纹，优先使用预埋的
		if len(fingerprints) == 0 {
			fingerprints = info.Fingerprints
		}
	}

	verifyResult, err := u.Verifier.Verify(tempPath, fingerprints, u.Config.GetFallbackConfig())
	if err != nil {
		os.Remove(tempPath)
		u.updateProgress(StatusFailed, fmt.Sprintf("验证失败: %v", err), 0, 0, 0)
		return "", nil, err
	}

	if !verifyResult.Valid {
		os.Remove(tempPath)
		u.updateProgress(StatusFailed, fmt.Sprintf("签名无效: %s", verifyResult.Message), 0, 0, 0)
		return "", verifyResult, fmt.Errorf("签名验证失败: %s", verifyResult.Message)
	}

	u.mu.Lock()
	u.progress.CanRollback = true
	u.mu.Unlock()

	if verifyResult.NeedsConfirm {
		u.updateProgress(StatusReady, "需要确认新证书", 0, 0, 0)
	} else {
		u.updateProgress(StatusReady, "更新已准备就绪", 0, 0, 0)
	}

	return tempPath, verifyResult, nil
}

// ApplyUpdate 应用更新
func (u *Upgrader) ApplyUpdate(ctx context.Context, newExePath string, version string) error {
	u.updateProgress(StatusApplying, "正在应用更新...", 0, 0, 0)

	plan, err := u.Updater.PrepareUpdate(ctx, newExePath)
	if err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("准备更新失败: %v", err), 0, 0, 0)
		return err
	}

	plan.Version = version

	u.mu.Lock()
	u.currentPlan = plan
	u.mu.Unlock()

	if err := u.Updater.ApplyUpdate(plan); err != nil {
		u.updateProgress(StatusFailed, fmt.Sprintf("应用更新失败: %v", err), 0, 0, 0)
		// 尝试回滚
		if rollbackErr := u.Updater.Rollback(plan); rollbackErr != nil {
			return fmt.Errorf("应用更新失败: %w，回滚也失败: %v", err, rollbackErr)
		}
		return err
	}

	u.updateProgress(StatusSuccess, "更新成功，请重启程序", 0, 0, 0)
	return nil
}

// Rollback 回滚更新
func (u *Upgrader) Rollback() error {
	u.mu.RLock()
	plan := u.currentPlan
	u.mu.RUnlock()

	if plan == nil {
		// 尝试从最新备份回滚
		backupPath, err := GetLatestBackup()
		if err != nil {
			return fmt.Errorf("没有可回滚的版本: %w", err)
		}

		exe, err := os.Executable()
		if err != nil {
			return err
		}

		plan = &UpdatePlan{
			CurrentExePath: exe,
			BackupExePath:  backupPath,
		}
	}

	return u.Updater.Rollback(plan)
}

// SkipVersion 跳过当前版本
func (u *Upgrader) SkipVersion(version string) {
	u.Config.SkippedVersion = version
}

// ShouldCheckUpdate 检查是否应该检查更新
func (u *Upgrader) ShouldCheckUpdate() bool {
	if !u.Config.Enabled {
		return false
	}

	if u.Config.LastCheck == "" {
		return true
	}

	lastCheck, err := time.Parse(time.RFC3339, u.Config.LastCheck)
	if err != nil {
		return true
	}

	interval := time.Duration(u.Config.CheckInterval) * time.Hour
	return time.Since(lastCheck) >= interval
}

// UpdateLastCheck 更新上次检查时间
func (u *Upgrader) UpdateLastCheck() {
	u.Config.LastCheck = time.Now().Format(time.RFC3339)
}

// updateProgress 更新进度
func (u *Upgrader) updateProgress(status UpdateStatus, message string, downloaded, total int64, speed float64) {
	u.mu.Lock()
	u.progress.Status = status
	u.progress.Message = message
	u.progress.Downloaded = downloaded
	u.progress.Total = total
	u.progress.Speed = speed
	if total > 0 {
		u.progress.Percent = float64(downloaded) / float64(total) * 100
	} else {
		u.progress.Percent = 0
	}
	onProgress := u.onProgress
	progress := u.progress
	u.mu.Unlock()

	if onProgress != nil {
		onProgress(progress)
	}
}

// FormatSpeed 格式化下载速度
func FormatSpeed(bytesPerSec float64) string {
	if bytesPerSec < 1024 {
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
	if bytesPerSec < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/1024)
	}
	return fmt.Sprintf("%.1f MB/s", bytesPerSec/1024/1024)
}

// FormatSize 格式化文件大小
func FormatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/1024/1024)
}
