package upgrade

import (
	"testing"
	"time"
)

// TestFormatSpeed 测试下载速度格式化
func TestFormatSpeed(t *testing.T) {
	tests := []struct {
		name        string
		bytesPerSec float64
		expected    string
	}{
		{"零速度", 0, "0 B/s"},
		{"字节级别", 500, "500 B/s"},
		{"刚好1KB", 1024, "1.0 KB/s"},
		{"KB级别", 5120, "5.0 KB/s"},
		{"刚好1MB", 1024 * 1024, "1.0 MB/s"},
		{"MB级别", 5 * 1024 * 1024, "5.0 MB/s"},
		{"高速下载", 10.5 * 1024 * 1024, "10.5 MB/s"},
		{"小数KB", 1536, "1.5 KB/s"},
		{"小数MB", 1.5 * 1024 * 1024, "1.5 MB/s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSpeed(tt.bytesPerSec)
			if result != tt.expected {
				t.Errorf("FormatSpeed(%f) = %q, want %q", tt.bytesPerSec, result, tt.expected)
			}
		})
	}
}

// TestFormatSize 测试文件大小格式化
func TestFormatSize(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"零字节", 0, "0 B"},
		{"字节级别", 500, "500 B"},
		{"刚好1KB", 1024, "1.0 KB"},
		{"KB级别", 5120, "5.0 KB"},
		{"刚好1MB", 1024 * 1024, "1.0 MB"},
		{"MB级别", 5 * 1024 * 1024, "5.0 MB"},
		{"大文件", 10 * 1024 * 1024, "10.0 MB"},
		{"小数KB", 1536, "1.5 KB"},
		{"小数MB", int64(1.5 * 1024 * 1024), "1.5 MB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormatSize(tt.bytes)
			if result != tt.expected {
				t.Errorf("FormatSize(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

// TestUpdateStatusString 测试更新状态的字符串表示
func TestUpdateStatusString(t *testing.T) {
	tests := []struct {
		status   UpdateStatus
		expected string
	}{
		{StatusIdle, "空闲"},
		{StatusChecking, "检查中"},
		{StatusAvailable, "有可用更新"},
		{StatusDownloading, "下载中"},
		{StatusVerifying, "验证中"},
		{StatusReady, "准备就绪"},
		{StatusApplying, "应用中"},
		{StatusSuccess, "成功"},
		{StatusFailed, "失败"},
		{UpdateStatus(100), "未知"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.status.String()
			if result != tt.expected {
				t.Errorf("UpdateStatus(%d).String() = %q, want %q", tt.status, result, tt.expected)
			}
		})
	}
}

// TestShouldCheckUpdate 测试是否应该检查更新
func TestShouldCheckUpdate(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected bool
	}{
		{
			"禁用升级",
			&Config{Enabled: false},
			false,
		},
		{
			"首次检查（空LastCheck）",
			&Config{Enabled: true, LastCheck: ""},
			true,
		},
		{
			"无效的LastCheck格式",
			&Config{Enabled: true, LastCheck: "invalid-date"},
			true,
		},
		{
			"刚检查过（1小时前）",
			&Config{
				Enabled:       true,
				CheckInterval: 24,
				LastCheck:     time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
			},
			false,
		},
		{
			"超过检查间隔（25小时前）",
			&Config{
				Enabled:       true,
				CheckInterval: 24,
				LastCheck:     time.Now().Add(-25 * time.Hour).Format(time.RFC3339),
			},
			true,
		},
		{
			"刚好到检查间隔",
			&Config{
				Enabled:       true,
				CheckInterval: 24,
				LastCheck:     time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &Upgrader{Config: tt.config}
			result := u.ShouldCheckUpdate()
			if result != tt.expected {
				t.Errorf("ShouldCheckUpdate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestDefaultConfig 测试默认配置
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.Enabled {
		t.Error("默认配置应该启用升级检查")
	}

	if cfg.Channel != ChannelStable {
		t.Errorf("默认通道 = %q, want %q", cfg.Channel, ChannelStable)
	}

	if cfg.CheckInterval != 24 {
		t.Errorf("默认检查间隔 = %d, want 24", cfg.CheckInterval)
	}

	if cfg.TrustedCountry != "CN" {
		t.Errorf("默认可信国家 = %q, want 'CN'", cfg.TrustedCountry)
	}
}

// TestGetFallbackConfig 测试获取回退验证配置
func TestGetFallbackConfig(t *testing.T) {
	cfg := &Config{
		TrustedOrg:     "TestOrg",
		TrustedCountry: "US",
		TrustedCAs:     []string{"CA1", "CA2"},
	}

	fallback := cfg.GetFallbackConfig()

	if fallback.TrustedOrg != "TestOrg" {
		t.Errorf("TrustedOrg = %q, want 'TestOrg'", fallback.TrustedOrg)
	}

	if fallback.TrustedCountry != "US" {
		t.Errorf("TrustedCountry = %q, want 'US'", fallback.TrustedCountry)
	}

	if len(fallback.TrustedCAs) != 2 {
		t.Errorf("TrustedCAs 长度 = %d, want 2", len(fallback.TrustedCAs))
	}
}

// TestErrNeedChainUpgrade 测试链式升级错误
func TestErrNeedChainUpgrade(t *testing.T) {
	err := &ErrNeedChainUpgrade{
		CurrentVersion: "1.0.0",
		TargetVersion:  "2.0.0",
		MinVersion:     "1.5.0",
	}

	expected := "当前版本 1.0.0 低于最低要求 1.5.0，需要链式升级到 2.0.0"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

// TestUpgraderProgressCallbacks 测试进度回调
func TestUpgraderProgressCallbacks(t *testing.T) {
	cfg := &Config{Enabled: true}
	u := &Upgrader{Config: cfg}

	// 初始状态
	progress := u.GetProgress()
	if progress.Status != StatusIdle {
		t.Errorf("初始状态 = %v, want StatusIdle", progress.Status)
	}

	// 设置回调
	var callbackCalled bool
	var receivedProgress UpdateProgress
	u.SetOnProgress(func(p UpdateProgress) {
		callbackCalled = true
		receivedProgress = p
	})

	// 更新进度
	u.updateProgress(StatusDownloading, "下载中...", 500, 1000, 100.0)

	if !callbackCalled {
		t.Error("进度回调未被调用")
	}

	if receivedProgress.Status != StatusDownloading {
		t.Errorf("回调状态 = %v, want StatusDownloading", receivedProgress.Status)
	}

	if receivedProgress.Downloaded != 500 {
		t.Errorf("Downloaded = %d, want 500", receivedProgress.Downloaded)
	}

	if receivedProgress.Total != 1000 {
		t.Errorf("Total = %d, want 1000", receivedProgress.Total)
	}

	if receivedProgress.Percent != 50.0 {
		t.Errorf("Percent = %f, want 50.0", receivedProgress.Percent)
	}
}

// TestUpgraderProgressPercent 测试进度百分比计算
func TestUpgraderProgressPercent(t *testing.T) {
	cfg := &Config{Enabled: true}
	u := &Upgrader{Config: cfg}

	tests := []struct {
		name        string
		downloaded  int64
		total       int64
		wantPercent float64
	}{
		{"正常进度", 500, 1000, 50.0},
		{"完成", 1000, 1000, 100.0},
		{"开始", 0, 1000, 0.0},
		{"未知总大小", 500, 0, 0.0},
		{"未知总大小-负数", 500, -1, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u.updateProgress(StatusDownloading, "test", tt.downloaded, tt.total, 0)
			progress := u.GetProgress()

			if progress.Percent != tt.wantPercent {
				t.Errorf("Percent = %f, want %f", progress.Percent, tt.wantPercent)
			}
		})
	}
}

// TestUpgraderSkipVersion 测试跳过版本
func TestUpgraderSkipVersion(t *testing.T) {
	cfg := &Config{Enabled: true}
	u := &Upgrader{Config: cfg}

	u.SkipVersion("1.2.0")

	if u.Config.SkippedVersion != "1.2.0" {
		t.Errorf("SkippedVersion = %q, want '1.2.0'", u.Config.SkippedVersion)
	}
}

// TestUpgraderUpdateLastCheck 测试更新上次检查时间
func TestUpgraderUpdateLastCheck(t *testing.T) {
	cfg := &Config{Enabled: true}
	u := &Upgrader{Config: cfg}

	before := time.Now().Add(-1 * time.Second) // 给一点时间余量
	u.UpdateLastCheck()
	after := time.Now().Add(1 * time.Second)

	lastCheck, err := time.Parse(time.RFC3339, u.Config.LastCheck)
	if err != nil {
		t.Fatalf("解析 LastCheck 失败: %v", err)
	}

	if lastCheck.Before(before) || lastCheck.After(after) {
		t.Errorf("LastCheck = %v, 期望在 %v 和 %v 之间", lastCheck, before, after)
	}
}
