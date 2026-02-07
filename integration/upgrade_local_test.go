//go:build integration

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sslctlw/upgrade"
)

// TestUpgradeLocalOperations 本地升级操作测试（不需要外部服务）
// 运行方式: go test -tags=integration ./integration/... -run TestUpgradeLocal -v
func TestUpgradeLocalOperations(t *testing.T) {

	t.Run("HTTPDownloader", func(t *testing.T) {
		// 创建测试服务器
		content := "This is test content for download integration test."
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "51")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(content))
		}))
		defer server.Close()

		tmpDir := t.TempDir()
		destPath := filepath.Join(tmpDir, "downloaded.exe")

		downloader := upgrade.NewHTTPDownloader()

		var progressReports int
		err := downloader.Download(context.Background(), server.URL, destPath, func(downloaded, total int64, speed float64) {
			progressReports++
			t.Logf("下载进度: %d/%d bytes, 速度: %s",
				downloaded, total, upgrade.FormatSpeed(speed))
		})

		if err != nil {
			t.Fatalf("下载失败: %v", err)
		}

		// 验证文件
		data, _ := os.ReadFile(destPath)
		if string(data) != content {
			t.Errorf("内容不匹配")
		}

		t.Logf("下载成功，进度回调 %d 次", progressReports)
	})

	t.Run("BackupOperations", func(t *testing.T) {
		tmpDir := t.TempDir()
		backupDir := filepath.Join(tmpDir, ".backup")
		os.MkdirAll(backupDir, 0700)

		// 创建模拟备份文件
		backups := []string{
			"sslctlw-20240101120000.exe.bak",
			"sslctlw-20240102120000.exe.bak",
			"sslctlw-20240103120000.exe.bak",
		}

		for _, name := range backups {
			path := filepath.Join(backupDir, name)
			os.WriteFile(path, []byte("backup content"), 0644)
		}

		t.Logf("创建了 %d 个测试备份", len(backups))

		// 测试 Cleanup
		updater := upgrade.NewWindowsUpdater()
		plan := &upgrade.UpdatePlan{
			BackupExePath: filepath.Join(backupDir, backups[2]),
		}

		err := updater.Cleanup(plan)
		if err != nil {
			t.Fatalf("Cleanup 失败: %v", err)
		}

		// 验证保留了最新的 1 个
		entries, _ := os.ReadDir(backupDir)
		var bakCount int
		for _, e := range entries {
			if filepath.Ext(e.Name()) == ".bak" {
				bakCount++
				t.Logf("保留的备份: %s", e.Name())
			}
		}

		if bakCount != 1 {
			t.Errorf("应该保留 1 个备份，实际 %d 个", bakCount)
		}
	})

	t.Run("UpgraderConfig", func(t *testing.T) {
		cfg := upgrade.DefaultConfig()
		cfg.Enabled = true
		cfg.CheckInterval = 24
		cfg.LastCheck = ""

		upgrader := &upgrade.Upgrader{Config: cfg}

		// 首次应该检查
		if !upgrader.ShouldCheckUpdate() {
			t.Error("首次应该需要检查更新")
		}

		// 更新检查时间
		upgrader.UpdateLastCheck()

		// 刚检查过，不应该再检查
		if upgrader.ShouldCheckUpdate() {
			t.Error("刚检查过，不应该需要再次检查")
		}

		t.Logf("LastCheck: %s", cfg.LastCheck)
	})

	t.Run("VersionCompare", func(t *testing.T) {
		tests := []struct {
			v1, v2   string
			expected int
		}{
			{"1.0.0", "1.0.0", 0},
			{"1.0.0", "1.0.1", -1},
			{"2.0.0", "1.9.9", 1},
			{"1.0.0-alpha", "1.0.0", -1},
			{"1.0.0-beta", "1.0.0-alpha", 1},
		}

		for _, tt := range tests {
			result := upgrade.CompareVersion(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersion(%s, %s) = %d, want %d",
					tt.v1, tt.v2, result, tt.expected)
			} else {
				t.Logf("CompareVersion(%s, %s) = %d ✓", tt.v1, tt.v2, result)
			}
		}
	})

	t.Run("FormatFunctions", func(t *testing.T) {
		// 测试速度格式化
		speeds := []float64{100, 1024, 1024 * 1024, 10 * 1024 * 1024}
		for _, s := range speeds {
			t.Logf("FormatSpeed(%.0f) = %s", s, upgrade.FormatSpeed(s))
		}

		// 测试大小格式化
		sizes := []int64{100, 1024, 1024 * 1024, 10 * 1024 * 1024}
		for _, s := range sizes {
			t.Logf("FormatSize(%d) = %s", s, upgrade.FormatSize(s))
		}
	})
}

// TestUpgradeSignatureVerification 测试签名验证
func TestUpgradeSignatureVerification(t *testing.T) {
	verifier := upgrade.NewAuthenticodeVerifier()

	t.Run("VerifyCurrentExecutable", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Skipf("无法获取当前可执行文件: %v", err)
		}

		exe, _ = filepath.EvalSymlinks(exe)
		t.Logf("验证: %s", exe)

		result, err := verifier.Verify(exe, nil, nil)
		if err != nil {
			t.Logf("验证错误: %v", err)
		}

		if result != nil {
			t.Logf("验证结果:")
			t.Logf("  Valid: %v", result.Valid)
			t.Logf("  Subject: %s", result.Subject)
			t.Logf("  Organization: %s", result.Organization)
			t.Logf("  Issuer: %s", result.Issuer)
			t.Logf("  Fingerprint: %s", result.Fingerprint)
			t.Logf("  Message: %s", result.Message)
		}
	})

	t.Run("VerifySystemExecutable", func(t *testing.T) {
		// 验证一个已签名的系统文件
		systemExe := `C:\Windows\System32\notepad.exe`
		if _, err := os.Stat(systemExe); os.IsNotExist(err) {
			t.Skip("notepad.exe 不存在")
		}

		t.Logf("验证系统文件: %s", systemExe)

		result, err := verifier.Verify(systemExe, nil, nil)
		if err != nil {
			t.Logf("验证错误: %v", err)
		}

		if result != nil {
			t.Logf("验证结果:")
			t.Logf("  Valid: %v", result.Valid)
			t.Logf("  Subject: %s", result.Subject)
			t.Logf("  Organization: %s", result.Organization)
			t.Logf("  Issuer: %s", result.Issuer)

			if result.Valid {
				t.Log("系统文件签名验证通过 ✓")
			}
		}
	})
}

// TestUpgradeDownloadWithTimeout 测试下载超时
func TestUpgradeDownloadWithTimeout(t *testing.T) {
	// 创建一个慢速服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// 慢速发送
		for i := 0; i < 100; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
				w.Write(make([]byte, 10000))
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "slow.exe")

	downloader := upgrade.NewHTTPDownloader()

	// 设置短超时
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := downloader.Download(ctx, server.URL, destPath, nil)

	if err == nil {
		t.Error("应该因超时返回错误")
	} else {
		t.Logf("正确返回超时错误: %v", err)
	}
}
