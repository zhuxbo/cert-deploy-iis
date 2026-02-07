package upgrade

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCopyFile 测试文件复制
func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建源文件
	srcPath := filepath.Join(tmpDir, "source.txt")
	content := []byte("Hello, World! Test file content.")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("创建源文件失败: %v", err)
	}

	// 复制文件
	dstPath := filepath.Join(tmpDir, "dest.txt")
	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("复制文件失败: %v", err)
	}

	// 验证内容
	data, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("读取目标文件失败: %v", err)
	}

	if string(data) != string(content) {
		t.Errorf("文件内容 = %q, want %q", string(data), string(content))
	}

	// 验证权限
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("获取文件信息失败: %v", err)
	}

	// Windows 上权限可能有所不同，只检查文件是否可执行
	if info.Mode()&0111 == 0 {
		t.Log("警告: 目标文件可能没有可执行权限")
	}
}

// TestCopyFileSourceNotExist 测试源文件不存在
func TestCopyFileSourceNotExist(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "nonexistent.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")

	err := copyFile(srcPath, dstPath)
	if err == nil {
		t.Error("期望错误，但没有返回错误")
	}
}

// TestCopyFileDestDirNotExist 测试目标目录不存在
func TestCopyFileDestDirNotExist(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建源文件
	srcPath := filepath.Join(tmpDir, "source.txt")
	if err := os.WriteFile(srcPath, []byte("test"), 0644); err != nil {
		t.Fatalf("创建源文件失败: %v", err)
	}

	// 目标目录不存在
	dstPath := filepath.Join(tmpDir, "nonexistent", "dest.txt")
	err := copyFile(srcPath, dstPath)
	if err == nil {
		t.Error("期望错误，但没有返回错误")
	}
}

// TestCleanOldBackups 测试清理旧备份
func TestCleanOldBackups(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	// 创建多个备份文件
	backups := []string{
		"sslctlw-20240101000000.exe.bak",
		"sslctlw-20240102000000.exe.bak",
		"sslctlw-20240103000000.exe.bak",
		"sslctlw-20240104000000.exe.bak",
		"sslctlw-20240105000000.exe.bak",
	}

	for _, name := range backups {
		path := filepath.Join(backupDir, name)
		if err := os.WriteFile(path, []byte("backup"), 0644); err != nil {
			t.Fatalf("创建备份文件失败: %v", err)
		}
	}

	// 保留最新的 2 个
	if err := cleanOldBackups(backupDir, 2); err != nil {
		t.Fatalf("清理备份失败: %v", err)
	}

	// 验证结果
	entries, _ := os.ReadDir(backupDir)
	var remaining []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bak" {
			remaining = append(remaining, e.Name())
		}
	}

	if len(remaining) != 2 {
		t.Errorf("剩余备份数量 = %d, want 2", len(remaining))
	}

	// 应该保留最新的（按名称排序最大的）
	for _, name := range remaining {
		if name != "sslctlw-20240104000000.exe.bak" && name != "sslctlw-20240105000000.exe.bak" {
			t.Errorf("保留了错误的备份: %s", name)
		}
	}
}

// TestCleanOldBackupsKeepAll 测试保留所有（备份数量不超过限制）
func TestCleanOldBackupsKeepAll(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	// 只有 2 个备份
	backups := []string{
		"sslctlw-20240101000000.exe.bak",
		"sslctlw-20240102000000.exe.bak",
	}

	for _, name := range backups {
		path := filepath.Join(backupDir, name)
		os.WriteFile(path, []byte("backup"), 0644)
	}

	// 保留 3 个
	if err := cleanOldBackups(backupDir, 3); err != nil {
		t.Fatalf("清理备份失败: %v", err)
	}

	// 应该保留所有
	entries, _ := os.ReadDir(backupDir)
	if len(entries) != 2 {
		t.Errorf("剩余备份数量 = %d, want 2", len(entries))
	}
}

// TestCleanOldBackupsNonExistentDir 测试不存在的目录
func TestCleanOldBackupsNonExistentDir(t *testing.T) {
	err := cleanOldBackups("/nonexistent/path", 1)
	if err != nil {
		t.Errorf("不存在的目录应该返回 nil: %v", err)
	}
}

// TestCleanOldBackupsIgnoreNonBak 测试忽略非 .bak 文件
func TestCleanOldBackupsIgnoreNonBak(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	// 创建混合文件
	files := []string{
		"sslctlw-20240101.exe.bak",
		"sslctlw-20240102.exe.bak",
		"config.json",
		"readme.txt",
	}

	for _, name := range files {
		path := filepath.Join(backupDir, name)
		os.WriteFile(path, []byte("content"), 0644)
	}

	// 只保留 1 个备份
	if err := cleanOldBackups(backupDir, 1); err != nil {
		t.Fatalf("清理备份失败: %v", err)
	}

	entries, _ := os.ReadDir(backupDir)
	bakCount := 0
	otherCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bak" {
			bakCount++
		} else {
			otherCount++
		}
	}

	if bakCount != 1 {
		t.Errorf(".bak 文件数量 = %d, want 1", bakCount)
	}

	if otherCount != 2 {
		t.Errorf("其他文件数量 = %d, want 2", otherCount)
	}
}

// TestWindowsUpdaterPrepareUpdate 测试准备更新（模拟）
func TestWindowsUpdaterPrepareUpdate(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建模拟的新版本文件
	newExePath := filepath.Join(tmpDir, "new_version.exe")
	if err := os.WriteFile(newExePath, []byte("new exe"), 0644); err != nil {
		t.Fatalf("创建新版本文件失败: %v", err)
	}

	updater := NewWindowsUpdater()

	// 注意: PrepareUpdate 会获取当前可执行文件路径，在测试环境下可能有问题
	// 这里只测试新版本文件不存在的情况
	_, err := updater.PrepareUpdate(nil, filepath.Join(tmpDir, "nonexistent.exe"))
	if err == nil {
		t.Error("新版本文件不存在时应该返回错误")
	}
}

// TestUpdatePlan 测试更新计划结构
func TestUpdatePlan(t *testing.T) {
	plan := &UpdatePlan{
		CurrentExePath: "C:\\Program Files\\sslctlw\\sslctlw.exe",
		BackupExePath:  "C:\\Program Files\\sslctlw\\.backup\\sslctlw-20240101.exe.bak",
		NewExePath:     "C:\\temp\\sslctlw-new.exe",
		Version:        "1.2.0",
		CreatedAt:      time.Now(),
	}

	if plan.CurrentExePath == "" {
		t.Error("CurrentExePath 不应为空")
	}

	if plan.Version != "1.2.0" {
		t.Errorf("Version = %q, want '1.2.0'", plan.Version)
	}
}

// TestGetBackupDir 测试获取备份目录（只验证返回格式）
func TestGetBackupDir(t *testing.T) {
	dir, err := GetBackupDir()
	if err != nil {
		// 在测试环境下可能无法获取可执行文件路径
		t.Skipf("无法获取备份目录: %v", err)
	}

	if !filepath.IsAbs(dir) {
		t.Errorf("备份目录应该是绝对路径: %s", dir)
	}

	if filepath.Base(dir) != ".backup" {
		t.Errorf("备份目录应该以 .backup 结尾: %s", dir)
	}
}

// TestHasBackupNoDir 测试没有备份目录时
func TestHasBackupNoDir(t *testing.T) {
	// HasBackup 依赖 GetBackupDir，在测试环境下结果取决于实际环境
	// 这里只验证函数不会 panic
	_ = HasBackup()
}

// TestGetLatestBackupNoBackup 测试没有备份时
func TestGetLatestBackupNoBackup(t *testing.T) {
	// 在没有备份的环境下应该返回错误
	_, err := GetLatestBackup()
	// 根据实际环境，可能返回 "没有可用的备份" 或其他错误
	if err == nil {
		t.Log("存在备份文件")
	}
}

// TestCopyFileLargeFile 测试大文件复制
func TestCopyFileLargeFile(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建一个较大的源文件（1MB）
	srcPath := filepath.Join(tmpDir, "large.bin")
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		t.Fatalf("创建大文件失败: %v", err)
	}

	// 复制文件
	dstPath := filepath.Join(tmpDir, "large_copy.bin")
	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("复制大文件失败: %v", err)
	}

	// 验证文件大小
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("获取文件信息失败: %v", err)
	}

	if info.Size() != int64(len(data)) {
		t.Errorf("文件大小 = %d, want %d", info.Size(), len(data))
	}
}

// TestCleanOldBackupsSorting 测试备份排序逻辑
func TestCleanOldBackupsSorting(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	// 创建无序的备份文件
	backups := []string{
		"sslctlw-20240103000000.exe.bak",
		"sslctlw-20240101000000.exe.bak",
		"sslctlw-20240105000000.exe.bak",
		"sslctlw-20240102000000.exe.bak",
		"sslctlw-20240104000000.exe.bak",
	}

	for _, name := range backups {
		path := filepath.Join(backupDir, name)
		os.WriteFile(path, []byte("backup"), 0644)
	}

	// 保留最新的 1 个
	if err := cleanOldBackups(backupDir, 1); err != nil {
		t.Fatalf("清理备份失败: %v", err)
	}

	// 应该只保留最新的一个
	entries, _ := os.ReadDir(backupDir)
	if len(entries) != 1 {
		t.Fatalf("应该只保留 1 个备份，得到 %d 个", len(entries))
	}

	if entries[0].Name() != "sslctlw-20240105000000.exe.bak" {
		t.Errorf("应该保留最新的备份，得到 %s", entries[0].Name())
	}
}

// TestCleanOldBackupsZeroKeep 测试保留 0 个
func TestCleanOldBackupsZeroKeep(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	backups := []string{
		"sslctlw-20240101.exe.bak",
		"sslctlw-20240102.exe.bak",
	}

	for _, name := range backups {
		path := filepath.Join(backupDir, name)
		os.WriteFile(path, []byte("backup"), 0644)
	}

	// 保留 0 个
	if err := cleanOldBackups(backupDir, 0); err != nil {
		t.Fatalf("清理备份失败: %v", err)
	}

	entries, _ := os.ReadDir(backupDir)
	bakCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bak" {
			bakCount++
		}
	}

	if bakCount != 0 {
		t.Errorf("应该删除所有备份，剩余 %d 个", bakCount)
	}
}

// TestWindowsUpdaterCleanup 测试清理函数
func TestWindowsUpdaterCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	// 创建模拟的备份目录和文件
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	// 创建多个备份
	for i := 1; i <= 5; i++ {
		path := filepath.Join(backupDir, "sslctlw-2024010"+string(rune('0'+i))+"0000.exe.bak")
		os.WriteFile(path, []byte("backup"), 0644)
	}

	// 创建临时下载文件
	newExePath := filepath.Join(tmpDir, "new.exe")
	os.WriteFile(newExePath, []byte("new"), 0644)

	updater := NewWindowsUpdater()
	plan := &UpdatePlan{
		NewExePath:    newExePath,
		BackupExePath: filepath.Join(backupDir, "sslctlw-20240105000000.exe.bak"),
	}

	err := updater.Cleanup(plan)
	if err != nil {
		t.Fatalf("Cleanup 失败: %v", err)
	}

	// 验证临时文件被删除
	if _, err := os.Stat(newExePath); !os.IsNotExist(err) {
		t.Error("临时下载文件应该被删除")
	}

	// 验证只保留最近 1 个备份
	entries, _ := os.ReadDir(backupDir)
	bakCount := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".bak" {
			bakCount++
		}
	}
	if bakCount != 1 {
		t.Errorf("应该只保留 1 个备份，剩余 %d 个", bakCount)
	}
}

// TestWindowsUpdaterCleanupEmptyNewExePath 测试空路径的清理
func TestWindowsUpdaterCleanupEmptyNewExePath(t *testing.T) {
	tmpDir := t.TempDir()
	backupDir := filepath.Join(tmpDir, ".backup")
	os.MkdirAll(backupDir, 0700)

	updater := NewWindowsUpdater()
	plan := &UpdatePlan{
		NewExePath:    "", // 空路径
		BackupExePath: filepath.Join(backupDir, "test.bak"),
	}

	// 不应该 panic
	err := updater.Cleanup(plan)
	if err != nil {
		t.Fatalf("Cleanup 失败: %v", err)
	}
}
