package upgrade

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procMoveFileExW = kernel32.NewProc("MoveFileExW")
)

const (
	MOVEFILE_DELAY_UNTIL_REBOOT = 0x04
)

// WindowsUpdater Windows 平台自我更新器
type WindowsUpdater struct{}

// NewWindowsUpdater 创建 Windows 更新器
func NewWindowsUpdater() *WindowsUpdater {
	return &WindowsUpdater{}
}

// PrepareUpdate 准备更新（备份当前版本）
func (u *WindowsUpdater) PrepareUpdate(ctx context.Context, newExePath string) (*UpdatePlan, error) {
	// 获取当前可执行文件路径
	currentExe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取当前程序路径失败: %w", err)
	}

	// 解析符号链接
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return nil, fmt.Errorf("解析程序路径失败: %w", err)
	}

	// 验证新版本文件存在
	if _, err := os.Stat(newExePath); err != nil {
		return nil, fmt.Errorf("新版本文件不存在: %w", err)
	}

	// 创建备份目录
	backupDir := filepath.Join(filepath.Dir(currentExe), ".backup")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("创建备份目录失败: %w", err)
	}

	// 生成备份文件名（带时间戳）
	timestamp := time.Now().Format("20060102150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("sslctlw-%s.exe.bak", timestamp))

	return &UpdatePlan{
		CurrentExePath: currentExe,
		BackupExePath:  backupPath,
		NewExePath:     newExePath,
		CreatedAt:      time.Now(),
	}, nil
}

// ApplyUpdate 应用更新
// Windows 特殊处理：运行中的 EXE 可以重命名但不能删除/覆盖
func (u *WindowsUpdater) ApplyUpdate(plan *UpdatePlan) error {
	// 1. 将当前 EXE 重命名为备份
	if err := os.Rename(plan.CurrentExePath, plan.BackupExePath); err != nil {
		return fmt.Errorf("备份当前版本失败: %w", err)
	}

	// 2. 复制新版本到原位置
	if err := copyFile(plan.NewExePath, plan.CurrentExePath); err != nil {
		// 恢复备份
		os.Rename(plan.BackupExePath, plan.CurrentExePath)
		return fmt.Errorf("复制新版本失败: %w", err)
	}

	// 3. 标记备份文件在重启后删除（可选，清理旧版本）
	u.scheduleDeleteOnReboot(plan.BackupExePath)

	// 4. 删除临时下载文件
	os.Remove(plan.NewExePath)

	return nil
}

// Rollback 回滚到备份版本
func (u *WindowsUpdater) Rollback(plan *UpdatePlan) error {
	// 检查备份文件是否存在
	if _, err := os.Stat(plan.BackupExePath); os.IsNotExist(err) {
		return fmt.Errorf("备份文件不存在: %s", plan.BackupExePath)
	}

	// 尝试删除当前版本（可能失败，因为正在运行）
	os.Remove(plan.CurrentExePath)

	// 恢复备份
	if err := os.Rename(plan.BackupExePath, plan.CurrentExePath); err != nil {
		// 如果重命名失败，尝试复制
		if copyErr := copyFile(plan.BackupExePath, plan.CurrentExePath); copyErr != nil {
			return fmt.Errorf("恢复备份失败: %w (复制也失败: %v)", err, copyErr)
		}
	}

	return nil
}

// Cleanup 清理临时文件和旧备份
func (u *WindowsUpdater) Cleanup(plan *UpdatePlan) error {
	// 删除临时下载文件
	if plan.NewExePath != "" {
		os.Remove(plan.NewExePath)
	}

	// 清理旧备份（保留最近一个）
	backupDir := filepath.Dir(plan.BackupExePath)
	if err := cleanOldBackups(backupDir, 1); err != nil {
		return fmt.Errorf("清理旧备份失败: %w", err)
	}

	return nil
}

// scheduleDeleteOnReboot 标记文件在重启后删除
func (u *WindowsUpdater) scheduleDeleteOnReboot(filePath string) {
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return
	}

	// MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)
	// 标记文件在系统重启后删除
	procMoveFileExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		MOVEFILE_DELAY_UNTIL_REBOOT,
	)
}

// copyFile 复制文件
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

// cleanOldBackups 清理旧备份，保留最近 n 个
func cleanOldBackups(backupDir string, keep int) error {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	// 筛选备份文件
	var backups []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".bak" {
			backups = append(backups, entry)
		}
	}

	// 如果备份数量不超过保留数量，不需要清理
	if len(backups) <= keep {
		return nil
	}

	// 按修改时间排序（新的在前）
	// 由于文件名包含时间戳，可以直接按名称倒序排序
	for i := 0; i < len(backups)-1; i++ {
		for j := i + 1; j < len(backups); j++ {
			if backups[i].Name() < backups[j].Name() {
				backups[i], backups[j] = backups[j], backups[i]
			}
		}
	}

	// 删除多余的备份
	for i := keep; i < len(backups); i++ {
		path := filepath.Join(backupDir, backups[i].Name())
		os.Remove(path)
	}

	return nil
}

// RestartApplication 重启应用程序
func RestartApplication() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %w", err)
	}

	// 启动新进程
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动新进程失败: %w", err)
	}

	// 退出当前进程
	os.Exit(0)
	return nil
}

// GetBackupDir 获取备份目录路径
func GetBackupDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), ".backup"), nil
}

// HasBackup 检查是否有可用的备份
func HasBackup() bool {
	backupDir, err := GetBackupDir()
	if err != nil {
		return false
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".bak" {
			return true
		}
	}

	return false
}

// GetLatestBackup 获取最新的备份文件路径
func GetLatestBackup() (string, error) {
	backupDir, err := GetBackupDir()
	if err != nil {
		return "", err
	}

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return "", err
	}

	var latest string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".bak" {
			name := entry.Name()
			if name > latest {
				latest = name
			}
		}
	}

	if latest == "" {
		return "", fmt.Errorf("没有可用的备份")
	}

	return filepath.Join(backupDir, latest), nil
}
