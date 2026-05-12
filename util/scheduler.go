package util

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

const DefaultTaskName = "SSLCtlW"

// IsTaskExists 检查任务是否存在
func IsTaskExists(taskName string) bool {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return false
	}

	output, err := RunCmdCombined(ResolveSystem32Exe("schtasks.exe"), "/query", "/tn", taskName)
	if err != nil {
		return false
	}
	// 如果输出包含任务名称，说明存在
	return strings.Contains(output, taskName)
}

// CreateTask 创建计划任务（每天一次，随机时间）
func CreateTask(taskName string) error {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return fmt.Errorf("无效的任务名称: %w", err)
	}

	// 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}

	// 构建命令: 程序路径 + deploy --all
	taskRun := fmt.Sprintf("\"%s\" deploy --all", exePath)

	// 删除已存在的任务（如果有）
	DeleteTask(taskName)

	// 随机生成每天执行时间 (09:00 ~ 23:59)
	// 服务端 0-8 点自动签发，9 点后拉取确保证书已签发
	startTime := fmt.Sprintf("%02d:%02d", 9+rand.IntN(15), rand.IntN(60))

	// 创建任务
	// /sc DAILY: 每天执行一次
	// /st HH:MM: 随机开始时间
	// /ru SYSTEM: 以 SYSTEM 账户运行（需要管理员权限）
	// /rl HIGHEST: 最高权限运行
	// /f: 强制覆盖
	output, err := RunCmdCombined(ResolveSystem32Exe("schtasks.exe"),
		"/create",
		"/tn", taskName,
		"/tr", taskRun,
		"/sc", "DAILY",
		"/st", startTime,
		"/ru", "SYSTEM",
		"/rl", "HIGHEST",
		"/f",
	)

	if err != nil {
		return fmt.Errorf("创建任务失败: %v, 输出: %s", err, output)
	}

	// 验证任务是否创建成功
	if !IsTaskExists(taskName) {
		return fmt.Errorf("任务创建后验证失败")
	}

	return nil
}

// DeleteTask 删除计划任务
func DeleteTask(taskName string) error {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return fmt.Errorf("无效的任务名称: %w", err)
	}

	if !IsTaskExists(taskName) {
		return nil // 不存在则无需删除
	}

	output, err := RunCmdCombined(ResolveSystem32Exe("schtasks.exe"), "/delete", "/tn", taskName, "/f")
	if err != nil {
		return fmt.Errorf("删除任务失败: %v, 输出: %s", err, output)
	}

	return nil
}

// RunTaskNow 立即运行任务
func RunTaskNow(taskName string) error {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return fmt.Errorf("无效的任务名称: %w", err)
	}

	if !IsTaskExists(taskName) {
		return fmt.Errorf("任务不存在: %s", taskName)
	}

	output, err := RunCmdCombined(ResolveSystem32Exe("schtasks.exe"), "/run", "/tn", taskName)
	if err != nil {
		return fmt.Errorf("运行任务失败: %v, 输出: %s", err, output)
	}

	return nil
}

// GetTaskInfo 获取任务信息
func GetTaskInfo(taskName string) (string, error) {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return "", fmt.Errorf("无效的任务名称: %w", err)
	}

	if !IsTaskExists(taskName) {
		return "", fmt.Errorf("任务不存在")
	}

	output, err := RunCmd(ResolveSystem32Exe("schtasks.exe"), "/query", "/tn", taskName, "/v", "/fo", "LIST")
	if err != nil {
		return "", err
	}

	return output, nil
}
