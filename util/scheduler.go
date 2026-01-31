package util

import (
	"fmt"
	"os"
	"strings"
)

const DefaultTaskName = "CertDeployIIS"

// IsTaskExists 检查任务是否存在
func IsTaskExists(taskName string) bool {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return false
	}

	output, err := RunCmdCombined("schtasks", "/query", "/tn", taskName)
	if err != nil {
		return false
	}
	// 如果输出包含任务名称，说明存在
	return strings.Contains(output, taskName)
}

// CreateTask 创建计划任务
// intervalHours: 执行间隔（小时）
func CreateTask(taskName string, intervalHours int) error {
	// 验证任务名称
	if err := ValidateTaskName(taskName); err != nil {
		return fmt.Errorf("无效的任务名称: %w", err)
	}

	// 获取当前程序路径
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取程序路径失败: %v", err)
	}

	// 构建命令: 程序路径 + -auto 参数
	taskRun := fmt.Sprintf("\"%s\" -auto", exePath)

	// 删除已存在的任务（如果有）
	DeleteTask(taskName)

	// 创建任务
	// /sc HOURLY /mo N: 每 N 小时执行一次
	// /ru SYSTEM: 以 SYSTEM 账户运行（需要管理员权限）
	// /rl HIGHEST: 最高权限运行
	// /f: 强制覆盖
	output, err := RunCmdCombined("schtasks",
		"/create",
		"/tn", taskName,
		"/tr", taskRun,
		"/sc", "HOURLY",
		"/mo", fmt.Sprintf("%d", intervalHours),
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

	output, err := RunCmdCombined("schtasks", "/delete", "/tn", taskName, "/f")
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

	output, err := RunCmdCombined("schtasks", "/run", "/tn", taskName)
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

	output, err := RunCmd("schtasks", "/query", "/tn", taskName, "/v", "/fo", "LIST")
	if err != nil {
		return "", err
	}

	return output, nil
}
