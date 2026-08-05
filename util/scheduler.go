package util

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"
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

func buildCreateTaskArgs(taskName, exePath, startTime string) []string {
	taskRun := fmt.Sprintf(`"%s" deploy --all`, exePath)
	return []string{
		"/create",
		"/tn", taskName,
		"/tr", taskRun,
		"/sc", "DAILY",
		"/st", startTime,
		"/ru", "SYSTEM",
		"/rl", "HIGHEST",
		"/f",
	}
}

// CreateTask 创建计划任务（每天一次，随机时间）
// 使用 schtasks 参数而非手写 XML，兼容旧版 Windows Server；/f 覆盖旧任务
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

	// 随机生成每天执行时间 (09:00 ~ 23:59)
	// 服务端 0-8 点自动签发，9 点后拉取确保证书已签发
	startTime := fmt.Sprintf("%02d:%02d", 9+rand.IntN(15), rand.IntN(60))

	output, err := RunCmdCombined(
		ResolveSystem32Exe("schtasks.exe"),
		buildCreateTaskArgs(taskName, exePath, startTime)...,
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

// TaskHealth 计划任务最近运行信息
type TaskHealth struct {
	LastRunTime    time.Time
	LastTaskResult uint32
	HasRun         bool
}

// 任务健康相关常量
const (
	taskResultSuccess = 0x0     // 上次运行成功
	taskResultRunning = 0x41301 // 任务正在运行
	taskResultHasNot  = 0x41303 // 任务尚未运行
	taskResultQueued  = 0x41325 // 任务已排队

	// taskNeverRunYear Task Scheduler 用 1999-11-30 表示从未运行
	taskNeverRunYear = 2000

	// TaskStaleThreshold 每日任务超过该时长未运行视为停摆
	TaskStaleThreshold = 25 * time.Hour
)

// GetTaskHealth 查询任务上次运行时间与结果
// 使用 PowerShell Get-ScheduledTaskInfo 取结构化字段，避免解析 schtasks /query 的本地化表头
func GetTaskHealth(taskName string) (*TaskHealth, error) {
	if err := ValidateTaskName(taskName); err != nil {
		return nil, fmt.Errorf("无效的任务名称: %w", err)
	}

	// 任务名经 ValidateTaskName 白名单校验（字母数字._-），单引号包裹无注入风险
	// 时间格式化必须用 InvariantCulture：CurrentCulture 下用户自定义时间分隔符会改变输出（如 09.30.00）
	script := fmt.Sprintf(
		"$i = Get-ScheduledTaskInfo -TaskName '%s' -ErrorAction Stop; "+
			"'{0}|{1}' -f [uint32]$i.LastTaskResult, "+
			"$(if ($i.LastRunTime) { $i.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss', [System.Globalization.CultureInfo]::InvariantCulture) } else { '' })",
		taskName)
	output, err := RunPowerShell(script)
	if err != nil {
		return nil, fmt.Errorf("查询任务运行信息失败: %v", err)
	}
	return parseTaskInfoOutput(output)
}

// parseTaskInfoOutput 解析 "结果码|上次运行时间" 输出（纯函数）
func parseTaskInfoOutput(output string) (*TaskHealth, error) {
	// 取最后一个含分隔符的非空行，避免 PowerShell 配置产生的杂散输出干扰
	var line string
	for _, l := range strings.Split(output, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && strings.Contains(l, "|") {
			line = l
		}
	}
	if line == "" {
		return nil, fmt.Errorf("任务运行信息输出无法解析: %q", strings.TrimSpace(output))
	}

	parts := strings.SplitN(line, "|", 2)
	result, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("解析任务结果码失败: %v", err)
	}

	h := &TaskHealth{LastTaskResult: uint32(result)}
	if timeStr := strings.TrimSpace(parts[1]); timeStr != "" {
		// 解析失败显式报错而非静默按"从未运行"处理，避免掩盖格式问题
		ts, parseErr := time.ParseInLocation("2006-01-02 15:04:05", timeStr, time.Local)
		if parseErr != nil {
			return nil, fmt.Errorf("解析上次运行时间失败 (%q): %v", timeStr, parseErr)
		}
		h.LastRunTime = ts
		h.HasRun = ts.Year() >= taskNeverRunYear
	}
	return h, nil
}

// EvaluateTaskHealth 评估任务运行健康（纯函数），返回告警列表，空表示健康
func EvaluateTaskHealth(h *TaskHealth, now time.Time) []string {
	if h == nil {
		return []string{"无法获取任务运行信息"}
	}
	var warns []string
	if !h.HasRun {
		if h.LastTaskResult == taskResultRunning || h.LastTaskResult == taskResultQueued {
			return nil
		}
		return append(warns, "任务从未运行（新安装可忽略，超过一天仍未运行需排查）")
	}
	switch h.LastTaskResult {
	case taskResultSuccess, taskResultRunning, taskResultQueued, taskResultHasNot:
		// 正常状态
	default:
		warns = append(warns, fmt.Sprintf("上次运行结果异常 (0x%X)，自动续签可能已停摆", h.LastTaskResult))
	}
	if now.Sub(h.LastRunTime) > TaskStaleThreshold {
		warns = append(warns, fmt.Sprintf("超过 25 小时未运行（上次运行: %s）", h.LastRunTime.Format("2006-01-02 15:04")))
	}
	return warns
}

// TaskNeedsInitialRun 判断任务是否从未启动过，供升级后保留的历史任务触发一次自愈运行。
func TaskNeedsInitialRun(h *TaskHealth) bool {
	return h != nil && !h.HasRun && h.LastTaskResult == taskResultHasNot
}
