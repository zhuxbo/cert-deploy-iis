package util

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// 默认命令超时
var (
	DefaultCmdTimeout        = 2 * time.Minute
	DefaultPowerShellTimeout = 5 * time.Minute
)

// system32ExeCache 缓存已解析的系统工具路径
var system32ExeCache sync.Map

// ResolveSystem32Exe 将 System32 下的系统工具名解析为绝对路径。
// 避免依赖 PATH —— 当 PATH 被其他软件破坏（如多余引号、缺失条目）时，
// Go 的 exec.LookPath 会失败导致工具不可用。
//
// 解析顺序：
//  1. 缓存
//  2. powershell.exe 特例：位于 System32\WindowsPowerShell\v1.0
//  3. %SystemRoot%\System32\<name>
//  4. %SystemRoot%\Sysnative\<name>（32 位进程访问 64 位 System32）
//  5. exec.LookPath（PATH 兜底）
//  6. 原名（让调用方继续报错）
func ResolveSystem32Exe(name string) string {
	if name == "" {
		return name
	}
	if cached, ok := system32ExeCache.Load(name); ok {
		return cached.(string)
	}

	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}

	exeName := name
	if !strings.HasSuffix(strings.ToLower(exeName), ".exe") {
		exeName += ".exe"
	}

	var candidates []string
	if strings.EqualFold(exeName, "powershell.exe") {
		candidates = []string{
			filepath.Join(sysroot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
			filepath.Join(sysroot, "Sysnative", "WindowsPowerShell", "v1.0", "powershell.exe"),
		}
	} else {
		candidates = []string{
			filepath.Join(sysroot, "System32", exeName),
			filepath.Join(sysroot, "Sysnative", exeName),
		}
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			system32ExeCache.Store(name, p)
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		system32ExeCache.Store(name, p)
		return p
	}
	return name
}

// newCmdContext 创建带超时的命令，返回 cmd 和 cancel 函数
// 调用方必须在命令执行完毕后调用 cancel 释放资源
func newCmdContext(timeout time.Duration, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd, cancel
}

// RunPowerShell 执行 PowerShell 命令（隐藏窗口，UTF-8 输出）
func RunPowerShell(script string) (string, error) {
	// 在脚本开头设置 UTF-8 输出编码
	fullScript := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script

	cmd, cancel := newCmdContext(DefaultPowerShellTimeout, ResolveSystem32Exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", fullScript)
	defer cancel()

	// 隐藏窗口
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// RunPowerShellCombined 执行 PowerShell 命令，返回 stdout + stderr
func RunPowerShellCombined(script string) (string, error) {
	fullScript := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script

	cmd, cancel := newCmdContext(DefaultPowerShellTimeout, ResolveSystem32Exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", fullScript)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// RunPowerShellWithEnv 执行 PowerShell 命令，支持环境变量传递敏感数据
func RunPowerShellWithEnv(script string, env map[string]string) (string, error) {
	fullScript := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script

	cmd, cancel := newCmdContext(DefaultPowerShellTimeout, ResolveSystem32Exe("powershell.exe"), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", fullScript)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	// 追加环境变量
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}

	return string(output), nil
}

// RunCmd 执行普通命令（隐藏窗口）
func RunCmd(name string, args ...string) (string, error) {
	cmd, cancel := newCmdContext(DefaultCmdTimeout, name, args...)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// netsh 等命令可能输出 GBK 编码，尝试转换
	utf8Output, convErr := GBKToUTF8(output)
	if convErr != nil {
		return string(output), nil
	}

	return string(utf8Output), nil
}

// RunCmdCombined 执行普通命令，返回 stdout + stderr
func RunCmdCombined(name string, args ...string) (string, error) {
	cmd, cancel := newCmdContext(DefaultCmdTimeout, name, args...)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	output, err := cmd.CombinedOutput()

	// 尝试 GBK 转 UTF-8
	utf8Output, convErr := GBKToUTF8(output)
	if convErr != nil {
		return string(output), err
	}

	return string(utf8Output), err
}

// GBKToUTF8 将 GBK 编码转换为 UTF-8
// 如果已经是有效的 UTF-8（包括纯 ASCII），则不转换
func GBKToUTF8(data []byte) ([]byte, error) {
	// 有效的 UTF-8 直接返回（纯 ASCII 也是有效的 UTF-8）
	if utf8.Valid(data) {
		return data, nil
	}

	// 非有效 UTF-8，尝试 GBK 解码
	reader := transform.NewReader(bytes.NewReader(data), simplifiedchinese.GBK.NewDecoder())
	var buf bytes.Buffer
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// containsChineseUTF8 检查是否包含 UTF-8 编码的中文字符
func containsChineseUTF8(data []byte) bool {
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
		data = data[size:]
	}
	return false
}

// RunCmdDirect 直接执行命令（不经过 shell 解析，更安全）
// 适用于执行外部程序时需要防止命令注入的场景
func RunCmdDirect(name string, args ...string) (string, error) {
	cmd, cancel := newCmdContext(DefaultCmdTimeout, name, args...)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// 尝试 GBK 转 UTF-8
	utf8Output, convErr := GBKToUTF8(output)
	if convErr != nil {
		return string(output), nil
	}

	return string(utf8Output), nil
}

// RunCmdDirectCombined 直接执行命令，返回 stdout + stderr
func RunCmdDirectCombined(name string, args ...string) (string, error) {
	cmd, cancel := newCmdContext(DefaultCmdTimeout, name, args...)
	defer cancel()

	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}

	output, err := cmd.CombinedOutput()

	// 尝试 GBK 转 UTF-8
	utf8Output, convErr := GBKToUTF8(output)
	if convErr != nil {
		return string(output), err
	}

	return string(utf8Output), err
}
