package util

import (
	"bytes"
	"os/exec"
	"syscall"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// RunPowerShell 执行 PowerShell 命令（隐藏窗口，UTF-8 输出）
func RunPowerShell(script string) (string, error) {
	// 在脚本开头设置 UTF-8 输出编码
	fullScript := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; " + script

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", fullScript)

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

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", fullScript)

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

// RunCmd 执行普通命令（隐藏窗口）
func RunCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)

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
	cmd := exec.Command(name, args...)

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
// 如果已经是有效的 UTF-8 且包含中文，则不转换
func GBKToUTF8(data []byte) ([]byte, error) {
	// 如果已经是有效的 UTF-8，直接返回
	if utf8.Valid(data) && containsChineseUTF8(data) {
		return data, nil
	}

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
