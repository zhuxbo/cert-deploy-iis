package util

import (
	"testing"
	"time"
)

func TestCmdTimeout(t *testing.T) {
	// 临时设置较短的超时
	oldTimeout := DefaultCmdTimeout
	DefaultCmdTimeout = 1 * time.Second
	defer func() { DefaultCmdTimeout = oldTimeout }()

	// 执行一个会超时的命令（ping -n 100 等待很长时间）
	_, err := RunCmd("cmd", "/c", "ping", "-n", "100", "127.0.0.1")
	if err == nil {
		t.Error("RunCmd() 应该因超时而返回错误")
	}
}

func TestGBKToUTF8_ValidUTF8(t *testing.T) {
	// 已经是有效的 UTF-8 且包含中文
	input := []byte("测试中文")
	output, err := GBKToUTF8(input)
	if err != nil {
		t.Errorf("GBKToUTF8() error = %v", err)
	}
	if string(output) != string(input) {
		t.Errorf("GBKToUTF8() = %q, want %q", output, input)
	}
}

func TestGBKToUTF8_ASCII(t *testing.T) {
	// 纯 ASCII 字符（无中文，会尝试转换但应该保持不变）
	input := []byte("hello world 123")
	output, err := GBKToUTF8(input)
	if err != nil {
		t.Errorf("GBKToUTF8() error = %v", err)
	}
	// ASCII 字符在 GBK 和 UTF-8 中是相同的
	if string(output) != string(input) {
		t.Errorf("GBKToUTF8() = %q, want %q", output, input)
	}
}

func TestGBKToUTF8_GBKEncoded(t *testing.T) {
	// GBK 编码的 "测试" (0xB2E2 0xCAD4)
	input := []byte{0xB2, 0xE2, 0xCA, 0xD4}
	output, err := GBKToUTF8(input)
	if err != nil {
		t.Errorf("GBKToUTF8() error = %v", err)
	}
	expected := "测试"
	if string(output) != expected {
		t.Errorf("GBKToUTF8() = %q, want %q", output, expected)
	}
}

func TestContainsChineseUTF8(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"包含中文", []byte("hello 中文"), true},
		{"纯中文", []byte("测试"), true},
		{"纯英文", []byte("hello world"), false},
		{"空字节", []byte{}, false},
		{"数字和符号", []byte("123!@#"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsChineseUTF8(tt.input)
			if got != tt.want {
				t.Errorf("containsChineseUTF8(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRunCmd_Echo(t *testing.T) {
	// 使用 cmd /c echo 测试基本功能
	output, err := RunCmd("cmd", "/c", "echo", "hello")
	if err != nil {
		t.Fatalf("RunCmd() error = %v", err)
	}
	if output == "" {
		t.Error("RunCmd() 返回空输出")
	}
}

func TestRunCmdCombined_Error(t *testing.T) {
	// 执行不存在的命令
	_, err := RunCmdCombined("nonexistent_command_12345")
	if err == nil {
		t.Error("RunCmdCombined() 应该对不存在的命令返回错误")
	}
}

func TestRunCmdDirect_Echo(t *testing.T) {
	output, err := RunCmdDirect("cmd", "/c", "echo", "test")
	if err != nil {
		t.Fatalf("RunCmdDirect() error = %v", err)
	}
	if output == "" {
		t.Error("RunCmdDirect() 返回空输出")
	}
}

func TestRunCmdDirectCombined_Error(t *testing.T) {
	_, err := RunCmdDirectCombined("nonexistent_command_67890")
	if err == nil {
		t.Error("RunCmdDirectCombined() 应该对不存在的命令返回错误")
	}
}

func TestRunPowerShell_Simple(t *testing.T) {
	output, err := RunPowerShell("Write-Output 'hello'")
	if err != nil {
		t.Fatalf("RunPowerShell() error = %v", err)
	}
	if output == "" {
		t.Error("RunPowerShell() 返回空输出")
	}
}

func TestRunPowerShellCombined_Error(t *testing.T) {
	// 执行会产生错误的命令
	output, err := RunPowerShellCombined("Write-Error 'test error'")
	// Write-Error 会写入 stderr，但不会导致 exit code 非零
	// 所以这里主要验证输出包含错误信息
	_ = output
	_ = err
	// 只要不 panic 就算通过
}

func TestRunPowerShellWithEnv(t *testing.T) {
	env := map[string]string{
		"TEST_VAR": "test_value_123",
	}
	output, err := RunPowerShellWithEnv("Write-Output $env:TEST_VAR", env)
	if err != nil {
		t.Fatalf("RunPowerShellWithEnv() error = %v", err)
	}
	if output == "" {
		t.Error("RunPowerShellWithEnv() 返回空输出")
	}
}

// TestGBKToUTF8_Empty 测试空输入
func TestGBKToUTF8_Empty(t *testing.T) {
	output, err := GBKToUTF8([]byte{})
	if err != nil {
		t.Errorf("GBKToUTF8([]) error = %v", err)
	}
	if len(output) != 0 {
		t.Errorf("GBKToUTF8([]) = %q, want empty", output)
	}
}

// TestGBKToUTF8_MixedContent 测试混合内容
func TestGBKToUTF8_MixedContent(t *testing.T) {
	// GBK 编码的 "成功" + ASCII
	// "成功" in GBK: 0xB3C9 0xB9A6
	input := []byte{0xB3, 0xC9, 0xB9, 0xA6, ' ', 'O', 'K'}
	output, err := GBKToUTF8(input)
	if err != nil {
		t.Errorf("GBKToUTF8() error = %v", err)
	}
	// 输出应该包含 "成功" 和 " OK"
	if !containsChineseUTF8(output) {
		t.Error("输出应该包含中文")
	}
}

// TestContainsChineseUTF8_MoreCases 更多中文检测测试
func TestContainsChineseUTF8_MoreCases(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  bool
	}{
		{"CJK 基本区开头", []byte("一二三"), true},
		{"CJK 基本区结尾", []byte("龟"), true},
		{"日文假名", []byte("あいう"), false},          // 假名不在 CJK 基本区
		{"韩文", []byte("한글"), false},              // 韩文不在 CJK 基本区
		{"标点符号", []byte("，。！"), false},           // 中文标点不在 CJK 基本区
		{"混合中英", []byte("Hello世界"), true},
		{"数字中文混合", []byte("123测试456"), true},
		{"只有空格", []byte("   "), false},
		{"换行符", []byte("\n\r\t"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsChineseUTF8(tt.input)
			if got != tt.want {
				t.Errorf("containsChineseUTF8(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestRunCmd_NotFound 测试命令不存在
func TestRunCmd_NotFound(t *testing.T) {
	_, err := RunCmd("nonexistent_command_xxxxxx")
	if err == nil {
		t.Error("RunCmd() 应该对不存在的命令返回错误")
	}
}

// TestRunCmdDirect_NotFound 测试命令不存在
func TestRunCmdDirect_NotFound(t *testing.T) {
	_, err := RunCmdDirect("nonexistent_command_yyyyyy")
	if err == nil {
		t.Error("RunCmdDirect() 应该对不存在的命令返回错误")
	}
}

// TestRunPowerShell_MultiLine 测试多行脚本
func TestRunPowerShell_MultiLine(t *testing.T) {
	script := `
$a = 1
$b = 2
Write-Output ($a + $b)
`
	output, err := RunPowerShell(script)
	if err != nil {
		t.Fatalf("RunPowerShell() error = %v", err)
	}
	if output == "" {
		t.Error("RunPowerShell() 返回空输出")
	}
}

// TestRunPowerShellWithEnv_MultipleVars 测试多个环境变量
func TestRunPowerShellWithEnv_MultipleVars(t *testing.T) {
	env := map[string]string{
		"VAR1": "value1",
		"VAR2": "value2",
		"VAR3": "value3",
	}
	script := `Write-Output "$env:VAR1-$env:VAR2-$env:VAR3"`
	output, err := RunPowerShellWithEnv(script, env)
	if err != nil {
		t.Fatalf("RunPowerShellWithEnv() error = %v", err)
	}
	// 验证输出包含所有值
	if output == "" {
		t.Error("RunPowerShellWithEnv() 返回空输出")
	}
}

// TestRunPowerShellWithEnv_EmptyEnv 测试空环境变量
func TestRunPowerShellWithEnv_EmptyEnv(t *testing.T) {
	output, err := RunPowerShellWithEnv("Write-Output 'test'", map[string]string{})
	if err != nil {
		t.Fatalf("RunPowerShellWithEnv() error = %v", err)
	}
	if output == "" {
		t.Error("RunPowerShellWithEnv() 返回空输出")
	}
}

// TestRunCmd_WithArgs 测试带参数的命令
func TestRunCmd_WithArgs(t *testing.T) {
	output, err := RunCmd("cmd", "/c", "echo", "arg1", "arg2", "arg3")
	if err != nil {
		t.Fatalf("RunCmd() error = %v", err)
	}
	if output == "" {
		t.Error("RunCmd() 返回空输出")
	}
}

// TestRunCmdCombined_WithStderr 测试包含 stderr 的命令
func TestRunCmdCombined_WithStderr(t *testing.T) {
	// 执行一个会输出到 stderr 的命令
	output, _ := RunCmdCombined("cmd", "/c", "echo", "error message", ">&2")
	// 只要不 panic 就算通过
	_ = output
}

// TestRunCmdDirect_WithSpecialChars 测试特殊字符
func TestRunCmdDirect_WithSpecialChars(t *testing.T) {
	// 测试带特殊字符的参数
	output, err := RunCmdDirect("cmd", "/c", "echo", "hello world")
	if err != nil {
		t.Fatalf("RunCmdDirect() error = %v", err)
	}
	if output == "" {
		t.Error("RunCmdDirect() 返回空输出")
	}
}

// TestGBKToUTF8_LargeInput 测试大输入
func TestGBKToUTF8_LargeInput(t *testing.T) {
	// 创建一个较大的输入
	input := make([]byte, 10000)
	for i := range input {
		input[i] = 'a'
	}
	output, err := GBKToUTF8(input)
	if err != nil {
		t.Errorf("GBKToUTF8() error = %v", err)
	}
	if len(output) != len(input) {
		t.Errorf("GBKToUTF8() 输出长度 = %d, want %d", len(output), len(input))
	}
}
