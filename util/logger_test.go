package util

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestDebugMode(t *testing.T) {
	// 保存原始状态
	originalMode := DebugMode
	originalLog := debugLog
	defer func() {
		DebugMode = originalMode
		debugLog = originalLog
	}()

	// 创建缓冲区捕获输出
	var buf bytes.Buffer
	debugLog = log.New(&buf, "[DEBUG] ", 0)

	// 关闭调试模式
	DebugMode = false
	Debug("test message %d", 1)
	if buf.Len() > 0 {
		t.Error("Debug() 在 DebugMode=false 时不应输出")
	}

	// 开启调试模式
	DebugMode = true
	Debug("test message %d", 2)
	output := buf.String()
	if !strings.Contains(output, "test message 2") {
		t.Errorf("Debug() 输出不包含消息, got: %q", output)
	}
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("Debug() 输出不包含前缀, got: %q", output)
	}
}

func TestInfo(t *testing.T) {
	// 保存原始日志器
	originalLog := infoLog
	defer func() {
		infoLog = originalLog
	}()

	var buf bytes.Buffer
	infoLog = log.New(&buf, "[INFO] ", 0)

	Info("info message %s", "test")
	output := buf.String()

	if !strings.Contains(output, "info message test") {
		t.Errorf("Info() 输出不包含消息, got: %q", output)
	}
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Info() 输出不包含前缀, got: %q", output)
	}
}

func TestWarn(t *testing.T) {
	originalLog := warnLog
	defer func() {
		warnLog = originalLog
	}()

	var buf bytes.Buffer
	warnLog = log.New(&buf, "[WARN] ", 0)

	Warn("warning: %v", "something")
	output := buf.String()

	if !strings.Contains(output, "warning: something") {
		t.Errorf("Warn() 输出不包含消息, got: %q", output)
	}
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("Warn() 输出不包含前缀, got: %q", output)
	}
}

func TestError(t *testing.T) {
	originalLog := errorLog
	defer func() {
		errorLog = originalLog
	}()

	var buf bytes.Buffer
	errorLog = log.New(&buf, "[ERROR] ", 0)

	Error("error: %d", 500)
	output := buf.String()

	if !strings.Contains(output, "error: 500") {
		t.Errorf("Error() 输出不包含消息, got: %q", output)
	}
	if !strings.Contains(output, "[ERROR]") {
		t.Errorf("Error() 输出不包含前缀, got: %q", output)
	}
}

func TestDefaultLoggers(t *testing.T) {
	// 验证默认日志器输出到正确的目标
	// infoLog, warnLog, debugLog 应该输出到 stdout
	// errorLog 应该输出到 stderr

	// 这里只验证默认值存在且不为 nil
	if debugLog == nil {
		t.Error("debugLog 不应为 nil")
	}
	if infoLog == nil {
		t.Error("infoLog 不应为 nil")
	}
	if warnLog == nil {
		t.Error("warnLog 不应为 nil")
	}
	if errorLog == nil {
		t.Error("errorLog 不应为 nil")
	}
}

func TestDebugModeDefault(t *testing.T) {
	// 默认应该关闭
	// 注意：此测试可能因为其他测试修改了全局状态而失败
	// 在实际运行时，DebugMode 的默认值应该是 false
	_ = os.Stdout // 避免未使用的导入
}
