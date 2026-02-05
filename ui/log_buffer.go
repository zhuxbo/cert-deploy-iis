package ui

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

// LogBuffer 日志缓存组件
type LogBuffer struct {
	mu       sync.Mutex
	lines    []string
	maxLines int
	edit     *ui.Edit
}

// NewLogBuffer 创建新的日志缓存
func NewLogBuffer(edit *ui.Edit, maxLines int) *LogBuffer {
	if maxLines <= 0 {
		maxLines = 100
	}
	return &LogBuffer{
		lines:    make([]string, 0, maxLines),
		maxLines: maxLines,
		edit:     edit,
	}
}

// Append 追加日志行（带时间戳）
func (lb *LogBuffer) Append(text string) {
	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s", timestamp, text)
	lb.AppendRaw(logLine)
}

// AppendRaw 追加原始日志行（不带时间戳）
func (lb *LogBuffer) AppendRaw(text string) {
	lb.mu.Lock()
	lb.lines = append(lb.lines, text)
	needRebuild := len(lb.lines) > lb.maxLines
	if needRebuild {
		lb.lines = lb.lines[len(lb.lines)-lb.maxLines:]
	}
	var fullText string
	if needRebuild {
		fullText = strings.Join(lb.lines, "\r\n") + "\r\n"
	}
	lb.mu.Unlock()

	// UI 操作放在锁外避免死锁
	if needRebuild {
		lb.edit.SetText(fullText)
	} else {
		// 追加新行到末尾
		textLen, _ := lb.edit.Hwnd().SendMessage(co.WM_GETTEXTLENGTH, 0, 0)
		lb.edit.Hwnd().SendMessage(EM_SETSEL, win.WPARAM(textLen), win.LPARAM(textLen))
		newText := text + "\r\n"
		ptr, _ := syscall.UTF16PtrFromString(newText)
		lb.edit.Hwnd().SendMessage(EM_REPLACESEL, 0, win.LPARAM(unsafe.Pointer(ptr)))
	}

	// 滚动到底部
	lb.edit.Hwnd().SendMessage(EM_LINESCROLL, 0, 0xFFFF)
}

// Clear 清空日志
func (lb *LogBuffer) Clear() {
	lb.mu.Lock()
	lb.lines = lb.lines[:0]
	lb.mu.Unlock()
	lb.edit.SetText("")
}

// GetLines 获取所有日志行
func (lb *LogBuffer) GetLines() []string {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	result := make([]string, len(lb.lines))
	copy(result, lb.lines)
	return result
}

// LineCount 返回当前日志行数
func (lb *LogBuffer) LineCount() int {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	return len(lb.lines)
}

// SetMaxLines 设置最大行数
func (lb *LogBuffer) SetMaxLines(max int) {
	if max <= 0 {
		return
	}
	lb.mu.Lock()
	lb.maxLines = max
	var fullText string
	needRebuild := len(lb.lines) > max
	if needRebuild {
		lb.lines = lb.lines[len(lb.lines)-max:]
		fullText = strings.Join(lb.lines, "\r\n") + "\r\n"
	}
	lb.mu.Unlock()
	if needRebuild {
		lb.edit.SetText(fullText)
	}
}
