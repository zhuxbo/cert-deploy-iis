package util

import "unicode/utf8"

// TruncateString 安全截断字符串，不会切断多字节 UTF-8 字符
// maxBytes: 最大字节数
func TruncateString(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	// 从 maxBytes 位置往回找到有效的 UTF-8 边界
	for maxBytes > 0 && !utf8.RuneStart(s[maxBytes]) {
		maxBytes--
	}
	return s[:maxBytes]
}
