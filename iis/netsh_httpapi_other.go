//go:build !windows

package iis

// queryFullBinding 在非 Windows 平台无 httpapi.dll，返回 nil 使 captureBinding 降级为最小捕获。
// 生产二进制仅面向 Windows；此桩仅用于跨平台编译与纯逻辑测试。
func queryFullBinding(keyParam, keyValue string) *capturedBinding {
	return nil
}
