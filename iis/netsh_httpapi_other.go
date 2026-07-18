//go:build !windows

package iis

import "errors"

// queryFullBinding 在非 Windows 平台无 httpapi.dll，返回 error 使 captureBinding 降级为最小捕获。
// 生产二进制仅面向 Windows；此桩仅用于跨平台编译与纯逻辑测试。
func queryFullBinding(keyParam, keyValue string) (*capturedBinding, error) {
	return nil, errors.New("当前平台不支持 httpapi SSL 绑定查询")
}
