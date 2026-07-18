package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// EncryptionPrefix 旧的用户作用域加密前缀（仅用于兼容解密）
const EncryptionPrefix = "v1:"

// EncryptionPrefixMachine 机器作用域加密前缀（当前加密输出）
const EncryptionPrefixMachine = "vm:"

// DPAPI 标志常量
const (
	// CRYPTPROTECT_UI_FORBIDDEN 禁止在加密/解密过程中显示 UI
	cryptprotectUIForbidden = 0x1
	// CRYPTPROTECT_LOCAL_MACHINE 绑定到机器而非当前用户，SYSTEM 计划任务方可解密
	cryptprotectLocalMachine = 0x4
)

var (
	dllCrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllKernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procEncryptData = dllCrypt32.NewProc("CryptProtectData")
	procDecryptData = dllCrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllKernel32.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// EncryptToken 使用 DPAPI 加密 Token
func EncryptToken(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	input := []byte(plaintext)
	inputBlob := dataBlob{
		cbData: uint32(len(input)),
		pbData: &input[0],
	}

	var outputBlob dataBlob
	r, _, err := procEncryptData.Call(
		uintptr(unsafe.Pointer(&inputBlob)),
		0, // szDataDescr (可选描述)
		0, // pOptionalEntropy (可选熵)
		0, // pvReserved (保留)
		0, // pPromptStruct (提示结构)
		cryptprotectUIForbidden|cryptprotectLocalMachine, // dwFlags - 禁止 UI 弹窗 + 机器作用域
		uintptr(unsafe.Pointer(&outputBlob)),
	)
	if r == 0 {
		return "", err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	output := make([]byte, outputBlob.cbData)
	copy(output, unsafe.Slice(outputBlob.pbData, outputBlob.cbData))

	// 输出机器作用域前缀，便于识别并做幂等迁移
	return EncryptionPrefixMachine + base64.StdEncoding.EncodeToString(output), nil
}

// DecryptToken 使用 DPAPI 解密 Token
func DecryptToken(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	// 兼容机器作用域(vm:)与旧用户作用域(v1:)两种前缀；
	// DPAPI 解密由密文自身携带作用域信息，无需在标志中区分
	var data string
	switch {
	case strings.HasPrefix(encrypted, EncryptionPrefixMachine):
		data = strings.TrimPrefix(encrypted, EncryptionPrefixMachine)
	case strings.HasPrefix(encrypted, EncryptionPrefix):
		data = strings.TrimPrefix(encrypted, EncryptionPrefix)
	default:
		return "", errors.New("无效的加密格式")
	}

	input, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.New("无效的加密数据")
	}

	if len(input) == 0 {
		return "", errors.New("无效的加密数据")
	}

	inputBlob := dataBlob{
		cbData: uint32(len(input)),
		pbData: &input[0],
	}

	var outputBlob dataBlob
	r, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(&inputBlob)),
		0,                           // ppszDataDescr (输出描述)
		0,                           // pOptionalEntropy (可选熵)
		0,                           // pvReserved (保留)
		0,                           // pPromptStruct (提示结构)
		cryptprotectUIForbidden,     // dwFlags - 禁止 UI 弹窗
		uintptr(unsafe.Pointer(&outputBlob)),
	)
	if r == 0 {
		return "", errors.New("解密失败")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	output := make([]byte, outputBlob.cbData)
	copy(output, unsafe.Slice(outputBlob.pbData, outputBlob.cbData))
	result := string(output)

	// 清零中间 byte slice，减少内存中明文残留
	for i := range output {
		output[i] = 0
	}

	return result, nil
}

// TokenNeedsMigration 判断密文是否为旧的用户作用域格式（需迁移到机器作用域）
// 纯字符串判定，不触发 DPAPI，便于测试
func TokenNeedsMigration(encrypted string) bool {
	if encrypted == "" {
		return false
	}
	if strings.HasPrefix(encrypted, EncryptionPrefixMachine) {
		return false
	}
	return strings.HasPrefix(encrypted, EncryptionPrefix)
}
