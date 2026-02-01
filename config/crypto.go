package config

import (
	"encoding/base64"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

// EncryptionPrefix 加密版本前缀
const EncryptionPrefix = "v1:"

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
		0, 0, 0, 0,
		0,
		uintptr(unsafe.Pointer(&outputBlob)),
	)
	if r == 0 {
		return "", err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	output := make([]byte, outputBlob.cbData)
	copy(output, unsafe.Slice(outputBlob.pbData, outputBlob.cbData))

	return EncryptionPrefix + base64.StdEncoding.EncodeToString(output), nil
}

// DecryptToken 使用 DPAPI 解密 Token
func DecryptToken(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	if !strings.HasPrefix(encrypted, EncryptionPrefix) {
		return "", errors.New("无效的加密格式")
	}

	data := strings.TrimPrefix(encrypted, EncryptionPrefix)
	input, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.New("无效的加密数据")
	}

	inputBlob := dataBlob{
		cbData: uint32(len(input)),
		pbData: &input[0],
	}

	var outputBlob dataBlob
	r, _, err := procDecryptData.Call(
		uintptr(unsafe.Pointer(&inputBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outputBlob)),
	)
	if r == 0 {
		return "", errors.New("解密失败")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	output := make([]byte, outputBlob.cbData)
	copy(output, unsafe.Slice(outputBlob.pbData, outputBlob.cbData))

	return string(output), nil
}
