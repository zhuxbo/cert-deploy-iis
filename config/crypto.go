package config

import (
	"encoding/base64"
	"syscall"
	"unsafe"
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

	return base64.StdEncoding.EncodeToString(output), nil
}

// DecryptToken 使用 DPAPI 解密 Token
func DecryptToken(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}

	input, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		// 可能是旧版明文 Token，直接返回
		return encrypted, nil
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
		// 解密失败，可能是明文 Token
		return encrypted, nil
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outputBlob.pbData)))

	output := make([]byte, outputBlob.cbData)
	copy(output, unsafe.Slice(outputBlob.pbData, outputBlob.cbData))

	return string(output), nil
}
