package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wintrust           = syscall.NewLazyDLL("wintrust.dll")
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	procWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject = crypt32.NewProc("CryptQueryObject")
	procCertGetNameStringW = crypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
	procCryptMsgClose = crypt32.NewProc("CryptMsgClose")
	procCertCloseStore = crypt32.NewProc("CertCloseStore")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCertFindCertificateInStore = crypt32.NewProc("CertFindCertificateInStore")
)

// Windows 常量
const (
	INVALID_HANDLE_VALUE          = ^uintptr(0)
	WTD_UI_NONE                   = 2
	WTD_REVOKE_NONE               = 0
	WTD_CHOICE_FILE               = 1
	WTD_STATEACTION_VERIFY        = 1
	WTD_STATEACTION_CLOSE         = 2
	TRUST_E_NOSIGNATURE           = 0x800B0100
	TRUST_E_SUBJECT_NOT_TRUSTED   = 0x800B0004
	TRUST_E_PROVIDER_UNKNOWN      = 0x800B0001
	CERT_QUERY_OBJECT_FILE        = 1
	CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
	CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
	CMSG_SIGNER_INFO_PARAM        = 6
	CERT_FIND_SUBJECT_CERT        = 0x00020007
	CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
	CERT_NAME_ATTR_TYPE           = 3
	szOID_COMMON_NAME             = "2.5.4.3"
	szOID_ORGANIZATION_NAME       = "2.5.4.10"
	szOID_COUNTRY_NAME            = "2.5.4.6"
)

// GUID for WINTRUST_ACTION_GENERIC_VERIFY_V2
var WINTRUST_ACTION_GENERIC_VERIFY_V2 = syscall.GUID{
	Data1: 0xaac56b,
	Data2: 0xcd44,
	Data3: 0x11d0,
	Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
}

// WINTRUST_FILE_INFO 结构
type WINTRUST_FILE_INFO struct {
	cbStruct       uint32
	pcwszFilePath  *uint16
	hFile          syscall.Handle
	pgKnownSubject *syscall.GUID
}

// WINTRUST_DATA 结构
type WINTRUST_DATA struct {
	cbStruct            uint32
	pPolicyCallbackData uintptr
	pSIPClientData      uintptr
	dwUIChoice          uint32
	fdwRevocationChecks uint32
	dwUnionChoice       uint32
	pFile               *WINTRUST_FILE_INFO
	dwStateAction       uint32
	hWVTStateData       syscall.Handle
	pwszURLReference    *uint16
	dwProvFlags         uint32
	dwUIContext         uint32
	pSignatureSettings  uintptr
}

// CMSG_SIGNER_INFO 结构
type CMSG_SIGNER_INFO struct {
	dwVersion                   uint32
	Issuer                      CRYPT_DATA_BLOB
	SerialNumber                CRYPT_DATA_BLOB
	HashAlgorithm               CRYPT_ALGORITHM_IDENTIFIER
	HashEncryptionAlgorithm     CRYPT_ALGORITHM_IDENTIFIER
	EncryptedHash               CRYPT_DATA_BLOB
	AuthAttrs                   CRYPT_ATTRIBUTES
	UnauthAttrs                 CRYPT_ATTRIBUTES
}

type CRYPT_DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type CRYPT_ALGORITHM_IDENTIFIER struct {
	pszObjId   *byte
	Parameters CRYPT_DATA_BLOB
}

type CRYPT_ATTRIBUTES struct {
	cAttr  uint32
	rgAttr uintptr
}

type CERT_INFO struct {
	dwVersion            uint32
	SerialNumber         CRYPT_DATA_BLOB
	SignatureAlgorithm   CRYPT_ALGORITHM_IDENTIFIER
	Issuer               CRYPT_DATA_BLOB
	NotBefore            syscall.Filetime
	NotAfter             syscall.Filetime
	Subject              CRYPT_DATA_BLOB
	SubjectPublicKeyInfo uintptr // 简化
	IssuerUniqueId       CRYPT_DATA_BLOB
	SubjectUniqueId      CRYPT_DATA_BLOB
	cExtension           uint32
	rgExtension          uintptr
}

type CERT_CONTEXT struct {
	dwCertEncodingType uint32
	pbCertEncoded      *byte
	cbCertEncoded      uint32
	pCertInfo          *CERT_INFO
	hCertStore         syscall.Handle
}

// AuthenticodeVerifier Authenticode 签名验证器
type AuthenticodeVerifier struct{}

// NewAuthenticodeVerifier 创建验证器
func NewAuthenticodeVerifier() *AuthenticodeVerifier {
	return &AuthenticodeVerifier{}
}

// Verify 验证文件签名
func (v *AuthenticodeVerifier) Verify(filePath string, trustedFingerprints []string, fallbackConfig *FallbackVerifyConfig) (*VerifyResult, error) {
	result := &VerifyResult{
		Valid: false,
	}

	// 1. 验证 Authenticode 签名有效性
	if err := v.verifySignature(filePath); err != nil {
		result.Message = fmt.Sprintf("签名验证失败: %v", err)
		return result, nil
	}

	// 2. 获取签名证书信息
	certInfo, err := v.getCertificateInfo(filePath)
	if err != nil {
		result.Message = fmt.Sprintf("获取证书信息失败: %v", err)
		return result, nil
	}

	result.Fingerprint = certInfo.fingerprint
	result.Subject = certInfo.subject
	result.Organization = certInfo.organization
	result.Country = certInfo.country
	result.Issuer = certInfo.issuer
	result.Valid = true

	// 3. 检查指纹是否在白名单中
	for _, fp := range trustedFingerprints {
		if strings.EqualFold(fp, certInfo.fingerprint) {
			result.FingerprintMatch = true
			result.Message = "签名验证通过（指纹匹配）"
			return result, nil
		}
	}

	// 4. 指纹不匹配，进入回退验证
	if fallbackConfig == nil {
		result.Valid = false
		result.Message = "证书指纹不在白名单中"
		return result, nil
	}

	result.FallbackUsed = true

	// 验证组织名称
	if fallbackConfig.TrustedOrg != "" {
		if !strings.EqualFold(certInfo.organization, fallbackConfig.TrustedOrg) {
			result.Valid = false
			result.Message = fmt.Sprintf("组织名称不匹配: 期望 %s, 实际 %s", fallbackConfig.TrustedOrg, certInfo.organization)
			return result, nil
		}
	}

	// 验证国家代码
	if fallbackConfig.TrustedCountry != "" {
		if !strings.EqualFold(certInfo.country, fallbackConfig.TrustedCountry) {
			result.Valid = false
			result.Message = fmt.Sprintf("国家代码不匹配: 期望 %s, 实际 %s", fallbackConfig.TrustedCountry, certInfo.country)
			return result, nil
		}
	}

	// 验证 CA
	if len(fallbackConfig.TrustedCAs) > 0 {
		caMatched := false
		for _, ca := range fallbackConfig.TrustedCAs {
			if strings.Contains(strings.ToLower(certInfo.issuer), strings.ToLower(ca)) {
				caMatched = true
				break
			}
		}
		if !caMatched {
			result.Valid = false
			result.Message = fmt.Sprintf("CA 不在可信列表中: %s", certInfo.issuer)
			return result, nil
		}
	}

	// 回退验证通过，需要用户确认
	result.NeedsConfirm = true
	result.Message = fmt.Sprintf("证书指纹已更新，请确认是否信任新证书\n组织: %s\n国家: %s\nCA: %s\n指纹: %s",
		certInfo.organization, certInfo.country, certInfo.issuer, certInfo.fingerprint)

	return result, nil
}

// verifySignature 使用 WinVerifyTrust 验证签名
func (v *AuthenticodeVerifier) verifySignature(filePath string) error {
	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return err
	}

	fileInfo := WINTRUST_FILE_INFO{
		cbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		pcwszFilePath: filePathPtr,
		hFile:         0,
	}

	trustData := WINTRUST_DATA{
		cbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		dwUIChoice:          WTD_UI_NONE,
		fdwRevocationChecks: WTD_REVOKE_NONE,
		dwUnionChoice:       WTD_CHOICE_FILE,
		pFile:               &fileInfo,
		dwStateAction:       WTD_STATEACTION_VERIFY,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		INVALID_HANDLE_VALUE,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	// 清理状态
	trustData.dwStateAction = WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(
		INVALID_HANDLE_VALUE,
		uintptr(unsafe.Pointer(&WINTRUST_ACTION_GENERIC_VERIFY_V2)),
		uintptr(unsafe.Pointer(&trustData)),
	)

	if ret != 0 {
		switch ret {
		case TRUST_E_NOSIGNATURE:
			return fmt.Errorf("文件未签名")
		case TRUST_E_SUBJECT_NOT_TRUSTED:
			return fmt.Errorf("签名者不受信任")
		case TRUST_E_PROVIDER_UNKNOWN:
			return fmt.Errorf("未知的信任提供程序")
		default:
			return fmt.Errorf("签名验证失败: 0x%X", ret)
		}
	}

	return nil
}

// certificateInfo 证书信息
type certificateInfo struct {
	fingerprint  string
	subject      string
	organization string
	country      string
	issuer       string
}

// getCertificateInfo 获取签名证书信息
func (v *AuthenticodeVerifier) getCertificateInfo(filePath string) (*certificateInfo, error) {
	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return nil, err
	}

	var dwEncoding, dwContentType, dwFormatType uint32
	var hStore, hMsg syscall.Handle
	var pCertContext *CERT_CONTEXT

	ret, _, err := procCryptQueryObject.Call(
		CERT_QUERY_OBJECT_FILE,
		uintptr(unsafe.Pointer(filePathPtr)),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		uintptr(unsafe.Pointer(&dwEncoding)),
		uintptr(unsafe.Pointer(&dwContentType)),
		uintptr(unsafe.Pointer(&dwFormatType)),
		uintptr(unsafe.Pointer(&hStore)),
		uintptr(unsafe.Pointer(&hMsg)),
		uintptr(unsafe.Pointer(&pCertContext)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptQueryObject 失败: %v", err)
	}

	defer func() {
		// 释放 CryptQueryObject 返回的证书上下文
		if pCertContext != nil {
			procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(pCertContext)))
		}
		if hStore != 0 {
			procCertCloseStore.Call(uintptr(hStore), 0)
		}
		if hMsg != 0 {
			procCryptMsgClose.Call(uintptr(hMsg))
		}
	}()

	// 获取签名者信息大小
	var signerInfoSize uint32
	ret, _, _ = procCryptMsgGetParam.Call(
		uintptr(hMsg),
		CMSG_SIGNER_INFO_PARAM,
		0,
		0,
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)

	if ret == 0 || signerInfoSize == 0 {
		return nil, fmt.Errorf("获取签名者信息大小失败")
	}

	// 获取签名者信息
	signerInfoBuf := make([]byte, signerInfoSize)
	ret, _, _ = procCryptMsgGetParam.Call(
		uintptr(hMsg),
		CMSG_SIGNER_INFO_PARAM,
		0,
		uintptr(unsafe.Pointer(&signerInfoBuf[0])),
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("获取签名者信息失败")
	}

	signerInfo := (*CMSG_SIGNER_INFO)(unsafe.Pointer(&signerInfoBuf[0]))

	// 构造 CERT_INFO 用于查找证书
	certInfoForSearch := CERT_INFO{
		Issuer:       signerInfo.Issuer,
		SerialNumber: signerInfo.SerialNumber,
	}

	// 在存储中查找证书
	certCtx, _, _ := procCertFindCertificateInStore.Call(
		uintptr(hStore),
		uintptr(0x00000001|0x00010000), // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
		0,
		CERT_FIND_SUBJECT_CERT,
		uintptr(unsafe.Pointer(&certInfoForSearch)),
		0,
	)

	if certCtx == 0 {
		return nil, fmt.Errorf("未找到签名证书")
	}

	// Windows API 返回的 certCtx 是有效的指针，转换为 CERT_CONTEXT 是安全的
	// nolint:gosec // G103: Windows API 交互必须使用 unsafe.Pointer
	pCert := (*CERT_CONTEXT)(unsafe.Pointer(certCtx))
	defer procCertFreeCertificateContext.Call(certCtx)

	// 获取证书信息
	info := &certificateInfo{}

	// 计算指纹 (SHA-256)
	// 使用 unsafe.Slice 安全地创建证书数据切片 (Go 1.17+)
	certData := unsafe.Slice(pCert.pbCertEncoded, pCert.cbCertEncoded)
	hash := sha256.Sum256(certData)
	info.fingerprint = strings.ToUpper(hex.EncodeToString(hash[:]))

	// 获取主题名称
	info.subject = v.getCertNameString(certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, "")
	info.organization = v.getCertNameString(certCtx, CERT_NAME_ATTR_TYPE, 0, szOID_ORGANIZATION_NAME)
	info.country = v.getCertNameString(certCtx, CERT_NAME_ATTR_TYPE, 0, szOID_COUNTRY_NAME)

	// 获取颁发者 (CERT_NAME_ISSUER_FLAG = 0x1)
	info.issuer = v.getCertNameString(certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0x1, "")

	return info, nil
}

// getCertNameString 获取证书名称字符串
// dwFlags: 0 获取主题名称，CERT_NAME_ISSUER_FLAG (0x1) 获取颁发者名称
func (v *AuthenticodeVerifier) getCertNameString(certCtx uintptr, dwType uint32, dwFlags uint32, pszOID string) string {
	var oidPtr uintptr
	var oidBytes []byte
	if pszOID != "" {
		oidBytes = append([]byte(pszOID), 0)
		oidPtr = uintptr(unsafe.Pointer(&oidBytes[0]))
	}

	// 获取所需缓冲区大小
	sizeRet, _, _ := procCertGetNameStringW.Call(
		certCtx,
		uintptr(dwType),
		uintptr(dwFlags),
		oidPtr,
		0,
		0,
	)

	// 范围检查并转换为 int
	if sizeRet <= 1 || sizeRet > 4096 {
		runtime.KeepAlive(oidBytes)
		return ""
	}
	size := int(sizeRet)

	// 获取名称
	buf := make([]uint16, size)
	procCertGetNameStringW.Call(
		certCtx,
		uintptr(dwType),
		uintptr(dwFlags),
		oidPtr,
		uintptr(unsafe.Pointer(&buf[0])),
		sizeRet,
	)

	// 确保 oidBytes 在 syscall 期间不被 GC
	runtime.KeepAlive(oidBytes)

	return syscall.UTF16ToString(buf)
}
