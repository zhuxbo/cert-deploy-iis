//go:build windows

package iis

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// 通过 httpapi.dll 的 HttpQueryServiceConfiguration 结构化查询 SSL 绑定完整参数（locale 无关）。
// 结构定义严格对齐 MSDN（http.h）；任何失败均返回 nil，由 captureBinding 降级为 netsh 最小捕获。

var (
	dllHTTPAPI                        = syscall.NewLazyDLL("httpapi.dll")
	procHTTPInitialize                = dllHTTPAPI.NewProc("HttpInitialize")
	procHTTPTerminate                 = dllHTTPAPI.NewProc("HttpTerminate")
	procHTTPQueryServiceConfiguration = dllHTTPAPI.NewProc("HttpQueryServiceConfiguration")
)

const (
	// HTTP_INITIALIZE_CONFIG：初始化配置管理功能（查询/设置服务配置所需）
	httpInitializeConfig = 0x00000002

	// HTTP_SERVICE_CONFIG_ID 枚举
	httpServiceConfigSSLCertInfo    = 1 // ipport 绑定（HttpServiceConfigSSLCertInfo）
	httpServiceConfigSSLSniCertInfo = 5 // hostnameport SNI 绑定（HttpServiceConfigSslSniCertInfo）

	// HTTP_SERVICE_CONFIG_QUERY_TYPE
	httpServiceConfigQueryExact = 0

	afInet = 2 // AF_INET（IPv4）

	errorInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
)

// guidLE 对应 Windows GUID（Data1/Data2/Data3 为主机字节序，Data4 为字节数组）
type guidLE struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// httpServiceConfigSSLParam 对应 HTTP_SERVICE_CONFIG_SSL_PARAM
type httpServiceConfigSSLParam struct {
	SslHashLength                        uint32
	pSslHash                             uintptr
	AppID                                guidLE
	pSslCertStoreName                    uintptr
	DefaultCertCheckMode                 uint32
	DefaultRevocationFreshnessTime       uint32
	DefaultRevocationURLRetrievalTimeout uint32
	pDefaultSslCtlIdentifier             uintptr
	pDefaultSslCtlStoreName              uintptr
	DefaultFlags                         uint32
}

// httpServiceConfigSSLKey 对应 HTTP_SERVICE_CONFIG_SSL_KEY { PSOCKADDR pIpPort }
type httpServiceConfigSSLKey struct {
	pIpPort uintptr
}

// httpServiceConfigSSLQuery 对应 HTTP_SERVICE_CONFIG_SSL_QUERY
type httpServiceConfigSSLQuery struct {
	QueryDesc uint32
	KeyDesc   httpServiceConfigSSLKey
	dwToken   uint32
}

// httpServiceConfigSSLSet 对应 HTTP_SERVICE_CONFIG_SSL_SET
type httpServiceConfigSSLSet struct {
	KeyDesc   httpServiceConfigSSLKey
	ParamDesc httpServiceConfigSSLParam
}

// httpServiceConfigSSLSniKey 对应 HTTP_SERVICE_CONFIG_SSL_SNI_KEY
// IpPort 为 SOCKADDR_STORAGE（128 字节），Host 为 PWSTR
type httpServiceConfigSSLSniKey struct {
	IpPort [128]byte
	Host   uintptr
}

// httpServiceConfigSSLSniQuery 对应 HTTP_SERVICE_CONFIG_SSL_SNI_QUERY
type httpServiceConfigSSLSniQuery struct {
	QueryDesc uint32
	KeyDesc   httpServiceConfigSSLSniKey
	dwToken   uint32
}

// httpServiceConfigSSLSniSet 对应 HTTP_SERVICE_CONFIG_SSL_SNI_SET
type httpServiceConfigSSLSniSet struct {
	KeyDesc   httpServiceConfigSSLSniKey
	ParamDesc httpServiceConfigSSLParam
}

// queryFullBinding 经 httpapi 结构化查询捕获绑定完整参数；失败返回 nil（调用方降级）。
// keyParam: "ipport"（IPv4）或 "hostnameport"（SNI）；SNI 与 IPv6 ipport 之外的场景返回 nil。
func queryFullBinding(keyParam, keyValue string) *capturedBinding {
	host := ParseHostFromBinding(keyValue)
	port := ParsePortFromBinding(keyValue)
	if host == "" || port <= 0 || port > 65535 {
		return nil
	}

	// HttpInitialize(HTTPAPI_VERSION{1,0} 打包为 uintptr(1), HTTP_INITIALIZE_CONFIG, NULL)
	if ret, _, _ := procHTTPInitialize.Call(uintptr(1), uintptr(httpInitializeConfig), 0); ret != 0 {
		return nil
	}
	defer func() { _, _, _ = procHTTPTerminate.Call(uintptr(httpInitializeConfig), 0) }()

	switch keyParam {
	case "ipport":
		return queryIPPortBinding(host, port)
	case "hostnameport":
		return querySNIBinding(host, port)
	default:
		return nil
	}
}

// queryIPPortBinding 查询 ipport（IPv4）绑定
func queryIPPortBinding(ip string, port int) *capturedBinding {
	var sa [16]byte // sockaddr_in
	if !fillSockaddrIn4(sa[:], ip, port) {
		return nil // 非 IPv4（含 IPv6 通配），降级
	}
	query := httpServiceConfigSSLQuery{
		QueryDesc: httpServiceConfigQueryExact,
		KeyDesc:   httpServiceConfigSSLKey{pIpPort: uintptr(unsafe.Pointer(&sa[0]))},
	}
	buf := queryServiceConfig(httpServiceConfigSSLCertInfo, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(&sa)
	runtime.KeepAlive(&query)
	if buf == nil || len(buf) < int(unsafe.Sizeof(httpServiceConfigSSLSet{})) {
		return nil
	}
	set := (*httpServiceConfigSSLSet)(unsafe.Pointer(&buf[0]))
	return parseSSLParam(&set.ParamDesc, buf)
}

// querySNIBinding 查询 hostnameport（SNI）绑定，IpPort 用 IPv4 通配 0.0.0.0:port
func querySNIBinding(host string, port int) *capturedBinding {
	hostPtr, err := syscall.UTF16PtrFromString(host)
	if err != nil {
		return nil
	}
	var key httpServiceConfigSSLSniKey
	if !fillSockaddrIn4(key.IpPort[:], "0.0.0.0", port) {
		return nil
	}
	key.Host = uintptr(unsafe.Pointer(hostPtr))
	query := httpServiceConfigSSLSniQuery{
		QueryDesc: httpServiceConfigQueryExact,
		KeyDesc:   key,
	}
	buf := queryServiceConfig(httpServiceConfigSSLSniCertInfo, unsafe.Pointer(&query), unsafe.Sizeof(query))
	runtime.KeepAlive(hostPtr)
	runtime.KeepAlive(&query)
	if buf == nil || len(buf) < int(unsafe.Sizeof(httpServiceConfigSSLSniSet{})) {
		return nil
	}
	set := (*httpServiceConfigSSLSniSet)(unsafe.Pointer(&buf[0]))
	return parseSSLParam(&set.ParamDesc, buf)
}

// queryServiceConfig 执行 HttpQueryServiceConfiguration，处理缓冲区不足重试；失败返回 nil。
// 返回的缓冲区 8 字节对齐，供结构体指针安全解引用。
func queryServiceConfig(configID uint32, input unsafe.Pointer, inputLen uintptr) []byte {
	buf := alignedBuf(4096)
	var retLen uint32
	ret, _, _ := procHTTPQueryServiceConfiguration.Call(
		0,
		uintptr(configID),
		uintptr(input),
		inputLen,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
		0,
	)
	if ret == errorInsufficientBuffer && retLen > uint32(len(buf)) {
		buf = alignedBuf(int(retLen))
		ret, _, _ = procHTTPQueryServiceConfiguration.Call(
			0,
			uintptr(configID),
			uintptr(input),
			inputLen,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&retLen)),
			0,
		)
	}
	if ret != 0 {
		return nil // 未查到 / 错误：降级
	}
	return buf
}

// parseSSLParam 从 HTTP_SERVICE_CONFIG_SSL_PARAM 提取完整绑定参数；异常返回 nil（降级）。
func parseSSLParam(p *httpServiceConfigSSLParam, buf []byte) *capturedBinding {
	hash := readBufBytes(buf, p.pSslHash, p.SslHashLength)
	// 证书哈希应为 SHA-1(20) 或 SHA-256(32)，否则视为结构解析异常，降级
	if len(hash) != 20 && len(hash) != 32 {
		return nil
	}
	b := &capturedBinding{
		CertHash:                strings.ToLower(hex.EncodeToString(hash)),
		AppID:                   formatGUID(p.AppID),
		CertStoreName:           storeOrDefault(readBufWString(buf, p.pSslCertStoreName)),
		full:                    true,
		certCheckMode:           p.DefaultCertCheckMode,
		revocationFreshnessTime: p.DefaultRevocationFreshnessTime,
		urlRetrievalTimeout:     p.DefaultRevocationURLRetrievalTimeout,
		sslCtlIdentifier:        readBufWString(buf, p.pDefaultSslCtlIdentifier),
		sslCtlStoreName:         readBufWString(buf, p.pDefaultSslCtlStoreName),
		defaultFlags:            p.DefaultFlags,
	}
	return b
}

// fillSockaddrIn4 将 IPv4 地址与端口写入 sockaddr_in 起始字节；非 IPv4 返回 false
func fillSockaddrIn4(dst []byte, ipStr string, port int) bool {
	if len(dst) < 8 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	binary.LittleEndian.PutUint16(dst[0:2], afInet)    // sin_family
	binary.BigEndian.PutUint16(dst[2:4], uint16(port)) // sin_port（网络字节序）
	copy(dst[4:8], ip4)                                // sin_addr
	return true
}

// formatGUID 按 netsh appid 形态格式化 GUID（小写、大括号）
func formatGUID(g guidLE) string {
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// alignedBuf 分配 8 字节对齐的字节缓冲区（供结构体指针安全解引用）
func alignedBuf(size int) []byte {
	if size <= 0 {
		size = 8
	}
	u := make([]uint64, (size+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*8)
}

// ptrOffsetInBuf 校验 ptr 落在 buf 范围内并返回偏移
func ptrOffsetInBuf(buf []byte, ptr uintptr) (int, bool) {
	if ptr == 0 || len(buf) == 0 {
		return 0, false
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	if ptr < base || ptr >= base+uintptr(len(buf)) {
		return 0, false
	}
	return int(ptr - base), true
}

// readBufBytes 从 buf 内 ptr 处读取 n 字节（越界返回 nil）
func readBufBytes(buf []byte, ptr uintptr, n uint32) []byte {
	off, ok := ptrOffsetInBuf(buf, ptr)
	if !ok || n == 0 || off+int(n) > len(buf) {
		return nil
	}
	out := make([]byte, n)
	copy(out, buf[off:off+int(n)])
	return out
}

// readBufWString 从 buf 内 ptr 处读取 NUL 结尾的 UTF-16 字符串（越界/空返回 ""）
func readBufWString(buf []byte, ptr uintptr) string {
	off, ok := ptrOffsetInBuf(buf, ptr)
	if !ok {
		return ""
	}
	var u16 []uint16
	for i := off; i+1 < len(buf); i += 2 {
		c := binary.LittleEndian.Uint16(buf[i : i+2])
		if c == 0 {
			break
		}
		u16 = append(u16, c)
	}
	return string(utf16.Decode(u16))
}
