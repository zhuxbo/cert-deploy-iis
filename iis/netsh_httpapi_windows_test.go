//go:build windows

package iis

import (
	"testing"
	"unsafe"
)

// TestHTTPAPIStructLayout 核对 httpapi 结构体内存布局与 MSDN http.h 一致（amd64）。
// 布局错位会导致 HttpQueryServiceConfiguration 读到错位数据；此测试在 Windows CI 上守护。
func TestHTTPAPIStructLayout(t *testing.T) {
	check := func(name string, got, want uintptr) {
		if got != want {
			t.Errorf("%s = %d, want %d", name, got, want)
		}
	}

	check("sizeof(guidLE)", unsafe.Sizeof(guidLE{}), 16)

	var p httpServiceConfigSSLParam
	check("sizeof(SSL_PARAM)", unsafe.Sizeof(p), 80)
	check("off SslHashLength", unsafe.Offsetof(p.SslHashLength), 0)
	check("off pSslHash", unsafe.Offsetof(p.pSslHash), 8)
	check("off AppID", unsafe.Offsetof(p.AppID), 16)
	check("off pSslCertStoreName", unsafe.Offsetof(p.pSslCertStoreName), 32)
	check("off DefaultCertCheckMode", unsafe.Offsetof(p.DefaultCertCheckMode), 40)
	check("off DefaultRevocationFreshnessTime", unsafe.Offsetof(p.DefaultRevocationFreshnessTime), 44)
	check("off DefaultRevocationURLRetrievalTimeout", unsafe.Offsetof(p.DefaultRevocationURLRetrievalTimeout), 48)
	check("off pDefaultSslCtlIdentifier", unsafe.Offsetof(p.pDefaultSslCtlIdentifier), 56)
	check("off pDefaultSslCtlStoreName", unsafe.Offsetof(p.pDefaultSslCtlStoreName), 64)
	check("off DefaultFlags", unsafe.Offsetof(p.DefaultFlags), 72)

	check("sizeof(SSL_KEY)", unsafe.Sizeof(httpServiceConfigSSLKey{}), 8)
	var q httpServiceConfigSSLQuery
	check("sizeof(SSL_QUERY)", unsafe.Sizeof(q), 24)
	check("off Q.KeyDesc", unsafe.Offsetof(q.KeyDesc), 8)
	check("off Q.dwToken", unsafe.Offsetof(q.dwToken), 16)
	var s httpServiceConfigSSLSet
	check("sizeof(SSL_SET)", unsafe.Sizeof(s), 88)
	check("off SET.KeyDesc", unsafe.Offsetof(s.KeyDesc), 0)
	check("off SET.ParamDesc", unsafe.Offsetof(s.ParamDesc), 8)

	var sk httpServiceConfigSSLSniKey
	check("sizeof(SNI_KEY)", unsafe.Sizeof(sk), 136)
	check("off SNI_KEY.Host", unsafe.Offsetof(sk.Host), 128)
	var sq httpServiceConfigSSLSniQuery
	check("sizeof(SNI_QUERY)", unsafe.Sizeof(sq), 152)
	check("off SNI_Q.KeyDesc", unsafe.Offsetof(sq.KeyDesc), 8)
	check("off SNI_Q.dwToken", unsafe.Offsetof(sq.dwToken), 144)
	var ss httpServiceConfigSSLSniSet
	check("sizeof(SNI_SET)", unsafe.Sizeof(ss), 216)
	check("off SNI_SET.KeyDesc", unsafe.Offsetof(ss.KeyDesc), 0)
	check("off SNI_SET.ParamDesc", unsafe.Offsetof(ss.ParamDesc), 136)
}

// TestFillSockaddrIn4 校验 sockaddr_in 字节写入（family/port 网络序/addr）
func TestFillSockaddrIn4(t *testing.T) {
	var sa [16]byte
	if !fillSockaddrIn4(sa[:], "1.2.3.4", 443) {
		t.Fatal("IPv4 应成功写入")
	}
	// sin_family = AF_INET(2) 小端
	if sa[0] != 2 || sa[1] != 0 {
		t.Errorf("sin_family = %v, want [2 0]", sa[0:2])
	}
	// sin_port = 443 = 0x01BB 网络序（大端）
	if sa[2] != 0x01 || sa[3] != 0xBB {
		t.Errorf("sin_port = %v, want [0x01 0xBB]", sa[2:4])
	}
	// sin_addr = 1.2.3.4
	if sa[4] != 1 || sa[5] != 2 || sa[6] != 3 || sa[7] != 4 {
		t.Errorf("sin_addr = %v, want [1 2 3 4]", sa[4:8])
	}
	// IPv6 应降级失败
	if fillSockaddrIn4(sa[:], "::1", 443) {
		t.Error("IPv6 应返回 false（降级）")
	}
}

// TestFormatGUID 校验 GUID 格式化与 netsh appid 形态一致
func TestFormatGUID(t *testing.T) {
	g := guidLE{Data1: 0x00112233, Data2: 0x4455, Data3: 0x6677, Data4: [8]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}}
	got := formatGUID(g)
	want := "{00112233-4455-6677-8899-aabbccddeeff}"
	if got != want {
		t.Errorf("formatGUID = %q, want %q", got, want)
	}
	// 全零 GUID 应等于 defaultAppID
	if z := formatGUID(guidLE{}); z != defaultAppID {
		t.Errorf("全零 GUID = %q, want %q", z, defaultAppID)
	}
}
