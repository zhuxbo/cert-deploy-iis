package iis

import (
	"fmt"
)

// 命令执行 mock 函数类型
type RunCmdFunc func(name string, args ...string) (string, error)
type RunCmdCombinedFunc func(name string, args ...string) (string, error)

// MockRunCmd 用于测试的命令执行 mock
var (
	mockRunCmdFunc         RunCmdFunc
	mockRunCmdCombinedFunc RunCmdCombinedFunc
	mockEnabled            bool
)

// EnableMock 启用 mock 模式
func EnableMock() {
	mockEnabled = true
}

// DisableMock 禁用 mock 模式
func DisableMock() {
	mockEnabled = false
	mockRunCmdFunc = nil
	mockRunCmdCombinedFunc = nil
}

// SetMockRunCmd 设置 RunCmd 的 mock 函数
func SetMockRunCmd(fn RunCmdFunc) {
	mockRunCmdFunc = fn
}

// SetMockRunCmdCombined 设置 RunCmdCombined 的 mock 函数
func SetMockRunCmdCombined(fn RunCmdCombinedFunc) {
	mockRunCmdCombinedFunc = fn
}

// 测试用的 appcmd 输出
const testAppcmdSiteListXML = `<?xml version="1.0" encoding="UTF-8"?>
<appcmd>
<SITE SITE.NAME="Default Web Site" SITE.ID="1" bindings="http/*:80:,https/*:443:www.example.com" state="Started" />
<SITE SITE.NAME="Test Site" SITE.ID="2" bindings="http/*:80:test.example.com,https/*:443:test.example.com" state="Started" />
<SITE SITE.NAME="Empty Site" SITE.ID="3" bindings="" state="Stopped" />
</appcmd>`

const testAppcmdEmptyXML = `<?xml version="1.0" encoding="UTF-8"?>
<appcmd>
</appcmd>`

// 测试用的 netsh 输出
const testNetshBindingOutput = `
SSL Certificate bindings:
-------------------------

    Hostname:port                : www.example.com:443
    Certificate Hash             : ABC123DEF456789012345678901234567890ABCD
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : My

    Hostname:port                : api.example.com:443
    Certificate Hash             : DEF456789012345678901234567890ABCDEF1234
    Application ID               : {4dc3e181-e14b-4a21-b022-59fc669b0914}
    Certificate Store Name       : My
`

const testNetshEmptyOutput = `
SSL Certificate bindings:
-------------------------

`

const testNetshSuccessOutput = `
SSL certificate successfully added
`

const testNetshSuccessOutputChinese = `
SSL 证书绑定添加成功
`

// MockSiteInfo 创建测试用的站点信息
func MockSiteInfo(id int64, name, state string, bindings []BindingInfo) SiteInfo {
	return SiteInfo{
		ID:       id,
		Name:     name,
		State:    state,
		Bindings: bindings,
	}
}

// MockBindingInfo 创建测试用的绑定信息
func MockBindingInfo(protocol, ip string, port int, host string, hasSSL bool) BindingInfo {
	return BindingInfo{
		Protocol: protocol,
		IP:       ip,
		Port:     port,
		Host:     host,
		HasSSL:   hasSSL,
	}
}

// MockSSLBinding 创建测试用的 SSL 绑定
func MockSSLBinding(hostnamePort, certHash, appID, storeName string) SSLBinding {
	return SSLBinding{
		HostnamePort:  hostnamePort,
		CertHash:      certHash,
		AppID:         appID,
		CertStoreName: storeName,
	}
}

// MockError 创建测试用的错误
func MockError(msg string) error {
	return fmt.Errorf("%s", msg)
}

// 测试常量
const (
	TestThumbprint      = "ABC123DEF456789012345678901234567890ABCD"
	TestThumbprintLower = "abc123def456789012345678901234567890abcd"
	TestDomain          = "www.example.com"
	TestWildcardDomain  = "*.example.com"
	TestPort            = 443
	TestSiteName        = "Default Web Site"
)
