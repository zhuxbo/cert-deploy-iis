package iis

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// SiteInfo IIS 站点信息
type SiteInfo struct {
	ID       int64
	Name     string
	State    string
	Bindings []BindingInfo
}

// BindingInfo 绑定信息
type BindingInfo struct {
	Protocol  string
	IP        string
	Port      int
	Host      string
	CertHash  string
	CertStore string
	HasSSL    bool
	SSLFlags  int // 0=IP-based, 1=SNI, 2=Central Certificate Store
}

// CertInfo 证书信息
type CertInfo struct {
	Thumbprint   string
	Subject      string
	Issuer       string
	NotBefore    time.Time
	NotAfter     time.Time
	FriendlyName string
	HasPrivKey   bool
}

// BindResult 绑定操作结果
type BindResult struct {
	Success bool
	Message string
}

// EndpointKey 唯一标识一个 HTTP.sys SSL 绑定端点。
type EndpointKey struct {
	IPBinding bool
	Host      string
	Port      int
}

// NormalizeEndpoint 规范化配置或绑定端点。配置端口 0 使用 HTTPS 默认端口 443。
func NormalizeEndpoint(ipBinding bool, host string, port int) (EndpointKey, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return EndpointKey{}, fmt.Errorf("绑定主机不能为空")
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return EndpointKey{}, fmt.Errorf("绑定端口 %d 无效", port)
	}

	if ipBinding {
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			return EndpointKey{}, fmt.Errorf("IP 绑定地址 %q 无效", host)
		}
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if host == "" || strings.Contains(host, ":") {
			return EndpointKey{}, fmt.Errorf("SNI 主机名 %q 无效", host)
		}
	}

	return EndpointKey{IPBinding: ipBinding, Host: host, Port: port}, nil
}
