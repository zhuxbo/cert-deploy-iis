package iis

import "time"

// SiteInfo IIS 站点信息
type SiteInfo struct {
	ID       int64
	Name     string
	State    string
	Bindings []BindingInfo
}

// BindingInfo 绑定信息
type BindingInfo struct {
	Protocol   string
	IP         string
	Port       int
	Host       string
	CertHash   string
	CertStore  string
	HasSSL     bool
	SSLFlags   int // 0=IP-based, 1=SNI, 2=Central Certificate Store
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
