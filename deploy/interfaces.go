package deploy

import (
	"context"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/iis"
)

// CertConverter 证书转换接口
type CertConverter interface {
	// PEMToPFX 将 PEM 格式证书转换为 PFX 格式
	// 返回 PFX 文件路径
	PEMToPFX(certPEM, keyPEM, intermediatePEM, password string) (string, error)
}

// CertInstaller 证书安装接口
type CertInstaller interface {
	// InstallPFX 安装 PFX 证书到 Windows 证书存储
	InstallPFX(pfxPath, password string) (*cert.InstallResult, error)
	// SetFriendlyName 设置证书友好名称
	SetFriendlyName(thumbprint, friendlyName string) error
}

// IISBinder IIS 绑定接口
type IISBinder interface {
	// BindCertificate 使用 SNI 模式绑定证书
	BindCertificate(hostname string, port int, certHash string) error
	// BindCertificateByIP 使用 IP 模式绑定证书
	BindCertificateByIP(ip string, port int, certHash string) error
	// FindBindingsForDomains 查找域名匹配的绑定
	FindBindingsForDomains(domains []string) (map[string]*iis.SSLBinding, error)
	// IsIIS7 检查是否为 IIS7
	IsIIS7() bool
}

// APIClient API 客户端接口
type APIClient interface {
	// GetCertByOrderID 按订单 ID 获取证书
	GetCertByOrderID(ctx context.Context, orderID int) (*api.CertData, error)
	// ListCertsByDomain 按域名列出证书
	ListCertsByDomain(ctx context.Context, domain string) ([]api.CertData, error)
	// SubmitCSR 提交 CSR
	SubmitCSR(ctx context.Context, req *api.CSRRequest) (*api.CSRResponse, error)
	// Callback 发送部署回调
	Callback(ctx context.Context, req *api.CallbackRequest) error
}

// OrderStore 订单存储接口
type OrderStore interface {
	// HasPrivateKey 检查是否有私钥
	HasPrivateKey(orderID int) bool
	// LoadPrivateKey 加载私钥
	LoadPrivateKey(orderID int) (string, error)
	// SavePrivateKey 保存私钥
	SavePrivateKey(orderID int, keyPEM string) error
	// SaveCertificate 保存证书
	SaveCertificate(orderID int, certPEM, chainPEM string) error
	// SaveMeta 保存元数据
	SaveMeta(orderID int, meta *cert.OrderMeta) error
	// DeleteOrder 删除订单
	DeleteOrder(orderID int) error
}

// Deployer 部署器，聚合所有依赖
type Deployer struct {
	Converter CertConverter
	Installer CertInstaller
	Binder    IISBinder
	Client    APIClient
	Store     OrderStore
}
