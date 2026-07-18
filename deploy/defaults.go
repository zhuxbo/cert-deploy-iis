package deploy

import (
	"fmt"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
)

// defaultCertConverter 默认证书转换器
type defaultCertConverter struct{}

func (d *defaultCertConverter) PEMToPFX(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
	return cert.PEMToPFX(certPEM, keyPEM, intermediatePEM, password)
}

// defaultCertInstaller 默认证书安装器
type defaultCertInstaller struct{}

func (d *defaultCertInstaller) InstallPFX(pfxPath, password string) (*cert.InstallResult, error) {
	return cert.InstallPFX(pfxPath, password)
}

func (d *defaultCertInstaller) SetFriendlyName(thumbprint, friendlyName string) error {
	return cert.SetFriendlyName(thumbprint, friendlyName)
}

// defaultIISBinder 默认 IIS 绑定器
type defaultIISBinder struct{}

func (d *defaultIISBinder) BindCertificate(hostname string, port int, certHash string) error {
	return iis.BindCertificate(hostname, port, certHash)
}

func (d *defaultIISBinder) BindCertificateByIP(ip string, port int, certHash string) error {
	return iis.BindCertificateByIP(ip, port, certHash)
}

func (d *defaultIISBinder) FindBindingsForDomains(domains []string) (map[string]*iis.SSLBinding, error) {
	return iis.FindBindingsForDomains(domains)
}

// defaultOrderStore 默认订单存储包装器
type defaultOrderStore struct {
	store *cert.OrderStore
}

func (d *defaultOrderStore) HasPrivateKey(orderID int) bool {
	return d.store.HasPrivateKey(orderID)
}

func (d *defaultOrderStore) LoadPrivateKey(orderID int) (string, error) {
	return d.store.LoadPrivateKey(orderID)
}

func (d *defaultOrderStore) SavePrivateKey(orderID int, keyPEM string) error {
	return d.store.SavePrivateKey(orderID, keyPEM)
}

func (d *defaultOrderStore) SaveCertificate(orderID int, certPEM, chainPEM string) error {
	return d.store.SaveCertificate(orderID, certPEM, chainPEM)
}

func (d *defaultOrderStore) LoadCertificate(orderID int) (certPEM, chainPEM string, err error) {
	return d.store.LoadCertificate(orderID)
}

func (d *defaultOrderStore) ListOrders() ([]int, error) {
	return d.store.ListOrders()
}

func (d *defaultOrderStore) DeleteOrder(orderID int) error {
	return d.store.DeleteOrder(orderID)
}

// DefaultDeployer 创建默认部署器（不含 API Client）
func DefaultDeployer(cfg *config.Config, store *cert.OrderStore) *Deployer {
	return &Deployer{
		Converter: &defaultCertConverter{},
		Installer: &defaultCertInstaller{},
		Binder:    &defaultIISBinder{},
		Store:     &defaultOrderStore{store: store},
	}
}

// NewClientForCert 为单个证书创建 API 客户端
func NewClientForCert(certCfg *config.CertConfig) (*api.Client, error) {
	apiURL := certCfg.API.URL
	token, err := certCfg.API.GetToken()
	if err != nil {
		// 解密失败（如 SYSTEM 计划任务读取交互账户加密的密文）显式暴露，不再当作"未配置"
		return nil, fmt.Errorf("证书 %s (订单 %d) %w", certCfg.Domain, certCfg.OrderID, err)
	}

	if apiURL == "" {
		return nil, fmt.Errorf("证书 %s (订单 %d) 未配置 API 地址", certCfg.Domain, certCfg.OrderID)
	}
	if token == "" {
		return nil, fmt.Errorf("证书 %s (订单 %d) 未配置 API Token", certCfg.Domain, certCfg.OrderID)
	}

	return api.NewClient(apiURL, token), nil
}
