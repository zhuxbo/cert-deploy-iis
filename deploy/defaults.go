package deploy

import (
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
type defaultIISBinder struct {
	iis7Mode bool
}

func (d *defaultIISBinder) BindCertificate(hostname string, port int, certHash string) error {
	return iis.BindCertificate(hostname, port, certHash)
}

func (d *defaultIISBinder) BindCertificateByIP(ip string, port int, certHash string) error {
	return iis.BindCertificateByIP(ip, port, certHash)
}

func (d *defaultIISBinder) FindBindingsForDomains(domains []string) (map[string]*iis.SSLBinding, error) {
	return iis.FindBindingsForDomains(domains)
}

func (d *defaultIISBinder) IsIIS7() bool {
	return d.iis7Mode || iis.IsIIS7()
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

func (d *defaultOrderStore) SaveMeta(orderID int, meta *cert.OrderMeta) error {
	return d.store.SaveMeta(orderID, meta)
}

func (d *defaultOrderStore) LoadMeta(orderID int) (*cert.OrderMeta, error) {
	return d.store.LoadMeta(orderID)
}

func (d *defaultOrderStore) ListOrders() ([]int, error) {
	return d.store.ListOrders()
}

func (d *defaultOrderStore) DeleteOrder(orderID int) error {
	return d.store.DeleteOrder(orderID)
}

// DefaultDeployer 创建默认部署器
func DefaultDeployer(cfg *config.Config, store *cert.OrderStore) *Deployer {
	return &Deployer{
		Converter: &defaultCertConverter{},
		Installer: &defaultCertInstaller{},
		Binder:    &defaultIISBinder{iis7Mode: cfg.IIS7Mode},
		Client:    api.NewClient(cfg.APIBaseURL, cfg.GetToken()),
		Store:     &defaultOrderStore{store: store},
	}
}

// NewDeployerWithClient 使用指定的 API 客户端创建部署器
func NewDeployerWithClient(cfg *config.Config, store *cert.OrderStore, client APIClient) *Deployer {
	return &Deployer{
		Converter: &defaultCertConverter{},
		Installer: &defaultCertInstaller{},
		Binder:    &defaultIISBinder{iis7Mode: cfg.IIS7Mode},
		Client:    client,
		Store:     &defaultOrderStore{store: store},
	}
}
