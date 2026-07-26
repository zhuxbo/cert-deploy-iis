package deploy

import (
	"context"
	"testing"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
)

// MockAPIClient 模拟 API 客户端
type MockAPIClient struct {
	GetCertByOrderIDFunc  func(ctx context.Context, orderID int) (*api.CertData, error)
	ListCertsByDomainFunc func(ctx context.Context, domain string) ([]api.CertData, error)
	ListCertsByQueryFunc  func(ctx context.Context, query string) ([]api.CertData, error)
	ListAllCertsFunc      func(ctx context.Context) ([]api.CertData, error)
	SubmitCSRFunc         func(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error)
	CallbackFunc          func(ctx context.Context, req *api.CallbackRequest) error
}

func (m *MockAPIClient) GetCertByOrderID(ctx context.Context, orderID int) (*api.CertData, error) {
	if m.GetCertByOrderIDFunc != nil {
		return m.GetCertByOrderIDFunc(ctx, orderID)
	}
	return nil, nil
}

func (m *MockAPIClient) ListCertsByDomain(ctx context.Context, domain string) ([]api.CertData, error) {
	if m.ListCertsByDomainFunc != nil {
		return m.ListCertsByDomainFunc(ctx, domain)
	}
	return nil, nil
}

func (m *MockAPIClient) ListCertsByQuery(ctx context.Context, query string) ([]api.CertData, error) {
	if m.ListCertsByQueryFunc != nil {
		return m.ListCertsByQueryFunc(ctx, query)
	}
	return nil, nil
}

func (m *MockAPIClient) ListAllCerts(ctx context.Context) ([]api.CertData, error) {
	if m.ListAllCertsFunc != nil {
		return m.ListAllCertsFunc(ctx)
	}
	return nil, nil
}

func (m *MockAPIClient) SubmitCSR(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
	if m.SubmitCSRFunc != nil {
		return m.SubmitCSRFunc(ctx, req)
	}
	return nil, nil
}

func (m *MockAPIClient) Callback(ctx context.Context, req *api.CallbackRequest) error {
	if m.CallbackFunc != nil {
		return m.CallbackFunc(ctx, req)
	}
	return nil
}

// MockOrderStore 模拟订单存储
type MockOrderStore struct {
	HasPrivateKeyFunc            func(orderID int) bool
	LoadPrivateKeyFunc           func(orderID int) (string, error)
	SavePrivateKeyFunc           func(orderID int, keyPEM string) error
	HasPendingPrivateKeyFunc     func(certName string) bool
	LoadPendingPrivateKeyFunc    func(certName string) (string, error)
	SavePendingPrivateKeyFunc    func(certName, keyPEM string) error
	SavePendingCSRFunc           func(certName, csrPEM string) error
	LoadPendingCSRFunc           func(certName string) (string, error)
	PromotePendingPrivateKeyFunc func(certName string, orderID int, deployedKey string) error
	SaveCertificateFunc          func(orderID int, certPEM, chainPEM string) error
	LoadCertificateFunc          func(orderID int) (certPEM, chainPEM string, err error)
	ListOrdersFunc               func() ([]int, error)
	DeleteOrderFunc              func(orderID int) error
}

func (m *MockOrderStore) HasPrivateKey(orderID int) bool {
	if m.HasPrivateKeyFunc != nil {
		return m.HasPrivateKeyFunc(orderID)
	}
	return false
}

func (m *MockOrderStore) LoadPrivateKey(orderID int) (string, error) {
	if m.LoadPrivateKeyFunc != nil {
		return m.LoadPrivateKeyFunc(orderID)
	}
	return "", nil
}

func (m *MockOrderStore) SavePrivateKey(orderID int, keyPEM string) error {
	if m.SavePrivateKeyFunc != nil {
		return m.SavePrivateKeyFunc(orderID, keyPEM)
	}
	return nil
}

func (m *MockOrderStore) HasPendingPrivateKey(certName string) bool {
	if m.HasPendingPrivateKeyFunc != nil {
		return m.HasPendingPrivateKeyFunc(certName)
	}
	return false
}

func (m *MockOrderStore) LoadPendingPrivateKey(certName string) (string, error) {
	if m.LoadPendingPrivateKeyFunc != nil {
		return m.LoadPendingPrivateKeyFunc(certName)
	}
	return "", nil
}

func (m *MockOrderStore) SavePendingPrivateKey(certName, keyPEM string) error {
	if m.SavePendingPrivateKeyFunc != nil {
		return m.SavePendingPrivateKeyFunc(certName, keyPEM)
	}
	return nil
}

func (m *MockOrderStore) SavePendingCSR(certName, csrPEM string) error {
	if m.SavePendingCSRFunc != nil {
		return m.SavePendingCSRFunc(certName, csrPEM)
	}
	return nil
}

func (m *MockOrderStore) LoadPendingCSR(certName string) (string, error) {
	if m.LoadPendingCSRFunc != nil {
		return m.LoadPendingCSRFunc(certName)
	}
	return "", nil
}

func (m *MockOrderStore) PromotePendingPrivateKey(certName string, orderID int, deployedKey string) error {
	if m.PromotePendingPrivateKeyFunc != nil {
		return m.PromotePendingPrivateKeyFunc(certName, orderID, deployedKey)
	}
	return nil
}

func (m *MockOrderStore) SaveCertificate(orderID int, certPEM, chainPEM string) error {
	if m.SaveCertificateFunc != nil {
		return m.SaveCertificateFunc(orderID, certPEM, chainPEM)
	}
	return nil
}

func (m *MockOrderStore) LoadCertificate(orderID int) (certPEM, chainPEM string, err error) {
	if m.LoadCertificateFunc != nil {
		return m.LoadCertificateFunc(orderID)
	}
	return "", "", nil
}

func (m *MockOrderStore) ListOrders() ([]int, error) {
	if m.ListOrdersFunc != nil {
		return m.ListOrdersFunc()
	}
	return []int{}, nil
}

func (m *MockOrderStore) DeleteOrder(orderID int) error {
	if m.DeleteOrderFunc != nil {
		return m.DeleteOrderFunc(orderID)
	}
	return nil
}

// 测试用的证书数据
func makeTestCertData(t *testing.T, orderID int, domain, status, expiresAt string) *api.CertData {
	t.Helper()
	certPEM, keyPEM := genSelfSignedPair(t, domain)
	return &api.CertData{
		OrderID:     orderID,
		Domains:     domain,
		Status:      status,
		ExpiresAt:   expiresAt,
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		CACert:      testCACertPEM,
	}
}

// 测试用的配置数据
func makeTestCertConfig(orderID int, domain string, enabled bool) config.CertConfig {
	return config.CertConfig{
		OrderID: orderID,
		Domain:  domain,
		Domains: []string{domain},
		Enabled: enabled,
		BindRules: []config.BindRule{
			{Domain: domain, Port: 443},
		},
	}
}

// 测试用的 PEM 证书（仅用于解析测试，非真实证书）
const testCertPEM = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P4KX0zANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o5e7RvS/VvOO+5HJX1FjZ5P8p5wXxF5qYL/ePJIxeGNvwJXL1XfT9p5g6J6nZxpP
F9X4E5fF1L0FQBxRPvJXfZF6F6Y5xoZH5qXZTc6TqfR9XXL6W5F6E5F5X4E5F5F5
F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5
F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5
F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5F5AgMBAAEwDQYJKoZIhvcNAQEL
BQADggEBABZf
-----END CERTIFICATE-----`

// testKeyPEM 测试用假私钥（无效数据，仅用于单元测试）
const testKeyPEM = `-----BEGIN TEST PRIVATE KEY-----
VEVTVC1LRVktREFUQS1GT1ItVU5JVC1URVNUSU5HLU9OTFk=
VEVTVC1LRVktREFUQS1GT1ItVU5JVC1URVNUSU5HLU9OTFk=
-----END TEST PRIVATE KEY-----`

const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P4KCATANBGKQHKIG9W0BAQUFADAUMRIWGAYDVQQDDALB
DGFHDHZDQHAEHCNMDQWMTAWMDAWMFOCHMTUWMTAWMDAWMFOWFDESJHDGA1U
-----END CERTIFICATE-----`

// MockCertConverter 模拟证书转换器
type MockCertConverter struct {
	PEMToPFXFunc func(certPEM, keyPEM, intermediatePEM, password string) (string, error)
}

func (m *MockCertConverter) PEMToPFX(certPEM, keyPEM, intermediatePEM, password string) (string, error) {
	if m.PEMToPFXFunc != nil {
		return m.PEMToPFXFunc(certPEM, keyPEM, intermediatePEM, password)
	}
	return "/tmp/test.pfx", nil
}

// MockCertInstaller 模拟证书安装器
type MockCertInstaller struct {
	InstallPFXFunc      func(pfxPath, password string) (*cert.InstallResult, error)
	SetFriendlyNameFunc func(thumbprint, friendlyName string) error
}

func (m *MockCertInstaller) InstallPFX(pfxPath, password string) (*cert.InstallResult, error) {
	if m.InstallPFXFunc != nil {
		return m.InstallPFXFunc(pfxPath, password)
	}
	return &cert.InstallResult{
		Success:    true,
		Thumbprint: "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234",
	}, nil
}

func (m *MockCertInstaller) SetFriendlyName(thumbprint, friendlyName string) error {
	if m.SetFriendlyNameFunc != nil {
		return m.SetFriendlyNameFunc(thumbprint, friendlyName)
	}
	return nil
}

// MockIISBinder 模拟 IIS 绑定器
type MockIISBinder struct {
	BindCertificateFunc        func(hostname string, port int, certHash string) error
	BindCertificateByIPFunc    func(ip string, port int, certHash string) error
	FindBindingsForDomainsFunc func(domains []string) ([]iis.SSLBinding, error)
}

func (m *MockIISBinder) BindCertificate(hostname string, port int, certHash string) error {
	if m.BindCertificateFunc != nil {
		return m.BindCertificateFunc(hostname, port, certHash)
	}
	return nil
}

func (m *MockIISBinder) BindCertificateByIP(ip string, port int, certHash string) error {
	if m.BindCertificateByIPFunc != nil {
		return m.BindCertificateByIPFunc(ip, port, certHash)
	}
	return nil
}

func (m *MockIISBinder) FindBindingsForDomains(domains []string) ([]iis.SSLBinding, error) {
	if m.FindBindingsForDomainsFunc != nil {
		return m.FindBindingsForDomainsFunc(domains)
	}
	return nil, nil
}

// NewMockDeployer 创建用于测试的 Mock 部署器
func NewMockDeployer() *Deployer {
	return &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
}

// NewMockClient 创建用于测试的 Mock API 客户端
func NewMockClient() *MockAPIClient {
	return &MockAPIClient{}
}
