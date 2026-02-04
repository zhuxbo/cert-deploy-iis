package deploy

import (
	"context"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
)

// MockAPIClient 模拟 API 客户端
type MockAPIClient struct {
	GetCertByOrderIDFunc  func(ctx context.Context, orderID int) (*api.CertData, error)
	ListCertsByDomainFunc func(ctx context.Context, domain string) ([]api.CertData, error)
	SubmitCSRFunc         func(req *api.CSRRequest) (*api.CSRResponse, error)
	CallbackFunc          func(req *api.CallbackRequest) error
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

func (m *MockAPIClient) SubmitCSR(req *api.CSRRequest) (*api.CSRResponse, error) {
	if m.SubmitCSRFunc != nil {
		return m.SubmitCSRFunc(req)
	}
	return nil, nil
}

func (m *MockAPIClient) Callback(req *api.CallbackRequest) error {
	if m.CallbackFunc != nil {
		return m.CallbackFunc(req)
	}
	return nil
}

// MockOrderStore 模拟订单存储
type MockOrderStore struct {
	HasPrivateKeyFunc  func(orderID int) bool
	LoadPrivateKeyFunc func(orderID int) (string, error)
	SavePrivateKeyFunc func(orderID int, keyPEM string) error
	SaveCertificateFunc func(orderID int, certPEM, chainPEM string) error
	SaveMetaFunc       func(orderID int, meta *cert.OrderMeta) error
	DeleteOrderFunc    func(orderID int) error
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

func (m *MockOrderStore) SaveCertificate(orderID int, certPEM, chainPEM string) error {
	if m.SaveCertificateFunc != nil {
		return m.SaveCertificateFunc(orderID, certPEM, chainPEM)
	}
	return nil
}

func (m *MockOrderStore) SaveMeta(orderID int, meta *cert.OrderMeta) error {
	if m.SaveMetaFunc != nil {
		return m.SaveMetaFunc(orderID, meta)
	}
	return nil
}

func (m *MockOrderStore) DeleteOrder(orderID int) error {
	if m.DeleteOrderFunc != nil {
		return m.DeleteOrderFunc(orderID)
	}
	return nil
}

// 测试用的证书数据
func makeTestCertData(orderID int, domain, status, expiresAt string) *api.CertData {
	return &api.CertData{
		OrderID:     orderID,
		Domain:      domain,
		Domains:     domain,
		Status:      status,
		ExpiresAt:   expiresAt,
		Certificate: testCertPEM,
		PrivateKey:  testKeyPEM,
		CACert:      testCACertPEM,
	}
}

// 测试用的配置数据
func makeTestCertConfig(orderID int, domain string, enabled bool) config.CertConfig {
	return config.CertConfig{
		OrderID:    orderID,
		Domain:     domain,
		Domains:    []string{domain},
		Enabled:    enabled,
		UseLocalKey: false,
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
