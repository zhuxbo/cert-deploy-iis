package deploy

import (
	"testing"

	"sslctlw/cert"
	"sslctlw/config"
)

func TestDefaultDeployer_NonNil(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL: "https://example.com",
	}
	store := &cert.OrderStore{BaseDir: t.TempDir()}

	deployer := DefaultDeployer(cfg, store)

	if deployer == nil {
		t.Fatal("DefaultDeployer() 返回 nil")
	}
	if deployer.Converter == nil {
		t.Error("Converter 不应为 nil")
	}
	if deployer.Installer == nil {
		t.Error("Installer 不应为 nil")
	}
	if deployer.Binder == nil {
		t.Error("Binder 不应为 nil")
	}
	if deployer.Client == nil {
		t.Error("Client 不应为 nil")
	}
	if deployer.Store == nil {
		t.Error("Store 不应为 nil")
	}
}

func TestNewDeployerWithClient_NonNil(t *testing.T) {
	cfg := &config.Config{
		APIBaseURL: "https://example.com",
	}
	store := &cert.OrderStore{BaseDir: t.TempDir()}

	// 使用 nil client 测试其他字段仍然非空
	deployer := NewDeployerWithClient(cfg, store, nil)

	if deployer == nil {
		t.Fatal("NewDeployerWithClient() 返回 nil")
	}
	if deployer.Converter == nil {
		t.Error("Converter 不应为 nil")
	}
	if deployer.Installer == nil {
		t.Error("Installer 不应为 nil")
	}
	if deployer.Binder == nil {
		t.Error("Binder 不应为 nil")
	}
	if deployer.Store == nil {
		t.Error("Store 不应为 nil")
	}
	// Client 应该为 nil（我们传入了 nil）
	if deployer.Client != nil {
		t.Error("Client 应该为 nil（传入了 nil）")
	}
}
