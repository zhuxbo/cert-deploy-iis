package deploy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/config"
	"sslctlw/iis"
)

// genSelfSignedPair 生成配对的自签证书与 EC 私钥 PEM（仅测试用）
func genSelfSignedPair(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试密钥失败: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// callbackRecorder 线程安全的回调记录器（sendCallback 为异步 goroutine）
type callbackRecorder struct {
	mu   sync.Mutex
	reqs []api.CallbackRequest
}

func (r *callbackRecorder) record(req *api.CallbackRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, *req)
}

func (r *callbackRecorder) all() []api.CallbackRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]api.CallbackRequest, len(r.reqs))
	copy(out, r.reqs)
	return out
}

// TestVerifyDeployKeyPair 部署前配对校验纯函数
func TestVerifyDeployKeyPair(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "match.example.com")
	_, otherKey := genSelfSignedPair(t, "other.example.com")

	tests := []struct {
		name       string
		certPEM    string
		keyPEM     string
		wantOK     bool
		wantReason string
	}{
		{"配对匹配", certPEM, keyPEM, true, ""},
		{"配对不匹配", certPEM, otherKey, false, "证书与私钥不匹配"},
		{"证书无效", "not-a-cert", keyPEM, false, "证书私钥配对校验失败"},
		{"私钥无效", certPEM, "not-a-key", false, "证书私钥配对校验失败"},
		{"私钥为空", certPEM, "", false, "证书私钥配对校验失败"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := verifyDeployKeyPair(tt.certPEM, tt.keyPEM)
			if ok != tt.wantOK {
				t.Errorf("verifyDeployKeyPair() ok = %v, want %v (reason=%q)", ok, tt.wantOK, reason)
			}
			if tt.wantReason == "" && reason != "" {
				t.Errorf("reason = %q, want empty", reason)
			}
			if tt.wantReason != "" && !strings.HasPrefix(reason, tt.wantReason) {
				t.Errorf("reason = %q, want prefix %q", reason, tt.wantReason)
			}
		})
	}
}

// TestDeployCertWithRules_KeyPairMismatch 规则模式：配对不匹配时不转换不安装，失败结果+失败回调
func TestDeployCertWithRules_KeyPairMismatch(t *testing.T) {
	certPEM, _ := genSelfSignedPair(t, "a.example.com")
	_, wrongKey := genSelfSignedPair(t, "b.example.com")

	converterCalled := false
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			converterCalled = true
			return "/tmp/test.pfx", nil
		}},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
	client := &MockAPIClient{CallbackFunc: func(ctx context.Context, req *api.CallbackRequest) error {
		rec.record(req)
		return nil
	}}

	certData := &api.CertData{
		OrderID:     101,
		Domains:     "a.example.com",
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	certCfg := makeTestCertConfig(101, "a.example.com", true)

	results := deployCertWithRules(d, client, certData, wrongKey, certCfg, nil, nil)
	d.WaitCallbacks()

	if converterCalled {
		t.Error("配对不匹配时不应调用 PEMToPFX")
	}
	if len(results) != len(certCfg.BindRules) {
		t.Fatalf("results 数量 = %d, want %d", len(results), len(certCfg.BindRules))
	}
	for _, r := range results {
		if r.Success {
			t.Errorf("结果应为失败: %+v", r)
		}
		if !strings.Contains(r.Message, "不匹配") {
			t.Errorf("失败原因应包含配对信息: %q", r.Message)
		}
	}
	cbs := rec.all()
	if len(cbs) != 1 {
		t.Fatalf("回调数量 = %d, want 1", len(cbs))
	}
	if cbs[0].Status != "failure" || cbs[0].OrderID != 101 {
		t.Errorf("回调 = %+v, want failure/101", cbs[0])
	}
}

// TestDeployCertAutoMode_KeyPairMismatch 自动模式：配对不匹配时不转换不查绑定，失败结果+失败回调
func TestDeployCertAutoMode_KeyPairMismatch(t *testing.T) {
	certPEM, _ := genSelfSignedPair(t, "a.example.com")
	_, wrongKey := genSelfSignedPair(t, "b.example.com")

	converterCalled := false
	findCalled := false
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			converterCalled = true
			return "/tmp/test.pfx", nil
		}},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) (map[string]*iis.SSLBinding, error) {
			findCalled = true
			return nil, nil
		}},
		Store: &MockOrderStore{},
	}
	client := &MockAPIClient{CallbackFunc: func(ctx context.Context, req *api.CallbackRequest) error {
		rec.record(req)
		return nil
	}}

	certData := &api.CertData{
		OrderID:     102,
		Domains:     "a.example.com",
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	certCfg := config.CertConfig{
		OrderID:      102,
		Domain:       "a.example.com",
		Domains:      []string{"a.example.com"},
		Enabled:      true,
		AutoBindMode: true,
	}

	results := deployCertAutoMode(d, client, certData, wrongKey, certCfg)
	d.WaitCallbacks()

	if converterCalled {
		t.Error("配对不匹配时不应调用 PEMToPFX")
	}
	if findCalled {
		t.Error("配对不匹配时不应查询 IIS 绑定")
	}
	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_ValidPair_Proceeds 配对匹配时正常走转换安装绑定并发 success 回调
func TestDeployCertWithRules_ValidPair_Proceeds(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "ok.example.com")

	converterCalled := false
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			converterCalled = true
			return "/nonexistent/test.pfx", nil
		}},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
	client := &MockAPIClient{CallbackFunc: func(ctx context.Context, req *api.CallbackRequest) error {
		rec.record(req)
		return nil
	}}

	certData := &api.CertData{
		OrderID:     103,
		Domains:     "ok.example.com",
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	certCfg := makeTestCertConfig(103, "ok.example.com", true)

	results := deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	if !converterCalled {
		t.Error("配对匹配时应调用 PEMToPFX")
	}
	if len(results) != 1 || !results[0].Success {
		t.Fatalf("应有一条成功结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "success" {
		t.Fatalf("应收到一条 success 回调: %+v", cbs)
	}
}
