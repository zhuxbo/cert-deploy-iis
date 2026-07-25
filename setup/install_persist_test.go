package setup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
)

func setupTestPair(t *testing.T, cn string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("生成测试证书失败: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试密钥失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// newSetupStub 注入证书安装与 IIS 绑定结果，并返回记录回调状态的本地 API 客户端。
func newSetupStub(t *testing.T, br bindResult, bindErr error) (*api.Client, *[]string) {
	t.Helper()
	oldInstall, oldBind := installPFXFn, bindCertToIISFn
	t.Cleanup(func() { installPFXFn, bindCertToIISFn = oldInstall, oldBind })
	installPFXFn = func(string, string) (*cert.InstallResult, error) {
		return &cert.InstallResult{Success: true, Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD"}, nil
	}
	bindCertToIISFn = func(api.CertData, string) (bindResult, error) { return br, bindErr }

	statuses := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req api.CallbackRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		*statuses = append(*statuses, req.Status)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{}}`))
	}))
	t.Cleanup(srv.Close)
	return api.NewClient(srv.URL, "tok"), statuses
}

// TestInstallCert_BindFailureStillPersistsConfig 坐实并回归：
// 证书已装入 Windows 证书存储后，绑定失败只应影响回调与失败计数，
// 不能连配置都不写——那样该证书完全脱管，计划任务永远接管不了，只能人工重跑 setup。
func TestInstallCert_BindFailureStillPersistsConfig(t *testing.T) {
	certPEM, keyPEM := setupTestPair(t, "example.com")
	certData := api.CertData{OrderID: 400, Domains: "example.com", Certificate: certPEM, CACert: certPEM}

	tests := []struct {
		name    string
		br      bindResult
		bindErr error
	}{
		{"部分绑定失败", bindResult{Succeeded: 1, Failed: 1}, nil},
		{"全部绑定失败", bindResult{Failed: 2}, nil},
		{"查找绑定出错", bindResult{}, errors.New("查找 IIS 绑定失败")},
		{"未找到可绑定站点", bindResult{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, statuses := newSetupStub(t, tt.br, tt.bindErr)
			var certConfigs []config.CertConfig
			result := &RunResult{}

			ok := installCert(client, certData, keyPEM, "S", Options{URL: "https://x.example.com", Token: "t"},
				&certConfigs, result, false, false)

			if ok {
				t.Error("绑定未全部生效应判为部署失败")
			}
			if result.Installed != 0 {
				t.Errorf("部署失败不应计入 Installed, got %d", result.Installed)
			}
			if len(certConfigs) != 1 {
				t.Fatalf("证书已入存储，必须写入配置交给计划任务续签接管, got %d 条", len(certConfigs))
			}
			if !certConfigs[0].Enabled {
				t.Error("写入的配置应处于启用状态")
			}
			if len(*statuses) != 1 || (*statuses)[0] != "failure" {
				t.Errorf("应上报一条 failure 回调, got %v", *statuses)
			}
		})
	}
}

// TestInstallCert_SuccessPersistsOnce 全部绑定成功时写入一次配置并上报 success。
func TestInstallCert_SuccessPersistsOnce(t *testing.T) {
	certPEM, keyPEM := setupTestPair(t, "example.com")
	certData := api.CertData{OrderID: 401, Domains: "example.com", Certificate: certPEM, CACert: certPEM}

	client, statuses := newSetupStub(t, bindResult{Succeeded: 2}, nil)
	var certConfigs []config.CertConfig
	result := &RunResult{}

	if ok := installCert(client, certData, keyPEM, "S", Options{URL: "https://x.example.com", Token: "t"},
		&certConfigs, result, false, false); !ok {
		t.Fatal("全部绑定成功应判为部署成功")
	}
	if result.Installed != 1 {
		t.Errorf("Installed = %d, want 1", result.Installed)
	}
	if len(certConfigs) != 1 {
		t.Fatalf("成功路径应只写入一条配置, got %d 条", len(certConfigs))
	}
	if len(*statuses) != 1 || (*statuses)[0] != "success" {
		t.Errorf("应上报一条 success 回调, got %v", *statuses)
	}
}
