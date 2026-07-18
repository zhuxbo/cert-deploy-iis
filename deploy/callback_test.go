package deploy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
)

// newRecordingClient 返回记录回调的 mock client
func newRecordingClient(rec *callbackRecorder) *MockAPIClient {
	return &MockAPIClient{CallbackFunc: func(ctx context.Context, req *api.CallbackRequest) error {
		rec.record(req)
		return nil
	}}
}

// autoModeCertData 构造自动模式测试数据（配对有效的证书与私钥）
func autoModeCertData(t *testing.T, orderID int, domain string) (*api.CertData, string, config.CertConfig) {
	t.Helper()
	certPEM, keyPEM := genSelfSignedPair(t, domain)
	certData := &api.CertData{
		OrderID:     orderID,
		Domains:     domain,
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	certCfg := config.CertConfig{
		OrderID:      orderID,
		Domain:       domain,
		Domains:      []string{domain},
		Enabled:      true,
		AutoBindMode: true,
	}
	return certData, keyPEM, certCfg
}

// TestDeployCertAutoMode_NoBindings_ReportsFailure 自动模式未找到绑定应上报失败而非静默跳过
func TestDeployCertAutoMode_NoBindings_ReportsFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 201, "nobind.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) (map[string]*iis.SSLBinding, error) {
			return map[string]*iis.SSLBinding{}, nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 {
		t.Fatalf("results 数量 = %d, want 1", len(results))
	}
	if results[0].Success {
		t.Errorf("未找到绑定应为失败结果: %+v", results[0])
	}
	if !strings.Contains(results[0].Message, "未找到匹配") {
		t.Errorf("失败原因应说明未找到绑定: %q", results[0].Message)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" || cbs[0].OrderID != 201 {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_FindBindingsError_SendsCallback 查绑定出错应发失败回调
func TestDeployCertAutoMode_FindBindingsError_SendsCallback(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 202, "finderr.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) (map[string]*iis.SSLBinding, error) {
			return nil, fmt.Errorf("netsh 执行失败")
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_ConvertFail_SendsCallback 转换失败应发失败回调
func TestDeployCertAutoMode_ConvertFail_SendsCallback(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 203, "convfail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			return "", fmt.Errorf("openssl 转换错误")
		}},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" || cbs[0].OrderID != 203 {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_InstallFail_SendsCallback 安装失败应发失败回调
func TestDeployCertAutoMode_InstallFail_SendsCallback(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 204, "instfail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{InstallPFXFunc: func(pfxPath, password string) (*cert.InstallResult, error) {
			return &cert.InstallResult{Success: false, ErrorMessage: "证书导入失败"}, nil
		}},
		Binder: &MockIISBinder{},
		Store:  &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_ConvertFail_SendsCallback 规则模式转换失败发一条失败回调
func TestDeployCertWithRules_ConvertFail_SendsCallback(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "rulesconv.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			return "", fmt.Errorf("转换错误")
		}},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	certData := &api.CertData{
		OrderID:     205,
		Domains:     "rulesconv.example.com",
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	certCfg := makeTestCertConfig(205, "rulesconv.example.com", true)

	results := deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" || cbs[0].OrderID != 205 {
		t.Fatalf("应收到一条 failure 回调: %+v", cbs)
	}
}

// rulesCertData 构造规则模式测试数据（配对有效的证书与私钥 + 多条绑定规则）
func rulesCertData(t *testing.T, orderID int, domain string, ruleDomains ...string) (*api.CertData, string, config.CertConfig) {
	t.Helper()
	certPEM, keyPEM := genSelfSignedPair(t, domain)
	certData := &api.CertData{
		OrderID:     orderID,
		Domains:     domain,
		Status:      "active",
		Certificate: certPEM,
		CACert:      "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
	}
	rules := make([]config.BindRule, 0, len(ruleDomains))
	for _, rd := range ruleDomains {
		rules = append(rules, config.BindRule{Domain: rd, Port: 443})
	}
	certCfg := config.CertConfig{
		OrderID:   orderID,
		Domain:    domain,
		Domains:   ruleDomains,
		Enabled:   true,
		BindRules: rules,
	}
	return certData, keyPEM, certCfg
}

// TestDeployCertWithRules_MixedBindings_SingleFailureCallback 多绑定一成一败：按订单聚合仅一条 failure 回调
func TestDeployCertWithRules_MixedBindings_SingleFailureCallback(t *testing.T) {
	certData, keyPEM, certCfg := rulesCertData(t, 210, "multi.example.com", "ok.example.com", "fail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{BindCertificateFunc: func(hostname string, port int, certHash string) error {
			if hostname == "fail.example.com" {
				return fmt.Errorf("netsh 绑定失败")
			}
			return nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" || cbs[0].OrderID != 210 {
		t.Fatalf("多绑定混合成败应仅一条 failure 回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_AllSuccess_SingleSuccessCallback 多绑定全成功：按订单聚合仅一条 success 回调
func TestDeployCertWithRules_AllSuccess_SingleSuccessCallback(t *testing.T) {
	certData, keyPEM, certCfg := rulesCertData(t, 211, "allok.example.com", "a.example.com", "b.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{}, // 默认全部绑定成功
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "success" || cbs[0].OrderID != 211 {
		t.Fatalf("多绑定全成功应仅一条 success 回调: %+v", cbs)
	}
}

// TestAggregatedFailureMessage 聚合失败原因摘要纯函数
func TestAggregatedFailureMessage(t *testing.T) {
	tests := []struct {
		name        string
		total       int
		failed      int
		firstReason string
		want        string
	}{
		{"2/3 带首因", 3, 2, "www.example.com: netsh 绑定失败", "2/3 绑定失败: www.example.com: netsh 绑定失败"},
		{"1/1 带首因", 1, 1, "证书与私钥不匹配", "1/1 绑定失败: 证书与私钥不匹配"},
		{"无首因省略后缀", 2, 1, "", "1/2 绑定失败"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := aggregatedFailureMessage(tt.total, tt.failed, tt.firstReason); got != tt.want {
				t.Errorf("aggregatedFailureMessage(%d,%d,%q) = %q, want %q", tt.total, tt.failed, tt.firstReason, got, tt.want)
			}
		})
	}
}

// TestDeployCertWithRules_AggregatedFailureMessage 规则模式聚合 failure 回调携带 "N/M 绑定失败: 首因"
func TestDeployCertWithRules_AggregatedFailureMessage(t *testing.T) {
	// 规则顺序确定（slice）：ok 先成功，fail 后失败 → 1/2 绑定失败，首因取 fail
	certData, keyPEM, certCfg := rulesCertData(t, 220, "multi.example.com", "ok.example.com", "fail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{BindCertificateFunc: func(hostname string, port int, certHash string) error {
			if hostname == "fail.example.com" {
				return fmt.Errorf("netsh 绑定失败")
			}
			return nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" {
		t.Fatalf("应仅一条 failure 回调: %+v", cbs)
	}
	wantMsg := "1/2 绑定失败: fail.example.com: netsh 绑定失败"
	if cbs[0].Message != wantMsg {
		t.Errorf("聚合 failure message = %q, want %q", cbs[0].Message, wantMsg)
	}
}

// TestDeployCertWithRules_SuccessCallbackNoMessage 全成功聚合 success 回调不携带 message
func TestDeployCertWithRules_SuccessCallbackNoMessage(t *testing.T) {
	certData, keyPEM, certCfg := rulesCertData(t, 221, "allok.example.com", "a.example.com", "b.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{}, // 默认全部绑定成功
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	deployCertWithRules(d, client, certData, keyPEM, certCfg, nil, nil)
	d.WaitCallbacks()

	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "success" {
		t.Fatalf("应仅一条 success 回调: %+v", cbs)
	}
	if cbs[0].Message != "" {
		t.Errorf("success 回调不应携带 message，实际 = %q", cbs[0].Message)
	}
}

// TestDeployCertAutoMode_MixedBindings_SingleFailureCallback 自动模式多绑定一成一败：仅一条 failure 回调
func TestDeployCertAutoMode_MixedBindings_SingleFailureCallback(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 212, "auto.example.com")
	certCfg.Domains = []string{"ok.example.com", "fail.example.com"}
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{
			FindBindingsForDomainsFunc: func(domains []string) (map[string]*iis.SSLBinding, error) {
				return map[string]*iis.SSLBinding{
					"ok.example.com":   {HostnamePort: "ok.example.com:443"},
					"fail.example.com": {HostnamePort: "fail.example.com:443"},
				}, nil
			},
			BindCertificateFunc: func(hostname string, port int, certHash string) error {
				if hostname == "fail.example.com" {
					return fmt.Errorf("netsh 绑定失败")
				}
				return nil
			},
		},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	cbs := rec.all()
	if len(cbs) != 1 || cbs[0].Status != "failure" || cbs[0].OrderID != 212 {
		t.Fatalf("自动模式多绑定混合成败应仅一条 failure 回调: %+v", cbs)
	}
}
