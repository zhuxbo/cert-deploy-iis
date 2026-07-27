package deploy

import (
	"context"
	"fmt"
	"reflect"
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

// deployCertWithRules / deployCertAutoMode 只返回结构化报告，绝不自行发送回调（deploy-spec §2.8）。
// 以下用例断言：底层函数返回正确的 deployReport，且回调记录器为空（未产生任何回调）。

// TestDeployCertAutoMode_NoBindings_ReportsFailure 自动模式未找到绑定：报告失败，但不自行回调
func TestDeployCertAutoMode_NoBindings_ReportsFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 201, "nobind.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
			return nil, nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("未找到绑定应为失败结果: %+v", results)
	}
	if !strings.Contains(results[0].Message, "未找到匹配") {
		t.Errorf("失败原因应说明未找到绑定: %q", results[0].Message)
	}
	if !rep.report || rep.success || !strings.Contains(rep.message, "未找到匹配") {
		t.Fatalf("应返回可回调的失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_FindBindingsError_ReportsFailure 查绑定出错：报告失败，不自行回调
func TestDeployCertAutoMode_FindBindingsError_ReportsFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 202, "finderr.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
			return nil, fmt.Errorf("netsh 执行失败")
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	if !rep.report || rep.success {
		t.Fatalf("应返回失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_ConvertFail_ReportsFailure 转换失败：报告失败，不自行回调
func TestDeployCertAutoMode_ConvertFail_ReportsFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 203, "convfail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{PEMToPFXFunc: func(c, k, i, p string) (string, error) {
			return "", fmt.Errorf("openssl 转换错误")
		}},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
			return []iis.SSLBinding{{HostnamePort: "convfail.example.com:443"}}, nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	if !rep.report || rep.success || !strings.Contains(rep.message, "转换 PFX 失败") {
		t.Fatalf("应返回转换失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertAutoMode_InstallFail_ReportsFailure 安装失败：报告失败，不自行回调
func TestDeployCertAutoMode_InstallFail_ReportsFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 204, "instfail.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{InstallPFXFunc: func(pfxPath, password string) (*cert.InstallResult, error) {
			return &cert.InstallResult{Success: false, ErrorMessage: "证书导入失败"}, nil
		}},
		Binder: &MockIISBinder{FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
			return []iis.SSLBinding{{HostnamePort: "instfail.example.com:443"}}, nil
		}},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	if !rep.report || rep.success || !strings.Contains(rep.message, "安装证书失败") {
		t.Fatalf("应返回安装失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_ConvertFail_ReportsFailure 规则模式转换失败：报告失败，不自行回调
func TestDeployCertWithRules_ConvertFail_ReportsFailure(t *testing.T) {
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

	results, rep := deployCertWithRules(d, client, certData, keyPEM, certCfg, 0, nil, nil)
	d.WaitCallbacks()

	if len(results) != 1 || results[0].Success {
		t.Fatalf("应有一条失败结果: %+v", results)
	}
	if !rep.report || rep.success {
		t.Fatalf("应返回失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
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

// TestDeployCertWithRules_MixedBindings_ReportsAggregatedFailure 多绑定一成一败：聚合为单条失败报告
func TestDeployCertWithRules_MixedBindings_ReportsAggregatedFailure(t *testing.T) {
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

	results, rep := deployCertWithRules(d, client, certData, keyPEM, certCfg, 0, nil, nil)
	d.WaitCallbacks()

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	if !rep.report || rep.success {
		t.Fatalf("多绑定混合成败应聚合为失败报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_AllSuccess_ReportsSuccess 多绑定全成功：聚合为单条成功报告
func TestDeployCertWithRules_AllSuccess_ReportsSuccess(t *testing.T) {
	certData, keyPEM, certCfg := rulesCertData(t, 211, "allok.example.com", "a.example.com", "b.example.com")
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{}, // 默认全部绑定成功
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertWithRules(d, client, certData, keyPEM, certCfg, 0, nil, nil)
	d.WaitCallbacks()

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	if !rep.report || !rep.success || rep.message != "" {
		t.Fatalf("多绑定全成功应聚合为无 message 的成功报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("底层部署函数不得自行发送回调: %+v", cbs)
	}
}

// TestDeployCertWithRules_AllConflictsSkipped_NoReport 全部冲突跳过：无绑定被处理，不产生回调
func TestDeployCertWithRules_AllConflictsSkipped_NoReport(t *testing.T) {
	certData, keyPEM, certCfg := rulesCertData(t, 213, "conflict.example.com", "shared.example.com")
	// shared.example.com 冲突且最佳证书是另一个订单（索引 1）
	other := config.CertConfig{Enabled: true, OrderID: 999, Metadata: config.CertMetadata{CertExpiresAt: "2099-12-31"},
		BindRules: []config.BindRule{{Domain: "shared.example.com", Port: 443}}}
	allCerts := []config.CertConfig{certCfg, other}
	conflicts := map[iis.EndpointKey][]int{{Host: "shared.example.com", Port: 443}: {0, 1}}
	rec := &callbackRecorder{}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder:    &MockIISBinder{},
		Store:     &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertWithRules(d, client, certData, keyPEM, certCfg, 0, conflicts, allCerts)
	d.WaitCallbacks()

	if len(results) != 0 {
		t.Fatalf("全部冲突跳过应无绑定结果: %+v", results)
	}
	if rep.report {
		t.Fatalf("无绑定被处理时不应产生回调报告: %+v", rep)
	}
	if cbs := rec.all(); len(cbs) != 0 {
		t.Fatalf("不应发送任何回调: %+v", cbs)
	}
}

// TestReportFromOutcome 由聚合绑定结果生成部署报告（纯函数）
func TestReportFromOutcome(t *testing.T) {
	tests := []struct {
		name        string
		outcome     bindOutcome
		wantReport  bool
		wantSuccess bool
		wantMsg     string
	}{
		{"零处理不回调", bindOutcome{}, false, false, ""},
		{"全成功", bindOutcome{success: 2}, true, true, ""},
		{"全失败带首因", bindOutcome{failed: 2, firstFail: "a: x"}, true, false, "2/2 绑定失败: a: x"},
		{"部分失败带首因", bindOutcome{success: 1, failed: 1, firstFail: "b: y"}, true, false, "1/2 绑定失败: b: y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reportFromOutcome(tt.outcome)
			if got.report != tt.wantReport || got.success != tt.wantSuccess || got.message != tt.wantMsg {
				t.Errorf("reportFromOutcome(%+v) = %+v, want report=%v success=%v msg=%q",
					tt.outcome, got, tt.wantReport, tt.wantSuccess, tt.wantMsg)
			}
		})
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

// TestDeployCertWithRules_AggregatedFailureMessage 规则模式聚合失败报告携带 "N/M 绑定失败: 首因"
func TestDeployCertWithRules_AggregatedFailureMessage(t *testing.T) {
	// 规则顺序确定（slice）：ok 先成功，fail 后失败 → 1/2 绑定失败，首因取 fail
	certData, keyPEM, certCfg := rulesCertData(t, 220, "multi.example.com", "ok.example.com", "fail.example.com")

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

	_, rep := deployCertWithRules(d, NewMockClient(), certData, keyPEM, certCfg, 0, nil, nil)

	wantMsg := "1/2 绑定失败: fail.example.com: netsh 绑定失败"
	if rep.success || rep.message != wantMsg {
		t.Errorf("聚合失败报告 message = %q, want %q", rep.message, wantMsg)
	}
}

// TestDeployCertAutoMode_MixedBindings_ReportsAggregatedFailure 自动模式多绑定一成一败：聚合失败报告
func TestDeployCertAutoMode_MixedBindings_ReportsAggregatedFailure(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 212, "auto.example.com")
	certCfg.Domains = []string{"ok.example.com", "fail.example.com"}

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{
			FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
				return []iis.SSLBinding{
					{HostnamePort: "ok.example.com:443"},
					{HostnamePort: "fail.example.com:443"},
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

	results, rep := deployCertAutoMode(d, NewMockClient(), certData, keyPEM, certCfg)

	if len(results) != 2 {
		t.Fatalf("应有两条绑定结果: %+v", results)
	}
	if !rep.report || rep.success {
		t.Fatalf("自动模式多绑定混合成败应聚合为失败报告: %+v", rep)
	}
}

func TestDeployCertAutoMode_TwoPortsBindAllAndCallbackOnce(t *testing.T) {
	certData, keyPEM, certCfg := autoModeCertData(t, 214, "multiport.example.com")
	rec := &callbackRecorder{}
	var boundPorts []int

	d := &Deployer{
		Converter: &MockCertConverter{},
		Installer: &MockCertInstaller{},
		Binder: &MockIISBinder{
			FindBindingsForDomainsFunc: func(domains []string) ([]iis.SSLBinding, error) {
				return []iis.SSLBinding{
					{HostnamePort: "multiport.example.com:443"},
					{HostnamePort: "multiport.example.com:8443"},
				}, nil
			},
			BindCertificateFunc: func(hostname string, port int, certHash string) error {
				boundPorts = append(boundPorts, port)
				return nil
			},
		},
		Store: &MockOrderStore{},
	}
	client := newRecordingClient(rec)

	results, rep := deployCertAutoMode(d, client, certData, keyPEM, certCfg)
	emitDeployCallback(d, client, certData.OrderID, certCfg.Domain, rep, false)
	if warnings := d.WaitCallbacks(); len(warnings) != 0 {
		t.Fatalf("callback warnings = %v", warnings)
	}

	if len(results) != 2 || !reflect.DeepEqual(boundPorts, []int{443, 8443}) {
		t.Fatalf("多端口绑定不完整: results=%+v ports=%v", results, boundPorts)
	}
	callbacks := rec.all()
	if len(callbacks) != 1 || callbacks[0].OrderID != certData.OrderID || callbacks[0].Status != "success" {
		t.Fatalf("订单应只 callback 一次成功: %+v", callbacks)
	}
}

// TestEmitDeployCallback 编排层按部署报告发送回调：无处理不发、成功发一条、失败发一条、触顶标注上限
func TestEmitDeployCallback(t *testing.T) {
	tests := []struct {
		name       string
		rep        deployReport
		atRetryCap bool
		wantCount  int
		wantStatus string
		wantMsgHas string
		wantNoMsg  bool
	}{
		{"无处理不回调", deployReport{report: false}, false, 0, "", "", false},
		{"成功回调无 message", deployReport{report: true, success: true}, false, 1, "success", "", true},
		{"失败回调带原因", deployReport{report: true, success: false, message: "绑定失败: x"}, false, 1, "failure", "绑定失败: x", false},
		{"第10次失败标注上限", deployReport{report: true, success: false, message: "绑定失败: x"}, true, 1, "failure", retryCapNotice, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &callbackRecorder{}
			d := NewMockDeployer()
			client := newRecordingClient(rec)

			emitDeployCallback(d, client, 300, "example.com", tt.rep, tt.atRetryCap)
			d.WaitCallbacks()

			cbs := rec.all()
			if len(cbs) != tt.wantCount {
				t.Fatalf("回调数量 = %d, want %d (%+v)", len(cbs), tt.wantCount, cbs)
			}
			if tt.wantCount == 0 {
				return
			}
			if cbs[0].Status != tt.wantStatus {
				t.Errorf("回调状态 = %q, want %q", cbs[0].Status, tt.wantStatus)
			}
			if tt.wantNoMsg && cbs[0].Message != "" {
				t.Errorf("成功回调不应携带 message, got %q", cbs[0].Message)
			}
			if tt.wantMsgHas != "" && !strings.Contains(cbs[0].Message, tt.wantMsgHas) {
				t.Errorf("回调 message = %q, want contains %q", cbs[0].Message, tt.wantMsgHas)
			}
		})
	}
}

// TestAppendRetryCapNotice 触顶标注纯函数：空串直接返回标注，非空追加且幂等
func TestAppendRetryCapNotice(t *testing.T) {
	if got := appendRetryCapNotice(""); got != retryCapNotice {
		t.Errorf("空串应返回标注本身: %q", got)
	}
	base := "绑定失败: x"
	once := appendRetryCapNotice(base)
	if !strings.Contains(once, retryCapNotice) || !strings.Contains(once, base) {
		t.Errorf("非空应追加标注: %q", once)
	}
	if twice := appendRetryCapNotice(once); twice != once {
		t.Errorf("重复追加应幂等: %q -> %q", once, twice)
	}
}

func TestWaitCallbacks_ReturnsAndClearsConcurrentWarnings(t *testing.T) {
	d := NewMockDeployer()
	client := &MockAPIClient{CallbackFunc: func(context.Context, *api.CallbackRequest) error {
		return fmt.Errorf("manager rejected callback")
	}}

	const callbackCount = 16
	for i := 0; i < callbackCount; i++ {
		sendCallback(d, client, 400+i, "warning.example.com", false, "deploy failed")
	}

	warnings := d.WaitCallbacks()
	if len(warnings) != callbackCount {
		t.Fatalf("并发 callback warning 数量 = %d, want %d: %v", len(warnings), callbackCount, warnings)
	}
	for _, warning := range warnings {
		if !strings.Contains(warning, "manager rejected callback") {
			t.Fatalf("warning 未保留 callback 最终错误: %q", warning)
		}
	}
	if stale := d.WaitCallbacks(); len(stale) != 0 {
		t.Fatalf("读取后必须清空，避免下一轮串入旧 warning: %v", stale)
	}
}
