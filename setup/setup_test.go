package setup

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
)

func preserveSetupConfigFile(t *testing.T) string {
	t.Helper()
	path := config.GetConfigPath()
	original, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.WriteFile(path, original, 0600)
		} else {
			_ = os.Remove(path)
		}
	})
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeSetupConfig(t *testing.T, path string, cfg *config.Config) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func mustMakeCertConfig(t *testing.T, certData api.CertData, opts Options, serial string) config.CertConfig {
	t.Helper()
	cfg, err := makeCertConfig(certData, opts, serial)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func setupRunOptions(t *testing.T) Options {
	t.Helper()
	certPEM, keyPEM := setupTestPair(t, "setup.example.com")
	certData := api.CertData{
		OrderID: 1, Domains: "setup.example.com", Status: "active",
		Certificate: certPEM, CACert: certPEM, PrivateKey: keyPEM,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok", "data": map[string]any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data": []api.CertData{certData}, "currentPage": 1, "pageSize": 100, "total": 1,
			},
		})
	}))
	t.Cleanup(server.Close)
	return Options{URL: server.URL, Token: "token", Order: "1"}
}

func stubSetupRunEffects(t *testing.T, saveErr, taskErr, runTaskErr error) (*[]string, **config.Config) {
	t.Helper()
	oldInstall, oldBind := installPFXFn, bindCertToIISFn
	oldSave, oldCreate, oldRunTask := saveSetupConfigFn, createTaskFn, runTaskNowFn
	t.Cleanup(func() {
		installPFXFn, bindCertToIISFn = oldInstall, oldBind
		saveSetupConfigFn, createTaskFn, runTaskNowFn = oldSave, oldCreate, oldRunTask
	})

	events := &[]string{}
	var savedCfg *config.Config
	installPFXFn = func(string, string) (*cert.InstallResult, error) {
		*events = append(*events, "install")
		return &cert.InstallResult{Success: true, Thumbprint: "AABBCCDDEEFF00112233445566778899AABBCCDD"}, nil
	}
	bindCertToIISFn = func(api.CertData, string) (bindResult, error) {
		return bindResult{Succeeded: 1}, nil
	}
	saveSetupConfigFn = func(cfg *config.Config) error {
		*events = append(*events, "save")
		savedCfg = cfg
		return saveErr
	}
	createTaskFn = func(string) error {
		*events = append(*events, "task")
		return taskErr
	}
	runTaskNowFn = func(string) error {
		*events = append(*events, "start")
		return runTaskErr
	}
	return events, &savedCfg
}

func TestMakeCertConfigReturnsTokenEncryptionFailure(t *testing.T) {
	want := errors.New("DPAPI unavailable")
	cfg, err := makeCertConfigWithTokenSetter(
		api.CertData{OrderID: 7, Domains: "example.com"},
		Options{URL: "https://example.com/api", Token: "secret"},
		"SERIAL",
		func(*config.CertAPIConfig, string) error { return want },
	)
	if !errors.Is(err, want) {
		t.Fatalf("error=%v want=%v", err, want)
	}
	if cfg.OrderID != 0 || cfg.API.EncryptedToken != "" {
		t.Fatalf("失败时不应返回可保存配置: %+v", cfg)
	}
}

func TestInstallCertTokenFailureKeepsInstalledFactWithoutConfig(t *testing.T) {
	certPEM, keyPEM := setupTestPair(t, "example.com")
	client, statuses := newSetupStub(t, bindResult{Succeeded: 1}, nil)
	var certConfigs []config.CertConfig
	result := &RunResult{}
	want := errors.New("DPAPI unavailable")
	maker := func(api.CertData, Options, string) (config.CertConfig, error) {
		return config.CertConfig{}, want
	}

	deployed, err := installCert(
		client,
		api.CertData{OrderID: 8, Domains: "example.com", Certificate: certPEM, CACert: certPEM},
		keyPEM, "SERIAL", Options{URL: "https://example.com/api", Token: "secret"},
		&certConfigs, result, false, false, maker,
	)
	if !deployed || !errors.Is(err, want) {
		t.Fatalf("deployed=%v error=%v", deployed, err)
	}
	if result.Installed != 1 || result.Failed != 0 || len(certConfigs) != 0 {
		t.Fatalf("result=%+v certConfigs=%+v", result, certConfigs)
	}
	if len(*statuses) != 1 || (*statuses)[0] != "success" {
		t.Fatalf("配置构造失败不得吞掉实际部署成功回调: %v", *statuses)
	}
}

func TestInstallCertKeepsBindAndTokenErrorsWithoutDoubleCounting(t *testing.T) {
	certPEM, keyPEM := setupTestPair(t, "failed.example.com")
	bindErr := errors.New("binding root cause")
	client, statuses := newSetupStub(t, bindResult{}, bindErr)
	var certConfigs []config.CertConfig
	result := &RunResult{}
	tokenErr := errors.New("DPAPI unavailable")

	deployed, err := installCert(
		client,
		api.CertData{OrderID: 9, Domains: "failed.example.com", Certificate: certPEM, CACert: certPEM},
		keyPEM, "SERIAL", Options{URL: "https://example.com/api", Token: "secret"},
		&certConfigs, result, false, false,
		func(api.CertData, Options, string) (config.CertConfig, error) {
			return config.CertConfig{}, tokenErr
		},
	)
	if !deployed {
		result.Failed++
	}
	if deployed || !errors.Is(err, tokenErr) || !strings.Contains(err.Error(), bindErr.Error()) {
		t.Fatalf("deployed=%v error=%v", deployed, err)
	}
	if result.Installed != 0 || result.Failed != 1 || len(certConfigs) != 0 {
		t.Fatalf("result=%+v certConfigs=%+v", result, certConfigs)
	}
	if len(*statuses) != 1 || (*statuses)[0] != "failure" {
		t.Fatalf("应按实际绑定失败发送一次回调: %v", *statuses)
	}
}

func TestRunConfigLoadFailureStopsBeforeInstallSaveAndTask(t *testing.T) {
	path := preserveSetupConfigFile(t)
	if err := os.WriteFile(path, []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	events, _ := stubSetupRunEffects(t, nil, nil, nil)

	result, err := Run(setupRunOptions(t), nil, nil)
	if err == nil || result != nil {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if len(*events) != 0 {
		t.Fatalf("Load 失败后不应安装、保存或建任务: %v", *events)
	}
}

func TestRunSaveFailureStopsTaskAndReturnsInstalledFact(t *testing.T) {
	path := preserveSetupConfigFile(t)
	writeSetupConfig(t, path, config.DefaultConfig())
	saveErr := errors.New("save failed")
	events, savedCfg := stubSetupRunEffects(t, saveErr, nil, nil)
	var messages []string

	result, err := Run(setupRunOptions(t), func(_, _ int, message string) {
		messages = append(messages, message)
	}, nil)
	if result == nil || result.Installed != 1 || !errors.Is(err, saveErr) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if strings.Join(*events, ",") != "install,save" {
		t.Fatalf("events=%v", *events)
	}
	if *savedCfg == nil || !(*savedCfg).AutoCheckEnabled {
		t.Fatalf("保存前应写入用户自动检查意图: %+v", *savedCfg)
	}
	for _, message := range messages {
		if strings.HasPrefix(message, "完成:") {
			t.Fatalf("失败路径不应报告成功完成: %q", message)
		}
	}
}

func TestRunCreateTaskFailureKeepsSavedInstalledFact(t *testing.T) {
	path := preserveSetupConfigFile(t)
	writeSetupConfig(t, path, config.DefaultConfig())
	taskErr := errors.New("task failed")
	events, savedCfg := stubSetupRunEffects(t, nil, taskErr, nil)

	result, err := Run(setupRunOptions(t), nil, nil)
	if result == nil || result.Installed != 1 || !errors.Is(err, taskErr) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if strings.Join(*events, ",") != "install,save,task" {
		t.Fatalf("events=%v", *events)
	}
	if *savedCfg == nil || !(*savedCfg).AutoCheckEnabled {
		t.Fatalf("建任务失败仍须保留已保存配置事实: %+v", *savedCfg)
	}
}

func TestRunSuccessSavesBeforeCreatingTask(t *testing.T) {
	path := preserveSetupConfigFile(t)
	writeSetupConfig(t, path, config.DefaultConfig())
	events, _ := stubSetupRunEffects(t, nil, nil, nil)

	result, err := Run(setupRunOptions(t), nil, nil)
	if err != nil || result == nil || result.Installed != 1 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if strings.Join(*events, ",") != "install,save,task,start" {
		t.Fatalf("events=%v", *events)
	}
}

func TestRunStartTaskFailureKeepsCreatedSchedule(t *testing.T) {
	path := preserveSetupConfigFile(t)
	writeSetupConfig(t, path, config.DefaultConfig())
	runTaskErr := errors.New("start failed")
	events, savedCfg := stubSetupRunEffects(t, nil, nil, runTaskErr)

	result, err := Run(setupRunOptions(t), nil, nil)
	if result == nil || result.Installed != 1 || !errors.Is(err, runTaskErr) {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	if strings.Join(*events, ",") != "install,save,task,start" {
		t.Fatalf("events=%v", *events)
	}
	if *savedCfg == nil || !(*savedCfg).AutoCheckEnabled {
		t.Fatalf("首次启动失败仍须保留已创建任务与启用配置: %+v", *savedCfg)
	}
}
