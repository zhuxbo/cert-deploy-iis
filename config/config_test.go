package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateValidationMethod(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		method   string
		wantErr  bool
		errMatch string
	}{
		// 文件验证（HTTP-01）
		{"文件验证-普通域名", "example.com", ValidationMethodFile, false, ""},
		{"文件验证-子域名", "www.example.com", ValidationMethodFile, false, ""},
		{"文件验证-通配符", "*.example.com", ValidationMethodFile, true, "通配符域名不支持文件验证"},
		{"文件验证-IP地址", "192.168.1.1", ValidationMethodFile, false, ""},

		// 委托验证（DNS-01）
		{"委托验证-普通域名", "example.com", ValidationMethodDelegation, false, ""},
		{"委托验证-子域名", "www.example.com", ValidationMethodDelegation, false, ""},
		{"委托验证-通配符", "*.example.com", ValidationMethodDelegation, false, ""},
		{"委托验证-IP地址", "192.168.1.1", ValidationMethodDelegation, true, "IP 地址不支持委托验证"},
		{"委托验证-IPv6", "2001:db8::1", ValidationMethodDelegation, true, "IP 地址不支持委托验证"},

		// 空方法（自动选择）
		{"空方法-普通域名", "example.com", "", false, ""},
		{"空方法-通配符", "*.example.com", "", false, ""},
		{"空方法-IP", "192.168.1.1", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := ValidateValidationMethod(tt.domain, tt.method)
			hasErr := errMsg != ""
			if hasErr != tt.wantErr {
				t.Errorf("ValidateValidationMethod(%q, %q) = %q, wantErr %v", tt.domain, tt.method, errMsg, tt.wantErr)
			}
			if tt.wantErr && tt.errMatch != "" && errMsg != tt.errMatch {
				t.Errorf("ValidateValidationMethod(%q, %q) = %q, want error containing %q", tt.domain, tt.method, errMsg, tt.errMatch)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	if cfg.RenewDaysLocal != 15 {
		t.Errorf("RenewDaysLocal = %d, want 15", cfg.RenewDaysLocal)
	}

	if cfg.RenewDaysFetch != 13 {
		t.Errorf("RenewDaysFetch = %d, want 13", cfg.RenewDaysFetch)
	}

	if cfg.CheckInterval != 6 {
		t.Errorf("CheckInterval = %d, want 6", cfg.CheckInterval)
	}

	if cfg.TaskName != "SSLCtlW" {
		t.Errorf("TaskName = %q, want %q", cfg.TaskName, "SSLCtlW")
	}

	if cfg.AutoCheckEnabled {
		t.Error("AutoCheckEnabled should be false by default")
	}

	if cfg.IIS7Mode {
		t.Error("IIS7Mode should be false by default")
	}
}

func TestGetDefaultBindRules(t *testing.T) {
	tests := []struct {
		name    string
		domains []string
		want    int
	}{
		{"单个域名", []string{"example.com"}, 1},
		{"多个域名", []string{"example.com", "www.example.com"}, 2},
		{"空列表", []string{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := GetDefaultBindRules(tt.domains)
			if len(rules) != tt.want {
				t.Errorf("GetDefaultBindRules(%v) returned %d rules, want %d", tt.domains, len(rules), tt.want)
			}

			// 验证每个规则的端口
			for _, rule := range rules {
				if rule.Port != 443 {
					t.Errorf("Rule for %s has port %d, want 443", rule.Domain, rule.Port)
				}
			}
		})
	}
}

func TestCertConfig_GetCertificateByOrderID(t *testing.T) {
	cfg := &Config{
		Certificates: []CertConfig{
			{OrderID: 100, Domain: "a.com"},
			{OrderID: 200, Domain: "b.com"},
			{OrderID: 300, Domain: "c.com"},
		},
	}

	tests := []struct {
		name    string
		orderID int
		want    string
		wantNil bool
	}{
		{"找到第一个", 100, "a.com", false},
		{"找到中间", 200, "b.com", false},
		{"找到最后", 300, "c.com", false},
		{"未找到", 999, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cfg.GetCertificateByOrderID(tt.orderID)
			if tt.wantNil {
				if got != nil {
					t.Errorf("GetCertificateByOrderID(%d) = %+v, want nil", tt.orderID, got)
				}
			} else {
				if got == nil {
					t.Errorf("GetCertificateByOrderID(%d) = nil, want %s", tt.orderID, tt.want)
				} else if got.Domain != tt.want {
					t.Errorf("GetCertificateByOrderID(%d).Domain = %s, want %s", tt.orderID, got.Domain, tt.want)
				}
			}
		})
	}
}

func TestCertConfig_RemoveCertificateByIndex(t *testing.T) {
	tests := []struct {
		name       string
		initial    []CertConfig
		removeIdx  int
		wantLen    int
		wantDomain string // 验证第一个元素的域名
	}{
		{
			"移除第一个",
			[]CertConfig{{Domain: "a.com"}, {Domain: "b.com"}, {Domain: "c.com"}},
			0,
			2,
			"b.com",
		},
		{
			"移除中间",
			[]CertConfig{{Domain: "a.com"}, {Domain: "b.com"}, {Domain: "c.com"}},
			1,
			2,
			"a.com",
		},
		{
			"移除最后",
			[]CertConfig{{Domain: "a.com"}, {Domain: "b.com"}, {Domain: "c.com"}},
			2,
			2,
			"a.com",
		},
		{
			"索引越界-负数",
			[]CertConfig{{Domain: "a.com"}},
			-1,
			1,
			"a.com",
		},
		{
			"索引越界-过大",
			[]CertConfig{{Domain: "a.com"}},
			10,
			1,
			"a.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Certificates: make([]CertConfig, len(tt.initial))}
			copy(cfg.Certificates, tt.initial)

			cfg.RemoveCertificateByIndex(tt.removeIdx)

			if len(cfg.Certificates) != tt.wantLen {
				t.Errorf("After RemoveCertificateByIndex(%d), len = %d, want %d", tt.removeIdx, len(cfg.Certificates), tt.wantLen)
			}

			if len(cfg.Certificates) > 0 && cfg.Certificates[0].Domain != tt.wantDomain {
				t.Errorf("After RemoveCertificateByIndex(%d), first domain = %s, want %s", tt.removeIdx, cfg.Certificates[0].Domain, tt.wantDomain)
			}
		})
	}
}

func TestConfig_AddCertificate(t *testing.T) {
	cfg := &Config{Certificates: []CertConfig{}}

	// 添加第一个证书
	cfg.AddCertificate(CertConfig{OrderID: 100, Domain: "a.com"})
	if len(cfg.Certificates) != 1 {
		t.Errorf("添加后证书数量 = %d, want 1", len(cfg.Certificates))
	}

	// 添加第二个证书
	cfg.AddCertificate(CertConfig{OrderID: 200, Domain: "b.com"})
	if len(cfg.Certificates) != 2 {
		t.Errorf("添加后证书数量 = %d, want 2", len(cfg.Certificates))
	}

	// 验证顺序
	if cfg.Certificates[0].OrderID != 100 {
		t.Errorf("第一个证书 OrderID = %d, want 100", cfg.Certificates[0].OrderID)
	}
	if cfg.Certificates[1].OrderID != 200 {
		t.Errorf("第二个证书 OrderID = %d, want 200", cfg.Certificates[1].OrderID)
	}
}

func TestConfig_UpdateCertificate(t *testing.T) {
	cfg := &Config{
		Certificates: []CertConfig{
			{OrderID: 100, Domain: "a.com", Enabled: false},
			{OrderID: 200, Domain: "b.com", Enabled: false},
		},
	}

	// 更新第一个证书
	cfg.UpdateCertificate(0, CertConfig{OrderID: 100, Domain: "a-updated.com", Enabled: true})
	if cfg.Certificates[0].Domain != "a-updated.com" {
		t.Errorf("更新后域名 = %s, want a-updated.com", cfg.Certificates[0].Domain)
	}
	if !cfg.Certificates[0].Enabled {
		t.Error("更新后 Enabled 应该为 true")
	}

	// 索引越界不应该 panic
	cfg.UpdateCertificate(-1, CertConfig{})
	cfg.UpdateCertificate(100, CertConfig{})
	// 验证原有数据未被修改
	if len(cfg.Certificates) != 2 {
		t.Errorf("越界更新后证书数量 = %d, want 2", len(cfg.Certificates))
	}
}

func TestConfig_GetToken_Empty(t *testing.T) {
	cfg := &Config{}
	token := cfg.GetToken()
	if token != "" {
		t.Errorf("GetToken() = %q, want empty string", token)
	}
}

func TestConfig_SetToken(t *testing.T) {
	cfg := &Config{}
	err := cfg.SetToken("test-token-12345")
	if err != nil {
		t.Fatalf("SetToken() error = %v", err)
	}

	// 验证加密后的 Token 存在
	if cfg.EncryptedToken == "" {
		t.Error("EncryptedToken 应该不为空")
	}

	// 验证明文 Token 被清除
	if cfg.Token != "" {
		t.Errorf("Token 应该被清除, got %q", cfg.Token)
	}

	// 验证可以正确解密
	decrypted := cfg.GetToken()
	if decrypted != "test-token-12345" {
		t.Errorf("GetToken() = %q, want %q", decrypted, "test-token-12345")
	}
}

func TestConfig_SetToken_Empty(t *testing.T) {
	cfg := &Config{Token: "old-token"}
	err := cfg.SetToken("")
	if err != nil {
		t.Fatalf("SetToken(\"\") error = %v", err)
	}

	// 空 token 加密后应该是空字符串
	if cfg.EncryptedToken != "" {
		t.Errorf("空 Token 加密后应该为空, got %q", cfg.EncryptedToken)
	}
}

func TestBindRule_Fields(t *testing.T) {
	rule := BindRule{
		Domain:   "www.example.com",
		Port:     8443,
		SiteName: "Custom Site",
	}

	if rule.Domain != "www.example.com" {
		t.Errorf("Domain = %q", rule.Domain)
	}
	if rule.Port != 8443 {
		t.Errorf("Port = %d", rule.Port)
	}
	if rule.SiteName != "Custom Site" {
		t.Errorf("SiteName = %q", rule.SiteName)
	}
}

func TestCertConfig_AllFields(t *testing.T) {
	cert := CertConfig{
		OrderID:          123,
		Domain:           "example.com",
		Domains:          []string{"example.com", "www.example.com"},
		ExpiresAt:        "2025-12-31",
		SerialNumber:     "ABC123",
		Enabled:          true,
		UseLocalKey:      true,
		ValidationMethod: "file",
		AutoBindMode:     true,
		BindRules: []BindRule{
			{Domain: "www.example.com", Port: 443},
		},
	}

	if cert.OrderID != 123 {
		t.Errorf("OrderID = %d", cert.OrderID)
	}
	if cert.Domain != "example.com" {
		t.Errorf("Domain = %q", cert.Domain)
	}
	if len(cert.Domains) != 2 {
		t.Errorf("Domains 长度 = %d", len(cert.Domains))
	}
	if cert.ExpiresAt != "2025-12-31" {
		t.Errorf("ExpiresAt = %q", cert.ExpiresAt)
	}
	if cert.SerialNumber != "ABC123" {
		t.Errorf("SerialNumber = %q", cert.SerialNumber)
	}
	if !cert.Enabled {
		t.Error("Enabled 应该为 true")
	}
	if !cert.UseLocalKey {
		t.Error("UseLocalKey 应该为 true")
	}
	if cert.ValidationMethod != "file" {
		t.Errorf("ValidationMethod = %q", cert.ValidationMethod)
	}
	if !cert.AutoBindMode {
		t.Error("AutoBindMode 应该为 true")
	}
}

func TestValidationMethodConstants(t *testing.T) {
	if ValidationMethodFile != "file" {
		t.Errorf("ValidationMethodFile = %q, want %q", ValidationMethodFile, "file")
	}
	if ValidationMethodDelegation != "delegation" {
		t.Errorf("ValidationMethodDelegation = %q, want %q", ValidationMethodDelegation, "delegation")
	}
}

func TestDataDirName(t *testing.T) {
	if DataDirName != "sslctlw" {
		t.Errorf("DataDirName = %q, want %q", DataDirName, "sslctlw")
	}
}

// TestGetDataDir 测试获取数据目录
func TestGetDataDir(t *testing.T) {
	dir := GetDataDir()
	if dir == "" {
		t.Error("GetDataDir() 返回空字符串")
	}
	// 应该包含 sslctlw
	if !containsString(dir, DataDirName) {
		t.Errorf("GetDataDir() = %q, 应该包含 %q", dir, DataDirName)
	}
}

func TestResolveDataDir_PrimarySuccess(t *testing.T) {
	exePath := "C:\\Program Files\\sslctlw\\sslctlw.exe"
	appData := "C:\\Users\\Tester\\AppData\\Roaming"

	calls := []string{}
	mkdir := func(path string, perm os.FileMode) error {
		calls = append(calls, path)
		return nil
	}

	got := resolveDataDir(exePath, appData, mkdir)
	want := filepath.Join(filepath.Dir(exePath), DataDirName)

	if got != want {
		t.Errorf("resolveDataDir() = %q, want %q", got, want)
	}
	if len(calls) != 1 || calls[0] != want {
		t.Errorf("resolveDataDir() 调用次数/路径异常: %v", calls)
	}
}

func TestResolveDataDir_Fallback(t *testing.T) {
	exePath := "C:\\Program Files\\sslctlw\\sslctlw.exe"
	appData := "C:\\Users\\Tester\\AppData\\Roaming"

	calls := []string{}
	mkdir := func(path string, perm os.FileMode) error {
		calls = append(calls, path)
		if strings.Contains(path, "Program Files") {
			return errors.New("permission denied")
		}
		return nil
	}

	got := resolveDataDir(exePath, appData, mkdir)
	wantPrimary := filepath.Join(filepath.Dir(exePath), DataDirName)
	wantFallback := filepath.Join(appData, DataDirName)

	if got != wantFallback {
		t.Errorf("resolveDataDir() = %q, want %q", got, wantFallback)
	}
	if len(calls) < 2 || calls[0] != wantPrimary || calls[1] != wantFallback {
		t.Errorf("resolveDataDir() 未按预期尝试 fallback: %v", calls)
	}
}

func TestLoad_PlainTokenRejected(t *testing.T) {
	path := GetConfigPath()
	dir := filepath.Dir(path)

	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Skipf("无法创建配置目录: %v", err)
	}

	orig, origErr := os.ReadFile(path)

	data := `{"api_base_url":"https://api.example.com","token":"plain-token","certificates":[]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Skipf("无法写入配置文件: %v", err)
	}
	defer func() {
		if origErr == nil {
			_ = os.WriteFile(path, orig, 0600)
		} else {
			_ = os.Remove(path)
		}
	}()

	cfg, err := Load()
	if err == nil {
		t.Fatal("Load() 应该拒绝明文 Token")
	}
	if cfg == nil {
		t.Fatal("Load() 应该返回配置对象")
	}
	if cfg.Token != "" {
		t.Errorf("Load() 应清理明文 Token, got %q", cfg.Token)
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestGetConfigPath 测试获取配置文件路径
func TestGetConfigPath(t *testing.T) {
	path := GetConfigPath()
	if path == "" {
		t.Error("GetConfigPath() 返回空字符串")
	}
	// 应该以 config.json 结尾
	if !hasSuffix(path, "config.json") {
		t.Errorf("GetConfigPath() = %q, 应该以 config.json 结尾", path)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// TestGetLogDir 测试获取日志目录
func TestGetLogDir(t *testing.T) {
	dir := GetLogDir()
	if dir == "" {
		t.Error("GetLogDir() 返回空字符串")
	}
	// 应该包含 logs
	if !containsString(dir, "logs") {
		t.Errorf("GetLogDir() = %q, 应该包含 logs", dir)
	}
}

// TestLoad_DefaultConfig 测试加载默认配置（文件不存在时）
func TestLoad_DefaultConfig(t *testing.T) {
	// 这个测试依赖于实际的文件系统
	// 在配置文件不存在的情况下应该返回默认配置
	cfg, err := Load()
	if err != nil {
		// 如果有错误可能是因为无法创建目录等
		t.Skipf("Load() error = %v（可能是权限问题）", err)
	}

	if cfg == nil {
		t.Fatal("Load() 返回 nil")
	}

	// 验证默认值
	if cfg.RenewDaysLocal == 0 {
		t.Error("RenewDaysLocal 应该有默认值")
	}
	if cfg.RenewDaysFetch == 0 {
		t.Error("RenewDaysFetch 应该有默认值")
	}
}

// TestConfig_Save_And_Load 测试保存和加载
func TestConfig_Save_And_Load(t *testing.T) {
	// 创建测试配置
	cfg := DefaultConfig()
	cfg.APIBaseURL = "https://test.example.com/api"
	cfg.SetToken("test-token-12345")
	cfg.AddCertificate(CertConfig{
		OrderID: 999,
		Domain:  "test.example.com",
		Enabled: true,
	})

	// 保存
	err := cfg.Save()
	if err != nil {
		t.Skipf("Save() error = %v（可能是权限问题）", err)
	}

	// 重新加载
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// 验证
	if loaded.APIBaseURL != "https://test.example.com/api" {
		t.Errorf("APIBaseURL = %q", loaded.APIBaseURL)
	}

	// Token 应该能正确解密
	token := loaded.GetToken()
	if token != "test-token-12345" {
		t.Errorf("GetToken() = %q, want %q", token, "test-token-12345")
	}

	// 验证证书配置
	foundCert := false
	for _, cert := range loaded.Certificates {
		if cert.OrderID == 999 {
			foundCert = true
			if cert.Domain != "test.example.com" {
				t.Errorf("cert.Domain = %q", cert.Domain)
			}
		}
	}
	if !foundCert {
		t.Error("未找到保存的证书配置")
	}
}

// TestValidateValidationMethod_MoreCases 更多验证方法测试
func TestValidateValidationMethod_MoreCases(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		method  string
		wantErr bool
	}{
		// IPv4 测试
		{"IPv4-文件验证", "1.2.3.4", "file", false},
		{"IPv4-委托验证", "1.2.3.4", "delegation", true},
		{"IPv4-空方法", "1.2.3.4", "", false},

		// IPv6 测试
		{"IPv6-简写", "::1", "delegation", true},
		{"IPv6-完整", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "delegation", true},

		// 通配符测试
		{"通配符-一级", "*.com", "file", true},
		{"通配符-二级", "*.example.com", "file", true},

		// 普通域名
		{"普通域名-文件", "example.com", "file", false},
		{"普通域名-委托", "example.com", "delegation", false},
		{"普通域名-空", "example.com", "", false},

		// 子域名
		{"子域名-文件", "www.example.com", "file", false},
		{"子域名-委托", "www.example.com", "delegation", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := ValidateValidationMethod(tt.domain, tt.method)
			hasErr := errMsg != ""
			if hasErr != tt.wantErr {
				t.Errorf("ValidateValidationMethod(%q, %q) = %q, wantErr %v", tt.domain, tt.method, errMsg, tt.wantErr)
			}
		})
	}
}

// TestConfig_AllFields 测试 Config 所有字段
func TestConfig_AllFields(t *testing.T) {
	cfg := &Config{
		APIBaseURL:       "https://api.example.com",
		Token:            "plain-token",
		EncryptedToken:   "encrypted-token",
		Certificates:     []CertConfig{{OrderID: 1}},
		RenewDaysLocal:   20,
		RenewDaysFetch:   10,
		LastCheck:        "2024-01-01 00:00:00",
		AutoCheckEnabled: true,
		CheckInterval:    12,
		TaskName:         "CustomTask",
		IIS7Mode:         true,
	}

	if cfg.APIBaseURL != "https://api.example.com" {
		t.Errorf("APIBaseURL = %q", cfg.APIBaseURL)
	}
	if cfg.Token != "plain-token" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.EncryptedToken != "encrypted-token" {
		t.Errorf("EncryptedToken = %q", cfg.EncryptedToken)
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates 长度 = %d", len(cfg.Certificates))
	}
	if cfg.RenewDaysLocal != 20 {
		t.Errorf("RenewDaysLocal = %d", cfg.RenewDaysLocal)
	}
	if cfg.RenewDaysFetch != 10 {
		t.Errorf("RenewDaysFetch = %d", cfg.RenewDaysFetch)
	}
	if cfg.LastCheck != "2024-01-01 00:00:00" {
		t.Errorf("LastCheck = %q", cfg.LastCheck)
	}
	if !cfg.AutoCheckEnabled {
		t.Error("AutoCheckEnabled 应该为 true")
	}
	if cfg.CheckInterval != 12 {
		t.Errorf("CheckInterval = %d", cfg.CheckInterval)
	}
	if cfg.TaskName != "CustomTask" {
		t.Errorf("TaskName = %q", cfg.TaskName)
	}
	if !cfg.IIS7Mode {
		t.Error("IIS7Mode 应该为 true")
	}
}

// TestCertConfig_AutoBindMode 测试自动绑定模式
func TestCertConfig_AutoBindMode(t *testing.T) {
	cert := CertConfig{
		OrderID:      123,
		Domain:       "example.com",
		AutoBindMode: true,
		BindRules:    nil, // 自动绑定模式不需要绑定规则
	}

	if !cert.AutoBindMode {
		t.Error("AutoBindMode 应该为 true")
	}
	if cert.BindRules != nil && len(cert.BindRules) > 0 {
		t.Error("自动绑定模式不应该有绑定规则")
	}
}

// TestGetDefaultBindRules_Domains 测试默认绑定规则生成
func TestGetDefaultBindRules_Domains(t *testing.T) {
	domains := []string{"example.com", "www.example.com", "api.example.com"}
	rules := GetDefaultBindRules(domains)

	if len(rules) != 3 {
		t.Fatalf("GetDefaultBindRules() 返回 %d 条规则, want 3", len(rules))
	}

	// 验证每条规则
	for i, rule := range rules {
		if rule.Domain != domains[i] {
			t.Errorf("rules[%d].Domain = %q, want %q", i, rule.Domain, domains[i])
		}
		if rule.Port != 443 {
			t.Errorf("rules[%d].Port = %d, want 443", i, rule.Port)
		}
		if rule.SiteName != "" {
			t.Errorf("rules[%d].SiteName = %q, want empty", i, rule.SiteName)
		}
	}
}

// TestConfig_SetToken_Multiple 测试多次设置 Token
func TestConfig_SetToken_Multiple(t *testing.T) {
	cfg := &Config{}

	// 第一次设置
	err := cfg.SetToken("token1")
	if err != nil {
		t.Fatalf("SetToken(token1) error = %v", err)
	}

	token1 := cfg.GetToken()
	if token1 != "token1" {
		t.Errorf("GetToken() = %q, want %q", token1, "token1")
	}

	// 第二次设置（覆盖）
	err = cfg.SetToken("token2")
	if err != nil {
		t.Fatalf("SetToken(token2) error = %v", err)
	}

	token2 := cfg.GetToken()
	if token2 != "token2" {
		t.Errorf("GetToken() = %q, want %q", token2, "token2")
	}
}
