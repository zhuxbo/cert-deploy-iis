package setup

import (
	"errors"
	"strings"
	"testing"

	"sslctlw/config"
)

// errAssert 测试用固定错误
var errAssert = errors.New("查找失败")

// TestIsOrderLocalMode setup 重跑时按现有配置判定订单续签模式
func TestIsOrderLocalMode(t *testing.T) {
	mkCfg := func(globalMode string, certs ...config.CertConfig) *config.Config {
		cfg := config.DefaultConfig()
		cfg.Schedule.RenewMode = globalMode
		cfg.Certificates = certs
		return cfg
	}

	tests := []struct {
		name    string
		cfg     *config.Config
		orderID int
		want    bool
	}{
		{
			name:    "配置为 nil（加载失败）默认 pull",
			cfg:     nil,
			orderID: 1,
			want:    false,
		},
		{
			name:    "订单未配置（新证书）默认 pull",
			cfg:     mkCfg("pull", config.CertConfig{OrderID: 2, RenewMode: "local"}),
			orderID: 1,
			want:    false,
		},
		{
			name:    "证书级 local",
			cfg:     mkCfg("pull", config.CertConfig{OrderID: 1, RenewMode: "local"}),
			orderID: 1,
			want:    true,
		},
		{
			name:    "证书级 pull",
			cfg:     mkCfg("local", config.CertConfig{OrderID: 1, RenewMode: "pull"}),
			orderID: 1,
			want:    false,
		},
		{
			name:    "证书级为空继承全局 local",
			cfg:     mkCfg("local", config.CertConfig{OrderID: 1}),
			orderID: 1,
			want:    true,
		},
		{
			name:    "证书级为空继承全局 pull",
			cfg:     mkCfg("pull", config.CertConfig{OrderID: 1}),
			orderID: 1,
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOrderLocalMode(tt.cfg, tt.orderID); got != tt.want {
				t.Errorf("isOrderLocalMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEvalBindOutcome 绑定结果判定：至少一个成功为部署生效，无匹配/全败/查错为失败
func TestEvalBindOutcome(t *testing.T) {
	tests := []struct {
		name       string
		br         bindResult
		bindErr    error
		wantOK     bool
		wantReason string
	}{
		{"查找绑定出错", bindResult{}, errAssert, false, "查找失败"},
		{"未找到可绑定站点", bindResult{}, nil, false, "未找到可绑定"},
		{"全部绑定失败", bindResult{Failed: 3}, nil, false, "全部 3 个绑定失败"},
		{"全部成功", bindResult{Succeeded: 2}, nil, true, ""},
		{"部分成功视为生效", bindResult{Succeeded: 1, Failed: 2}, nil, true, "部分绑定失败"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, reason := evalBindOutcome(tt.br, tt.bindErr)
			if ok != tt.wantOK {
				t.Errorf("evalBindOutcome() ok = %v, want %v (reason=%q)", ok, tt.wantOK, reason)
			}
			if tt.wantReason == "" && reason != "" {
				t.Errorf("reason = %q, want empty", reason)
			}
			if tt.wantReason != "" && !strings.Contains(reason, tt.wantReason) {
				t.Errorf("reason = %q, want contains %q", reason, tt.wantReason)
			}
		})
	}
}

// TestDecideReissueNotify 配置不可读时跳过续签模式通知
func TestDecideReissueNotify(t *testing.T) {
	localCfg := config.DefaultConfig()
	localCfg.Certificates = []config.CertConfig{{OrderID: 1, RenewMode: "local"}}

	tests := []struct {
		name      string
		cfg       *config.Config
		cfgLoadOK bool
		orderID   int
		wantNotif bool
		wantLocal bool
	}{
		{"配置加载失败跳过通知", nil, false, 1, false, false},
		{"配置正常且订单为 local", localCfg, true, 1, true, true},
		{"配置正常且订单未配置（新证书 pull）", localCfg, true, 2, true, false},
		{"无配置文件（Load 返回默认配置）通知 pull", config.DefaultConfig(), true, 1, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notify, useLocal := decideReissueNotify(tt.cfg, tt.cfgLoadOK, tt.orderID)
			if notify != tt.wantNotif || useLocal != tt.wantLocal {
				t.Errorf("decideReissueNotify() = (%v, %v), want (%v, %v)", notify, useLocal, tt.wantNotif, tt.wantLocal)
			}
		})
	}
}

// TestDecideExistingCert 已存在证书路径与新装路径共用 evalBindOutcome：
// 零成功（查找出错/全部失败/零匹配）判失败（发 failure 回调、计 Failed、不写配置），
// 至少一个成功判部署生效（计 Skipped、补通知、写配置）
func TestDecideExistingCert(t *testing.T) {
	tests := []struct {
		name         string
		br           bindResult
		bindErr      error
		wantDeployed bool
	}{
		{"查找出错→失败", bindResult{}, errAssert, false},
		{"零匹配→失败", bindResult{}, nil, false},
		{"全部失败→失败", bindResult{Failed: 2}, nil, false},
		{"无法取指纹（bindErr）→失败", bindResult{}, errors.New("无法获取已存在证书的指纹"), false},
		{"全部成功→部署生效", bindResult{Succeeded: 2}, nil, true},
		{"部分成功→部署生效", bindResult{Succeeded: 1, Failed: 1}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := decideExistingCert(tt.br, tt.bindErr)
			if dec.Deployed != tt.wantDeployed {
				t.Errorf("decideExistingCert().Deployed = %v, want %v (reason=%q)", dec.Deployed, tt.wantDeployed, dec.Reason)
			}
			// 失败必须带原因，供 failure 回调与日志说明
			if !dec.Deployed && dec.Reason == "" {
				t.Error("失败判定应带原因")
			}
		})
	}
}
