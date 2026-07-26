package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sslctlw/config"
	"sslctlw/deploy"
	"sslctlw/util"
)

func enabledSingleCertConfig(orderID int) *config.Config {
	return &config.Config{Certificates: []config.CertConfig{{
		OrderID: orderID, Domain: "a.example.com", Enabled: true,
	}}}
}

func TestDeploySingleCertWithRunnerPreservesFullConfigRoundTrip(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{OrderID: 101, Domain: "a.example.com", Enabled: true},
			{OrderID: 202, Domain: "b.example.com", Enabled: true},
		},
		Schedule:         config.Schedule{RenewMode: "local", RenewBeforeDays: 19},
		AutoCheckEnabled: true,
		TaskName:         "keep-top-level-fields",
		UpgradeEnabled:   true,
		UpgradeChannel:   "dev",
		UpgradeInterval:  123,
	}
	deployer := &deploy.Deployer{}
	savedPath := filepath.Join(t.TempDir(), "config.json")
	runner := func(gotCfg *config.Config, gotDeployer *deploy.Deployer, opts deploy.RunOptions) deploy.RunReport {
		if gotCfg != cfg {
			t.Fatal("必须把完整原始配置传给 AutoDeploy")
		}
		if gotDeployer != deployer {
			t.Fatal("必须使用调用方提供的 deployer")
		}
		if opts.OnlyOrderID != 101 {
			t.Fatalf("OnlyOrderID = %d, want 101", opts.OnlyOrderID)
		}
		data, err := json.Marshal(gotCfg)
		if err != nil {
			t.Fatalf("序列化完整配置: %v", err)
		}
		if err := os.WriteFile(savedPath, data, 0600); err != nil {
			t.Fatalf("保存完整配置: %v", err)
		}
		return deploy.RunReport{Results: []deploy.Result{{
			OrderID: 101, Domain: "a.example.com", Success: true, Message: "部署成功",
		}}}
	}

	var out bytes.Buffer
	if err := deploySingleCertWithRunner(cfg, deployer, 101, runner, &out); err != nil {
		t.Fatalf("deploySingleCertWithRunner() error = %v", err)
	}
	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("重新读取配置: %v", err)
	}
	var loaded config.Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("重新加载配置: %v", err)
	}
	if len(loaded.Certificates) != 2 || loaded.Certificates[1].OrderID != 202 {
		t.Fatalf("非目标证书配置丢失: %+v", loaded.Certificates)
	}
	if loaded.Schedule.RenewMode != "local" || loaded.Schedule.RenewBeforeDays != 19 ||
		!loaded.AutoCheckEnabled || loaded.TaskName != "keep-top-level-fields" ||
		!loaded.UpgradeEnabled || loaded.UpgradeChannel != "dev" || loaded.UpgradeInterval != 123 {
		t.Fatalf("顶层配置字段丢失: %+v", loaded)
	}
}

func TestDeploySingleCertWithRunnerReturnsCombinedFailures(t *testing.T) {
	cfg := enabledSingleCertConfig(101)
	runner := func(*config.Config, *deploy.Deployer, deploy.RunOptions) deploy.RunReport {
		return deploy.RunReport{
			Results: []deploy.Result{{
				OrderID: 101, Domain: "a.example.com", Success: false, Message: "运行失败",
			}},
			Attention: []deploy.CertAttention{{
				OrderID: 202, Domain: "a.example.com", Reason: "CAPPED",
			}},
		}
	}

	err := deploySingleCertWithRunner(cfg, &deploy.Deployer{}, 101, runner, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "运行失败") || !strings.Contains(err.Error(), "CAPPED") {
		t.Fatalf("应同时返回运行失败与实际订单 attention, got %v", err)
	}
}

func TestDeploySingleCertWithRunnerRejectsInvalidTargetsBeforeRun(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"目标不存在", &config.Config{Certificates: []config.CertConfig{{OrderID: 202}}}, "未找到订单 101"},
		{"目标禁用", &config.Config{Certificates: []config.CertConfig{{OrderID: 101, Enabled: false}}}, "已禁用"},
		{"订单重复", &config.Config{Certificates: []config.CertConfig{
			{OrderID: 101, Enabled: true},
			{OrderID: 101, Enabled: true},
		}}, "存在 2 条配置"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			runner := func(*config.Config, *deploy.Deployer, deploy.RunOptions) deploy.RunReport {
				called = true
				return deploy.RunReport{}
			}
			err := deploySingleCertWithRunner(tt.cfg, &deploy.Deployer{}, 101, runner, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want contains %q", err, tt.want)
			}
			if called {
				t.Fatal("无效目标不得启动自动部署")
			}
		})
	}
}

func TestDeploySingleCertWithRunnerKeepsNormalNoActionStatesSuccessful(t *testing.T) {
	tests := []struct {
		name   string
		report deploy.RunReport
		want   string
	}{
		{"processing或未到期", deploy.RunReport{}, "本次无需部署"},
		{"已有运行", deploy.RunReport{AlreadyRunning: true}, "已有部署正在运行"},
		{"callback warning", deploy.RunReport{
			Results:  []deploy.Result{{OrderID: 101, Success: true}},
			Warnings: []string{"callback rejected"},
		}, "callback rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			runner := func(*config.Config, *deploy.Deployer, deploy.RunOptions) deploy.RunReport {
				return tt.report
			}
			if err := deploySingleCertWithRunner(enabledSingleCertConfig(101), &deploy.Deployer{}, 101, runner, &out); err != nil {
				t.Fatalf("正常无动作或 callback warning 不应成为部署失败: %v", err)
			}
			if !strings.Contains(out.String(), tt.want) {
				t.Fatalf("输出 = %q, want contains %q", out.String(), tt.want)
			}
		})
	}
}

func TestDeploySingleCertWithRunnerPreservesErrorIdentity(t *testing.T) {
	sentinel := errors.New("运行失败")
	runner := func(*config.Config, *deploy.Deployer, deploy.RunOptions) deploy.RunReport {
		return deploy.RunReport{Errors: []error{sentinel}}
	}
	err := deploySingleCertWithRunner(enabledSingleCertConfig(101), &deploy.Deployer{}, 101, runner, &bytes.Buffer{})
	if !errors.Is(err, sentinel) {
		t.Fatalf("必须保留 RunReport 错误链: %v", err)
	}
}

func TestDeployAllWithRunnerConsumesCompleteRunReport(t *testing.T) {
	sentinel := errors.New("cursor save failed")
	tests := []struct {
		name    string
		report  deploy.RunReport
		wantOut string
		wantErr error
		notOut  string
	}{
		{
			name:    "已有运行",
			report:  deploy.RunReport{AlreadyRunning: true},
			wantOut: "已有部署正在运行",
		},
		{
			name: "人工处理项",
			report: deploy.RunReport{Attention: []deploy.CertAttention{{
				OrderID: 9, Domain: "attention.example.com", Reason: "CAPPED",
			}}},
			wantOut: "需人工处理",
		},
		{
			name:    "空结果运行错误",
			report:  deploy.RunReport{Errors: []error{sentinel}},
			wantOut: "cursor save failed",
			wantErr: sentinel,
			notOut:  "无需部署",
		},
		{
			name:    "只有警告",
			report:  deploy.RunReport{Warnings: []string{"callback failed"}},
			wantOut: "callback failed",
			notOut:  "无需部署",
		},
		{
			name:    "真正无动作",
			report:  deploy.RunReport{},
			wantOut: "本次无需部署",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := deployAllWithRunner(func() deploy.RunReport { return tt.report }, &out)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error=%v want=%v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("error=%v", err)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Fatalf("output=%q want contains %q", out.String(), tt.wantOut)
			}
			if tt.notOut != "" && strings.Contains(out.String(), tt.notOut) {
				t.Fatalf("output=%q must not contain %q", out.String(), tt.notOut)
			}
		})
	}
}

func TestWriteTaskHealthStatusDoesNotMisreportQueryFailureAsMissing(t *testing.T) {
	var out bytes.Buffer
	queryErr := errors.New("powershell unavailable")
	err := writeTaskHealthStatus(
		&out,
		true,
		"SSLCtlW",
		time.Date(2026, 7, 26, 12, 0, 0, 0, time.Local),
		func(string) (*util.TaskHealth, error) { return nil, queryErr },
	)
	if !errors.Is(err, queryErr) {
		t.Fatalf("error=%v want=%v", err, queryErr)
	}
	if !strings.Contains(out.String(), "不健康") || strings.Contains(out.String(), "未创建") {
		t.Fatalf("output=%q", out.String())
	}
}

func TestWriteTaskHealthStatusDisabledDoesNotQuery(t *testing.T) {
	var out bytes.Buffer
	err := writeTaskHealthStatus(
		&out,
		false,
		"SSLCtlW",
		time.Date(2026, 7, 26, 12, 0, 0, 0, time.Local),
		func(string) (*util.TaskHealth, error) {
			t.Fatal("自动部署已停止时不应查询任务")
			return nil, nil
		},
	)
	if err != nil {
		t.Fatalf("error=%v", err)
	}
	if !strings.Contains(out.String(), "不健康") || !strings.Contains(out.String(), "已停止") {
		t.Fatalf("output=%q", out.String())
	}
}
