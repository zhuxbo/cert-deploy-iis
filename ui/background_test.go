package ui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"sslctlw/config"
	"sslctlw/deploy"
	"sslctlw/util"
)

func TestBackgroundTask_CheckGuard(t *testing.T) {
	task := NewBackgroundTask()

	if !task.tryStartCheck() {
		t.Fatal("首次 tryStartCheck 应该成功")
	}
	if task.tryStartCheck() {
		t.Fatal("重复 tryStartCheck 应该被拒绝")
	}

	task.endCheck()

	if !task.tryStartCheck() {
		t.Fatal("endCheck 后应允许再次开始")
	}
}

func TestBackgroundTaskConsumesRunReport(t *testing.T) {
	tests := []struct {
		name       string
		report     deploy.RunReport
		wantStatus TaskStatus
		wantText   string
	}{
		{
			name:       "空结果但有运行错误",
			report:     deploy.RunReport{Errors: []error{errors.New("save failed")}},
			wantStatus: TaskStatusFailed,
			wantText:   "save failed",
		},
		{
			name: "只有人工处理项",
			report: deploy.RunReport{Attention: []deploy.CertAttention{{
				OrderID: 7, Domain: "example.com", Reason: "CAPPED",
			}}},
			wantStatus: TaskStatusFailed,
			wantText:   "人工处理",
		},
		{
			name:       "已有运行",
			report:     deploy.RunReport{AlreadyRunning: true},
			wantStatus: TaskStatusRunning,
			wantText:   "已有部署正在运行",
		},
		{
			name: "已有运行且有警告",
			report: deploy.RunReport{
				AlreadyRunning: true,
				Warnings:       []string{"callback warning"},
			},
			wantStatus: TaskStatusRunning,
			wantText:   "已有部署正在运行",
		},
		{
			name:       "真正无动作",
			report:     deploy.RunReport{},
			wantStatus: TaskStatusSuccess,
			wantText:   "无需更新",
		},
		{
			name:       "只有警告",
			report:     deploy.RunReport{Warnings: []string{"callback rejected"}},
			wantStatus: TaskStatusSuccess,
			wantText:   "警告 1 条",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.Local)
			task := newBackgroundTask(
				func() (*config.Config, error) {
					return &config.Config{Certificates: []config.CertConfig{{OrderID: 7, Enabled: true}}}, nil
				},
				func(*config.Config) deploy.RunReport { return tt.report },
				func() time.Time { return now },
			)
			task.RunOnceSync()
			status, message := task.GetStatus()
			if status != tt.wantStatus || !strings.Contains(message, tt.wantText) {
				t.Fatalf("status=%v message=%q", status, message)
			}
		})
	}
}

func TestBackgroundTaskClearsPreviousReportBeforeFailedRun(t *testing.T) {
	loadCalls := 0
	task := newBackgroundTask(
		func() (*config.Config, error) {
			loadCalls++
			if loadCalls > 1 {
				return nil, errors.New("load failed")
			}
			return &config.Config{Certificates: []config.CertConfig{{OrderID: 7, Enabled: true}}}, nil
		},
		func(*config.Config) deploy.RunReport {
			return deploy.RunReport{Warnings: []string{"old warning"}}
		},
		time.Now,
	)

	task.RunOnceSync()
	task.RunOnceSync()

	report := task.GetReport()
	if len(report.Results) != 0 || len(report.Errors) != 0 ||
		len(report.Warnings) != 0 || len(report.Attention) != 0 {
		t.Fatalf("失败的新一轮不应暴露上一轮报告: %+v", report)
	}
}

func TestQueryTaskHealthPresentation(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.Local)
	tests := []struct {
		name      string
		enabled   bool
		query     func(string) (*util.TaskHealth, error)
		wantOK    bool
		wantText  string
		wantCalls int
	}{
		{
			name:     "用户意图已停止",
			enabled:  false,
			query:    func(string) (*util.TaskHealth, error) { t.Fatal("已停止时不应查询任务"); return nil, nil },
			wantText: "已停止",
		},
		{
			name:    "查询失败统一不健康",
			enabled: true,
			query: func(string) (*util.TaskHealth, error) {
				return nil, errors.New("query failed")
			},
			wantText: "不健康", wantCalls: 1,
		},
		{
			name:    "从未运行可见",
			enabled: true,
			query: func(string) (*util.TaskHealth, error) {
				return &util.TaskHealth{HasRun: false}, nil
			},
			wantText: "从未运行", wantCalls: 1,
		},
		{
			name:    "超过25小时可见",
			enabled: true,
			query: func(string) (*util.TaskHealth, error) {
				return &util.TaskHealth{HasRun: true, LastRunTime: now.Add(-26 * time.Hour)}, nil
			},
			wantText: "25 小时", wantCalls: 1,
		},
		{
			name:    "非零结果可见",
			enabled: true,
			query: func(string) (*util.TaskHealth, error) {
				return &util.TaskHealth{HasRun: true, LastRunTime: now.Add(-time.Hour), LastTaskResult: 1}, nil
			},
			wantText: "结果异常", wantCalls: 1,
		},
		{
			name:    "健康",
			enabled: true,
			query: func(string) (*util.TaskHealth, error) {
				return &util.TaskHealth{HasRun: true, LastRunTime: now.Add(-time.Hour)}, nil
			},
			wantOK: true, wantText: "健康", wantCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			healthy, message := queryTaskHealthPresentation(tt.enabled, "SSLCtlW", now, func(name string) (*util.TaskHealth, error) {
				calls++
				return tt.query(name)
			})
			if healthy != tt.wantOK || !strings.Contains(message, tt.wantText) || calls != tt.wantCalls {
				t.Fatalf("healthy=%v message=%q calls=%d", healthy, message, calls)
			}
		})
	}
}

func TestQueryTaskHealthPresentationStartsNeverRunTask(t *testing.T) {
	startCalls := 0
	healthy, message := queryTaskHealthPresentation(
		true,
		"SSLCtlW",
		time.Now(),
		func(string) (*util.TaskHealth, error) {
			return &util.TaskHealth{LastTaskResult: 0x41303}, nil
		},
		func(name string) error {
			startCalls++
			if name != "SSLCtlW" {
				t.Fatalf("task name = %q", name)
			}
			return nil
		},
	)
	if !healthy || startCalls != 1 || !strings.Contains(message, "首次检查已启动") {
		t.Fatalf("healthy=%v message=%q startCalls=%d", healthy, message, startCalls)
	}
}

func TestObserveWorkerTimeoutDoesNotFinishBeforeWorker(t *testing.T) {
	done := make(chan struct{})
	timeout := make(chan time.Time, 1)
	timedOut := make(chan struct{}, 1)
	returned := make(chan bool, 1)

	go func() {
		returned <- observeWorker(done, timeout, nil, func() {
			timedOut <- struct{}{}
		})
	}()
	timeout <- time.Now()
	select {
	case <-timedOut:
	case <-time.After(time.Second):
		t.Fatal("未观察到超时通知")
	}
	select {
	case <-returned:
		t.Fatal("观察超时后 worker 未结束，不得恢复按钮")
	default:
	}
	close(done)
	select {
	case completed := <-returned:
		if !completed {
			t.Fatal("worker 完成后应允许恢复按钮")
		}
	case <-time.After(time.Second):
		t.Fatal("worker 完成后观察函数未返回")
	}
}

func TestObserveWorkerCancelled(t *testing.T) {
	done := make(chan struct{})
	timeout := make(chan time.Time)
	cancelled := make(chan struct{})
	close(cancelled)

	if observeWorker(done, timeout, cancelled, nil) {
		t.Fatal("窗口已关闭时不得继续触发完成后的 UI 工作")
	}
}
