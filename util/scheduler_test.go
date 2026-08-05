package util

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCreateTask_InvalidName(t *testing.T) {
	tests := []struct {
		name     string
		taskName string
	}{
		{"空名称", ""},
		{"带空格", "my task"},
		{"带中文", "任务"},
		{"带特殊字符", "task@name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateTask(tt.taskName)
			if err == nil {
				t.Errorf("CreateTask(%q) 应该返回错误", tt.taskName)
			}
		})
	}
}

func TestDeleteTask_InvalidName(t *testing.T) {
	tests := []struct {
		name     string
		taskName string
	}{
		{"空名称", ""},
		{"带空格", "my task"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DeleteTask(tt.taskName)
			if err == nil {
				t.Errorf("DeleteTask(%q) 应该返回错误", tt.taskName)
			}
		})
	}
}

func TestRunTaskNow_InvalidName(t *testing.T) {
	err := RunTaskNow("")
	if err == nil {
		t.Error("RunTaskNow(\"\") 应该返回错误")
	}
}

func TestGetTaskInfo_InvalidName(t *testing.T) {
	_, err := GetTaskInfo("")
	if err == nil {
		t.Error("GetTaskInfo(\"\") 应该返回错误")
	}
}

func TestIsTaskExists_InvalidName(t *testing.T) {
	// 无效任务名应该返回 false
	if IsTaskExists("") {
		t.Error("IsTaskExists(\"\") 应该返回 false")
	}
	if IsTaskExists("my task") {
		t.Error("IsTaskExists(\"my task\") 应该返回 false")
	}
}

func TestBuildCreateTaskArgs_UsesCompatibleSchtasksParameters(t *testing.T) {
	got := buildCreateTaskArgs(
		"SSLCtlW",
		`C:\Program Files\sslctlw\sslctlw.exe`,
		"09:23",
	)
	want := []string{
		"/create",
		"/tn", "SSLCtlW",
		"/tr", `"C:\Program Files\sslctlw\sslctlw.exe" deploy --all`,
		"/sc", "DAILY",
		"/st", "09:23",
		"/ru", "SYSTEM",
		"/rl", "HIGHEST",
		"/f",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("创建任务参数 = %#v, want %#v", got, want)
	}
}

// TestParseTaskInfoOutput 任务信息输出解析
func TestParseTaskInfoOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantErr    bool
		wantResult uint32
		wantHasRun bool
	}{
		{
			name:       "正常成功",
			output:     "0|2026-07-16 09:30:00\r\n",
			wantResult: 0,
			wantHasRun: true,
		},
		{
			name:       "结果码非零",
			output:     "2147942402|2026-07-16 09:30:00",
			wantResult: 2147942402, // 0x80070002
			wantHasRun: true,
		},
		{
			name:       "从未运行（哨兵日期）",
			output:     "267011|1999-11-30 00:00:00",
			wantResult: 267011,
			wantHasRun: false,
		},
		{
			name:       "从未运行（空时间）",
			output:     "267011|",
			wantResult: 267011,
			wantHasRun: false,
		},
		{
			name:       "带杂散输出取最后有效行",
			output:     "Loading profile...\n0|2026-07-16 09:30:00\n",
			wantResult: 0,
			wantHasRun: true,
		},
		{
			name:    "空输出",
			output:  "",
			wantErr: true,
		},
		{
			name:    "无分隔符",
			output:  "garbage",
			wantErr: true,
		},
		{
			name:    "结果码非数字",
			output:  "abc|2026-07-16 09:30:00",
			wantErr: true,
		},
		{
			// CurrentCulture 自定义分隔符的产物（如 09.30.00）必须显式报错，
			// 不允许静默按"从未运行"处理
			name:    "非法时间分隔符显式报错",
			output:  "0|2026-07-16 09.30.00",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := parseTaskInfoOutput(tt.output)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if h.LastTaskResult != tt.wantResult {
				t.Errorf("LastTaskResult = %d, want %d", h.LastTaskResult, tt.wantResult)
			}
			if h.HasRun != tt.wantHasRun {
				t.Errorf("HasRun = %v, want %v", h.HasRun, tt.wantHasRun)
			}
		})
	}
}

// TestEvaluateTaskHealth 任务健康评估
func TestEvaluateTaskHealth(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.Local)
	recent := now.Add(-3 * time.Hour)
	stale := now.Add(-30 * time.Hour)

	tests := []struct {
		name      string
		health    *TaskHealth
		wantWarns int
		wantSub   string
	}{
		{"nil 信息", nil, 1, "无法获取"},
		{"从未运行", &TaskHealth{HasRun: false, LastTaskResult: 267011}, 1, "从未运行"},
		{"首次运行中", &TaskHealth{HasRun: false, LastTaskResult: 0x41301}, 0, ""},
		{"首次运行已排队", &TaskHealth{HasRun: false, LastTaskResult: 0x41325}, 0, ""},
		{"健康", &TaskHealth{HasRun: true, LastRunTime: recent, LastTaskResult: 0}, 0, ""},
		{"运行中不告警", &TaskHealth{HasRun: true, LastRunTime: recent, LastTaskResult: 0x41301}, 0, ""},
		{"结果异常", &TaskHealth{HasRun: true, LastRunTime: recent, LastTaskResult: 0x80070002}, 1, "结果异常"},
		{"超时未运行", &TaskHealth{HasRun: true, LastRunTime: stale, LastTaskResult: 0}, 1, "25 小时"},
		{"结果异常且停摆", &TaskHealth{HasRun: true, LastRunTime: stale, LastTaskResult: 1}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns := EvaluateTaskHealth(tt.health, now)
			if len(warns) != tt.wantWarns {
				t.Fatalf("告警数量 = %d (%v), want %d", len(warns), warns, tt.wantWarns)
			}
			if tt.wantSub != "" && len(warns) > 0 && !strings.Contains(warns[0], tt.wantSub) {
				t.Errorf("告警 %q 应包含 %q", warns[0], tt.wantSub)
			}
		})
	}
}

func TestTaskNeedsInitialRun(t *testing.T) {
	tests := []struct {
		name   string
		health *TaskHealth
		want   bool
	}{
		{"任务从未运行", &TaskHealth{LastTaskResult: 0x41303}, true},
		{"首次运行中", &TaskHealth{LastTaskResult: 0x41301}, false},
		{"首次运行已排队", &TaskHealth{LastTaskResult: 0x41325}, false},
		{"已有运行记录", &TaskHealth{HasRun: true, LastTaskResult: 0}, false},
		{"无任务信息", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TaskNeedsInitialRun(tt.health); got != tt.want {
				t.Fatalf("TaskNeedsInitialRun() = %v, want %v", got, tt.want)
			}
		})
	}
}
