package util

import (
	"encoding/xml"
	"io"
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

// taskXMLDoc 用于验证生成 XML 的结构
type taskXMLDoc struct {
	XMLName  xml.Name `xml:"Task"`
	Triggers struct {
		CalendarTrigger struct {
			StartBoundary string `xml:"StartBoundary"`
			ScheduleByDay struct {
				DaysInterval int `xml:"DaysInterval"`
			} `xml:"ScheduleByDay"`
		} `xml:"CalendarTrigger"`
	} `xml:"Triggers"`
	Principals struct {
		Principal struct {
			UserID   string `xml:"UserId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		StartWhenAvailable bool `xml:"StartWhenAvailable"`
	} `xml:"Settings"`
	Actions struct {
		Exec struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func decodeTaskXML(t *testing.T, xmlStr string) *taskXMLDoc {
	t.Helper()
	var doc taskXMLDoc
	dec := xml.NewDecoder(strings.NewReader(xmlStr))
	// 内容为 Go 字符串（UTF-8），声明的 UTF-16 编码仅用于落盘，直通读取
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) { return input, nil }
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("生成的任务 XML 无法解析: %v\n%s", err, xmlStr)
	}
	return &doc
}

// TestBuildTaskXML 任务 XML 生成
func TestBuildTaskXML(t *testing.T) {
	xmlStr := buildTaskXML(taskXMLParams{
		ExePath:   `C:\Program Files\sslctlw\sslctlw.exe`,
		Arguments: "deploy --all",
		StartDate: "2026-07-17",
		StartTime: "09:23",
	})
	doc := decodeTaskXML(t, xmlStr)

	if !doc.Settings.StartWhenAvailable {
		t.Error("StartWhenAvailable 应为 true（错过补偿）")
	}
	if doc.Principals.Principal.UserID != "S-1-5-18" {
		t.Errorf("UserId = %q, want SYSTEM SID S-1-5-18", doc.Principals.Principal.UserID)
	}
	if doc.Principals.Principal.RunLevel != "HighestAvailable" {
		t.Errorf("RunLevel = %q, want HighestAvailable", doc.Principals.Principal.RunLevel)
	}
	if doc.Triggers.CalendarTrigger.StartBoundary != "2026-07-17T09:23:00" {
		t.Errorf("StartBoundary = %q", doc.Triggers.CalendarTrigger.StartBoundary)
	}
	if doc.Triggers.CalendarTrigger.ScheduleByDay.DaysInterval != 1 {
		t.Errorf("DaysInterval = %d, want 1", doc.Triggers.CalendarTrigger.ScheduleByDay.DaysInterval)
	}
	if doc.Actions.Exec.Command != `C:\Program Files\sslctlw\sslctlw.exe` {
		t.Errorf("Command = %q", doc.Actions.Exec.Command)
	}
	if doc.Actions.Exec.Arguments != "deploy --all" {
		t.Errorf("Arguments = %q", doc.Actions.Exec.Arguments)
	}
}

// TestBuildTaskXML_EscapesSpecialChars 路径含 XML 特殊字符时正确转义
func TestBuildTaskXML_EscapesSpecialChars(t *testing.T) {
	rawPath := `C:\Tools & Apps\a<b>\sslctlw.exe`
	xmlStr := buildTaskXML(taskXMLParams{
		ExePath:   rawPath,
		Arguments: "deploy --all",
		StartDate: "2026-07-17",
		StartTime: "10:00",
	})
	doc := decodeTaskXML(t, xmlStr)
	if doc.Actions.Exec.Command != rawPath {
		t.Errorf("特殊字符路径往返失败: got %q, want %q", doc.Actions.Exec.Command, rawPath)
	}
	if strings.Contains(xmlStr, "Tools & Apps") {
		t.Error("原始 & 未转义")
	}
}

// TestEncodeUTF16LEWithBOM UTF-16LE 编码
func TestEncodeUTF16LEWithBOM(t *testing.T) {
	got := encodeUTF16LEWithBOM("A续")
	if len(got) != 6 {
		t.Fatalf("长度 = %d, want 6", len(got))
	}
	if got[0] != 0xFF || got[1] != 0xFE {
		t.Fatalf("应以 UTF-16LE BOM (FF FE) 开头: % X", got[:2])
	}
	// 'A' = 0x0041 → 41 00
	if got[2] != 0x41 || got[3] != 0x00 {
		t.Errorf("'A' 编码 = % X, want 41 00", got[2:4])
	}
	// '续' = U+7EED → ED 7E
	if got[4] != 0xED || got[5] != 0x7E {
		t.Errorf("'续' 编码 = % X, want ED 7E", got[4:6])
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
