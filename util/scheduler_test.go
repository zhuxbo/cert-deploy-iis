package util

import (
	"testing"
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
			err := CreateTask(tt.taskName, 1)
			if err == nil {
				t.Errorf("CreateTask(%q, 1) 应该返回错误", tt.taskName)
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
