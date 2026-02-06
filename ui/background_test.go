package ui

import "testing"

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
