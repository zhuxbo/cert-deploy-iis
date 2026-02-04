package ui

import (
	"github.com/rodrigocfd/windigo/ui"
)

// ButtonGroup 按钮组，批量管理状态
type ButtonGroup struct {
	buttons []*ui.Button
}

// NewButtonGroup 创建新的按钮组
func NewButtonGroup(buttons ...*ui.Button) *ButtonGroup {
	return &ButtonGroup{
		buttons: buttons,
	}
}

// Add 添加按钮到组
func (g *ButtonGroup) Add(btn *ui.Button) {
	g.buttons = append(g.buttons, btn)
}

// Enable 启用所有按钮
func (g *ButtonGroup) Enable() {
	g.SetEnabled(true)
}

// Disable 禁用所有按钮
func (g *ButtonGroup) Disable() {
	g.SetEnabled(false)
}

// SetEnabled 设置所有按钮的启用状态
func (g *ButtonGroup) SetEnabled(enabled bool) {
	for _, btn := range g.buttons {
		if btn != nil {
			btn.Hwnd().EnableWindow(enabled)
		}
	}
}

// Count 返回按钮数量
func (g *ButtonGroup) Count() int {
	return len(g.buttons)
}
