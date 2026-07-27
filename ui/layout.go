package ui

import windigoui "github.com/rodrigocfd/windigo/ui"

type layoutRect struct {
	x, y, width, height int
}

type mainLayoutMetrics struct {
	marginSmallX      int
	marginSmallY      int
	marginMediumX     int
	marginMediumY     int
	marginLargeX      int
	buttonHeight      int
	buttonWidthMed    int
	buttonWidthLarge  int
	statusBarHeight   int
	taskPanelHeight   int
	listMinHeight     int
	taskSectionWidth  int
	taskSectionHeight int
	buttonOffsetY     int
	statusOffsetY     int
	logOffsetY        int
	indicatorX        int
	indicatorWidth    int
	indicatorHeight   int
	statusLabelX      int
	statusLabelGap    int
	statusLabelHeight int
}

type mainLayout struct {
	siteList        layoutRect
	taskSection     layoutRect
	autoButton      layoutRect
	checkButton     layoutRect
	configButton    layoutRect
	statusIndicator layoutRect
	statusLabel     layoutRect
	taskLog         layoutRect
}

func currentMainLayoutMetrics() mainLayoutMetrics {
	return mainLayoutMetrics{
		marginSmallX:      windigoui.DpiX(MarginSmall),
		marginSmallY:      windigoui.DpiY(MarginSmall),
		marginMediumX:     windigoui.DpiX(MarginMedium),
		marginMediumY:     windigoui.DpiY(MarginMedium),
		marginLargeX:      windigoui.DpiX(MarginLarge),
		buttonHeight:      windigoui.DpiY(ButtonHeight),
		buttonWidthMed:    windigoui.DpiX(ButtonWidthMedium),
		buttonWidthLarge:  windigoui.DpiX(ButtonWidthLarge),
		statusBarHeight:   windigoui.DpiY(StatusBarHeight),
		taskPanelHeight:   windigoui.DpiY(TaskPanelHeight),
		listMinHeight:     windigoui.DpiY(ListMinHeight),
		taskSectionWidth:  windigoui.DpiX(200),
		taskSectionHeight: windigoui.DpiY(20),
		buttonOffsetY:     windigoui.DpiY(25),
		statusOffsetY:     windigoui.DpiY(30),
		logOffsetY:        windigoui.DpiY(60),
		indicatorX:        windigoui.DpiX(300),
		indicatorWidth:    windigoui.DpiX(indicatorWidth),
		indicatorHeight:   windigoui.DpiY(indicatorHeight),
		statusLabelX:      windigoui.DpiX(330),
		statusLabelGap:    windigoui.DpiX(350),
		statusLabelHeight: windigoui.DpiY(20),
	}
}

func calculateMainLayout(cx, cy int, m mainLayoutMetrics) mainLayout {
	toolbarHeight := m.marginMediumY + m.buttonHeight + m.marginMediumY
	listHeight := cy - toolbarHeight - m.statusBarHeight - m.taskPanelHeight
	if listHeight < m.listMinHeight {
		listHeight = m.listMinHeight
	}
	taskPanelY := toolbarHeight + listHeight + m.marginSmallY
	buttonY := taskPanelY + m.buttonOffsetY
	statusY := taskPanelY + m.statusOffsetY
	logY := taskPanelY + m.logOffsetY
	logHeight := cy - logY - m.statusBarHeight - m.marginSmallY
	if logHeight < 0 {
		logHeight = 0
	}

	return mainLayout{
		siteList: layoutRect{
			x: m.marginMediumX, y: toolbarHeight,
			width: cx - m.marginLargeX, height: listHeight,
		},
		taskSection: layoutRect{
			x: m.marginMediumX, y: taskPanelY,
			width: m.taskSectionWidth, height: m.taskSectionHeight,
		},
		autoButton: layoutRect{
			x: m.marginMediumX, y: buttonY,
			width: m.buttonWidthLarge, height: m.buttonHeight,
		},
		checkButton: layoutRect{
			x: m.marginMediumX + m.buttonWidthLarge + m.marginMediumX, y: buttonY,
			width: m.buttonWidthMed, height: m.buttonHeight,
		},
		configButton: layoutRect{
			x: m.marginMediumX + m.buttonWidthLarge + m.buttonWidthMed + m.marginLargeX, y: buttonY,
			width: m.buttonWidthMed, height: m.buttonHeight,
		},
		statusIndicator: layoutRect{
			x: m.indicatorX, y: taskPanelY + m.buttonHeight,
			width: m.indicatorWidth, height: m.indicatorHeight,
		},
		statusLabel: layoutRect{
			x: m.statusLabelX, y: statusY,
			width: cx - m.statusLabelGap, height: m.statusLabelHeight,
		},
		taskLog: layoutRect{
			x: m.marginMediumX, y: logY,
			width: cx - m.marginLargeX, height: logHeight,
		},
	}
}

// 布局常量
const (
	// MarginSmall 小边距
	MarginSmall = 5
	// MarginMedium 中等边距
	MarginMedium = 10
	// MarginLarge 大边距
	MarginLarge = 20

	// ButtonHeight 标准按钮高度
	ButtonHeight = 28
	// ButtonWidthSmall 小按钮宽度
	ButtonWidthSmall = 70
	// ButtonWidthMedium 中等按钮宽度
	ButtonWidthMedium = 80
	// ButtonWidthLarge 大按钮宽度
	ButtonWidthLarge = 100

	// StatusBarHeight 状态栏高度
	StatusBarHeight = 22

	// TaskPanelHeight 任务面板高度
	TaskPanelHeight = 180

	// ListMinHeight 列表最小高度
	ListMinHeight = 100
)

// Windows 消息常量
const (
	// EM_SETSEL 设置选择范围
	EM_SETSEL = 0x00B1
	// EM_REPLACESEL 替换选中文本
	EM_REPLACESEL = 0x00C2
	// EM_LINESCROLL 滚动到行
	EM_LINESCROLL = 0x00B6
	// EM_SETPASSWORDCHAR 设置密码字符
	EM_SETPASSWORDCHAR = 0x00CC
)
