package ui

import "testing"

func scaledMainLayoutMetrics(dpi int) mainLayoutMetrics {
	scale := func(value int) int { return value * dpi / 96 }
	return mainLayoutMetrics{
		marginSmallX:      scale(MarginSmall),
		marginSmallY:      scale(MarginSmall),
		marginMediumX:     scale(MarginMedium),
		marginMediumY:     scale(MarginMedium),
		marginLargeX:      scale(MarginLarge),
		buttonHeight:      scale(ButtonHeight),
		buttonWidthMed:    scale(ButtonWidthMedium),
		buttonWidthLarge:  scale(ButtonWidthLarge),
		statusBarHeight:   scale(StatusBarHeight),
		taskPanelHeight:   scale(TaskPanelHeight),
		listMinHeight:     scale(ListMinHeight),
		taskSectionWidth:  scale(200),
		taskSectionHeight: scale(20),
		buttonOffsetY:     scale(25),
		statusOffsetY:     scale(30),
		logOffsetY:        scale(60),
		indicatorX:        scale(300),
		indicatorWidth:    scale(indicatorWidth),
		indicatorHeight:   scale(indicatorHeight),
		statusLabelX:      scale(330),
		statusLabelGap:    scale(350),
		statusLabelHeight: scale(20),
	}
}

func TestCalculateMainLayout_ScalesAtSupportedDPIValues(t *testing.T) {
	tests := []struct {
		name           string
		dpi            int
		clientWidth    int
		clientHeight   int
		wantListHeight int
		wantTaskY      int
		wantLogY       int
		wantLogHeight  int
		wantButtonW    int
		wantButtonH    int
	}{
		{"100%", 96, 900, 700, 450, 503, 563, 110, 100, 28},
		{"125%", 120, 1125, 875, 564, 629, 704, 138, 125, 35},
		{"150%", 144, 1350, 1050, 675, 754, 844, 166, 150, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculateMainLayout(
				tt.clientWidth,
				tt.clientHeight,
				scaledMainLayoutMetrics(tt.dpi),
			)

			if got.siteList.height != tt.wantListHeight {
				t.Fatalf("站点列表高度 = %d, want %d", got.siteList.height, tt.wantListHeight)
			}
			if got.taskSection.y != tt.wantTaskY {
				t.Fatalf("任务面板 Y = %d, want %d", got.taskSection.y, tt.wantTaskY)
			}
			if got.taskLog.y != tt.wantLogY || got.taskLog.height != tt.wantLogHeight {
				t.Fatalf(
					"任务日志区域 = %+v, want y=%d height=%d",
					got.taskLog,
					tt.wantLogY,
					tt.wantLogHeight,
				)
			}
			if got.autoButton.width != tt.wantButtonW || got.autoButton.height != tt.wantButtonH {
				t.Fatalf(
					"自动部署按钮未按 DPI 缩放: %+v, want width=%d height=%d",
					got.autoButton,
					tt.wantButtonW,
					tt.wantButtonH,
				)
			}
		})
	}
}
