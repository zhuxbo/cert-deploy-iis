package ui

import (
	"syscall"
	"unsafe"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/win"
)

// IndicatorState 指示器状态
type IndicatorState int

const (
	IndicatorStopped IndicatorState = iota // 红色方块
	IndicatorRunning                       // 绿色三角
)

// StatusIndicator 状态指示器控件
type StatusIndicator struct {
	hwnd   win.HWND
	parent win.HWND
	state  IndicatorState
	ctrlID int
}

const (
	indicatorWidth  = 20
	indicatorHeight = 20
)

var (
	user32                = syscall.NewLazyDLL("user32.dll")
	gdi32                 = syscall.NewLazyDLL("gdi32.dll")
	procCreateWindowExW   = user32.NewProc("CreateWindowExW")
	procInvalidateRect    = user32.NewProc("InvalidateRect")
	procFillRect          = user32.NewProc("FillRect")
	procCreateSolidBrush  = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject      = gdi32.NewProc("DeleteObject")
	procPolygon           = gdi32.NewProc("Polygon")
	procSelectObject      = gdi32.NewProc("SelectObject")
	procGetStockObject    = gdi32.NewProc("GetStockObject")
)

type point struct {
	x, y int32
}

// NewStatusIndicator 创建状态指示器
func NewStatusIndicator(parent win.HWND, x, y, ctrlID int) *StatusIndicator {
	si := &StatusIndicator{
		parent: parent,
		state:  IndicatorStopped,
		ctrlID: ctrlID,
	}

	// 创建一个静态子窗口
	className, _ := syscall.UTF16PtrFromString("STATIC")
	// SS_OWNERDRAW = 0x000D
	style := uintptr(co.WS_CHILD) | uintptr(co.WS_VISIBLE) | 0x000D
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0, // 无文本
		style,
		uintptr(x),
		uintptr(y),
		uintptr(indicatorWidth),
		uintptr(indicatorHeight),
		uintptr(parent),
		uintptr(ctrlID),
		0,
		0,
	)

	si.hwnd = win.HWND(hwnd)
	return si
}

// Hwnd 获取窗口句柄
func (si *StatusIndicator) Hwnd() win.HWND {
	return si.hwnd
}

// CtrlID 获取控件 ID
func (si *StatusIndicator) CtrlID() int {
	return si.ctrlID
}

// SetState 设置状态
func (si *StatusIndicator) SetState(state IndicatorState) {
	si.state = state
	si.invalidate()
}

// GetState 获取状态
func (si *StatusIndicator) GetState() IndicatorState {
	return si.state
}

// SetPosition 设置位置
func (si *StatusIndicator) SetPosition(x, y int) {
	si.hwnd.SetWindowPos(0, x, y, indicatorWidth, indicatorHeight, co.SWP_NOZORDER)
}

// invalidate 使控件无效，触发重绘
func (si *StatusIndicator) invalidate() {
	procInvalidateRect.Call(uintptr(si.hwnd), 0, 1)
}

// HandleDrawItem 处理 WM_DRAWITEM 消息
// 参数: ctrlID 为控件ID, dis 为 windigo 的 DRAWITEMSTRUCT
func (si *StatusIndicator) HandleDrawItem(ctrlID int, dis *win.DRAWITEMSTRUCT) bool {
	// 检查是否是我们的控件
	if ctrlID != si.ctrlID {
		return false
	}

	hdc := uintptr(dis.Hdc)
	rc := dis.RcItem

	// 清除背景（使用窗口背景色）
	bgBrush, _, _ := procGetStockObject.Call(0) // WHITE_BRUSH
	fillRect := struct {
		left, top, right, bottom int32
	}{rc.Left, rc.Top, rc.Right, rc.Bottom}
	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&fillRect)), bgBrush)

	if si.state == IndicatorRunning {
		// 绿色三角形 ▶
		si.drawTriangle(hdc, rc.Left, rc.Top, rc.Right, rc.Bottom)
	} else {
		// 红色方块 ■
		si.drawSquare(hdc, rc.Left, rc.Top, rc.Right, rc.Bottom)
	}

	return true
}

// drawTriangle 绘制绿色三角形
func (si *StatusIndicator) drawTriangle(hdc uintptr, left, top, right, bottom int32) {
	// 创建绿色画刷
	greenBrush, _, _ := procCreateSolidBrush.Call(0x0000AA00) // BGR(0, 170, 0) - 深绿色
	defer procDeleteObject.Call(greenBrush)

	// 选择画刷
	oldBrush, _, _ := procSelectObject.Call(hdc, greenBrush)
	defer procSelectObject.Call(hdc, oldBrush)

	// 选择无边框笔
	nullPen, _, _ := procGetStockObject.Call(8) // NULL_PEN
	oldPen, _, _ := procSelectObject.Call(hdc, nullPen)
	defer procSelectObject.Call(hdc, oldPen)

	// 计算三角形顶点（向右的三角形）
	cy := (bottom - top) / 2
	margin := int32(3)

	points := []point{
		{left + margin, top + margin},    // 左上
		{right - margin, top + cy},       // 右中
		{left + margin, bottom - margin}, // 左下
	}

	procPolygon.Call(hdc, uintptr(unsafe.Pointer(&points[0])), 3)
}

// drawSquare 绘制红色方块
func (si *StatusIndicator) drawSquare(hdc uintptr, left, top, right, bottom int32) {
	margin := int32(3)
	squareRect := struct {
		left, top, right, bottom int32
	}{left + margin, top + margin, right - margin, bottom - margin}

	// 创建红色画刷
	redBrush, _, _ := procCreateSolidBrush.Call(0x000000CC) // BGR(204, 0, 0) - 深红色
	defer procDeleteObject.Call(redBrush)

	procFillRect.Call(hdc, uintptr(unsafe.Pointer(&squareRect)), redBrush)
}
