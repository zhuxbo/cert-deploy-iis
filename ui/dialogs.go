package ui

import (
	"syscall"
	"unsafe"

	"github.com/rodrigocfd/windigo/win"
)

// ComboBox 消息常量
const (
	CB_SHOWDROPDOWN = 0x014F
)

// OPENFILENAME 结构体
type openFileName struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

var (
	comdlg32             = syscall.NewLazyDLL("comdlg32.dll")
	procGetOpenFileNameW = comdlg32.NewProc("GetOpenFileNameW")
)

// showOpenFileDialog 显示文件打开对话框
func showOpenFileDialog(hwnd win.HWND, title string, filter string) string {
	fileNameBuf := make([]uint16, 260)

	titleUTF16, _ := syscall.UTF16PtrFromString(title)
	filterUTF16, _ := syscall.UTF16PtrFromString(filter)

	ofn := openFileName{
		lStructSize: uint32(unsafe.Sizeof(openFileName{})),
		hwndOwner:   uintptr(hwnd),
		lpstrFilter: filterUTF16,
		lpstrFile:   &fileNameBuf[0],
		nMaxFile:    uint32(len(fileNameBuf)),
		lpstrTitle:  titleUTF16,
		flags:       0x00001000 | 0x00000800, // OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST
	}

	ret, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret != 0 {
		return syscall.UTF16ToString(fileNameBuf)
	}
	return ""
}
