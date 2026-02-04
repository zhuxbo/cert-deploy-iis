package ui

import (
	"fmt"

	"sslctlw/cert"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
)

// ShowInstallDialog 显示导入证书对话框
func ShowInstallDialog(owner ui.Parent, onSuccess func()) {
	logDebug("ShowInstallDialog: creating modal")
	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("导入证书").
			Size(ui.Dpi(500, 200)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)
	logDebug("ShowInstallDialog: modal created")

	// PFX 文件标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("PFX 文件:").
			Position(ui.Dpi(20, 30)),
	)

	// PFX 文件路径
	txtFile := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(90, 28)).
			Width(ui.DpiX(290)),
	)

	// 浏览按钮
	btnBrowse := ui.NewButton(dlg,
		ui.OptsButton().
			Text("浏览...").
			Position(ui.Dpi(390, 26)).
			Width(ui.DpiX(70)).
			Height(ui.DpiY(26)),
	)

	// 密码标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("密码:").
			Position(ui.Dpi(20, 70)),
	)

	// 密码输入
	txtPassword := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(90, 68)).
			Width(ui.DpiX(370)).
			CtrlStyle(co.ES_PASSWORD),
	)

	// 导入按钮
	btnInstall := ui.NewButton(dlg,
		ui.OptsButton().
			Text("导入").
			Position(ui.Dpi(290, 120)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 取消按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("取消").
			Position(ui.Dpi(380, 120)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 浏览按钮事件
	btnBrowse.On().BnClicked(func() {
		filePath := showOpenFileDialog(dlg.Hwnd(), "选择 PFX 文件", "PFX 文件 (*.pfx)\x00*.pfx\x00所有文件 (*.*)\x00*.*\x00\x00")
		if filePath != "" {
			txtFile.SetText(filePath)
		}
	})

	// 安装按钮事件
	btnInstall.On().BnClicked(func() {
		pfxPath := txtFile.Text()
		password := txtPassword.Text()

		if pfxPath == "" {
			ui.MsgOk(dlg, "提示", "请选择 PFX 文件", "请先选择要安装的 PFX 证书文件。")
			return
		}

		// 禁用按钮防止重复点击
		btnInstall.Hwnd().EnableWindow(false)
		btnCancel.Hwnd().EnableWindow(false)
		btnBrowse.Hwnd().EnableWindow(false)

		go func() {
			defer func() {
				if r := recover(); r != nil {
					dlg.UiThread(func() {
						btnInstall.Hwnd().EnableWindow(true)
						btnCancel.Hwnd().EnableWindow(true)
						btnBrowse.Hwnd().EnableWindow(true)
						ui.MsgError(dlg, "错误", "操作异常", fmt.Sprintf("%v", r))
					})
				}
			}()

			result, err := cert.InstallPFX(pfxPath, password)

			dlg.UiThread(func() {
				btnInstall.Hwnd().EnableWindow(true)
				btnCancel.Hwnd().EnableWindow(true)
				btnBrowse.Hwnd().EnableWindow(true)

				if err != nil {
					ui.MsgError(dlg, "错误", "安装失败", err.Error())
					return
				}

				if !result.Success {
					ui.MsgError(dlg, "错误", "安装失败", result.ErrorMessage)
					return
				}

				ui.MsgOk(dlg, "成功", "证书安装成功", fmt.Sprintf("指纹: %s", result.Thumbprint))
				dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
				if onSuccess != nil {
					onSuccess()
				}
			})
		}()
	})

	// 取消按钮事件
	btnCancel.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		logDebug("ShowInstallDialog WmCreate: initializing")
		return 0
	})

	logDebug("ShowInstallDialog: calling ShowModal")
	dlg.ShowModal()
	logDebug("ShowInstallDialog: ShowModal returned")
}
