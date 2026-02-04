package ui

import (
	"sslctlw/config"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

// ShowCertManagerDialog 显示证书管理对话框（简化版）
func ShowCertManagerDialog(owner ui.Parent, onSuccess func()) {
	cfg, _ := config.Load()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("管理自动更新证书").
			Size(ui.Dpi(600, 400)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	selectedIdx := -1

	// 提示文字
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("以下证书已配置自动更新，将在证书临近过期时自动从接口获取新证书并更新 IIS 绑定:").
			Position(ui.Dpi(20, 15)),
	)

	// 证书列表
	lstCerts := ui.NewListView(dlg,
		ui.OptsListView().
			Position(ui.Dpi(20, 40)).
			Size(ui.Dpi(555, 220)).
			CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_GRIDLINES).
			CtrlStyle(co.LVS_REPORT|co.LVS_SINGLESEL|co.LVS_SHOWSELALWAYS),
	)

	// 按钮行
	btnToggle := ui.NewButton(dlg, ui.OptsButton().Text("启用/停用").Position(ui.Dpi(20, 270)).Width(ui.DpiX(70)).Height(ui.DpiY(28)))
	btnRemove := ui.NewButton(dlg, ui.OptsButton().Text("删除").Position(ui.Dpi(95, 270)).Width(ui.DpiX(50)).Height(ui.DpiY(28)))
	btnToggleLocalKey := ui.NewButton(dlg, ui.OptsButton().Text("本地私钥").Position(ui.Dpi(150, 270)).Width(ui.DpiX(70)).Height(ui.DpiY(28)))
	btnToggleValidation := ui.NewButton(dlg, ui.OptsButton().Text("验证方法").Position(ui.Dpi(225, 270)).Width(ui.DpiX(70)).Height(ui.DpiY(28)))
	btnRefresh := ui.NewButton(dlg, ui.OptsButton().Text("刷新").Position(ui.Dpi(300, 270)).Width(ui.DpiX(50)).Height(ui.DpiY(28)))

	// 配置区
	chkIIS7Mode := ui.NewCheckBox(dlg, ui.OptsCheckBox().Text("IIS7 兼容模式").Position(ui.Dpi(20, 315)))

	// 底部按钮
	btnSave := ui.NewButton(dlg, ui.OptsButton().Text("保存").Position(ui.Dpi(400, 320)).Width(ui.DpiX(80)).Height(ui.DpiY(30)))
	btnClose := ui.NewButton(dlg, ui.OptsButton().Text("关闭").Position(ui.Dpi(490, 320)).Width(ui.DpiX(80)).Height(ui.DpiY(30)))

	// 获取验证方法显示名称
	getValidationDisplay := func(method string) string {
		switch method {
		case config.ValidationMethodFile:
			return "文件"
		case config.ValidationMethodDelegation:
			return "委托"
		default:
			return "自动"
		}
	}

	// 刷新列表
	refreshList := func() {
		lstCerts.Items.DeleteAll()
		for _, c := range cfg.Certificates {
			status := "启用"
			if !c.Enabled {
				status = "停用"
			}
			localKey := "否"
			validation := "-"
			if c.UseLocalKey {
				localKey = "是"
				validation = getValidationDisplay(c.ValidationMethod)
			}
			lstCerts.Items.Add(c.Domain, c.ExpiresAt, status, localKey, validation)
		}
	}

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		lstCerts.Cols.Add("域名", ui.DpiX(170))
		lstCerts.Cols.Add("过期时间", ui.DpiX(85))
		lstCerts.Cols.Add("状态", ui.DpiX(45))
		lstCerts.Cols.Add("本地私钥", ui.DpiX(60))
		lstCerts.Cols.Add("验证方法", ui.DpiX(60))

		chkIIS7Mode.SetCheck(cfg.IIS7Mode)
		refreshList()

		btnToggle.Hwnd().EnableWindow(false)
		btnRemove.Hwnd().EnableWindow(false)
		btnToggleLocalKey.Hwnd().EnableWindow(false)
		btnToggleValidation.Hwnd().EnableWindow(false)
		return 0
	})

	// 更新按钮状态
	updateButtonStates := func() {
		if selectedIdx >= 0 && selectedIdx < len(cfg.Certificates) {
			btnToggle.Hwnd().EnableWindow(true)
			btnRemove.Hwnd().EnableWindow(true)
			btnToggleLocalKey.Hwnd().EnableWindow(true)
			// 只有启用本地私钥时才能切换验证方法
			btnToggleValidation.Hwnd().EnableWindow(cfg.Certificates[selectedIdx].UseLocalKey)
		} else {
			btnToggle.Hwnd().EnableWindow(false)
			btnRemove.Hwnd().EnableWindow(false)
			btnToggleLocalKey.Hwnd().EnableWindow(false)
			btnToggleValidation.Hwnd().EnableWindow(false)
		}
	}

	// 选择事件
	lstCerts.On().NmClick(func(_ *win.NMITEMACTIVATE) {
		selected := lstCerts.Items.Selected()
		if len(selected) > 0 {
			selectedIdx = selected[0].Index()
		} else {
			selectedIdx = -1
		}
		updateButtonStates()
	})

	// 启用/停用
	btnToggle.On().BnClicked(func() {
		if selectedIdx >= 0 && selectedIdx < len(cfg.Certificates) {
			cfg.Certificates[selectedIdx].Enabled = !cfg.Certificates[selectedIdx].Enabled
			refreshList()
			if selectedIdx < lstCerts.Items.Count() {
				lstCerts.Items.Get(selectedIdx).Select(true)
			}
		}
	})

	// 删除
	btnRemove.On().BnClicked(func() {
		if selectedIdx >= 0 && selectedIdx < len(cfg.Certificates) {
			cfg.RemoveCertificateByIndex(selectedIdx)
			selectedIdx = -1
			refreshList()
			updateButtonStates()
		}
	})

	// 切换本地私钥
	btnToggleLocalKey.On().BnClicked(func() {
		if selectedIdx >= 0 && selectedIdx < len(cfg.Certificates) {
			cfg.Certificates[selectedIdx].UseLocalKey = !cfg.Certificates[selectedIdx].UseLocalKey
			// 关闭本地私钥时，清除验证方法
			if !cfg.Certificates[selectedIdx].UseLocalKey {
				cfg.Certificates[selectedIdx].ValidationMethod = ""
			}
			refreshList()
			if selectedIdx < lstCerts.Items.Count() {
				lstCerts.Items.Get(selectedIdx).Select(true)
			}
			updateButtonStates()
		}
	})

	// 切换验证方法（循环：自动 -> 文件 -> 委托 -> 自动）
	btnToggleValidation.On().BnClicked(func() {
		if selectedIdx >= 0 && selectedIdx < len(cfg.Certificates) {
			cert := &cfg.Certificates[selectedIdx]
			if !cert.UseLocalKey {
				return
			}

			// 获取下一个验证方法
			var nextMethod string
			switch cert.ValidationMethod {
			case "":
				nextMethod = config.ValidationMethodFile
			case config.ValidationMethodFile:
				nextMethod = config.ValidationMethodDelegation
			case config.ValidationMethodDelegation:
				nextMethod = ""
			}

			// 校验兼容性
			if nextMethod != "" {
				if errMsg := config.ValidateValidationMethod(cert.Domain, nextMethod); errMsg != "" {
					ui.MsgOk(dlg, "不兼容", "验证方法不支持", errMsg)
					// 跳过这个方法，继续下一个
					if nextMethod == config.ValidationMethodFile {
						nextMethod = config.ValidationMethodDelegation
						if errMsg2 := config.ValidateValidationMethod(cert.Domain, nextMethod); errMsg2 != "" {
							nextMethod = ""
						}
					} else {
						nextMethod = ""
					}
				}
			}

			cert.ValidationMethod = nextMethod
			refreshList()
			if selectedIdx < lstCerts.Items.Count() {
				lstCerts.Items.Get(selectedIdx).Select(true)
			}
		}
	})

	// 刷新（从配置文件重新加载）
	btnRefresh.On().BnClicked(func() {
		newCfg, err := config.Load()
		if err != nil {
			ui.MsgError(dlg, "错误", "加载配置失败", err.Error())
			return
		}
		if newCfg == nil {
			newCfg = config.DefaultConfig()
		}
		cfg = newCfg
		chkIIS7Mode.SetCheck(cfg.IIS7Mode)
		selectedIdx = -1
		refreshList()
		updateButtonStates()
	})

	// 保存
	btnSave.On().BnClicked(func() {
		cfg.IIS7Mode = chkIIS7Mode.IsChecked()

		if err := cfg.Save(); err != nil {
			ui.MsgError(dlg, "错误", "保存失败", err.Error())
			return
		}
		ui.MsgOk(dlg, "成功", "配置已保存", "")
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
		if onSuccess != nil {
			onSuccess()
		}
	})

	// 关闭
	btnClose.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.ShowModal()
}
