package ui

import (
	"context"
	"fmt"
	"strings"

	"sslctlw/setup"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
)

// ShowAPIDialog 显示一键部署对话框（粘贴命令模式）
func ShowAPIDialog(owner ui.Parent, onSuccess func()) {
	logDebug("ShowAPIDialog: creating modal")
	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("一键部署").
			Size(ui.Dpi(520, 400)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)
	logDebug("ShowAPIDialog: modal created")

	// 对话框级 context，用于取消 goroutine
	dlgCtx, dlgCancel := context.WithCancel(context.Background())

	// 命令输入标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("粘贴部署命令:").
			Position(ui.Dpi(20, 20)),
	)

	// 多行文本框
	txtCommand := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 40)).
			Width(ui.DpiX(470)).
			Height(ui.DpiY(80)).
			CtrlStyle(co.ES_MULTILINE|co.ES_AUTOVSCROLL|co.ES_WANTRETURN).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 提示文字
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("格式: sslctlw setup --url <地址> --token <令牌> --order <订单ID>").
			Position(ui.Dpi(20, 128)),
	)

	// 执行按钮
	btnExecute := ui.NewButton(dlg,
		ui.OptsButton().
			Text("执行").
			Position(ui.Dpi(380, 152)).
			Width(ui.DpiX(110)).
			Height(ui.DpiY(30)),
	)

	// 详情标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("执行结果:").
			Position(ui.Dpi(20, 192)),
	)

	// 详情文本框
	txtDetail := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 210)).
			Width(ui.DpiX(470)).
			Height(ui.DpiY(130)).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 关闭按钮
	btnClose := ui.NewButton(dlg,
		ui.OptsButton().
			Text("关闭").
			Position(ui.Dpi(410, 350)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		txtDetail.SetText("请粘贴部署命令后点击\"执行\"。\r\n\r\n示例:\r\nsslctlw setup --url https://deploy.example.com/api --token abc123 --order 12345")
		return 0
	})

	// 执行按钮事件
	btnExecute.On().BnClicked(func() {
		input := strings.TrimSpace(txtCommand.Text())
		if input == "" {
			ui.MsgOk(dlg, "提示", "请输入命令", "请粘贴部署命令。")
			return
		}

		// 解析命令
		opts, err := setup.ParseCommand(input)
		if err != nil {
			txtDetail.SetText(fmt.Sprintf("命令解析失败:\r\n%v", err))
			return
		}

		txtDetail.SetText("正在执行...")
		btnExecute.Hwnd().EnableWindow(false)

		// 异步执行
		go func() {
			defer func() {
				if r := recover(); r != nil {
					dlg.UiThread(func() {
						if dlgCtx.Err() != nil {
							return
						}
						btnExecute.Hwnd().EnableWindow(true)
						txtDetail.SetText(fmt.Sprintf("操作异常: %v", r))
					})
				}
			}()
			var lines []string
			progress := func(step, total int, message string) {
				lines = append(lines, fmt.Sprintf("[%d/%d] %s", step, total, message))
				dlg.UiThread(func() {
					if dlgCtx.Err() != nil {
						return
					}
					txtDetail.SetText(strings.Join(lines, "\r\n"))
				})
			}

			// GUI 交互回调：弹窗让用户粘贴私钥 PEM
			promptKey := func(domain string, certPEM string) string {
				ch := make(chan string, 1)
				dlg.UiThread(func() {
					if dlgCtx.Err() != nil {
						ch <- ""
						return
					}
					ch <- showPrivateKeyInputDialog(dlg, domain)
				})
				return <-ch
			}

			_, err := setup.Run(*opts, progress, promptKey)

			if dlgCtx.Err() != nil {
				return
			}
			dlg.UiThread(func() {
				if dlgCtx.Err() != nil {
					return
				}
				btnExecute.Hwnd().EnableWindow(true)
				if err != nil {
					lines = append(lines, fmt.Sprintf("\r\n执行失败: %v", err))
					txtDetail.SetText(strings.Join(lines, "\r\n"))
				} else {
					lines = append(lines, "\r\n部署完成!")
					txtDetail.SetText(strings.Join(lines, "\r\n"))
					if onSuccess != nil {
						onSuccess()
					}
				}
			})
		}()
	})

	// 关闭按钮
	btnClose.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	// 对话框关闭时取消所有 goroutine
	dlg.On().WmDestroy(func() {
		dlgCancel()
	})

	dlg.ShowModal()
}

// showPrivateKeyInputDialog 弹窗让用户粘贴私钥 PEM
// 返回私钥 PEM 内容，空字符串表示取消/跳过
func showPrivateKeyInputDialog(owner ui.Parent, domain string) string {
	var result string

	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("提供私钥").
			Size(ui.Dpi(480, 330)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	// 提示标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text(fmt.Sprintf("证书 %s 需要私钥，请粘贴 PEM 格式私钥:", domain)).
			Position(ui.Dpi(20, 15)),
	)

	// 多行文本框
	txtKey := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 40)).
			Width(ui.DpiX(430)).
			Height(ui.DpiY(230)).
			CtrlStyle(co.ES_MULTILINE|co.ES_AUTOVSCROLL|co.ES_WANTRETURN).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 确定按钮
	btnOk := ui.NewButton(dlg,
		ui.OptsButton().
			Text("确定").
			Position(ui.Dpi(260, 285)).
			Width(ui.DpiX(90)).
			Height(ui.DpiY(30)),
	)

	// 跳过按钮
	btnSkip := ui.NewButton(dlg,
		ui.OptsButton().
			Text("跳过").
			Position(ui.Dpi(360, 285)).
			Width(ui.DpiX(90)).
			Height(ui.DpiY(30)),
	)

	btnOk.On().BnClicked(func() {
		text := strings.TrimSpace(txtKey.Text())
		if text == "" {
			ui.MsgOk(dlg, "提示", "请粘贴私钥", "请粘贴 PEM 格式的私钥内容。")
			return
		}
		result = text
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	btnSkip.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.ShowModal()
	return result
}
