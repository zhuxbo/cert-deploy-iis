package ui

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"sslctlw/config"
	"sslctlw/upgrade"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
)

// ShowUpgradeDialog 显示升级对话框
func ShowUpgradeDialog(owner ui.Parent, currentVersion string, onComplete func()) {
	cfg, _ := config.Load()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	// 检查 Release URL 是否配置
	if cfg.ReleaseURL == "" {
		releaseURL := showConfigureReleaseURLDialog(owner, cfg)
		if releaseURL == "" {
			return // 用户取消
		}
		cfg.ReleaseURL = releaseURL
	}

	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("检查更新").
			Size(ui.Dpi(480, 380)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	dlgCtx, dlgCancel := context.WithCancel(context.Background())

	var latestInfo *upgrade.ReleaseInfo
	var downloadedPath string

	// 当前版本标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text(fmt.Sprintf("当前版本: %s", currentVersion)).
			Position(ui.Dpi(20, 20)),
	)

	// 状态标签
	lblStatus := ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("正在检查更新...").
			Position(ui.Dpi(20, 50)).
			Size(ui.Dpi(440, 20)),
	)

	// 更新说明标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("更新说明:").
			Position(ui.Dpi(20, 80)),
	)

	// 更新说明文本框
	txtNotes := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 100)).
			Width(ui.DpiX(440)).
			Height(ui.DpiY(150)).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 进度信息
	lblProgress := ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("").
			Position(ui.Dpi(20, 260)).
			Size(ui.Dpi(440, 20)),
	)

	// 立即更新按钮
	btnUpdate := ui.NewButton(dlg,
		ui.OptsButton().
			Text("立即更新").
			Position(ui.Dpi(200, 290)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 跳过此版本按钮
	btnSkip := ui.NewButton(dlg,
		ui.OptsButton().
			Text("跳过此版本").
			Position(ui.Dpi(290, 290)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 关闭按钮
	btnClose := ui.NewButton(dlg,
		ui.OptsButton().
			Text("关闭").
			Position(ui.Dpi(380, 290)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 创建升级器（安全配置从 DefaultConfig 获取，由 ldflags 编译时注入）
	defaultCfg := upgrade.DefaultConfig()
	upgradeCfg := &upgrade.Config{
		Enabled:        cfg.UpgradeEnabled,
		Channel:        upgrade.Channel(cfg.UpgradeChannel),
		CheckInterval:  cfg.UpgradeInterval,
		LastCheck:      cfg.LastUpgradeCheck,
		SkippedVersion: cfg.SkippedVersion,
		ReleaseURL:     cfg.ReleaseURL,
		// 安全配置从默认配置获取（编译时注入）
		Fingerprints:   defaultCfg.Fingerprints,
		TrustedOrg:     defaultCfg.TrustedOrg,
		TrustedCountry: defaultCfg.TrustedCountry,
		TrustedCAs:     defaultCfg.TrustedCAs,
	}

	upgrader := upgrade.NewUpgrader(upgradeCfg)

	// 进度回调
	upgrader.SetOnProgress(func(p upgrade.UpdateProgress) {
		dlg.UiThread(func() {
			if dlgCtx.Err() != nil {
				return
			}
			lblStatus.Hwnd().SetWindowText(p.Message)
			if p.Status == upgrade.StatusDownloading && p.Total > 0 {
				lblProgress.Hwnd().SetWindowText(fmt.Sprintf("%.1f%% - %s / %s - %s",
					p.Percent,
					upgrade.FormatSize(p.Downloaded),
					upgrade.FormatSize(p.Total),
					upgrade.FormatSpeed(p.Speed)))
			} else {
				lblProgress.Hwnd().SetWindowText("")
			}
		})
	})

	// 链式升级路径
	var upgradePath *upgrade.UpgradePath
	var needChainUpgrade bool

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		btnUpdate.Hwnd().EnableWindow(false)
		btnSkip.Hwnd().EnableWindow(false)
		txtNotes.SetText("正在检查更新...")

		// 异步检查更新
		go func() {
			info, err := upgrader.CheckForUpdate(dlgCtx, currentVersion)

			if dlgCtx.Err() != nil {
				return
			}

			// 检查是否需要链式升级
			var chainErr *upgrade.ErrNeedChainUpgrade
			if err != nil {
				if e, ok := err.(*upgrade.ErrNeedChainUpgrade); ok {
					chainErr = e
				}
			}

			dlg.UiThread(func() {
				if dlgCtx.Err() != nil {
					return
				}

				// 需要链式升级
				if chainErr != nil && info != nil {
					needChainUpgrade = true // 在 UI 线程中设置，避免竞态
					latestInfo = info
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("发现新版本: %s（需要链式升级）", info.Version))

					// 显示链式升级提示
					notes := fmt.Sprintf("当前版本 %s 需要先升级到中间版本才能升级到 %s\r\n\r\n",
						chainErr.CurrentVersion, chainErr.TargetVersion)
					notes += "点击「立即更新」将自动获取升级路径并依次升级。\r\n\r\n"
					if info.ReleaseNotes != "" {
						notes += "更新说明:\r\n" + strings.ReplaceAll(info.ReleaseNotes, "\n", "\r\n")
					}
					txtNotes.SetText(notes)

					btnUpdate.Hwnd().EnableWindow(true)
					btnSkip.Hwnd().EnableWindow(true)

					// 更新上次检查时间
					upgrader.UpdateLastCheck()
					cfg.LastUpgradeCheck = upgradeCfg.LastCheck
					if err := cfg.Save(); err != nil {
						lblStatus.Hwnd().SetWindowText(fmt.Sprintf("保存配置失败: %v", err))
						logDebug("save config failed after chain upgrade check: %v", err)
					}
					return
				}

				if err != nil {
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("检查失败: %v", err))
					txtNotes.SetText(fmt.Sprintf("检查更新时发生错误:\r\n%v", err))
					return
				}

				if info == nil {
					lblStatus.Hwnd().SetWindowText("已是最新版本")
					txtNotes.SetText("当前已是最新版本，无需更新。")
					return
				}

				latestInfo = info
				lblStatus.Hwnd().SetWindowText(fmt.Sprintf("发现新版本: %s", info.Version))

				// 显示更新说明
				notes := info.ReleaseNotes
				if notes == "" {
					notes = "无更新说明"
				}
				// 转换换行符
				notes = strings.ReplaceAll(notes, "\n", "\r\n")
				txtNotes.SetText(notes)

				btnUpdate.Hwnd().EnableWindow(true)
				btnSkip.Hwnd().EnableWindow(true)

				// 更新上次检查时间
				upgrader.UpdateLastCheck()
				cfg.LastUpgradeCheck = upgradeCfg.LastCheck
				if err := cfg.Save(); err != nil {
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("保存配置失败: %v", err))
					logDebug("save config failed after update check: %v", err)
				}
			})
		}()

		return 0
	})

	// 立即更新按钮
	btnUpdate.On().BnClicked(func() {
		if latestInfo == nil {
			return
		}

		btnUpdate.Hwnd().EnableWindow(false)
		btnSkip.Hwnd().EnableWindow(false)

		go func() {
			// 如果已经获取了升级路径（用户确认后第二次点击），直接执行链式升级
			if upgradePath != nil {
				dlg.UiThread(func() {
					executeChainUpgrade(dlg, dlgCtx, upgrader, upgradePath, currentVersion,
						lblStatus, lblProgress, txtNotes, btnUpdate, btnSkip, btnClose, onComplete)
				})
				return
			}

			// 如果需要链式升级，先获取升级路径
			if needChainUpgrade {
				dlg.UiThread(func() {
					lblStatus.Hwnd().SetWindowText("正在获取升级路径...")
				})

				path, err := upgrader.GetUpgradePath(dlgCtx, currentVersion, latestInfo.Version)

				if dlgCtx.Err() != nil {
					return
				}

				dlg.UiThread(func() {
					if dlgCtx.Err() != nil {
						return
					}

					if err != nil {
						lblStatus.Hwnd().SetWindowText(fmt.Sprintf("获取升级路径失败: %v", err))
						txtNotes.SetText(fmt.Sprintf("无法获取升级路径:\r\n%v\r\n\r\n请访问官网手动下载中间版本。", err))
						btnUpdate.Hwnd().EnableWindow(true)
						btnSkip.Hwnd().EnableWindow(true)
						return
					}

					upgradePath = path

					// 显示升级路径，等待用户确认
					pathInfo := "升级路径:\r\n"
					for i, step := range path.Steps {
						pathInfo += fmt.Sprintf("  %d. %s\r\n", i+1, step.Version)
					}
					pathInfo += "\r\n点击「开始升级」以执行链式升级。"
					txtNotes.SetText(pathInfo)
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("需要经过 %d 个版本升级", len(path.Steps)))

					// 修改按钮文本，重新启用，等待用户确认
					btnUpdate.SetText("开始升级")
					btnUpdate.Hwnd().EnableWindow(true)
					btnSkip.Hwnd().EnableWindow(true)
				})
				return
			}

			// 普通升级：下载并验证
			path, result, err := upgrader.DownloadAndVerify(dlgCtx, latestInfo)

			if dlgCtx.Err() != nil {
				return
			}

			dlg.UiThread(func() {
				if dlgCtx.Err() != nil {
					return
				}

				if err != nil {
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("下载失败: %v", err))
					btnUpdate.Hwnd().EnableWindow(true)
					btnSkip.Hwnd().EnableWindow(true)
					return
				}

				downloadedPath = path

				// 检查是否需要用户确认（回退验证）
				if result.NeedsConfirm {
					showCertConfirmDialog(dlg, result, func(confirmed bool) {
						if confirmed {
							applyUpdate(dlg, dlgCtx, upgrader, downloadedPath, latestInfo.Version,
								lblStatus, lblProgress, btnUpdate, btnSkip, btnClose, onComplete)
						} else {
							lblStatus.Hwnd().SetWindowText("用户取消升级")
							btnUpdate.Hwnd().EnableWindow(true)
							btnSkip.Hwnd().EnableWindow(true)
						}
					})
				} else {
					applyUpdate(dlg, dlgCtx, upgrader, downloadedPath, latestInfo.Version,
						lblStatus, lblProgress, btnUpdate, btnSkip, btnClose, onComplete)
				}
			})
		}()
	})

	// 跳过此版本
	btnSkip.On().BnClicked(func() {
		if latestInfo != nil {
			cfg.SkippedVersion = latestInfo.Version
			if err := cfg.Save(); err != nil {
				ui.MsgOk(dlg, "错误", "保存失败", fmt.Sprintf("保存跳过版本失败: %v", err))
				logDebug("save skipped version failed: %v", err)
				return
			}
			lblStatus.Hwnd().SetWindowText(fmt.Sprintf("已跳过版本 %s", latestInfo.Version))
		}
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	// 关闭按钮
	btnClose.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	// 关闭时清理
	dlg.On().WmDestroy(func() {
		dlgCancel()
	})

	dlg.ShowModal()
}

// executeChainUpgrade 执行链式升级
func executeChainUpgrade(dlg *ui.Modal, ctx context.Context, upgrader *upgrade.Upgrader,
	path *upgrade.UpgradePath, currentVersion string,
	lblStatus *ui.Static, lblProgress *ui.Static, txtNotes *ui.Edit,
	btnUpdate *ui.Button, btnSkip *ui.Button, btnClose *ui.Button,
	onComplete func()) {

	go func() {
		// 执行链式升级
		finalVersion, err := upgrader.ChainUpgrade(ctx, path, func(step upgrade.UpgradeStep, index, total int) bool {
			// 更新 UI 显示当前步骤
			dlg.UiThread(func() {
				lblStatus.Hwnd().SetWindowText(fmt.Sprintf("正在升级到 %s (%d/%d)", step.Version, index, total))
				if step.ReleaseNotes != "" {
					txtNotes.SetText(fmt.Sprintf("正在升级到 %s (%d/%d)\r\n\r\n%s",
						step.Version, index, total,
						strings.ReplaceAll(step.ReleaseNotes, "\n", "\r\n")))
				}
			})
			return true // 自动确认每一步
		})

		if ctx.Err() != nil {
			return
		}

		dlg.UiThread(func() {
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				lblStatus.Hwnd().SetWindowText(fmt.Sprintf("链式升级失败: %v", err))
				if finalVersion != "" {
					lblProgress.Hwnd().SetWindowText(fmt.Sprintf("已升级到 %s，请重启后继续", finalVersion))
					btnClose.Hwnd().SetWindowText("重启")
					btnClose.On().BnClicked(func() {
						dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
						upgrade.RestartApplication()
					})
				} else {
					btnUpdate.Hwnd().EnableWindow(true)
					btnSkip.Hwnd().EnableWindow(true)
				}
				return
			}

			lblStatus.Hwnd().SetWindowText(fmt.Sprintf("链式升级成功！已升级到 %s", finalVersion))
			lblProgress.Hwnd().SetWindowText("请重启程序以使用新版本")
			btnClose.Hwnd().SetWindowText("重启")

			btnClose.On().BnClicked(func() {
				dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
				upgrade.RestartApplication()
			})

			if onComplete != nil {
				onComplete()
			}
		})
	}()
}

// applyUpdate 应用更新
func applyUpdate(dlg *ui.Modal, ctx context.Context, upgrader *upgrade.Upgrader,
	downloadedPath string, version string,
	lblStatus *ui.Static, lblProgress *ui.Static,
	btnUpdate *ui.Button, btnSkip *ui.Button, btnClose *ui.Button,
	onComplete func()) {

	go func() {
		err := upgrader.ApplyUpdate(ctx, downloadedPath, version)

		if ctx.Err() != nil {
			return
		}

		dlg.UiThread(func() {
			if ctx.Err() != nil {
				return
			}

			if err != nil {
				lblStatus.Hwnd().SetWindowText(fmt.Sprintf("升级失败: %v", err))
				btnUpdate.Hwnd().EnableWindow(true)
				btnSkip.Hwnd().EnableWindow(true)
				return
			}

			lblStatus.Hwnd().SetWindowText("升级成功！")
			lblProgress.Hwnd().SetWindowText("请重启程序以使用新版本")
			btnClose.Hwnd().SetWindowText("重启")

			// 修改关闭按钮行为为重启
			btnClose.On().BnClicked(func() {
				dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
				upgrade.RestartApplication()
			})

			if onComplete != nil {
				onComplete()
			}
		})
	}()
}

// showCertConfirmDialog 显示证书确认对话框
func showCertConfirmDialog(owner ui.Parent, result *upgrade.VerifyResult, onResult func(confirmed bool)) {
	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("安全提示").
			Size(ui.Dpi(450, 300)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	// 警告图标（使用文字代替）
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("⚠").
			Position(ui.Dpi(20, 20)),
	)

	// 警告标题
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("证书指纹已更新").
			Position(ui.Dpi(50, 20)),
	)

	// 说明文字
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("下载的更新文件使用了新的签名证书。\r\n请确认以下信息是否正确：").
			Position(ui.Dpi(20, 50)).
			Size(ui.Dpi(410, 40)),
	)

	// 证书信息
	certInfo := fmt.Sprintf("组织: %s\r\n国家: %s\r\n颁发者: %s\r\n指纹: %s",
		result.Organization, result.Country, result.Issuer, result.Fingerprint)

	txtCertInfo := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 95)).
			Width(ui.DpiX(410)).
			Height(ui.DpiY(100)).
			Text(certInfo).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER),
	)
	_ = txtCertInfo

	// 提示
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("如果您确认此证书来自可信来源，请点击\"信任并继续\"。").
			Position(ui.Dpi(20, 205)).
			Size(ui.Dpi(410, 20)),
	)

	// 信任并继续按钮
	btnTrust := ui.NewButton(dlg,
		ui.OptsButton().
			Text("信任并继续").
			Position(ui.Dpi(230, 235)).
			Width(ui.DpiX(100)).
			Height(ui.DpiY(30)),
	)

	// 取消按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("取消").
			Position(ui.Dpi(340, 235)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	confirmed := false

	btnTrust.On().BnClicked(func() {
		confirmed = true
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	btnCancel.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.On().WmDestroy(func() {
		onResult(confirmed)
	})

	dlg.ShowModal()
}

// showConfigureReleaseURLDialog 弹出 Release URL 配置对话框
// 返回用户输入的 URL（空字符串表示用户取消）
func showConfigureReleaseURLDialog(owner ui.Parent, cfg *config.Config) string {
	var result string

	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("配置升级服务").
			Size(ui.Dpi(420, 190)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	// 提示标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("升级服务未配置，请输入 Release 服务地址：").
			Position(ui.Dpi(20, 20)).
			Size(ui.Dpi(380, 20)),
	)

	// URL 输入框
	txtURL := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 48)).
			Width(ui.DpiX(380)),
	)

	// 状态标签
	lblStatus := ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("").
			Position(ui.Dpi(20, 80)).
			Size(ui.Dpi(380, 20)),
	)

	// 确定按钮
	btnOK := ui.NewButton(dlg,
		ui.OptsButton().
			Text("确定").
			Position(ui.Dpi(230, 110)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 取消按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("取消").
			Position(ui.Dpi(320, 110)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	btnOK.On().BnClicked(func() {
		rawURL := strings.TrimSpace(txtURL.Text())

		// 空值检查
		if rawURL == "" {
			ui.MsgOk(dlg, "提示", "地址不能为空", "请输入 Release 服务地址。")
			return
		}

		// URL 格式校验
		parsed, err := url.Parse(rawURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			ui.MsgOk(dlg, "提示", "地址格式不正确", "请输入以 http:// 或 https:// 开头的有效地址。")
			return
		}

		// 禁用按钮，显示验证状态
		btnOK.Hwnd().EnableWindow(false)
		btnCancel.Hwnd().EnableWindow(false)
		lblStatus.Hwnd().SetWindowText("正在验证升级服务...")

		// 异步验证升级服务
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			checker := upgrade.NewGitHubChecker(rawURL)
			_, err := checker.CheckUpdate(ctx, "stable", "0.0.0")

			dlg.UiThread(func() {
				if err != nil {
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("验证失败: %v", err))
					btnOK.Hwnd().EnableWindow(true)
					btnCancel.Hwnd().EnableWindow(true)
					return
				}

				// 校验通过，保存配置
				cfg.ReleaseURL = rawURL
				if saveErr := cfg.Save(); saveErr != nil {
					lblStatus.Hwnd().SetWindowText(fmt.Sprintf("保存配置失败: %v", saveErr))
					btnOK.Hwnd().EnableWindow(true)
					btnCancel.Hwnd().EnableWindow(true)
					return
				}

				result = rawURL
				dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
			})
		}()
	})

	btnCancel.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.ShowModal()
	return result
}

// ShowUpgradeSettingsDialog 显示升级设置对话框
func ShowUpgradeSettingsDialog(owner ui.Parent) {
	cfg, _ := config.Load()
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("升级设置").
			Size(ui.Dpi(400, 250)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	// Release URL 标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("Release 服务地址:").
			Position(ui.Dpi(20, 25)),
	)

	// Release URL 输入
	txtReleaseURL := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(130, 22)).
			Width(ui.DpiX(240)).
			Text(cfg.ReleaseURL),
	)

	// 自动检查更新复选框
	chkAutoCheck := ui.NewCheckBox(dlg,
		ui.OptsCheckBox().
			Text("启动时自动检查更新").
			Position(ui.Dpi(20, 60)),
	)

	// 版本通道标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("版本通道:").
			Position(ui.Dpi(20, 95)),
	)

	// 版本通道下拉框
	cmbChannel := ui.NewComboBox(dlg,
		ui.OptsComboBox().
			Position(ui.Dpi(130, 92)).
			Width(ui.DpiX(100)).
			Texts("稳定版", "测试版").
			CtrlStyle(co.CBS_DROPDOWNLIST),
	)

	// 检查间隔标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("检查间隔 (小时):").
			Position(ui.Dpi(20, 130)),
	)

	// 检查间隔输入
	txtInterval := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(130, 127)).
			Width(ui.DpiX(60)).
			Text(fmt.Sprintf("%d", cfg.UpgradeInterval)),
	)

	// 状态标签
	lblStatus := ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("").
			Position(ui.Dpi(20, 170)).
			Size(ui.Dpi(170, 20)),
	)

	// 保存按钮
	btnSave := ui.NewButton(dlg,
		ui.OptsButton().
			Text("保存").
			Position(ui.Dpi(200, 170)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 取消按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("取消").
			Position(ui.Dpi(290, 170)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		chkAutoCheck.SetCheck(cfg.UpgradeEnabled)

		if cfg.UpgradeChannel == "beta" {
			cmbChannel.Items.Select(1)
		} else {
			cmbChannel.Items.Select(0)
		}

		return 0
	})

	// 保存
	btnSave.On().BnClicked(func() {
		cfg.ReleaseURL = strings.TrimSpace(txtReleaseURL.Text())
		cfg.UpgradeEnabled = chkAutoCheck.IsChecked()

		if cmbChannel.Items.Selected() == 1 {
			cfg.UpgradeChannel = "beta"
		} else {
			cfg.UpgradeChannel = "stable"
		}

		// 解析检查间隔
		var interval int
		fmt.Sscanf(txtInterval.Text(), "%d", &interval)
		if interval < 1 {
			interval = 24
		}
		cfg.UpgradeInterval = interval

		if err := cfg.Save(); err != nil {
			lblStatus.Hwnd().SetWindowText(fmt.Sprintf("保存失败: %v", err))
			return
		}

		lblStatus.Hwnd().SetWindowText("已保存")
	})

	// 取消
	btnCancel.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.ShowModal()
}
