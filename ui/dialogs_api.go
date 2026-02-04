package ui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

// formatAPIError 格式化 API 错误信息
func formatAPIError(err error) string {
	if apiErr, ok := err.(*api.APIError); ok {
		if apiErr.Message != "" {
			return fmt.Sprintf("获取失败: %s (错误码: %d)", apiErr.Message, apiErr.Code)
		}
		if apiErr.RawBody != "" {
			// 显示摘要
			body := apiErr.RawBody
			if len(body) > 100 {
				body = body[:100] + "..."
			}
			return fmt.Sprintf("返回数据错误 (HTTP %d):\r\n%s", apiErr.StatusCode, body)
		}
		return fmt.Sprintf("请求失败 (HTTP %d)", apiErr.StatusCode)
	}
	return fmt.Sprintf("获取失败: %v", err)
}

// ShowAPIDialog 显示从部署接口获取证书对话框
func ShowAPIDialog(owner ui.Parent, onSuccess func()) {
	// 加载配置获取默认值
	cfg, _ := config.Load()
	defaultURL := ""
	defaultToken := ""
	if cfg != nil {
		defaultURL = cfg.APIBaseURL
		defaultToken = cfg.GetToken()
	}

	logDebug("ShowAPIDialog: creating modal")
	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title("从部署接口获取证书").
			Size(ui.Dpi(550, 560)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)
	logDebug("ShowAPIDialog: modal created")

	// 证书数据列表
	var certDataList []api.CertData

	// 接口地址标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("部署接口:").
			Position(ui.Dpi(20, 20)),
	)

	// 接口地址输入
	txtAPIURL := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(110, 18)).
			Width(ui.DpiX(400)).
			Text(defaultURL),
	)

	// Token 标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("部署Token:").
			Position(ui.Dpi(20, 50)),
	)

	// Token 输入（密码样式，默认隐藏）
	txtToken := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(110, 48)).
			Width(ui.DpiX(320)).
			Text(defaultToken).
			CtrlStyle(co.ES_PASSWORD),
	)

	// 显示/隐藏 Token 按钮
	btnShowToken := ui.NewButton(dlg,
		ui.OptsButton().
			Text("显示").
			Position(ui.Dpi(440, 46)).
			Width(ui.DpiX(70)).
			Height(ui.DpiY(26)),
	)
	tokenVisible := false

	// 域名标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("域名 (可选):").
			Position(ui.Dpi(20, 80)),
	)

	// 域名输入
	txtDomain := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(110, 78)).
			Width(ui.DpiX(300)),
	)

	// 获取证书按钮
	btnFetch := ui.NewButton(dlg,
		ui.OptsButton().
			Text("获取证书").
			Position(ui.Dpi(420, 76)).
			Width(ui.DpiX(90)).
			Height(ui.DpiY(28)),
	)

	// 证书列表标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("证书列表:").
			Position(ui.Dpi(20, 115)),
	)

	// 证书列表 (ListView) - 支持多选 (Ctrl+Click, Shift+Click)
	lstCerts := ui.NewListView(dlg,
		ui.OptsListView().
			Position(ui.Dpi(20, 135)).
			Size(ui.Dpi(500, 120)).
			CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_GRIDLINES).
			CtrlStyle(co.LVS_REPORT|co.LVS_SHOWSELALWAYS),
	)

	// 全选按钮
	btnSelectAll := ui.NewButton(dlg,
		ui.OptsButton().
			Text("全选").
			Position(ui.Dpi(20, 260)).
			Width(ui.DpiX(50)).
			Height(ui.DpiY(24)),
	)

	// 取消全选按钮
	btnDeselectAll := ui.NewButton(dlg,
		ui.OptsButton().
			Text("清除").
			Position(ui.Dpi(75, 260)).
			Width(ui.DpiX(50)).
			Height(ui.DpiY(24)),
	)

	// 证书详情标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("已选证书:").
			Position(ui.Dpi(20, 290)),
	)

	// 证书详情显示
	txtDetail := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 308)).
			Width(ui.DpiX(500)).
			Height(ui.DpiY(107)).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 自动更新复选框
	chkAutoUpdate := ui.NewCheckBox(dlg,
		ui.OptsCheckBox().
			Text("自动更新").
			Position(ui.Dpi(20, 420)),
	)

	// 本地私钥复选框
	chkLocalKey := ui.NewCheckBox(dlg,
		ui.OptsCheckBox().
			Text("本地私钥").
			Position(ui.Dpi(110, 420)),
	)

	// 验证方法标签
	lblValidation := ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("验证方法:").
			Position(ui.Dpi(200, 422)),
	)

	// 验证方法下拉框
	cmbValidation := ui.NewComboBox(dlg,
		ui.OptsComboBox().
			Position(ui.Dpi(260, 418)).
			Width(ui.DpiX(100)).
			Texts("自动", "文件验证", "委托验证").
			CtrlStyle(co.CBS_DROPDOWNLIST),
	)

	// 导入证书按钮
	btnInstall := ui.NewButton(dlg,
		ui.OptsButton().
			Text("导入选中").
			Position(ui.Dpi(330, 470)).
			Width(ui.DpiX(90)).
			Height(ui.DpiY(30)),
	)

	// 关闭按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("关闭").
			Position(ui.Dpi(430, 470)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 保存配置的函数
	saveConfig := func() {
		apiURL := strings.TrimSpace(txtAPIURL.Text())
		token := strings.TrimSpace(txtToken.Text())
		if apiURL != "" || token != "" {
			cfg, _ := config.Load()
			if cfg == nil {
				cfg = config.DefaultConfig()
			}
			cfg.APIBaseURL = apiURL
			cfg.SetToken(token)
			cfg.Save()
		}
	}

	// 获取选中的证书索引列表
	getSelectedIndexes := func() []int {
		var indexes []int
		selected := lstCerts.Items.Selected()
		for _, item := range selected {
			indexes = append(indexes, item.Index())
		}
		return indexes
	}

	// 更新已选证书显示
	updateSelectedInfo := func() {
		indexes := getSelectedIndexes()
		if len(indexes) == 0 {
			txtDetail.SetText("(未选择)")
			return
		}
		var info strings.Builder
		for _, idx := range indexes {
			if idx < len(certDataList) {
				c := &certDataList[idx]
				info.WriteString(fmt.Sprintf("%s (%s)\r\n", c.Domain, c.ExpiresAt))
			}
		}
		txtDetail.SetText(info.String())
	}

	// 初始化
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		// 添加列
		lstCerts.Cols.Add("主域名", ui.DpiX(180))
		lstCerts.Cols.Add("过期时间", ui.DpiX(100))
		lstCerts.Cols.Add("订单ID", ui.DpiX(180))

		btnInstall.Hwnd().EnableWindow(false)
		btnSelectAll.Hwnd().EnableWindow(false)
		btnDeselectAll.Hwnd().EnableWindow(false)

		// 初始状态：禁用验证方法选择（只有勾选本地私钥时才启用）
		lblValidation.Hwnd().EnableWindow(false)
		cmbValidation.Hwnd().EnableWindow(false)
		cmbValidation.Items.Select(0) // 默认选择"自动"
		return 0
	})

	// 显示/隐藏 Token 按钮事件
	btnShowToken.On().BnClicked(func() {
		tokenVisible = !tokenVisible
		if tokenVisible {
			// 移除 ES_PASSWORD 样式（使用 SendMessage 设置密码字符为 0）
			txtToken.Hwnd().SendMessage(0x00CC, 0, 0) // EM_SETPASSWORDCHAR
			btnShowToken.SetText("隐藏")
		} else {
			// 添加 ES_PASSWORD 样式（设置密码字符为 '*'）
			txtToken.Hwnd().SendMessage(0x00CC, win.WPARAM('*'), 0) // EM_SETPASSWORDCHAR
			btnShowToken.SetText("显示")
		}
		// 刷新显示
		txtToken.Hwnd().InvalidateRect(nil, true)
	})

	// 本地私钥复选框变化事件
	chkLocalKey.On().BnClicked(func() {
		enabled := chkLocalKey.IsChecked()
		lblValidation.Hwnd().EnableWindow(enabled)
		cmbValidation.Hwnd().EnableWindow(enabled)
		if !enabled {
			cmbValidation.Items.Select(0) // 取消勾选时重置为"自动"
		}
	})

	// 全选按钮
	btnSelectAll.On().BnClicked(func() {
		count := lstCerts.Items.Count()
		for i := 0; i < count; i++ {
			lstCerts.Items.Get(i).Select(true)
		}
		updateSelectedInfo()
	})

	// 取消全选按钮
	btnDeselectAll.On().BnClicked(func() {
		count := lstCerts.Items.Count()
		for i := 0; i < count; i++ {
			lstCerts.Items.Get(i).Select(false)
		}
		updateSelectedInfo()
	})

	// ListView 点击事件 - 更新已选证书显示
	lstCerts.On().NmClick(func(_ *win.NMITEMACTIVATE) {
		updateSelectedInfo()
	})

	// ListView 键盘事件 - 更新已选证书显示（用户用键盘导航时）
	lstCerts.On().LvnKeyDown(func(_ *win.NMLVKEYDOWN) {
		// 延迟更新，等待选择状态变化后再更新显示
		go func() {
			dlg.UiThread(func() {
				updateSelectedInfo()
			})
		}()
	})

	// 获取证书按钮事件
	btnFetch.On().BnClicked(func() {
		domain := strings.TrimSpace(txtDomain.Text())
		apiURL := strings.TrimSpace(txtAPIURL.Text())
		token := strings.TrimSpace(txtToken.Text())

		if apiURL == "" {
			ui.MsgOk(dlg, "提示", "请输入接口地址", "请输入部署接口地址。")
			return
		}
		if token == "" {
			ui.MsgOk(dlg, "提示", "请输入 Token", "请输入部署 Token。")
			return
		}

		// 保存配置
		saveConfig()

		client := api.NewClient(apiURL, token)

		txtDetail.SetText("正在查询证书...")
		btnFetch.Hwnd().EnableWindow(false)
		btnInstall.Hwnd().EnableWindow(false)
		lstCerts.Items.DeleteAll()

		// 异步获取
		go func() {
			defer func() {
				if r := recover(); r != nil {
					dlg.UiThread(func() {
						btnFetch.Hwnd().EnableWindow(true)
						txtDetail.SetText(fmt.Sprintf("操作异常: %v", r))
					})
				}
			}()

			certList, err := client.ListCertsByDomain(context.Background(), domain)

			// 在 UI 线程更新
			dlg.UiThread(func() {
				btnFetch.Hwnd().EnableWindow(true)

				if err != nil {
					// 格式化错误信息
					errMsg := formatAPIError(err)
					txtDetail.SetText(errMsg)
					return
				}

				if len(certList) == 0 {
					txtDetail.SetText("未找到任何证书")
					return
				}

				// 更新证书列表
				certDataList = certList
				for _, c := range certList {
					lstCerts.Items.Add(c.Domain, c.ExpiresAt, fmt.Sprintf("%d", c.OrderID))
				}

				// 启用按钮
				btnSelectAll.Hwnd().EnableWindow(true)
				btnDeselectAll.Hwnd().EnableWindow(true)
				btnInstall.Hwnd().EnableWindow(true)

				// 显示提示
				txtDetail.SetText(fmt.Sprintf("找到 %d 个证书\r\n\r\n操作: 点击选择，Ctrl+点击多选，Shift+点击范围选，或点击\"全选\"", len(certList)))
			})
		}()
	})

	// 导入证书按钮事件
	btnInstall.On().BnClicked(func() {
		selectedIndexes := getSelectedIndexes()
		if len(selectedIndexes) == 0 {
			ui.MsgOk(dlg, "提示", "请先选择证书", "请先在列表中选择要导入的证书。\n\n提示: 点击选择，Ctrl+点击多选")
			return
		}

		// 收集要导入的证书
		var certsToInstall []api.CertData
		for _, idx := range selectedIndexes {
			if idx < len(certDataList) {
				certsToInstall = append(certsToInstall, certDataList[idx])
			}
		}

		if len(certsToInstall) == 0 {
			return
		}

		// 获取验证方法
		localKeyEnabled := chkLocalKey.IsChecked()
		validationMethod := ""
		if localKeyEnabled {
			validationIdx := cmbValidation.Items.Selected()
			switch validationIdx {
			case 1:
				validationMethod = config.ValidationMethodFile
			case 2:
				validationMethod = config.ValidationMethodDelegation
			}

			// 校验验证方法与域名的兼容性（校验选中证书的所有域名包括 SAN）
			if validationMethod != "" {
				for _, c := range certsToInstall {
					if errMsg := config.ValidateValidationMethod(c.Domain, validationMethod); errMsg != "" {
						ui.MsgOk(dlg, "校验失败", "验证方法不兼容", fmt.Sprintf("证书 [%s] 的主域名 %s: %s", c.Domain, c.Domain, errMsg))
						return
					}
					// 检查所有 SAN 域名
					for _, d := range c.GetDomainList() {
						if errMsg := config.ValidateValidationMethod(d, validationMethod); errMsg != "" {
							ui.MsgOk(dlg, "校验失败", "验证方法不兼容", fmt.Sprintf("证书 [%s] 的 SAN 域名 %s: %s", c.Domain, d, errMsg))
							return
						}
					}
				}
			}
		}

		txtDetail.SetText(fmt.Sprintf("正在检查 %d 个证书...", len(certsToInstall)))
		btnInstall.Hwnd().EnableWindow(false)
		btnFetch.Hwnd().EnableWindow(false)
		btnSelectAll.Hwnd().EnableWindow(false)
		btnDeselectAll.Hwnd().EnableWindow(false)

		// 在 goroutine 外先获取复选框状态
		autoUpdateEnabled := chkAutoUpdate.IsChecked()
		validationMethodCopy := validationMethod

		go func() {
			defer func() {
				if r := recover(); r != nil {
					dlg.UiThread(func() {
						btnInstall.Hwnd().EnableWindow(true)
						btnFetch.Hwnd().EnableWindow(true)
						btnSelectAll.Hwnd().EnableWindow(true)
						btnDeselectAll.Hwnd().EnableWindow(true)
						txtDetail.SetText(fmt.Sprintf("操作异常: %v", r))
					})
				}
			}()

			var results []string
			successCount := 0
			skipCount := 0
			failCount := 0
			manualBindCount := 0 // 需要手动绑定的数量

			for i, certToInstall := range certsToInstall {
				dlg.UiThread(func() {
					txtDetail.SetText(fmt.Sprintf("正在处理 (%d/%d): %s", i+1, len(certsToInstall), certToInstall.Domain))
				})

				// 检查证书是否已存在（按序列号）
				var existingThumbprint string
				serialNumber, err := cert.GetCertSerialNumber(certToInstall.Certificate)
				if err == nil {
					exists, existingCert, _ := cert.IsCertExists(serialNumber)
					if exists && existingCert != nil {
						results = append(results, fmt.Sprintf("- %s: 已存在 (指纹: %s...)", certToInstall.Domain, existingCert.Thumbprint[:16]))
						skipCount++
						existingThumbprint = existingCert.Thumbprint

						// 即使证书已存在，也检查并保存自动部署配置
						if autoUpdateEnabled {
							cfg, _ := config.Load()
							if cfg == nil {
								cfg = config.DefaultConfig()
							}
							existing := cfg.GetCertificateByOrderID(certToInstall.OrderID)
							if existing == nil {
								certConfig := config.CertConfig{
									OrderID:          certToInstall.OrderID,
									Domain:           certToInstall.Domain,
									Domains:          certToInstall.GetDomainList(),
									ExpiresAt:        certToInstall.ExpiresAt,
									SerialNumber:     serialNumber,
									Enabled:          true,
									UseLocalKey:      localKeyEnabled,
									ValidationMethod: validationMethodCopy,
									AutoBindMode:     true,
									BindRules:        []config.BindRule{},
								}
								cfg.AddCertificate(certConfig)
								cfg.Save()
								results = append(results, fmt.Sprintf("  → 已添加自动更新配置"))
							}
						}

						// 证书已存在，但仍需检查并添加缺失的 HTTPS 绑定
						allDomains := certToInstall.GetDomainList()
						if len(allDomains) == 0 && certToInstall.Domain != "" {
							allDomains = []string{certToInstall.Domain}
						}

						results = append(results, fmt.Sprintf("  [检查绑定] 证书域名: %v", allDomains))

						_, httpMatches, _ := iis.FindMatchingBindings(allDomains)
						if len(httpMatches) > 0 {
							results = append(results, fmt.Sprintf("  [检查绑定] 发现 %d 个 HTTP 绑定需要添加 HTTPS", len(httpMatches)))
							for _, match := range httpMatches {
								if err := iis.AddHttpsBinding(match.SiteName, match.Host, match.Port); err != nil {
									results = append(results, fmt.Sprintf("  ! 添加HTTPS绑定失败 %s: %v", match.Host, err))
									continue
								}
								if err := iis.BindCertificate(match.Host, match.Port, existingThumbprint); err == nil {
									results = append(results, fmt.Sprintf("  → 已添加绑定: %s:%d (站点: %s)", match.Host, match.Port, match.SiteName))
								} else {
									results = append(results, fmt.Sprintf("  ! 绑定证书失败 %s: %v", match.Host, err))
								}
							}
						}
						continue
					}
				}

				// 将 PEM 转换为 PFX
				pfxPath, err := cert.PEMToPFX(
					certToInstall.Certificate,
					certToInstall.PrivateKey,
					certToInstall.CACert,
					"",
				)

				if err != nil {
					results = append(results, fmt.Sprintf("✗ %s: 转换失败 - %v", certToInstall.Domain, err))
					failCount++
					continue
				}

				// 安装 PFX
				result, err := cert.InstallPFX(pfxPath, "")
				os.Remove(pfxPath)

				if err != nil {
					results = append(results, fmt.Sprintf("✗ %s: 安装失败 - %v", certToInstall.Domain, err))
					failCount++
					continue
				}

				if !result.Success {
					results = append(results, fmt.Sprintf("✗ %s: %s", certToInstall.Domain, result.ErrorMessage))
					failCount++
					continue
				}

				results = append(results, fmt.Sprintf("✓ %s: %s", certToInstall.Domain, result.Thumbprint))
				successCount++

				// 尝试默认绑定
				allDomains := certToInstall.GetDomainList()
				if len(allDomains) == 0 && certToInstall.Domain != "" {
					allDomains = []string{certToInstall.Domain}
				}

				// 调试: 显示证书域名列表
				results = append(results, fmt.Sprintf("  [调试] 证书域名: %v", allDomains))

				httpsMatches, httpMatches, findErr := iis.FindMatchingBindings(allDomains)
				if findErr != nil {
					results = append(results, fmt.Sprintf("  ! 查找绑定失败: %v", findErr))
				}

				// 调试: 显示匹配结果
				results = append(results, fmt.Sprintf("  [调试] 匹配: HTTPS=%d, HTTP=%d", len(httpsMatches), len(httpMatches)))
				for _, m := range httpMatches {
					results = append(results, fmt.Sprintf("  [调试] HTTP匹配: %s (站点: %s)", m.Host, m.SiteName))
				}

				boundCount := 0

				// 1. 更新已有的 HTTPS 绑定
				for _, match := range httpsMatches {
					var bindErr error
					// 判断是否 IP 绑定
					isIP := true
					for _, c := range match.Host {
						if c != '.' && (c < '0' || c > '9') {
							isIP = false
							break
						}
					}
					if isIP {
						bindErr = iis.BindCertificateByIP(match.Host, match.Port, result.Thumbprint)
					} else {
						bindErr = iis.BindCertificate(match.Host, match.Port, result.Thumbprint)
					}
					if bindErr == nil {
						boundCount++
						results = append(results, fmt.Sprintf("  → 已更新绑定: %s:%d", match.Host, match.Port))
					} else {
						results = append(results, fmt.Sprintf("  ! 更新绑定失败 %s:%d: %v", match.Host, match.Port, bindErr))
					}
				}

				// 2. 为 HTTP 绑定添加 HTTPS 绑定
				for _, match := range httpMatches {
					// 先添加 HTTPS 绑定
					if err := iis.AddHttpsBinding(match.SiteName, match.Host, match.Port); err != nil {
						results = append(results, fmt.Sprintf("  ! 添加HTTPS绑定失败 %s: %v", match.Host, err))
						continue
					}
					// 再绑定证书
					if err := iis.BindCertificate(match.Host, match.Port, result.Thumbprint); err == nil {
						boundCount++
						results = append(results, fmt.Sprintf("  → 已添加绑定: %s:%d (站点: %s)", match.Host, match.Port, match.SiteName))
					} else {
						results = append(results, fmt.Sprintf("  ! 绑定证书失败 %s: %v", match.Host, err))
					}
				}

				// 如果没有任何绑定，记录需要手动绑定
				if boundCount == 0 && len(httpsMatches) == 0 && len(httpMatches) == 0 {
					results = append(results, fmt.Sprintf("  ! 未找到匹配的 IIS 绑定，请手动绑定"))
					manualBindCount++
				}

				// 如果勾选了"自动更新"，保存证书配置
				if autoUpdateEnabled {
					cfg, _ := config.Load()
					if cfg == nil {
						cfg = config.DefaultConfig()
					}

					// 检查是否已存在（按 OrderID）
					existing := cfg.GetCertificateByOrderID(certToInstall.OrderID)
					if existing == nil {
						// 创建证书配置
						certConfig := config.CertConfig{
							OrderID:          certToInstall.OrderID,
							Domain:           certToInstall.Domain,
							Domains:          certToInstall.GetDomainList(),
							ExpiresAt:        certToInstall.ExpiresAt,
							SerialNumber:     serialNumber,
							Enabled:          true,
							UseLocalKey:      localKeyEnabled,
							ValidationMethod: validationMethodCopy,
							AutoBindMode:     true,
							BindRules:        []config.BindRule{},
						}
						cfg.AddCertificate(certConfig)
						cfg.Save()
					}
				}
			}

			dlg.UiThread(func() {
				btnInstall.Hwnd().EnableWindow(true)
				btnFetch.Hwnd().EnableWindow(true)
				btnSelectAll.Hwnd().EnableWindow(true)
				btnDeselectAll.Hwnd().EnableWindow(true)

				// 显示结果
				var info strings.Builder
				info.WriteString(fmt.Sprintf("处理完成: 导入 %d, 跳过 %d, 失败 %d\r\n\r\n", successCount, skipCount, failCount))
				for _, r := range results {
					info.WriteString(r + "\r\n")
				}
				txtDetail.SetText(info.String())

				if failCount == 0 && successCount > 0 {
					var msg string
					if manualBindCount > 0 {
						msg = fmt.Sprintf("导入: %d, 跳过(已存在): %d\n\n有 %d 个证书未找到匹配的 IIS 绑定，请使用\"绑定证书\"功能手动绑定。", successCount, skipCount, manualBindCount)
					} else {
						msg = fmt.Sprintf("导入: %d, 跳过(已存在): %d\n\n已自动绑定到匹配的 IIS 站点。", successCount, skipCount)
					}
					if autoUpdateEnabled {
						msg += "\n自动更新将自动检测并更新已绑定的证书。"
					}
					ui.MsgOk(dlg, "成功", "证书导入完成", msg)
					dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
					if onSuccess != nil {
						onSuccess()
					}
				} else if failCount == 0 && successCount == 0 {
					msg := fmt.Sprintf("跳过 %d 个已存在的证书", skipCount)
					if autoUpdateEnabled {
						msg += "\n\n自动更新配置已保存，将自动检测并更新已绑定的证书。"
					}
					ui.MsgOk(dlg, "提示", "所有证书已存在", msg)
				} else {
					ui.MsgOk(dlg, "完成", "部分证书导入失败",
						fmt.Sprintf("导入: %d, 跳过: %d, 失败: %d", successCount, skipCount, failCount))
				}
			})
		}()
	})

	// 取消按钮事件
	btnCancel.On().BnClicked(func() {
		dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)
	})

	dlg.ShowModal()
}
