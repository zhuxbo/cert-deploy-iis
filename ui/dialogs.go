package ui

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"cert-deploy/api"
	"cert-deploy/cert"
	"cert-deploy/config"
	"cert-deploy/iis"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

// ComboBox 消息常量
const (
	CB_SHOWDROPDOWN = 0x014F
)


// ShowBindDialog 显示证书绑定对话框
func ShowBindDialog(owner ui.Parent, site *iis.SiteInfo, certs []cert.CertInfo, onSuccess func()) {
	// 过滤出有私钥的证书
	allValidCerts := make([]cert.CertInfo, 0)
	for _, c := range certs {
		if c.HasPrivKey {
			allValidCerts = append(allValidCerts, c)
		}
	}

	// 当前过滤后的证书列表（会根据域名动态更新）
	filteredCerts := allValidCerts

	// 获取域名列表（用于下拉框）
	domainList := getDomainsFromSite(site)

	// 创建模态对话框
	dlg := ui.NewModal(owner,
		ui.OptsModal().
			Title(fmt.Sprintf("绑定证书 - %s", site.Name)).
			Size(ui.Dpi(500, 450)).
			Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),
	)

	// 域名标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("域名:").
			Position(ui.Dpi(20, 20)),
	)

	// 域名下拉框（可编辑）
	cmbDomain := ui.NewComboBox(dlg,
		ui.OptsComboBox().
			Position(ui.Dpi(70, 18)).
			Width(ui.DpiX(280)).
			Texts(domainList...).
			CtrlStyle(co.CBS_DROPDOWN), // 可编辑
	)

	// 端口标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("端口:").
			Position(ui.Dpi(360, 20)),
	)

	// 端口输入框
	txtPort := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(400, 18)).
			Width(ui.DpiX(60)).
			Text("443"),
	)

	// 当前绑定标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("当前绑定:").
			Position(ui.Dpi(20, 55)),
	)

	// 当前绑定显示
	txtCurrentBinding := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(90, 53)).
			Width(ui.DpiX(370)).
			CtrlStyle(co.ES_READONLY),
	)

	// 证书选择
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("新证书:").
			Position(ui.Dpi(20, 90)),
	)

	cmbCert := ui.NewComboBox(dlg,
		ui.OptsComboBox().
			Position(ui.Dpi(90, 88)).
			Width(ui.DpiX(370)).
			CtrlStyle(co.CBS_DROPDOWNLIST),
	)

	// 证书详情标签
	ui.NewStatic(dlg,
		ui.OptsStatic().
			Text("证书详情:").
			Position(ui.Dpi(20, 125)),
	)

	// 证书详情显示区域
	txtCertInfo := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(20, 145)).
			Width(ui.DpiX(450)).
			Height(ui.DpiY(180)).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 绑定按钮
	btnBind := ui.NewButton(dlg,
		ui.OptsButton().
			Text("绑定").
			Position(ui.Dpi(290, 350)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 关闭按钮
	btnCancel := ui.NewButton(dlg,
		ui.OptsButton().
			Text("关闭").
			Position(ui.Dpi(380, 350)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(30)),
	)

	// 生成证书显示名称（包含到期时间）
	getCertDisplayWithExpiry := func(c *cert.CertInfo) string {
		name := cert.GetCertDisplayName(c)
		expiry := c.NotAfter.Format("2006-01-02")
		return fmt.Sprintf("%s (到期: %s)", name, expiry)
	}

	// 更新证书下拉框
	updateCertList := func(domain string) {
		// 根据域名过滤证书
		if domain != "" {
			filteredCerts = cert.FilterByDomain(allValidCerts, domain)
		} else {
			filteredCerts = allValidCerts
		}

		// 如果没有匹配的证书，显示所有证书
		if len(filteredCerts) == 0 {
			filteredCerts = allValidCerts
		}

		// 先关闭下拉列表（如果已展开）
		cmbCert.Hwnd().SendMessage(CB_SHOWDROPDOWN, 0, 0)

		// 清空并重新添加
		cmbCert.Items.DeleteAll()
		for _, c := range filteredCerts {
			cmbCert.Items.Add(getCertDisplayWithExpiry(&c))
		}

		// 强制重绘
		cmbCert.Hwnd().InvalidateRect(nil, true)

		// 选择第一个
		if len(filteredCerts) > 0 {
			cmbCert.Items.Select(0)
		}
	}

	// 更新证书详情显示
	updateCertInfo := func() {
		idx := cmbCert.Items.Selected()
		if idx >= 0 && idx < len(filteredCerts) {
			c := filteredCerts[idx]
			sanStr := "(无)"
			if len(c.DNSNames) > 0 {
				sanStr = strings.Join(c.DNSNames, ", ")
			}
			info := fmt.Sprintf(
				"指纹: %s\r\n主题: %s\r\n颁发者: %s\r\n有效期: %s 至 %s\r\n状态: %s\r\nSAN: %s",
				c.Thumbprint,
				c.Subject,
				c.Issuer,
				c.NotBefore.Format("2006-01-02"),
				c.NotAfter.Format("2006-01-02"),
				cert.GetCertStatus(&c),
				sanStr,
			)
			txtCertInfo.SetText(info)
		} else {
			txtCertInfo.SetText("")
		}
	}

	// 查询当前绑定（实时查询，无缓存，支持通配符匹配）
	updateCurrentBinding := func() {
		domain := strings.TrimSpace(cmbDomain.Text())
		portStr := strings.TrimSpace(txtPort.Text())
		port := 443
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}

		if domain == "" {
			txtCurrentBinding.SetText("(请输入域名)")
			return
		}

		// 先尝试精确查询
		binding, err := iis.GetBindingForHost(domain, port)
		if err != nil {
			txtCurrentBinding.SetText(fmt.Sprintf("查询失败: %v", err))
			return
		}

		// 如果精确查询没找到，尝试查找匹配的通配符绑定
		matchedHost := domain
		if binding == nil {
			bindings, _ := iis.ListSSLBindings()
			for _, b := range bindings {
				host := iis.ParseHostFromBinding(b.HostnamePort)
				bindPort := iis.ParsePortFromBinding(b.HostnamePort)
				if bindPort != port {
					continue
				}
				// 检查是否是匹配的通配符
				if strings.HasPrefix(host, "*.") {
					suffix := host[1:] // .aaa.xljy.live
					if strings.HasSuffix(domain, suffix) {
						prefix := domain[:len(domain)-len(suffix)]
						// 确保只有一级子域名
						if !strings.Contains(prefix, ".") && len(prefix) > 0 {
							binding = &b
							matchedHost = host
							break
						}
					}
				}
			}
		}

		if binding == nil {
			txtCurrentBinding.SetText("(未绑定)")
			return
		}

		// 查找对应的证书信息
		certInfo := ""
		for _, c := range certs {
			if strings.EqualFold(c.Thumbprint, binding.CertHash) {
				name := cert.GetCertDisplayName(&c)
				expiry := c.NotAfter.Format("2006-01-02")
				if matchedHost != domain {
					// 显示通配符绑定域名
					certInfo = fmt.Sprintf("%s [%s] (到期: %s)", name, matchedHost, expiry)
				} else {
					certInfo = fmt.Sprintf("%s (到期: %s)", name, expiry)
				}
				break
			}
		}
		if certInfo == "" && len(binding.CertHash) >= 16 {
			if matchedHost != domain {
				certInfo = fmt.Sprintf("[%s] %s...", matchedHost, binding.CertHash[:16])
			} else {
				certInfo = binding.CertHash[:16] + "..."
			}
		}
		txtCurrentBinding.SetText(certInfo)
	}

	// 域名变化时更新证书列表和当前绑定
	updateForDomainText := func(domain string) {
		updateCertList(domain)
		updateCertInfo()
		updateCurrentBinding()
	}

	// 域名选择变化事件 - 通过索引获取选中的域名（避免时序问题）
	cmbDomain.On().CbnSelChange(func() {
		idx := cmbDomain.Items.Selected()
		if idx >= 0 && idx < len(domainList) {
			updateForDomainText(domainList[idx])
		}
	})

	// 域名编辑变化事件 - 使用文本框内容
	cmbDomain.On().CbnEditChange(func() {
		updateForDomainText(strings.TrimSpace(cmbDomain.Text()))
	})

	// 证书选择变化事件
	cmbCert.On().CbnSelChange(func() {
		updateCertInfo()
	})

	// 绑定按钮事件
	btnBind.On().BnClicked(func() {
		domain := strings.TrimSpace(cmbDomain.Text())
		portStr := strings.TrimSpace(txtPort.Text())
		certIdx := cmbCert.Items.Selected()

		if domain == "" {
			ui.MsgOk(dlg, "提示", "请输入域名", "请输入或选择要绑定的域名。")
			return
		}

		port := 443
		if portStr != "" {
			fmt.Sscanf(portStr, "%d", &port)
		}
		if port <= 0 || port > 65535 {
			ui.MsgOk(dlg, "提示", "端口无效", "端口必须在 1-65535 之间。")
			return
		}

		if certIdx < 0 || certIdx >= len(filteredCerts) {
			ui.MsgOk(dlg, "提示", "请选择证书", "请先选择要绑定的证书。")
			return
		}

		selectedCert := filteredCerts[certIdx]
		siteName := site.Name

		// 禁用按钮防止重复点击
		btnBind.Hwnd().EnableWindow(false)
		btnCancel.Hwnd().EnableWindow(false)
		txtCertInfo.SetText("正在绑定证书...")

		go func() {
			// 检查站点是否有对应的 https 绑定，如果没有则创建
			hasBinding := false
			for _, b := range site.Bindings {
				if b.Protocol == "https" && b.Host == domain && b.Port == port {
					hasBinding = true
					break
				}
			}

			if !hasBinding {
				// 创建 https 绑定（启用 SNI）
				if err := iis.AddHttpsBinding(siteName, domain, port); err != nil {
					dlg.UiThread(func() {
						btnBind.Hwnd().EnableWindow(true)
						btnCancel.Hwnd().EnableWindow(true)
						txtCertInfo.SetText(fmt.Sprintf("创建 HTTPS 绑定失败: %v", err))
						ui.MsgError(dlg, "错误", "创建绑定失败", err.Error())
					})
					return
				}
			}

			// 绑定证书
			err := iis.BindCertificate(domain, port, selectedCert.Thumbprint)

			dlg.UiThread(func() {
				btnBind.Hwnd().EnableWindow(true)
				btnCancel.Hwnd().EnableWindow(true)

				if err != nil {
					txtCertInfo.SetText(fmt.Sprintf("绑定失败: %v", err))
					ui.MsgError(dlg, "错误", "绑定失败", err.Error())
					return
				}

				// 更新当前绑定显示
				updateCurrentBinding()
				updateCertInfo()

				ui.MsgOk(dlg, "成功", "证书绑定成功", "证书已成功绑定到域名。")
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

	// 初始选择
	dlg.On().WmCreate(func(_ ui.WmCreate) int {
		// 选择第一个域名
		if len(domainList) > 0 {
			cmbDomain.Items.Select(0)
		}

		// 初始化证书列表和当前绑定
		domain := ""
		if len(domainList) > 0 {
			domain = domainList[0]
		}
		updateCertList(domain)
		updateCertInfo()
		updateCurrentBinding()

		return 0
	})

	dlg.ShowModal()
}

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

// getDomainsFromSite 从站点获取域名列表
func getDomainsFromSite(site *iis.SiteInfo) []string {
	domains := make([]string, 0)
	seen := make(map[string]bool)

	// 先添加所有绑定的域名
	for _, b := range site.Bindings {
		if b.Host != "" && !seen[b.Host] {
			domains = append(domains, b.Host)
			seen[b.Host] = true
		}
	}

	return domains
}

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

	// Token 输入
	txtToken := ui.NewEdit(dlg,
		ui.OptsEdit().
			Position(ui.Dpi(110, 48)).
			Width(ui.DpiX(400)).
			Text(defaultToken),
	)

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
			certList, err := client.ListCertsByDomain(domain)

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
	ui.NewStatic(dlg, ui.OptsStatic().Text("续签:").Position(ui.Dpi(20, 315)))
	txtRenewLocal := ui.NewEdit(dlg, ui.OptsEdit().Position(ui.Dpi(50, 313)).Width(ui.DpiX(30)).Text(fmt.Sprintf("%d", cfg.RenewDaysLocal)))
	ui.NewStatic(dlg, ui.OptsStatic().Text("天").Position(ui.Dpi(83, 315)))
	ui.NewStatic(dlg, ui.OptsStatic().Text("拉取:").Position(ui.Dpi(105, 315)))
	txtRenewFetch := ui.NewEdit(dlg, ui.OptsEdit().Position(ui.Dpi(135, 313)).Width(ui.DpiX(30)).Text(fmt.Sprintf("%d", cfg.RenewDaysFetch)))
	ui.NewStatic(dlg, ui.OptsStatic().Text("天").Position(ui.Dpi(168, 315)))

	chkIIS7Mode := ui.NewCheckBox(dlg, ui.OptsCheckBox().Text("IIS7 兼容模式").Position(ui.Dpi(200, 315)))

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
		txtRenewLocal.SetText(fmt.Sprintf("%d", cfg.RenewDaysLocal))
		txtRenewFetch.SetText(fmt.Sprintf("%d", cfg.RenewDaysFetch))
		chkIIS7Mode.SetCheck(cfg.IIS7Mode)
		selectedIdx = -1
		refreshList()
		updateButtonStates()
	})

	// 保存
	btnSave.On().BnClicked(func() {
		renewLocal := 15
		fmt.Sscanf(txtRenewLocal.Text(), "%d", &renewLocal)
		if renewLocal < 1 {
			renewLocal = 1
		}
		renewFetch := 13
		fmt.Sscanf(txtRenewFetch.Text(), "%d", &renewFetch)
		if renewFetch < 1 {
			renewFetch = 1
		}
		cfg.RenewDaysLocal = renewLocal
		cfg.RenewDaysFetch = renewFetch
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
