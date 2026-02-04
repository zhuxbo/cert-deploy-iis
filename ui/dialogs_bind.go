package ui

import (
	"fmt"
	"strings"

	"sslctlw/cert"
	"sslctlw/iis"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
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
	// 参数 domain: 当前选中/输入的域名，由调用方传入（避免 CbnSelChange 时 Text() 返回旧值的问题）
	updateCurrentBinding := func(domain string) {
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
		updateCurrentBinding(domain)
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
			defer func() {
				if r := recover(); r != nil {
					dlg.UiThread(func() {
						btnBind.Hwnd().EnableWindow(true)
						btnCancel.Hwnd().EnableWindow(true)
						txtCertInfo.SetText(fmt.Sprintf("操作异常: %v", r))
					})
				}
			}()

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
				updateCurrentBinding(domain)
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
		updateCurrentBinding(domain)

		return 0
	})

	dlg.ShowModal()
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
