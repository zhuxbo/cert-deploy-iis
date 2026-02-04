package ui

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
	"sslctlw/util"

	"github.com/rodrigocfd/windigo/co"
	"github.com/rodrigocfd/windigo/ui"
	"github.com/rodrigocfd/windigo/win"
)

// 调试模式
var (
	debugMode    bool
	debugLog     *log.Logger
	debugLogFile *os.File
)

// EnableDebugMode 启用调试模式
func EnableDebugMode() {
	debugMode = true
	f, err := os.OpenFile("debug.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return
	}
	debugLogFile = f
	debugLog = log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	logDebug("Debug mode enabled")
}

func logDebug(format string, v ...interface{}) {
	if debugMode && debugLog != nil {
		debugLog.Printf(format, v...)
		debugLogFile.Sync()
	}
}

// CloseDebugMode 关闭调试模式并释放资源
func CloseDebugMode() {
	if debugLogFile != nil {
		debugLogFile.Sync()
		debugLogFile.Close()
		debugLogFile = nil
		debugLog = nil
	}
}

// AppWindow 主窗口
type AppWindow struct {
	mainWnd    *ui.Main
	siteList   *ui.ListView
	statusBar  *ui.StatusBar
	certs      []cert.CertInfo
	sites      []SiteItem
	dataMu     sync.RWMutex // 保护 certs 和 sites 共享数据
	btnRefresh *ui.Button
	btnBind    *ui.Button
	btnInstall *ui.Button
	btnAPI     *ui.Button
	loading    bool
	loadingMu  sync.Mutex // 保护 loading 标志

	// context 用于取消后台 goroutine
	ctx       context.Context
	cancelCtx context.CancelFunc

	// 后台任务相关
	bgTask          *BackgroundTask
	lblTaskSection  *ui.Static
	btnAutoCheck    *ui.Button
	btnCheckNow     *ui.Button
	btnConfig       *ui.Button
	lblTaskStatus   *ui.Static
	txtTaskLog      *ui.Edit
	statusIndicator *StatusIndicator // 状态指示器

	// 日志缓存
	logLines []string
}

// getCerts 安全获取证书列表副本
func (app *AppWindow) getCerts() []cert.CertInfo {
	app.dataMu.RLock()
	defer app.dataMu.RUnlock()
	return append([]cert.CertInfo{}, app.certs...)
}

// getSites 安全获取站点列表副本
func (app *AppWindow) getSites() []SiteItem {
	app.dataMu.RLock()
	defer app.dataMu.RUnlock()
	return append([]SiteItem{}, app.sites...)
}

// getSite 安全获取指定索引的站点副本
func (app *AppWindow) getSite(idx int) *SiteItem {
	app.dataMu.RLock()
	defer app.dataMu.RUnlock()
	if idx < 0 || idx >= len(app.sites) {
		return nil
	}
	site := app.sites[idx]
	return &site
}

// SiteItem 站点列表项
type SiteItem struct {
	Name     string
	State    string
	Bindings string
	CertName string
	Expiry   string
	SiteInfo iis.SiteInfo
}

// RunApp 运行应用程序
func RunApp() {
	runtime.LockOSThread()

	// 确保程序退出时清理调试模式资源
	defer CloseDebugMode()

	ctx, cancel := context.WithCancel(context.Background())
	app := &AppWindow{
		bgTask:    NewBackgroundTask(),
		ctx:       ctx,
		cancelCtx: cancel,
	}

	// 创建主窗口
	app.mainWnd = ui.NewMain(
		ui.OptsMain().
			Title("IIS 证书部署工具").
			Size(ui.Dpi(900, 700)).
			Style(co.WS_OVERLAPPEDWINDOW),
	)

	// 创建工具栏按钮
	app.btnRefresh = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("刷新").
			Position(ui.Dpi(10, 10)).
			Width(ui.DpiX(70)).
			Height(ui.DpiY(28)),
	)

	app.btnBind = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("绑定证书").
			Position(ui.Dpi(90, 10)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(28)),
	)

	app.btnInstall = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("导入证书").
			Position(ui.Dpi(180, 10)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(28)),
	)

	app.btnAPI = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("部署接口").
			Position(ui.Dpi(270, 10)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(28)),
	)

	// 创建站点列表
	app.siteList = ui.NewListView(app.mainWnd,
		ui.OptsListView().
			Position(ui.Dpi(10, 50)).
			Size(ui.Dpi(860, 380)).
			CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_GRIDLINES).
			CtrlStyle(co.LVS_REPORT|co.LVS_SINGLESEL|co.LVS_SHOWSELALWAYS),
	)

	// === 后台任务面板 ===
	// 分隔标签
	app.lblTaskSection = ui.NewStatic(app.mainWnd,
		ui.OptsStatic().
			Text("─── 自动部署任务 ───").
			Position(ui.Dpi(10, 440)),
	)

	// 任务控制按钮
	app.btnAutoCheck = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("启动自动部署").
			Position(ui.Dpi(10, 460)).
			Width(ui.DpiX(100)).
			Height(ui.DpiY(28)),
	)

	app.btnCheckNow = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("立即检测").
			Position(ui.Dpi(120, 460)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(28)),
	)

	app.btnConfig = ui.NewButton(app.mainWnd,
		ui.OptsButton().
			Text("配置任务").
			Position(ui.Dpi(210, 460)).
			Width(ui.DpiX(80)).
			Height(ui.DpiY(28)),
	)

	// 任务状态标签
	app.lblTaskStatus = ui.NewStatic(app.mainWnd,
		ui.OptsStatic().
			Text("状态: 未启动").
			Position(ui.Dpi(310, 465)),
	)

	// 任务日志区域
	app.txtTaskLog = ui.NewEdit(app.mainWnd,
		ui.OptsEdit().
			Position(ui.Dpi(10, 495)).
			Width(ui.DpiX(860)).
			Height(ui.DpiY(120)).
			CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
			WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
	)

	// 创建状态栏
	app.statusBar = ui.NewStatusBar(app.mainWnd)

	// 窗口创建完成后初始化
	app.mainWnd.On().WmCreate(func(_ ui.WmCreate) int {
		// 添加列
		app.siteList.Cols.Add("站点名称", ui.DpiX(150))
		app.siteList.Cols.Add("状态", ui.DpiX(60))
		app.siteList.Cols.Add("绑定", ui.DpiX(280))
		app.siteList.Cols.Add("证书", ui.DpiX(200))
		app.siteList.Cols.Add("过期时间", ui.DpiX(100))

		// 添加状态栏分区
		app.statusBar.Parts.AddResizable("就绪", 1)

		// 创建状态指示器
		app.statusIndicator = NewStatusIndicator(app.mainWnd.Hwnd(), 300, 465, 1001)

		// 延迟初始化
		go func() {
			select {
			case <-app.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}

			// 异步检查任务计划状态
			go func() {
				// 检查 context 是否已取消
				select {
				case <-app.ctx.Done():
					return
				default:
				}

				cfg, _ := config.Load()
				taskName := util.DefaultTaskName
				if cfg != nil && cfg.TaskName != "" {
					taskName = cfg.TaskName
				}
				taskExists := util.IsTaskExists(taskName)

				// 再次检查 context
				select {
				case <-app.ctx.Done():
					return
				default:
				}

				app.mainWnd.UiThread(func() {
					if taskExists {
						app.btnAutoCheck.SetText("停止自动部署")
						app.statusIndicator.SetState(IndicatorRunning)
						app.lblTaskStatus.Hwnd().SetWindowText("状态: 任务计划运行中")
						app.appendTaskLog("检测到任务计划已启用")
					} else {
						app.btnAutoCheck.SetText("启动自动部署")
						app.statusIndicator.SetState(IndicatorStopped)
						app.lblTaskStatus.Hwnd().SetWindowText("状态: 未启动")
					}
				})
			}()

			// 检查 context
			select {
			case <-app.ctx.Done():
				return
			default:
			}

			// 加载数据
			app.mainWnd.UiThread(func() {
				app.setButtonsEnabled(false)
				app.setStatus("正在加载...")
			})
			app.doLoadDataAsync(nil)
		}()

		return 0
	})

	// 处理 WM_DRAWITEM 消息（用于 Owner-Draw 控件）
	app.mainWnd.On().WmDrawItem(func(p ui.WmDrawItem) {
		if app.statusIndicator != nil {
			app.statusIndicator.HandleDrawItem(p.ControlId(), p.DrawItemStruct())
		}
	})

	// 窗口大小改变时调整控件
	app.mainWnd.On().WmSize(func(p ui.WmSize) {
		req := p.Request()
		if req == co.SIZE_REQ_MINIMIZED {
			return
		}
		cx, cy := int(p.ClientAreaSize().Cx), int(p.ClientAreaSize().Cy)
		statusHeight := 22
		taskPanelHeight := 180

		// 调整站点列表大小
		listHeight := cy - 50 - statusHeight - taskPanelHeight
		if listHeight < 100 {
			listHeight = 100
		}
		app.siteList.Hwnd().SetWindowPos(0, 10, 50, cx-20, listHeight, co.SWP_NOZORDER)

		// 调整后台任务面板位置
		taskPanelY := 50 + listHeight + 5
		app.lblTaskSection.Hwnd().SetWindowPos(0, 10, taskPanelY, 200, 20, co.SWP_NOZORDER)
		app.btnAutoCheck.Hwnd().SetWindowPos(0, 10, taskPanelY+25, 100, 28, co.SWP_NOZORDER)
		app.btnCheckNow.Hwnd().SetWindowPos(0, 120, taskPanelY+25, 80, 28, co.SWP_NOZORDER)
		app.btnConfig.Hwnd().SetWindowPos(0, 210, taskPanelY+25, 80, 28, co.SWP_NOZORDER)

		// 状态指示器位置
		if app.statusIndicator != nil {
			app.statusIndicator.SetPosition(300, taskPanelY+28)
		}

		app.lblTaskStatus.Hwnd().SetWindowPos(0, 330, taskPanelY+30, cx-350, 20, co.SWP_NOZORDER)
		app.txtTaskLog.Hwnd().SetWindowPos(0, 10, taskPanelY+60, cx-20, cy-taskPanelY-60-statusHeight-5, co.SWP_NOZORDER)
	})

	// 按钮事件
	app.btnRefresh.On().BnClicked(func() {
		app.setButtonsEnabled(false)
		app.setStatus("正在加载...")
		app.doLoadDataAsync(nil)
	})

	app.btnBind.On().BnClicked(func() {
		app.bgTask.SetOnUpdate(nil)
		app.onBindCert()
		app.bgTask.SetOnUpdate(func() {
			app.mainWnd.UiThread(func() {
				app.updateTaskStatus()
			})
		})
	})

	app.btnInstall.On().BnClicked(func() {
		app.bgTask.SetOnUpdate(nil)
		ShowInstallDialog(app.mainWnd, func() {
			app.doLoadDataAsync(nil)
		})
		app.bgTask.SetOnUpdate(func() {
			app.mainWnd.UiThread(func() {
				app.updateTaskStatus()
			})
		})
	})

	app.btnAPI.On().BnClicked(func() {
		app.bgTask.SetOnUpdate(nil)
		ShowAPIDialog(app.mainWnd, func() {
			app.doLoadDataAsync(nil)
		})
		app.bgTask.SetOnUpdate(func() {
			app.mainWnd.UiThread(func() {
				app.updateTaskStatus()
			})
		})
	})

	// 后台任务按钮事件
	app.btnAutoCheck.On().BnClicked(func() {
		app.toggleAutoCheck()
	})

	app.btnCheckNow.On().BnClicked(func() {
		app.runCheckNow()
	})

	app.btnConfig.On().BnClicked(func() {
		app.bgTask.SetOnUpdate(nil)
		ShowCertManagerDialog(app.mainWnd, func() {
			go func() {
				app.mainWnd.UiThread(func() {
					app.appendTaskLog("配置已更新")
				})
			}()
		})
		app.bgTask.SetOnUpdate(func() {
			app.mainWnd.UiThread(func() {
				app.updateTaskStatus()
			})
		})
	})

	// 设置后台任务更新回调
	app.bgTask.SetOnUpdate(func() {
		app.mainWnd.UiThread(func() {
			app.updateTaskStatus()
		})
	})

	// 窗口关闭时清理资源
	app.mainWnd.On().WmDestroy(func() {
		// 取消所有后台 goroutine
		if app.cancelCtx != nil {
			app.cancelCtx()
		}
		// 停止后台任务
		if app.bgTask != nil {
			app.bgTask.Stop()
		}
		// 关闭调试模式
		CloseDebugMode()
	})

	app.mainWnd.RunAsMain()
}

// toggleAutoCheck 切换自动部署状态（使用 Windows 任务计划）
func (app *AppWindow) toggleAutoCheck() {
	app.btnAutoCheck.Hwnd().EnableWindow(false)

	go func() {
		// 检查 context 是否已取消
		select {
		case <-app.ctx.Done():
			return
		default:
		}

		cfg, _ := config.Load()
		taskName := util.DefaultTaskName
		if cfg != nil && cfg.TaskName != "" {
			taskName = cfg.TaskName
		}

		taskExists := util.IsTaskExists(taskName)

		if taskExists {
			// 停止：删除任务计划
			err := util.DeleteTask(taskName)

			app.mainWnd.UiThread(func() {
				app.btnAutoCheck.Hwnd().EnableWindow(true)

				if err != nil {
					app.appendTaskLog(fmt.Sprintf("删除任务失败: %v", err))
					app.appendTaskLog("请确保以管理员权限运行程序")
					return
				}

				if cfg != nil {
					cfg.AutoCheckEnabled = false
					if err := cfg.Save(); err != nil {
						app.appendTaskLog(fmt.Sprintf("警告: 保存配置失败: %v", err))
					}
				}

				app.btnAutoCheck.SetText("启动自动部署")
				app.statusIndicator.SetState(IndicatorStopped)
				app.lblTaskStatus.Hwnd().SetWindowText("状态: 已停止")
				app.appendTaskLog("自动部署已停止，任务计划已删除")
			})
		} else {
			// 启动：创建任务计划
			if cfg == nil || len(cfg.Certificates) == 0 {
				app.mainWnd.UiThread(func() {
					app.btnAutoCheck.Hwnd().EnableWindow(true)
					app.appendTaskLog("请先配置证书后再启动自动部署")
				})
				return
			}

			interval := cfg.CheckInterval
			if interval <= 0 {
				interval = 6
			}

			err := util.CreateTask(taskName, interval)

			app.mainWnd.UiThread(func() {
				app.btnAutoCheck.Hwnd().EnableWindow(true)

				if err != nil {
					app.appendTaskLog(fmt.Sprintf("创建任务失败: %v", err))
					app.appendTaskLog("请确保以管理员权限运行程序")
					return
				}

				cfg.AutoCheckEnabled = true
				if err := cfg.Save(); err != nil {
					app.appendTaskLog(fmt.Sprintf("警告: 保存配置失败: %v", err))
				}

				app.btnAutoCheck.SetText("停止自动部署")
				app.statusIndicator.SetState(IndicatorRunning)
				app.lblTaskStatus.Hwnd().SetWindowText(fmt.Sprintf("状态: 任务计划运行中 (每 %d 小时)", interval))
				app.appendTaskLog(fmt.Sprintf("自动部署已启动，每 %d 小时检查一次", interval))
				app.appendTaskLog("任务计划已创建: " + taskName)
			})
		}
	}()
}

// runCheckNow 立即执行检测
func (app *AppWindow) runCheckNow() {
	app.btnCheckNow.Hwnd().EnableWindow(false)

	go func() {
		// 检查 context 是否已取消
		select {
		case <-app.ctx.Done():
			return
		default:
		}

		cfg, _ := config.Load()

		if cfg == nil || len(cfg.Certificates) == 0 {
			app.mainWnd.UiThread(func() {
				app.btnCheckNow.Hwnd().EnableWindow(true)
				app.appendTaskLog("请先配置证书后再执行检测")
			})
			return
		}

		app.mainWnd.UiThread(func() {
			app.appendTaskLog("开始手动检测...")
		})

		app.bgTask.RunOnceSync()

		app.doLoadDataAsync(func() {
			app.mainWnd.UiThread(func() {
				app.btnCheckNow.Hwnd().EnableWindow(true)
			})
		})
	}()
}

// updateTaskStatus 更新任务状态显示
func (app *AppWindow) updateTaskStatus() {
	status, message := app.bgTask.GetStatus()

	statusText := "状态: "
	switch status {
	case TaskStatusIdle:
		statusText += "空闲"
	case TaskStatusRunning:
		statusText += "运行中"
	case TaskStatusSuccess:
		statusText += "成功"
	case TaskStatusFailed:
		statusText += "失败"
	}

	if message != "" {
		statusText += " - " + message
	}

	app.lblTaskStatus.Hwnd().SetWindowText(statusText)

	if status == TaskStatusRunning {
		app.appendTaskLog(message)
	} else if status == TaskStatusSuccess || status == TaskStatusFailed {
		app.appendTaskLog(message)
		results := app.bgTask.GetResults()
		for _, r := range results {
			if r.Success {
				app.appendTaskLog(fmt.Sprintf("  ✓ %s: %s", r.Domain, r.Message))
			} else {
				app.appendTaskLog(fmt.Sprintf("  ✗ %s: %s", r.Domain, r.Message))
			}
		}
	}
}

// appendTaskLog 追加任务日志
func (app *AppWindow) appendTaskLog(text string) {
	const maxLogLines = 100

	timestamp := time.Now().Format("15:04:05")
	logLine := fmt.Sprintf("[%s] %s", timestamp, text)

	app.logLines = append(app.logLines, logLine)
	if len(app.logLines) > maxLogLines {
		app.logLines = app.logLines[len(app.logLines)-maxLogLines:]
		app.txtTaskLog.SetText(strings.Join(app.logLines, "\r\n") + "\r\n")
	} else {
		textLen, _ := app.txtTaskLog.Hwnd().SendMessage(co.WM_GETTEXTLENGTH, 0, 0)
		app.txtTaskLog.Hwnd().SendMessage(0x00B1, win.WPARAM(textLen), win.LPARAM(textLen)) // EM_SETSEL
		newText := logLine + "\r\n"
		ptr, _ := syscall.UTF16PtrFromString(newText)
		app.txtTaskLog.Hwnd().SendMessage(0x00C2, 0, win.LPARAM(unsafe.Pointer(ptr))) // EM_REPLACESEL
	}

	app.txtTaskLog.Hwnd().SendMessage(0x00B6, 0, 0xFFFF) // EM_LINESCROLL
}

// doLoadDataAsync 异步加载数据
func (app *AppWindow) doLoadDataAsync(onComplete func()) {
	app.loadingMu.Lock()
	if app.loading {
		app.loadingMu.Unlock()
		return
	}
	app.loading = true
	app.loadingMu.Unlock()

	go func() {
		// 检查 context 是否已取消
		select {
		case <-app.ctx.Done():
			app.loadingMu.Lock()
			app.loading = false
			app.loadingMu.Unlock()
			return
		default:
		}

		var loadErr error
		var sites []iis.SiteInfo
		var certs []cert.CertInfo
		var sslBindings []iis.SSLBinding

		if err := iis.CheckIISInstalled(); err != nil {
			loadErr = err
		} else {
			sites, loadErr = iis.ScanSites()
			if loadErr == nil {
				var certErr, sslErr error
				certs, certErr = cert.ListCertificates()
				if certErr != nil {
					log.Printf("警告: 加载证书列表失败: %v", certErr)
				}
				sslBindings, sslErr = iis.ListSSLBindings()
				if sslErr != nil {
					log.Printf("警告: 加载 SSL 绑定失败: %v", sslErr)
				}
			}
		}

		var siteItems []SiteItem
		if loadErr == nil {
			siteItems = make([]SiteItem, 0, len(sites))
			for _, site := range sites {
				certName, expiry := getCertInfoForSite(site, sslBindings, certs)
				item := SiteItem{
					Name:     site.Name,
					State:    site.State,
					Bindings: formatBindings(site.Bindings),
					CertName: certName,
					Expiry:   expiry,
					SiteInfo: site,
				}
				siteItems = append(siteItems, item)
			}
		}

		app.mainWnd.UiThread(func() {
			if loadErr != nil {
				app.setStatus("加载失败: " + loadErr.Error())
			} else {
				app.dataMu.Lock()
				app.certs = certs
				app.sites = siteItems
				app.dataMu.Unlock()

				app.siteList.Items.DeleteAll()
				for _, item := range siteItems {
					app.siteList.Items.Add(
						item.Name,
						item.State,
						item.Bindings,
						item.CertName,
						item.Expiry,
					)
				}
				app.setStatus(fmt.Sprintf("已加载 %d 个站点, %d 个证书", len(sites), len(certs)))
			}

			app.loadingMu.Lock()
			app.loading = false
			app.loadingMu.Unlock()
			app.setButtonsEnabled(true)

			if onComplete != nil {
				onComplete()
			}
		})
	}()
}

// setButtonsEnabled 设置按钮启用状态
func (app *AppWindow) setButtonsEnabled(enabled bool) {
	if app.btnRefresh != nil {
		app.btnRefresh.Hwnd().EnableWindow(enabled)
	}
	if app.btnBind != nil {
		app.btnBind.Hwnd().EnableWindow(enabled)
	}
	if app.btnInstall != nil {
		app.btnInstall.Hwnd().EnableWindow(enabled)
	}
	if app.btnAPI != nil {
		app.btnAPI.Hwnd().EnableWindow(enabled)
	}
}

// formatBindings 格式化绑定信息
func formatBindings(bindings []iis.BindingInfo) string {
	parts := make([]string, 0, len(bindings))
	for _, b := range bindings {
		if b.Host != "" {
			parts = append(parts, fmt.Sprintf("%s://%s:%d", b.Protocol, b.Host, b.Port))
		} else {
			parts = append(parts, fmt.Sprintf("%s://*:%d", b.Protocol, b.Port))
		}
	}
	return strings.Join(parts, ", ")
}

// getCertInfoForSite 获取站点的证书信息
func getCertInfoForSite(site iis.SiteInfo, sslBindings []iis.SSLBinding, certs []cert.CertInfo) (string, string) {
	for _, b := range site.Bindings {
		if !b.HasSSL {
			continue
		}

		for _, ssl := range sslBindings {
			hostPort := fmt.Sprintf("%s:%d", b.Host, b.Port)
			if strings.EqualFold(ssl.HostnamePort, hostPort) ||
				strings.HasSuffix(ssl.HostnamePort, fmt.Sprintf(":%d", b.Port)) {
				thumbprint := strings.ToUpper(strings.ReplaceAll(ssl.CertHash, " ", ""))
				for _, c := range certs {
					if c.Thumbprint == thumbprint {
						name := cert.GetCertDisplayName(&c)
						expiry := c.NotAfter.Format("2006-01-02")
						return name, expiry
					}
				}
				if len(ssl.CertHash) >= 16 {
					return ssl.CertHash[:16] + "...", ""
				}
				return ssl.CertHash, ""
			}
		}
	}
	return "", ""
}

// onBindCert 绑定证书
func (app *AppWindow) onBindCert() {
	selected := app.siteList.Items.Selected()
	if len(selected) == 0 {
		ui.MsgOk(app.mainWnd, "提示", "请先选择一个站点", "请在列表中选择一个站点后再进行绑定操作。")
		return
	}

	idx := selected[0].Index()

	// 直接访问数据（UI 线程内安全）
	app.dataMu.RLock()
	if idx < 0 || idx >= len(app.sites) {
		app.dataMu.RUnlock()
		return
	}
	site := app.sites[idx].SiteInfo
	certs := make([]cert.CertInfo, len(app.certs))
	copy(certs, app.certs)
	app.dataMu.RUnlock()

	ShowBindDialog(app.mainWnd, &site, certs, func() {
		app.doLoadDataAsync(nil)
	})
}

// setStatus 设置状态栏
func (app *AppWindow) setStatus(text string) {
	if app.statusBar != nil && app.statusBar.Parts.Count() > 0 {
		app.statusBar.Parts.Get(0).SetText(text)
	}
}
