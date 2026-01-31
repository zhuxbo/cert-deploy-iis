# Windigo UI 规范

## 依赖

```go
import (
    "github.com/rodrigocfd/windigo/co"
    "github.com/rodrigocfd/windigo/ui"
    "github.com/rodrigocfd/windigo/win"
)
```

## 主窗口

```go
type AppWindow struct {
    mainWnd   *ui.Main
    siteList  *ui.ListView
    statusBar *ui.StatusBar
    btnXxx    *ui.Button
}

func RunApp() {
    runtime.LockOSThread()  // 必须锁定 OS 线程

    app := &AppWindow{}

    app.mainWnd = ui.NewMain(
        ui.OptsMain().
            Title("窗口标题").
            Size(ui.Dpi(900, 700)).
            Style(co.WS_OVERLAPPEDWINDOW),
    )

    // 创建控件...

    app.mainWnd.RunAsMain()
}
```

## 控件创建

### 按钮

```go
btn := ui.NewButton(parent,
    ui.OptsButton().
        Text("按钮文字").
        Position(ui.Dpi(10, 10)).
        Width(ui.DpiX(80)).
        Height(ui.DpiY(28)),
)

btn.On().BnClicked(func() {
    // 点击处理
})
```

### 列表视图

```go
list := ui.NewListView(parent,
    ui.OptsListView().
        Position(ui.Dpi(10, 50)).
        Size(ui.Dpi(860, 400)).
        CtrlExStyle(co.LVS_EX_FULLROWSELECT|co.LVS_EX_GRIDLINES).
        CtrlStyle(co.LVS_REPORT|co.LVS_SINGLESEL),
)

// 添加列（在 WmCreate 中）
list.Cols.Add("列名", ui.DpiX(150))

// 添加行
list.Items.Add("列1值", "列2值", "列3值")

// 删除所有
list.Items.DeleteAll()

// 获取选中
selected := list.Items.Selected()
if len(selected) > 0 {
    idx := selected[0].Index()
}
```

### 下拉框

```go
cmb := ui.NewComboBox(parent,
    ui.OptsComboBox().
        Position(ui.Dpi(100, 20)).
        Width(ui.DpiX(200)).
        Texts("选项1", "选项2").
        CtrlStyle(co.CBS_DROPDOWNLIST),
)

cmb.On().CbnSelChange(func() {
    idx := cmb.Items.Selected()
})
```

### 编辑框

```go
// 单行
txt := ui.NewEdit(parent,
    ui.OptsEdit().
        Position(ui.Dpi(100, 20)).
        Width(ui.DpiX(200)),
)

// 多行只读
txtLog := ui.NewEdit(parent,
    ui.OptsEdit().
        Position(ui.Dpi(10, 100)).
        Width(ui.DpiX(400)).
        Height(ui.DpiY(200)).
        CtrlStyle(co.ES_MULTILINE|co.ES_READONLY|co.ES_AUTOVSCROLL).
        WndStyle(co.WS_CHILD|co.WS_VISIBLE|co.WS_BORDER|co.WS_VSCROLL),
)

// 密码
txtPwd := ui.NewEdit(parent,
    ui.OptsEdit().
        CtrlStyle(co.ES_PASSWORD),
)

// 获取/设置文本
text := txt.Text()
txt.SetText("内容")
```

### 静态标签

```go
lbl := ui.NewStatic(parent,
    ui.OptsStatic().
        Text("标签文字").
        Position(ui.Dpi(20, 20)),
)

// 更新文字（无 SetText 方法）
lbl.Hwnd().SetWindowText("新文字")
```

## 模态对话框

**重要**: 必须添加 `co.WS_VISIBLE` 样式，否则对话框可能不显示。

```go
func ShowDialog(owner ui.Parent) {
    dlg := ui.NewModal(owner,
        ui.OptsModal().
            Title("对话框标题").
            Size(ui.Dpi(500, 400)).
            Style(co.WS_CAPTION|co.WS_SYSMENU|co.WS_POPUP|co.WS_VISIBLE),  // 必须有 WS_VISIBLE
    )

    // 创建控件...

    dlg.On().WmCreate(func(_ ui.WmCreate) int {
        // 初始化
        return 0
    })

    // 关闭对话框
    dlg.Hwnd().SendMessage(co.WM_CLOSE, 0, 0)

    dlg.ShowModal()
}
```

### 后台任务回调冲突

如果主窗口有后台任务的 `onUpdate` 回调，在显示模态对话框前必须禁用，否则会导致对话框卡死：

```go
btn.On().BnClicked(func() {
    // 1. 禁用后台任务回调
    app.bgTask.SetOnUpdate(nil)

    // 2. 显示模态对话框
    ShowDialog(app.mainWnd, func() {
        app.doLoadDataAsync(nil)
    })

    // 3. 恢复回调
    app.bgTask.SetOnUpdate(func() {
        app.mainWnd.UiThread(func() {
            app.updateTaskStatus()
        })
    })
})
```

## 动态布局

在 `WmSize` 中调整控件位置：

```go
app.mainWnd.On().WmSize(func(p ui.WmSize) {
    if p.Request() == co.SIZE_REQ_MINIMIZED {
        return
    }
    cx, cy := int(p.ClientAreaSize().Cx), int(p.ClientAreaSize().Cy)

    // 调整控件
    app.siteList.Hwnd().SetWindowPos(0, 10, 50, cx-20, cy-200, co.SWP_NOZORDER)
    app.btnXxx.Hwnd().SetWindowPos(0, 10, cy-180, 100, 28, co.SWP_NOZORDER)
})
```

## 防 UI 卡死（关键）

**原则**: `UiThread` 回调中**只能**更新 UI，**禁止**执行任何耗时操作。

### 耗时操作类型

- 文件读写 (`os.ReadFile`, `config.Load()`)
- 网络请求 (`http.Get`, API 调用)
- PowerShell/命令行 (`exec.Command`)
- 证书操作 (`cert.ListCertificates()`, `cert.GetCertByThumbprint()`)
- IIS 操作 (`iis.ScanSites()`, `iis.ListSSLBindings()`)

### 正确模式

```go
btn.On().BnClicked(func() {
    btn.Hwnd().EnableWindow(false)  // 1. 先禁用按钮

    go func() {
        // 2. goroutine 中执行所有耗时操作
        sites, _ := iis.ScanSites()
        certs, _ := cert.ListCertificates()

        // 3. 准备好所有数据
        items := prepareListItems(sites, certs)

        // 4. UiThread 只更新 UI（不调用任何函数）
        dlg.UiThread(func() {
            btn.Hwnd().EnableWindow(true)
            for _, item := range items {
                list.Items.Add(item.Name, item.Value)
            }
        })
    }()
})
```

### 错误示例

```go
// ❌ 错误：在 UiThread 中调用耗时函数
dlg.UiThread(func() {
    for _, site := range sites {
        certInfo := cert.GetCertByThumbprint(hash)  // 调用 PowerShell！卡死！
        list.Items.Add(site.Name, certInfo.Name)
    }
})

// ✓ 正确：先准备数据，UiThread 只更新 UI
go func() {
    items := make([]Item, len(sites))
    for i, site := range sites {
        certInfo, _ := cert.GetCertByThumbprint(hash)  // goroutine 中执行
        items[i] = Item{Name: site.Name, CertName: certInfo.Name}
    }

    dlg.UiThread(func() {
        for _, item := range items {
            list.Items.Add(item.Name, item.CertName)  // 只更新 UI
        }
    })
}()
```

## 消息框

```go
ui.MsgOk(parent, "标题", "主文本", "详细内容")
ui.MsgError(parent, "错误", "主文本", "详细内容")
```

## 控件启用/禁用

```go
btn.Hwnd().EnableWindow(false)  // 禁用
btn.Hwnd().EnableWindow(true)   // 启用
```

## 常见问题

### UI 卡死

**原因 1**: 在 `UiThread` 回调中调用了耗时函数（PowerShell、文件 I/O、网络请求）。

**排查**: 检查 `UiThread(func() { ... })` 内部是否调用了以下函数：
- `cert.ListCertificates()` / `cert.GetCertByThumbprint()`
- `iis.ScanSites()` / `iis.ListSSLBindings()`
- `config.Load()` / `config.Save()`
- `api.Client.GetCertByDomain()`
- 任何 `exec.Command()` 调用

**解决**: 将这些调用移到 `go func() { ... }` 中，在 `UiThread` 之前执行。

### 模态对话框不显示/卡死

**原因 1**: 缺少 `WS_VISIBLE` 样式。
**解决**: 在 `Style()` 中添加 `co.WS_VISIBLE`。

**原因 2**: 后台任务的 `onUpdate` 回调与模态对话框冲突。
**解决**: 显示对话框前调用 `bgTask.SetOnUpdate(nil)`，关闭后恢复。

### 调试模式

运行程序时添加 `-debug` 参数启用调试模式，会输出详细日志到 `debug.log`：

```
certdeploy.exe -debug
```

### Static 没有 SetText

用 `Hwnd().SetWindowText()` 替代。

### 控件位置不随窗口变化

在 `WmSize` 事件中用 `SetWindowPos` 手动调整。

### 隐藏控制台

编译时加 `-ldflags="-H windowsgui"`
