# Go 开发规范

## 项目结构

```
cert-deploy-iis/
├── main.go              # 入口
├── go.mod
├── main.manifest        # 管理员权限
├── rsrc.syso            # 嵌入资源
├── config.json          # 运行时配置
├── ui/
│   ├── mainwindow.go    # 主窗口
│   ├── dialogs.go       # 对话框
│   └── background.go    # 后台任务管理
├── iis/
│   ├── appcmd.go        # appcmd 封装
│   ├── netsh.go         # 证书绑定
│   └── types.go         # 数据结构
├── cert/
│   ├── store.go         # 证书存储查询
│   ├── installer.go     # PFX 安装
│   └── converter.go     # PEM 转 PFX
├── api/
│   └── client.go        # 远程 API
├── config/
│   └── config.go        # 配置管理
├── deploy/
│   └── auto.go          # 自动部署
└── util/
    └── exec.go          # 命令执行
```

## 技术栈

| 项 | 选择 |
|----|------|
| GUI | windigo (Windows 原生) |
| IIS | appcmd.exe + XML |
| 证书绑定 | netsh http |
| 证书操作 | PowerShell |

## 错误处理

```go
func DoSomething() error {
    output, err := exec.Command(cmd).Output()
    if err != nil {
        return fmt.Errorf("执行失败: %w", err)
    }
    return nil
}
```

## 外部命令

```go
cmd := exec.Command("appcmd.exe", "list", "site", "/xml")
output, err := cmd.Output()

// 需要 stderr
var stderr bytes.Buffer
cmd.Stderr = &stderr
err := cmd.Run()
```

## XML 解析

```go
type appcmdSites struct {
    XMLName xml.Name     `xml:"appcmd"`
    Sites   []appcmdSite `xml:"SITE"`
}

type appcmdSite struct {
    Name  string `xml:"SITE.NAME,attr"`
    State string `xml:"state,attr"`
}

var result appcmdSites
xml.Unmarshal(output, &result)
```

## PowerShell 调用

```go
script := `Get-ChildItem Cert:\LocalMachine\My | ForEach-Object { ... }`
cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
```

## 并发模式

后台任务使用 goroutine + channel：

```go
type BackgroundTask struct {
    stopChan chan struct{}
    running  bool
}

func (t *BackgroundTask) Start() {
    t.stopChan = make(chan struct{})
    go t.runLoop()
}

func (t *BackgroundTask) Stop() {
    close(t.stopChan)
}

func (t *BackgroundTask) runLoop() {
    ticker := time.NewTicker(1 * time.Hour)
    for {
        select {
        case <-t.stopChan:
            return
        case <-ticker.C:
            t.doWork()
        }
    }
}
```
