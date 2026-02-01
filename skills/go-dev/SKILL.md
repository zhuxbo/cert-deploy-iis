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

### 单引号字符串转义

PowerShell 单引号字符串中，只有 `'` 需要转义（`''` 表示一个单引号）：

```go
// 正确：$ 和反引号在单引号中是字面字符
func escapePassword(password string) string {
    return strings.ReplaceAll(password, "'", "''")
}

// 错误：多余转义会改变真实密码
password = strings.ReplaceAll(password, "$", "`$")  // 不需要
```

## 常见陷阱

### Token 加密存储

配置中 Token 可能是加密的，必须用 `GetToken()` 获取解密值：

```go
// 正确
token := cfg.GetToken()
client := api.NewClient(cfg.APIBaseURL, token)

// 错误：cfg.Token 可能是加密后的值
client := api.NewClient(cfg.APIBaseURL, cfg.Token)
```

### 路径安全校验

Windows 路径校验需注意：
1. 大小写不敏感（用 `strings.EqualFold`）
2. 前缀匹配不安全（`.well-known` 会匹配 `.well-known-evil`）

```go
// 正确：按路径段校验
relPath, _ := filepath.Rel(basePath, fullPath)
parts := strings.Split(relPath, string(os.PathSeparator))
if !strings.EqualFold(parts[0], ".well-known") {
    return fmt.Errorf("路径不在 .well-known 下")
}

// 错误：前缀匹配可被绕过
if !strings.HasPrefix(fullPath, expectedPrefix) { ... }
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
