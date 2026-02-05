# Go 开发规范

## 项目结构

```
sslctlw/
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

## 注意事项

### PowerShell Write-Error vs throw

PowerShell 的 `Write-Error` 不会设置退出码（exit code），Go 的 `exec.Command` 不会检测到错误。在需要让 Go 检测到失败的场景中，使用 `throw` 而非 `Write-Error`：

```powershell
# ❌ Write-Error：Go 侧 err == nil
Write-Error "证书不存在"

# ✓ throw：Go 侧 err != nil
throw "证书不存在"
```

### 多格式日期解析

Windows PowerShell 输出的日期格式因系统语言和区域设置不同而变化。不要硬编码单一格式，使用多格式尝试解析：

```go
func parseTimeMultiFormat(value string) time.Time {
    formats := []string{
        "2006-01-02 15:04:05", "2006/01/02 15:04:05",
        "01/02/2006 15:04:05", "02/01/2006 15:04:05",
        "1/2/2006 3:04:05 PM", // 美国格式
        "2006-01-02T15:04:05Z07:00", // ISO 8601
    }
    for _, f := range formats {
        if t, err := time.Parse(f, value); err == nil {
            return t
        }
    }
    return time.Time{}
}
```

### fmt.Printf 在 `-H windowsgui` 模式下不可见

使用 `-ldflags="-H windowsgui"` 编译后，`fmt.Printf`/`fmt.Println` 的输出不会显示在任何地方。使用 `log.Printf` 替代（输出到 stderr，可被日志系统捕获）。

### UTF-8 安全字符串截断

直接用 `s[:N]` 截断可能切断多字节 UTF-8 字符，导致无效字符串。使用 `util.TruncateString`：

```go
// ❌ 可能切断中文字符
output[:100]

// ✓ 安全截断
util.TruncateString(output, 100)
```

### io.LimitReader 限制响应体大小

HTTP 响应体应使用 `io.LimitReader` 限制大小，防止恶意或异常的超大响应耗尽内存：

```go
const maxResponseSize = 10 << 20 // 10MB
body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
```

### 临时文件清理责任

`PEMToPFX` 创建的临时 PFX 文件必须由调用方负责清理。使用 `defer util.CleanupTempFile(pfxPath)` 或 `defer os.Remove(pfxPath)` 确保清理：

```go
pfxPath, err := cert.PEMToPFX(certPEM, keyPEM, chainPEM, password)
if err != nil { return err }
defer util.CleanupTempFile(pfxPath)

result, err := cert.InstallPFX(pfxPath, password)
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
