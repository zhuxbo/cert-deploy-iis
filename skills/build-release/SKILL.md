# 构建发布

## 构建命令

```bash
# 开发
go build -o certdeploy.exe

# 发布（隐藏控制台 + 优化体积）
go build -ldflags="-s -w -H windowsgui" -o certdeploy.exe
```

| 参数 | 作用 |
|------|------|
| `-s` | 去除符号表 |
| `-w` | 去除调试信息 |
| `-H windowsgui` | 隐藏控制台 |

## Manifest 嵌入

```bash
# 安装工具
go install github.com/akavel/rsrc@latest

# 生成资源
rsrc -manifest main.manifest -o rsrc.syso

# 构建（自动包含 rsrc.syso）
go build
```

manifest 提供：管理员权限、高 DPI 支持、现代控件样式

## 版本注入

```go
var Version = "dev"
```

```bash
go build -ldflags="-X main.Version=1.0.0"
```

## 发布清单

1. `go build -ldflags="-s -w -H windowsgui"`
2. 验证管理员权限提示
3. 测试 IIS 扫描/证书绑定
4. `git tag v1.0.0 && git push --tags`
