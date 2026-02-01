# cert-deploy-iis

IIS SSL 证书部署工具，Go + windigo，单文件 exe。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。

## 核心指令

- **不要自动提交** - 完成修改后等待用户确认"提交"再执行 git commit/push
- **测试发现 bug 必须修复代码** - 测试的目的是发现 bug 并修复，绝不修改测试去迎合错误的代码

## 构建

```bash
go build -ldflags="-s -w -H windowsgui" -o certdeploy.exe
```

## 项目结构

```
ui/           # windigo GUI (mainwindow.go, dialogs.go, background.go)
iis/          # appcmd + netsh 封装
cert/         # 证书存储/安装/转换
api/          # Deploy API 客户端
config/       # JSON 配置
deploy/       # 自动部署逻辑
```

## 关键模式

- **防 UI 卡死**: 耗时操作用 `go func()` + `UiThread()` 回调
- **控件动态布局**: 在 `WmSize` 中用 `SetWindowPos` 调整位置
- **后台任务**: `BackgroundTask` 管理定时检测
- **证书选择**: 按域名查询列表，选 active + 最新过期的

## Git 规范

- **不要自动提交**: 修改完成后等待用户确认，不要主动 commit

## 知识管理

开发中发现重要信息时，更新 `skills/` 目录：

```
skills/api/SKILL.md          # Deploy API 接口
skills/windigo-ui/SKILL.md   # windigo GUI 用法
skills/iis-ops/SKILL.md      # IIS/netsh 操作
skills/go-dev/SKILL.md       # Go 开发规范
skills/build-release/SKILL.md # 构建发布
```
