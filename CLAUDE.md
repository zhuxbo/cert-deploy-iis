# sslctlw

IIS SSL 证书部署工具，Go + windigo，单文件 exe。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。

## 核心指令

- **测试发现 bug 必须修复代码** - 测试的目的是发现 bug 并修复，绝不修改测试去迎合错误的代码

## 项目结构

```
ui/           # windigo GUI (mainwindow.go, dialogs.go, background.go)
iis/          # appcmd + netsh 封装
cert/         # 证书存储/安装/转换
api/          # Deploy API 客户端
config/       # JSON 配置
deploy/       # 自动部署逻辑
integration/  # 端到端集成测试
```

## 构建

```bash
go build -ldflags="-s -w -H windowsgui" -o sslctlw.exe
```

## 测试

```bash
go test ./...                                    # 单元测试
go test -tags=integration ./integration/...      # 集成测试
```

## Skills 参考

| 主题 | 文档 |
|------|------|
| UI 开发 | `skills/windigo-ui/` |
| IIS 操作 | `skills/iis-ops/` |
| API 接口 | `skills/api/` |
| 构建发布 | `skills/build-release/` |

## Git 规范

- **不要自动提交**: 修改完成后等待用户确认，不要主动 commit

## 知识管理

开发中发现重要信息时，更新 `skills/` 目录：

```
skills/api/SKILL.md          # Deploy API 接口、证书选择逻辑、部署模式
skills/windigo-ui/SKILL.md   # windigo GUI、防 UI 卡死、动态布局
skills/iis-ops/SKILL.md      # IIS/netsh 操作、SSL 绑定类型
skills/go-dev/SKILL.md       # Go 开发规范
skills/build-release/SKILL.md # 构建发布、版本注入
```
