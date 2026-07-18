# sslctlw

IIS SSL 证书部署工具，Go + windigo，单文件 exe（Console 子系统）。

支持 CLI 和 GUI 两种模式：无参数运行打开 GUI，有子命令进入 CLI。

> **维护指引**：保持本文件精简，仅包含项目概览和快速参考。详细规范写入 `skills/` 目录。
>
> **统一规范**：跨项目共通行为规范见 `deploy-spec.md`

## 核心指令

- **测试发现 bug 必须修复代码** - 测试的目的是发现 bug 并修复，绝不修改测试去迎合错误的代码
- **版本号** - 开发构建默认版本为 `dev`，发布构建通过 `-ldflags` 注入版本号

## 命令行

```
sslctlw <command> [options]

命令: setup / scan / deploy / status / diagnose / upgrade / uninstall / version / help
无参数: GUI 模式（隐藏控制台窗口）
--debug: 仅 GUI 模式，写 debug.log
```

## 项目结构

```
main.go       # 入口：子命令路由 + 无参数开 GUI
diagnose/     # 诊断信息收集
setup/        # 一键部署核心逻辑（CLI/GUI 共用）
ui/           # windigo GUI (mainwindow.go, dialogs.go, background.go)
iis/          # appcmd + netsh 封装
cert/         # 证书存储/安装/转换/CSR/证书链检查与修复
api/          # Deploy API 客户端
config/       # JSON 配置（DPAPI 加密，API 配置在证书级）
deploy/       # 自动部署逻辑（per-cert client）
upgrade/      # 在线升级（签名验证）
util/         # 工具函数（含 console_windows.go）
build/        # 构建/发布/安装脚本
integration/  # 端到端集成测试
```

## 关键设计

- **证书级 API + per-cert client** - 每个 CertConfig 独立 `api` 字段（URL + DPAPI 加密 Token），无全局 API；deploy 层为每张证书创建独立 Client。详见 `skills/api/`
- **自动部署行为** - CLI `deploy --all` 证书间分散延迟（总上限 600s），GUI 不延迟；部署成功后从证书 PEM 提取 CN+SAN 回填配置。详见 `skills/api/`
- **Local 模式健壮性** - CSR 重试上限 10 次（spec §3.2），processing 按 spec §3.5 等待。详见 `skills/api/`
- **Console 子系统** - 构建为 Console 应用（非 `-H windowsgui`），GUI 模式运行时 `util.HideConsole()` 隐藏控制台。详见 `skills/windigo-ui/`
- **setup 共享** - `setup/` 的 `Run()` 被 CLI/GUI 共用，进度经 `ProgressFunc` 回调（GUI 无控制台，禁止直接 `fmt.Print`）。详见 `skills/go-dev/`

## 构建与发布

```bash
./build/release.sh 1.0.0             # 一键：构建 → 签名 → 发布
./build/build.sh 1.0.0               # 仅构建
./build/sign.sh                      # 仅签名 dist/sslctlw.exe
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

## 自定义命令

- `/finish-check` - 收尾检查：编译、vet、测试、GUI/IIS/API 专项检查、diff 审查、风险评估

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
