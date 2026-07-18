---
name: sslctlw
description: 路由 sslctlw 的 Go、IIS、Deploy API、windigo、构建发布和完成检查工作流。
---

# sslctlw Skill 路由

本文件只负责路由。先按任务选择最小叶子资源；跨平台公共语义始终以 `deploy-spec.md` 为准。

| 触发场景 | 读取资源 |
| --- | --- |
| 正式发布、测试版发布、发布恢复、版本验收 | `skills/remote-release.md` |
| 构建、版本注入、产物、Authenticode 签名 | `skills/build-release.md` |
| 完成检查、提交前验证、finish-check | `skills/finish-check.md` |
| Deploy API、续签状态、回调、证书选择 | `skills/api.md` |
| 模块边界、数据流、配置结构 | `skills/architecture.md` |
| Go 开发、DPAPI、共享 setup、通用陷阱 | `skills/go-dev.md` |
| IIS、appcmd、netsh、证书绑定与恢复 | `skills/iis-ops.md` |
| windigo GUI、线程、控件与布局 | `skills/windigo-ui.md` |

需要多个领域时可组合读取，但不得把叶子资源复制进工具指令或 `AGENTS.md`。
