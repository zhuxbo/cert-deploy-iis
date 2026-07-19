# sslctlw 项目智能体规则

## 项目与平台边界

- sslctlw 是面向 Windows amd64 / IIS 的 Go 证书部署工具，同一 Console 子系统 EXE 同时提供 CLI 与 windigo GUI。
- 跨仓公共行为以 `deploy-spec.md` 为准；本仓领域知识和工作流由 `skills/SKILL.md` 路由到对应叶子资源。任务命中某领域时，必须先读根路由及选中的叶子资源。
- Windows 运行期行为以 GitHub Actions 的 `windows-latest` 结果为准；非 Windows 本机的 `GOOS=windows GOARCH=amd64 go test -c` 仅证明测试可编译。
- 不得削弱 Authenticode、DPAPI、数据目录 ACL、证书私钥配对或 IIS 绑定恢复校验来迁就测试。
- 未经明确发布指令，不创建或移动 tag、GitHub Release，不上传发布节点；正式发布必须严格执行 `skills/remote-release.md`。
- Codex 原生入口只保留 `.agents/skills/remote-release/SKILL.md` 与 `.agents/skills/finish-check/SKILL.md`；Claude 对应入口位于 `.claude/commands/`。两套入口都必须是只调用权威叶子的薄层，不复制流程正文。

## 核心命令

```bash
GOOS=windows GOARCH=amd64 go build -o /dev/null .
GOOS=windows GOARCH=amd64 go vet ./...
go test ./...
bash build/check-governance.sh
```

完整收尾检查见 `skills/finish-check.md`；构建、签名与产物契约见 `skills/build-release.md`。

## 更新原则

- 只记录长期有效、项目级、会影响智能体行为的规则；临时决策、调试记录和单一模块实现细节不得写入本文件。
- 新内容先判断职责：跨仓公共行为写入 `deploy-spec.md`，领域知识和工作流写入对应叶子资源，本文件只保留入口与不可违反的项目约束，不复制正文。
- 只直接维护 `AGENTS.md`；`CLAUDE.md` 始终保持固定薄入口，不在其中追加项目规则。
- 新增、删除或重命名领域 skill 时，同步更新 `skills/SKILL.md` 及受影响的引用入口；两个工具原生薄入口由治理检查固定。
- 修改后删除失效或重复内容，并检查 `CLAUDE.md` 固定模板、skill 路由、引用路径和确定性防漂移门禁；未经明确需求不得新增全局约束。
