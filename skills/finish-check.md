# 完成检查

这是 sslctlw 本地 finish-check 的唯一清单。先确定审查范围，再逐项执行；任一必需项失败时结论只能是“需要修复”。不要把非 Windows 的测试编译报告成 Windows 运行测试通过。

## 0. 范围与环境

```bash
git status --short --branch
git diff --stat
git diff
git diff --cached
```

若改动已经在特性分支提交，以明确的 `<base>...HEAD` 检查全部提交和 diff。记录宿主平台、Go 版本、golangci-lint 版本以及本次跳过项的原因。

## 1. 确定性治理与脚本静态检查

```bash
bash build/check-governance.sh
bash -n build/build.sh build/sign.sh build/release.sh build/check-governance.sh build/release-helper-test.sh
bash build/release-helper-test.sh
bash build/release.sh --dry-run 1.2.3-rc.1
bash build/release.sh --dry-run 1.2.3
```

治理检查必须确认固定 `CLAUDE.md`、扁平 skill、路由叶子、旧路径清理和薄工具入口完全一致。dry-run 不得构建、签名、连接 SSH、修改 Git 或创建 bundle。

若修改发布脚本，再使用临时目录或 mock 验证以下语义：

- 稳定版与预发布版 SemVer 分流，非法版本拒绝。
- main bundle 拒绝脏工作区、非 main、`main != origin/main`；dev manifest 正确记录 `source_commit`/`dirty`。
- manifest 的正式资产集合只有 `sslctlw-windows-amd64.exe`，哈希在签名后计算。
- main 已存在版本目录或索引条目时拒绝覆盖；dev 同版本可替换。
- `stage` 先全节点隐藏暂存并校验，`publish` 才更新公开目录/索引；失败返回非零并保留 bundle。
- tag 后恢复只复用原 bundle，不调用构建或签名。

## 2. Windows amd64 编译与静态分析

所有非 Windows 主机命令固定发布目标，避免 Apple Silicon 等环境误用 windows/arm64：

```bash
GOOS=windows GOARCH=amd64 go build -o /dev/null .
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=check-test" -o /dev/null .
GOOS=windows GOARCH=amd64 go vet ./...
```

## 3. golangci-lint 基线零净增

本仓存在历史告警，只要求本次改动不新增。使用兼容 Go 1.24 的 golangci-lint 环境，且固定 `GOOS=windows GOARCH=amd64`：

```bash
GOOS=windows GOARCH=amd64 golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./...
```

若绝对结果非零，对比任务基线（通常 `origin/dev`），按“文件、linter、消息”归一化后确认 HEAD 侧零新增。工作区有改动时不得通过切换分支破坏用户文件，可使用独立临时 worktree 或对仅文档/脚本变更说明 Go 告警集合未受影响。macOS 新版 Go 出现 `context loading failed: no go files to analyze` 属工具链限制，不等于 lint 通过；应使用 Go 1.24 环境重跑或如实报告未验证。

## 4. 测试

Windows 发布/CI 环境：

```bash
go test -count=1 ./...
```

非 Windows 环境无法运行本仓依赖 windigo/Windows syscall 的测试；编译每个 Windows 测试包，并明确把运行期验证留给 Windows CI：

```bash
for d in $(GOOS=windows GOARCH=amd64 go list ./...); do
  GOOS=windows GOARCH=amd64 go test -count=1 -c -o /dev/null "$d" || exit 1
done
```

最终必须引用同一 commit 的 GitHub `windows-latest` 运行结果作为 Windows 行为证据。测试暴露生产缺陷时修复生产代码，不削弱安全校验或篡改断言迎合错误行为。

## 5. 变更面专项审查

只对本次涉及的包执行，但必须明确说明跳过理由：

- `ui/`：UI 更新只在 `UiThread`，耗时操作不进 UI 线程，goroutine 有 recover，模态回调正确停用/恢复，`LockOSThread` 与 LogBuffer 锁不被破坏。
- `iis/`、`cert/`、`config/`：参数化外部命令、PowerShell/路径输入安全、机器作用域 DPAPI 和 SYSTEM/Administrators DACL、SNI/IP 区分、替换前完整快照、状态未知不做破坏性回滚、恢复后复验。
- `api/`、`deploy/`：per-cert client、超时/响应关闭/Token 脱敏、回调字段和截断、订单级聚合单发、部分失败/无匹配不得假成功。
- `upgrade/`：SemVer、HTTPS/SHA256、Authenticode 组织/国家/CA 校验、临时文件与原子替换。
- `setup/`：CLI/GUI 共用进度只经 `ProgressFunc`，库层不直接 `fmt.Print`。
- `build/`：正式资产集合、签名后哈希、bundle 不重建、main 不可变、dev dirty 记录、多节点先暂存后公开、索引原子替换和恢复路径。

## 6. 规范与文档职责

- 本任务若未修改 `deploy-spec.md`，确认 diff 中没有该文件并跳过跨仓字节比较。
- 若明确修改了它，才由统一多仓流程检查四仓字节一致；单仓 finish-check 不拉取其他仓移动分支。
- 检查 `AGENTS.md`、skills、工具入口、README 和构建文档没有复制冲突规则，所有命令和路径真实存在。
- 新增过程文档只能位于被忽略的 `.superpowers/`，不得提交或被代码/入库文档引用。

## 7. 最终 diff 与提交准备

```bash
git diff --check
git status --short
git diff --stat
git diff
```

逐文件确认无意外改动、无调试代码、无失效引用、无秘密配置、无过期说明，`deploy-spec.md` 未被修改。提交信息遵循仓库历史的 `type: 中文主题`，body 2–10 条总结性要点，不添加 AI 署名。

## 输出

用表格报告：治理、脚本静态/dry-run、编译、版本注入、vet、lint、宿主测试、Windows 测试编译、Windows CI、专项审查、文档职责、`git diff --check`。每项给出实际命令、结果和限制；最后只给出“可以提交”或“需要修复”。
