完成本次修改的收尾检查，按以下步骤逐项执行，每项输出通过/不通过及简要说明。

---

## 0. 检查范围

先确定本次检查的 diff 范围，后续所有"审查改动"的步骤都以此范围为准：

- **工作区模式**（默认）：改动尚未提交，范围是 `git diff` + `git diff --cached`。
- **工作分支模式**：改动已按批次提交到特性分支，以基线分支（通常 `dev` 或 `origin/dev`）为对照：

```bash
git log --oneline <base>..HEAD    # 逐提交清单
git diff <base>...HEAD            # 全量改动
```

分支模式还需逐提交检查：每个提交只含单一主题的相关文件；提交信息为 `type: 中文主题` + 2–10 条要点式 body；无任何 AI 署名。

---

## 1. 编译检查

在仓库根目录执行（非 Windows 机器必须带 `GOOS=windows GOARCH=amd64`，下同；原因见第 2 节）：

```bash
GOOS=windows GOARCH=amd64 go build -o /dev/null .
```

确认主程序编译无错误。若编译失败，列出所有错误并修复。

---

## 2. go vet 静态分析

```bash
GOOS=windows GOARCH=amd64 go vet ./...
```

注意必须固定 `GOARCH=amd64`（发布目标）：Apple Silicon 等 arm64 主机上缺省 GOARCH 会取 arm64，而 windigo 无 windows/arm64 支持，导致误报失败。golangci-lint（第 3 节）同样必须固定 GOARCH，且后果更严重。

vet 会连同测试文件一起类型检查。修复所有 vet 报告的问题。

---

## 3. golangci-lint 检查

CI 未跑 golangci-lint（`.github/workflows/ci.yml` 只有 vet + test），lint 是本地收尾的必查项：

```bash
GOOS=windows GOARCH=amd64 golangci-lint run ./...
```

**必须固定 `GOOS=windows GOARCH=amd64`**：windigo、`syscall.NewLazyDLL` 等仅 Windows 可编译，arm64 主机缺省 GOARCH 会取 arm64，导致 `config` 等包 typecheck 失败。而 golangci-lint 一旦某包 typecheck 失败，会**短路该包其余全部 linter**——只报 1~2 条 typecheck 噪音，把真实的 errcheck / unused / staticcheck 问题全部掩盖。固定 GOARCH 后才能看到完整基线（这是本轮实证：不固定时仅见 typecheck 噪音，固定后才暴露 200 条基线告警）。

### 基线零净增政策

本仓存在既有基线告警（errcheck 为主）。golangci-lint **默认每 linter 截断 50 条**，默认视图约 73 条：

```
73 issues:  errcheck: 50(截断) / ineffassign: 1 / staticcheck: 9 / unused: 13
```

禁用截断后真实约 200 条（errcheck ~177）。因此判定标准**不是绝对 0，而是对比基线分支零净增**：本次改动不得引入任何新告警，既有基线不在本次范围。

先看禁用截断的完整计数（底部汇总）：

```bash
GOOS=windows GOARCH=amd64 golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./... 2>&1 | tail -6
```

再与基线分支对比（各存一份，按内容 diff，只关注 HEAD 侧新增）：

```bash
base=origin/dev   # 或 dev
run() { GOOS=windows GOARCH=amd64 golangci-lint run --max-issues-per-linter=0 --max-same-issues=0 ./... 2>&1 | sort; }
run > /tmp/lint-head.txt                                      # 当前 HEAD
git switch "$base"; run > /tmp/lint-base.txt; git switch -    # 基线（工作区有未提交改动时先 git stash，比对后 git stash pop）
diff /tmp/lint-base.txt /tmp/lint-head.txt                    # 关注 HEAD 侧新增（> 开头）行
```

只要无 HEAD 侧新增（`>`）告警即通过；有则只修本次改动引入的问题（**测试发现 bug 必须修代码**），不动既有基线。注意跨分支行号漂移可能造成 diff 噪音，必要时按"文件:告警类型:消息"归一化后再比。

---

## 4. 单元测试

- Windows 机器：`go test ./...`，所有测试必须通过。
- 非 Windows 机器：无法运行 Windows 二进制，退化为全部包的测试编译（运行交由 CI windows-latest），并在结论中注明"运行期验证交 CI"：

```bash
for d in $(GOOS=windows GOARCH=amd64 go list ./...); do GOOS=windows GOARCH=amd64 go test -count=1 -c -o /dev/null "$d" || echo "FAIL $d"; done
```

若有失败，分析是代码 bug 还是测试本身的问题——**测试发现 bug 必须修复代码，绝不修改测试去迎合错误的代码**。

gofmt 要求：本次改动的行必须符合项目 go.mod 对应版本的 gofmt；仓库基线存在历史格式差异（CI 不检查 gofmt），不要为此重排未触碰的既有代码。

---

## 5. Windigo GUI 专项检查

对本次修改涉及的 `ui/` 包代码，逐项检查：

- [ ] **UiThread 回调**：所有 goroutine 中对 UI 控件的操作（SetText、Enable、Disable、Items().Add 等）是否都在 `UiThread()` 回调内执行？直接在 goroutine 中操作 UI 控件会导致崩溃。
- [ ] **goroutine recover**：所有 `go func()` 是否都有 `defer func() { if r := recover(); r != nil { ... } }()`？缺少 recover 会导致整个程序闪退。
- [ ] **模态对话框回调**：模态对话框显示前是否调用了 `SetOnUpdate(nil)` 禁用后台任务回调？是否用 `defer` 恢复？否则后台回调会操作被模态对话框阻塞的 UI。
- [ ] **LockOSThread**：GUI 入口是否有 `runtime.LockOSThread()`？windigo 要求消息循环在固定 OS 线程。
- [ ] **LogBuffer 并发安全**：LogBuffer 的读写是否都在 mutex 保护下？UI 线程和 goroutine 并发访问会导致竞态。

若本次修改未涉及 `ui/` 包，跳过此项并说明。

---

## 6. IIS / Windows API 专项检查

对涉及 `iis/`、`cert/`、`config/` 包的修改：

- [ ] **命令注入**：传给 `exec.Command` 的参数是否直接传入参数列表（而非拼接到命令字符串）？特别注意站点名、域名等用户输入。
- [ ] **PowerShell 注入**：调用 PowerShell 的地方是否对用户输入做了转义或使用参数化？证书指纹等是否校验为合法的 hex 字符串？
- [ ] **路径遍历**：文件路径操作是否使用了 `filepath.Rel()` + 按路径段校验？防止 `../` 类攻击。
- [ ] **DPAPI 加密**：新增或修改的配置字段中，敏感数据（Token、密码）是否通过 DPAPI 加密存储？是否使用**机器作用域**（`vm:` 前缀），保证 SYSTEM 计划任务能解密交互账户写入的密文？机器作用域以账户隔离换取 SYSTEM 可解密，机密性改由**数据目录 ACL** 保障：改动是否维持数据目录仅限 SYSTEM/Administrators（安装脚本 `icacls /inheritance:r`，运行时 `util.EvaluateDataDirACL` 自检）？
- [ ] **SSL 绑定类型**：SSL 绑定操作是否正确区分了 SNI (`hostnameport`) 和 IP (`ipport`) 两种类型？
- [ ] **绑定变更可恢复**：删除/替换 SSL 绑定前是否先**捕获旧绑定完整参数**（优先 httpapi 结构化查询含高级 SSL 参数，查询失败降级 `netsh show` 最小三字段），失败时用捕获快照回绑还原？成败判定是否基于操作后实际绑定状态（locale 无关），而非输出关键词？

若本次修改未涉及这些包，跳过此项并说明。

---

## 7. API / Deploy 专项检查

对涉及 `api/`、`deploy/` 包的修改：

- [ ] **per-cert client**：是否为每个证书创建独立的 API Client（`NewClientForCert`）？是否遵循"API 配置在证书级"的设计？
- [ ] **HTTP 错误处理**：API 调用是否检查了 HTTP 状态码？错误响应的 body 是否被读取并关闭？
- [ ] **超时设置**：HTTP Client 是否设置了合理的超时？
- [ ] **Token 安全**：Token 是否仅通过 Authorization header 传输？日志中是否避免打印 Token？
- [ ] **回调契约**：回调请求体是否保持 spec §2.8 三字段 + 可选 message（仅 failure）（order_id/status/deployed_at/message）？message 是否经客户端脱敏 + 按 rune 截断 ≤256（`CallbackMessageMaxRunes`，服务端上限 500）？status 是否仅用 success/failure（回调不发 pending）？
- [ ] **订单级聚合单发**：一个订单内多个绑定的回调是否聚合为**单条**（循环内收集、循环后 `sendAggregatedCallback` 单发）？全成→success（无 message），任一失败→failure（message 取首因）；无绑定被处理时不回调？避免逐绑定竞态上报。
- [ ] **失败回调覆盖**：新增的失败路径是否都发送 failure 回调（client 可用时）？是否存在"只记本地日志"的静默失败让服务端视图错位？
- [ ] **假成功语义**：success 回调与成功统计是否以实际生效（绑定/部署校验通过）为前提？部分失败是否如实反映在结果与统计中？

若本次修改未涉及这些包，跳过此项并说明。

---

## 8. 升级模块专项检查

对涉及 `upgrade/` 包的修改：

- [ ] **签名验证链**：升级文件下载后是否执行了完整的 Authenticode 签名验证（EV 证书 + 组织名 + 国家代码 + 可信 CA）？
- [ ] **版本比较**：版本号比较逻辑是否正确处理了语义化版本？
- [ ] **原子替换**：文件替换是否是原子操作（先写临时文件再 rename）？

若本次修改未涉及此包，跳过此项并说明。

---

## 9. setup 共享逻辑检查

对涉及 `setup/` 包的修改：

- [ ] **ProgressFunc 回调**：`Run()` 的进度输出是否通过 `ProgressFunc` 回调而非直接 `fmt.Print`？CLI 和 GUI 共用此包，程序是 Console 子系统应用、GUI 模式已 `util.HideConsole()`，直接打印会导致 GUI 模式下输出丢失。

若本次修改未涉及此包，跳过此项并说明。

---

## 10. deploy-spec.md 一致性检查

`deploy-spec.md` 是四仓（sslctl / sslctlw / sslbt / sslnas）共通的部署行为规范，四份必须**字节一致**。仅当本次改动**触碰了 `deploy-spec.md`** 时执行本项：

```bash
for r in sslctl sslctlw sslbt sslnas; do
  shasum -a 256 "$HOME/work/code/$r/deploy-spec.md"
done
```

四行哈希必须完全相同。若有差异，说明未同步——与其他仓逐一 diff 对齐后一并提交到四仓：

```bash
diff "$HOME/work/code/sslctl/deploy-spec.md" "$HOME/work/code/sslctlw/deploy-spec.md"
```

未触碰 `deploy-spec.md` 时跳过并说明。

---

## 11. Git Diff 审查

按第 0 步确定的范围审查改动：

```bash
git status
git diff && git diff --cached        # 工作区模式
git diff <base>...HEAD               # 工作分支模式
```

审查所有改动，确认：

- [ ] 没有意外修改的文件（只有本次任务相关的文件被改动）
- [ ] 没有遗留的调试代码（`fmt.Println` 调试输出、`log.Println("DEBUG")`、硬编码测试值）
- [ ] 没有意外删除的代码或注释
- [ ] 没有引入新的未使用的 import（`go vet` 应已捕获，双重确认）
- [ ] 新增文件是否放在了正确的包目录下

---

## 12. 构建标签与平台兼容性

- [ ] 新增的 Windows 特定代码是否有 `//go:build windows` 标签？
- [ ] 集成测试文件是否有 `//go:build integration` 标签？
- [ ] 是否有代码在非 Windows 平台会编译失败？（本项目为 Windows 专用，但 `go vet` 和单元测试应能在任何平台运行）

---

## 13. 版本与构建兼容性

```bash
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.version=check-test" -o /dev/null .
```

确认 ldflags 版本注入仍然有效。

---

## 14. 已知局限性与潜在风险

将本次修改引入的局限性和风险按以下分类列出：

### 安全风险
- 是否引入了新的外部输入处理？输入校验是否充分？
- 是否改变了权限模型或加密逻辑？

### 兼容性风险
- 是否修改了配置文件格式？旧配置能否正常加载？
- 是否修改了 CLI 参数或输出格式？是否影响脚本调用方？
- 是否修改了 API 请求/响应结构？

### 稳定性风险
- 是否在 UI 线程引入了可能阻塞的操作？
- 是否有新的 goroutine 缺少错误处理？
- 是否有资源（文件句柄、HTTP 连接）未正确关闭？

### 部署风险
- 是否需要配合服务端变更才能工作？
- 是否影响了升级路径（旧版本能否升级到新版本）？

如果某个分类下无风险，明确标注"无"。

---

## 输出格式

以表格形式汇总所有检查项的结果：

| # | 检查项 | 结果 | 备注 |
|---|--------|------|------|
| 1 | 编译检查 | ✅/❌ | ... |
| 2 | go vet | ✅/❌ | ... |
| 3 | golangci-lint（基线零净增） | ✅/❌ | ... |
| ... | ... | ... | ... |

最后给出总体结论：**可以提交** 或 **需要修复**（列出待修复项）。
