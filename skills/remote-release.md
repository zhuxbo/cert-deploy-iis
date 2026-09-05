# 远程发布与恢复

这是 sslctlw 发布流程的唯一权威实现。必须同时遵守 `deploy-spec.md` 第 8 节；Windows 构建、Authenticode 和正式资产定义见 `skills/build-release.md`。任何一步失败都不得宣布发布成功。

## 输入与通道

用户输入是一个不带或带单个前导 `v` 的 SemVer，执行前去掉 `v`：

- 稳定版本 `X.Y.Z`：`main` 正式发布。
- 带预发布段的版本（如 `X.Y.Z-beta.1`、`X.Y.Z-rc.2`）：`dev` 测试发布。
- 缺少版本、build metadata、非 SemVer、稳定版本不高于当前 `main.latest`：停止。

所有公开产物必须通过 Authenticode；不得使用跳过签名、跳过 bundle 校验或单节点公开发布的临时路径。

## 本仓 release gates

适用于 PR commit、合并后的精确 `main` commit 和回同步后的精确 `dev` commit：

1. GitHub required check `test`（工作流 `CI`）成功：Windows Server 2022、Go 1.26.8、`go vet ./...`、`go test ./...`、治理防漂移检查和发布 helper 临时目录测试。
2. `skills/finish-check.md` 的本地门禁通过；非 Windows 环境只能把测试编译作为补充证据，不能替代 Windows CI 运行。
3. Windows 构建机执行 `go test ./...`、版本注入构建、签名机 HTTP API Authenticode 签名与本地验证成功；Bearer Token 只允许通过受保护的随机临时文件进入构建机，并在结束时删除。

每次等待检查都要核对结果对应的 commit SHA，不接受其他 commit 的历史绿灯。

## dev 测试版

dev 发布只执行发布数据路径，不修改 Git 或 GitHub：

1. 允许任意分支和未提交改动；不 fetch、commit、push、merge、checkout，不创建 tag 或 GitHub Release。
2. 运行 `bash build/release.sh dev <version>`。脚本从当前快照构建并签名一次，manifest 写入 `source_commit` 和真实 `dirty`。
3. 脚本将同一 bundle 暂存到全部配置节点，逐节点核对资产数量、SHA256 和 bundle 签名声明后，才提升版本目录并原子更新各节点 `releases.json.dev`。
4. 同版本允许覆盖；更新后的条目刷新 `released_at`、`checksums`、`source_commit`、`dirty` 和 `latest`，每通道只保留最近 5 条。
5. 最终 `verify` 必须确认全部节点版本目录可读、只有规范资产、远端 SHA256 与 manifest/索引一致，且所有节点 `dev.latest` 等于本次版本。

任一步失败，保留 bundle 和暂存目录，修复后对同一 bundle 重新执行 `stage`、`publish`、`verify`；不得把部分节点成功描述为发布成功。

## main 正式版

正式发布窗口从合并 PR 开始，到 `main` fast-forward 回同步 `dev` 并通过检查结束。窗口内不得向 `dev` 添加新提交。

### 1. 预检与 PR

1. 通过全部发布节点各自的公网域名读取 `releases.json`，确认稳定版本高于每个节点的 `main.latest`。
2. 确认工作区干净，本地 `dev == origin/dev`；确认本地、远端均不存在 `v<version>`，GitHub Release 和所有节点 `main/v<version>/` 均不存在。
3. 通过 `dev → main` PR 发布；等待 required check `test` 和本仓 release gates 在 PR commit 上成功后合并。
4. 同步本地 `main`，确认 `main == origin/main`、工作区干净；等待精确 main commit 的 required check `test` 和 release gates 成功。

### 2. 单次构建与全节点暂存

1. 在 Windows 发布机运行 `bash build/release.sh prepare <version>`，记下输出的持久化 bundle 路径。
2. 检查 manifest 的 `channel=main`、`dirty=false`、`source_commit=<main SHA>`、规范资产集合和签名声明。
3. 运行 `bash build/release.sh stage <bundle-dir>`。全部节点必须完成隐藏目录上传和远端 SHA256 校验；此时不更新公开版本目录或索引。
4. 保留 bundle，直到第 5 节最终验收完成。

### 3. 不可变对象与公开

严格按顺序：

1. 创建 annotated tag `v<version>` 指向该 main commit，并推送；已存在即停止，不删除、不移动、不覆盖。
2. 创建 target 为该 tag/commit 的 draft GitHub Release；从已保存 bundle 上传唯一正式资产 `sslctlw-windows-amd64.exe`，核对 GitHub 资产 SHA256。
3. 运行 `bash build/release.sh publish <bundle-dir>`，使用已暂存内容提升全部节点，并原子替换各自 `releases.json.main`。正式版本目录或索引条目已存在时脚本必须失败。
4. 将 draft GitHub Release 公开为非 prerelease、latest 正式版。
5. 运行 `bash build/release.sh verify <bundle-dir>` 完成全节点对账后，才将唯一可移动 tag `latest` 更新到 `v<version>`。

### 4. 回同步

1. 将 `main` 以 fast-forward 方式同步回 `dev` 并推送；若 `dev` 已前进导致不能 fast-forward，停止处理差异，禁止 force-push。
2. 等待精确 dev commit 的 required check `test` 和 release gates 成功。

### 5. 最终验收

全部满足后才宣布完成并允许清理 bundle：

- PR 已合并；三个阶段的 gates 都对应各自精确 commit。
- 本地/远端 main、dev、版本 tag、latest tag、GitHub Release target 指向同一 commit，工作区干净。
- 所有节点经各自公网域名读取的 `main.latest` 等于版本号。
- 所有节点和 GitHub Release 只有且完整包含规范正式资产，字节一致，SHA256 与 manifest 和 `releases.json.checksums` 一致。
- GitHub Release 已公开、非 draft、非 prerelease、标记 latest。
- EXE 内版本号为本次版本，Windows `Get-AuthenticodeSignature`/`signtool verify` 有效。
- 从每个发布节点的公网域名实际下载代表 EXE 并完成 SHA256 校验。

全部验收完成后运行 `bash build/release.sh cleanup <bundle-dir>`；随后才可按保留策略清理本地持久化 bundle。

## 中断恢复

- 版本 tag 创建前失败：可重新执行 `prepare`；若已有合格 bundle，也可继续复用。
- 版本 tag 创建后失败：禁止 `prepare`、`build/build.sh`、`build/sign.sh`；只读取原 bundle，先核对 manifest 的 commit 等于 tag target，再幂等执行 `stage`，从失败点继续 GitHub upload、`publish` 或 `verify`。
- `publish` 中断并导致节点处于不同阶段时，保留 bundle 内的 `.publish-token`，先运行 `resume-publish <bundle-dir>` 幂等完成公开并重新验收；若确认不能继续，再运行 `rollback <bundle-dir>` 恢复全部节点，然后用同一 bundle 重新 `stage`/`publish`，不得重建。普通 `publish` 不得接管已有 attempt。
- `stage` 会在每个发布根留下绑定 release ID、manifest 和 commit 的持久所有权；`publish` 再绑定唯一 attempt token。中断后只有持有原 bundle 和 token 的协调器可以继续。回滚必须先全节点预检并绑定排他的回滚阶段；部分节点完成时依靠完成标记重试。成功 `cleanup` 或完整 `rollback` 才释放 owner 和本地 token，禁止手工删除它们绕过恢复核查。
- GitHub draft、节点暂存、索引更新、分支回同步任一步失败，都保留不可变对象和 bundle。修复失败节点后重新做全部节点目录与各自公网域名验收。
- 任一节点索引出现部分推进，立即停止新发布并用同一 bundle 完成其余节点或恢复到发布前索引；不得长期保留分裂的 `latest`。
- 已完成正式版不得删除 tag、覆盖资产或重写同版本；修复和回滚均发布更高版本。

## 禁止事项

- 不以删除或移动 `v<version>` 恢复。
- 不对正式版使用同版本重发、重建、重签、单节点发布或 force-push。
- 不把交叉编译、dry-run、SSH 连通性或部分节点成功当成正式发布完成。
- 不在本文件之外复制或另行维护发布步骤；工具入口只传递版本参数。
