# 构建、签名与发布资产

本资源只定义 sslctlw 的平台构建和资产契约。跨仓发布语义以 `deploy-spec.md` 第 8 节为准；Git、GitHub 和多阶段发布编排见 `skills/remote-release.md`。

## 平台与正式资产集合

- 唯一目标：Windows amd64。
- 唯一规范正式资产：`sslctlw-windows-amd64.exe`。
- GitHub-only 附加资产：无。
- `install.ps1` 是发布节点上的非版本化安装入口，不属于正式资产，不写入版本条目的 `checksums`，也不上传 GitHub Release。
- `install.ps1` 必须兼容 Windows Server 2012 自带的 Windows PowerShell 3.0；构造 .NET 对象使用 `New-Object`，不得使用较新版本才支持的 `[Type]::new(...)`、`#Requires -RunAsAdministrator` 或 `Get-FileHash`。管理员权限与 SHA256 校验改用 3.0 可用的 .NET API，不能降级或跳过。
- 同一版本在所有发布节点和 GitHub Release 上的 EXE 必须来自同一个已签名 bundle，逐字节一致；禁止为不同目标重新构建或重新签名。

## 构建

`build/build.sh <version>` 是唯一发布构建入口：

1. 从 `go.mod` 读取并强制使用精确的 `toolchain go1.26.8`。
2. 要求 `build/build.conf` 提供 `TRUSTED_ORG`，可选 `TRUSTED_COUNTRY` 默认 `CN`。
3. 使用 `GOOS=windows GOARCH=amd64`、`-trimpath -s -w`，通过 `-X main.version=<version>` 注入不带 `v` 的 SemVer。
4. 输出临时文件 `dist/sslctlw.exe`；Console 子系统保持不变，不使用 `-H windowsgui`。

该脚本不运行测试：dev 发布按规范不增加本地 CI 门禁；main 的 Windows 测试属于 `skills/remote-release.md` 明确的 release gate，在构建 bundle 前已经对应精确 commit 通过。

开发构建可直接运行：

```bash
GOOS=windows GOARCH=amd64 go build -o sslctlw.exe .
```

## Authenticode 签名

所有公开的 `main` 和 `dev` 产物都必须签名，不提供跳过签名的发布入口。`build/sign.sh` 在 Windows 构建机调用签名机 HTTP API，严格执行异步上传、轮询、下载和结果 SHA256 校验，再使用 Windows SDK `signtool` 独立验签：

```bash
bash build/sign.sh dist/sslctlw.exe
bash build/sign.sh --verify dist/sslctlw.exe
```

`build/build.conf` 保存公开的 `SIGN_THUMBPRINT` 和 `SIGN_CERTIFICATE_SERIAL`，不得保存 Bearer Token。API 地址和 Token 保存在本机受保护且被忽略的 `.env`；执行远程发布时，只把 Token 写入 Windows 构建机的随机临时文件，以仅允许当前管理员和 `SYSTEM` 的 ACL 保护，通过 `SSLCTLW_SIGNING_BEARER_TOKEN_FILE` 传给脚本，并在结束时无条件删除。API 地址通过 `SSLCTLW_SIGNING_BASE_URL` 传入。

签名会改变 EXE 字节，因此 SHA256 只能在 API 结果哈希、PowerShell Authenticode 状态、证书序列号与指纹以及 `signtool verify /pa /all` 全部成功后计算。发布机必须可用 `cygpath`、Windows PowerShell 5.1 和 `signtool`，并能访问签名机 API；这些条件无法用 macOS 交叉构建替代。

Linux 发布节点不重复执行 Windows Authenticode API，而是要求远端 EXE 的 SHA256 与已在 Windows 验签的 bundle 完全一致；最终再从公网下载代表资产回到 Windows 验签，形成端到端证据。

## 持久化 bundle

`bash build/release.sh prepare <version>` 构建、签名并保存：

```text
build/recovery/v<version>-<source_commit>/
├── manifest.json
├── install.ps1
└── sslctlw-windows-amd64.exe
```

首次执行 `publish` 时会在该目录原子创建 `.publish-token` 恢复元数据；它不属于正式资产或 manifest。成功 `cleanup` 或完整 `rollback` 后脚本删除该 token；协调器中断时必须保留，并用 `resume-publish` 继续。

`manifest.json` 固定绑定：

- `schema_version`
- `product`、`channel`、`version`
- `source_commit`、`dirty`
- `created_at`
- `assets`（文件名、大小、`sha256:<hex>`）
- `install_script` 的 SHA256
- `signature.type = authenticode`、`signature.verified = true`

正式版 bundle 必须来自干净的本地 `main`，且 `main == origin/main`；路径在完整恢复窗口结束前不得删除。版本 tag 创建后，恢复只能使用该目录中的 manifest 和文件，禁止再次调用 `build/build.sh` 或 `build/sign.sh`。

`dev` bundle 允许脏工作区，manifest 必须记录当前 `source_commit` 和真实 `dirty`。同一 dev 版本重新发布会生成新的 bundle 并覆盖远端同版本条目。

## 发布脚本职责

```bash
bash build/release.sh --dry-run <version>       # 无构建、签名、网络或 Git 写入
bash build/release.sh prepare <version>         # 只生成持久化 bundle
bash build/release.sh stage <bundle-dir>        # 全节点隐藏暂存并校验
bash build/release.sh publish <bundle-dir>      # 提升目录并原子替换全节点索引
bash build/release.sh resume-publish <bundle-dir> # 协调器中断后复用原 publish token
bash build/release.sh verify <bundle-dir>       # 全节点、索引与哈希对账
bash build/release.sh rollback <bundle-dir>     # 中断造成部分提升时恢复全部节点
bash build/release.sh cleanup <bundle-dir>      # 验收后清理远端恢复数据与超额历史目录
bash build/release.sh dev <prerelease-version>  # prepare → stage → publish → verify
bash build/release.sh test                      # 只测试所有节点 SSH 与依赖
```

脚本不创建或移动 Git tag，不操作 GitHub Release，不合并或推送分支。`main` 不允许跳过构建/签名、单节点公开发布、覆盖已有正式目录或更新已有同版本索引；`stage` 可幂等重试，并要求所有节点生成的下一版索引字节一致。每个节点的发布根从 `stage` 到 `cleanup` 或成功 `rollback` 由同一 bundle 持久占用，其他发布必须失败；本地协调器互斥与首次 `publish` 生成的唯一 attempt token 共同阻止同一 bundle 的并发操作。回滚先在全部节点完成只读 CAS/备份预检，再绑定 `rolling-back` 阶段，最后才恢复公开状态；已完成节点在 `.staging/.control/` 中保留可验证完成标记，支持另一节点失败后的幂等重试。`publish` 比较生成待发布索引时的基线代际，拒绝覆盖已变化的索引。索引通过同目录临时文件原子替换，任一节点失败时返回非零。`verify` 保留暂存与回滚数据供恢复，只有完整验收后才运行 `cleanup`；持久 helper、互斥文件和完成标记统一位于 `.staging/.control/`，旧版互斥文件通过原子移动迁入而不直接删除。成功清理后发布根只保留 `.staging/` 与 `.rollback/` 两个隐藏目录，并清除旧版曾留在根目录的其他控制文件。

## 本地可执行验证

```bash
bash -n build/build.sh build/sign.sh build/release.sh build/check-governance.sh build/release-helper-test.sh
bash build/release-helper-test.sh
bash build/release.sh --dry-run 1.2.3-rc.1
bash build/release.sh --dry-run 1.2.3
bash build/check-governance.sh
```

这些检查不证明真实 Authenticode、SSH、多节点原子提升或公网下载可用；正式发布验收仍按 `skills/remote-release.md` 执行。
