# 构建、签名与发布工具

本目录只提供可执行工具和配置样例，不维护另一份发布流程。权威职责如下：

- Windows 构建、Authenticode、正式资产与 bundle：`skills/build-release.md`
- dev/main 发布编排、Git/GitHub、恢复和验收：`skills/remote-release.md`
- 跨仓统一语义：`deploy-spec.md` 第 8 节

## 工具

| 文件 | 单一职责 |
| --- | --- |
| `build.sh` | 构建 Windows amd64 EXE，注入版本和升级签名信任配置，不承担 CI 门禁 |
| `sign.sh` | 对一个 EXE 执行或验证 Authenticode 签名 |
| `release.sh` | 生成持久化 bundle；对全部发布节点执行 stage/publish/verify/cleanup |
| `release-helper.py` | 校验 manifest、维护协调器/发布根互斥和索引代际、执行节点提交/回滚/验收 |
| `release-helper-test.sh` | 在临时双节点测试不可变发布、并发拒绝、中断续跑、清理重试和部分失败回滚 |
| `check-governance.sh` | 检查智能体配置、skill 路由和薄工具入口漂移 |
| `install.ps1` | Windows 安装/升级入口 |

常用的无副作用检查：

```bash
bash build/release.sh --dry-run 1.2.3-rc.1
bash build/release-helper-test.sh
bash build/check-governance.sh
```

不要直接把 `release.sh` 当作完整正式发布入口；正式发布必须从 `skills/remote-release.md` 开始。

远端恢复所需的持久 helper、互斥文件和完成标记存放在 `.staging/.control/`；成功执行 `cleanup` 后，发布根只保留 `.staging/` 与 `.rollback/` 两个隐藏目录。

## 本地秘密配置

```bash
cp build/build.conf.example build/build.conf
cp build/release.conf.example build/release.conf
# Linux/macOS
chmod 600 build/build.conf build/release.conf
```

Windows 上的 Git Bash 无法用 `chmod 600` 表达 NTFS 权限。请在 PowerShell 中把两个配置文件的 DACL 收紧为仅当前账户可访问；`release.sh` 会拒绝仍继承权限或包含其他 Allow ACE 的 `release.conf`：

```powershell
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
foreach ($path in 'build/build.conf', 'build/release.conf') {
    $file = Get-Item -LiteralPath $path
    $acl = $file.GetAccessControl([Security.AccessControl.AccessControlSections]::Access)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($identity.User, 'FullControl', 'Allow')
    [void]$acl.AddAccessRule($rule)
    $file.SetAccessControl($acl)
}
```

两个实际配置文件均被 Git 忽略：

- `build.conf`：升级时信任的签名组织/国家、SimplySign 证书指纹和时间戳服务。
- `release.conf`：完整发布节点集合、SSH 用户和私钥。所有节点共同参与发布，不提供单节点公开发布入口。

Windows 发布机还需要 Git Bash/MSYS2、Go 1.24+、Python 3.9+、SimplySign Desktop、Windows SDK `signtool` 和 `cygpath`。发布节点需要 Python 3。
