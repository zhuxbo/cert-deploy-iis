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
| `release-helper.py` | 确定性校验 manifest、生成索引、节点提交/回滚/验收 |
| `release-helper-test.sh` | 在临时目录测试 main 不可变、dev 覆盖和回滚 |
| `check-governance.sh` | 检查智能体配置、skill 路由和薄工具入口漂移 |
| `install.ps1` | Windows 安装/升级入口 |

常用的无副作用检查：

```bash
bash build/release.sh --dry-run 1.2.3-rc.1
bash build/release-helper-test.sh
bash build/check-governance.sh
```

不要直接把 `release.sh` 当作完整正式发布入口；正式发布必须从 `skills/remote-release.md` 开始。

## 本地秘密配置

```bash
cp build/build.conf.example build/build.conf
cp build/release.conf.example build/release.conf
chmod 600 build/build.conf build/release.conf
```

两个实际配置文件均被 Git 忽略：

- `build.conf`：升级时信任的签名组织/国家、SimplySign 证书指纹和时间戳服务。
- `release.conf`：完整发布节点集合、SSH 用户和私钥。所有节点共同参与发布，不提供单节点公开发布入口。

Windows 发布机还需要 Git Bash/MSYS2、Go 1.24+、Python 3.9+、SimplySign Desktop、Windows SDK `signtool` 和 `cygpath`。发布节点需要 Python 3。
