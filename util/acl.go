package util

import (
	"fmt"
	"strconv"
	"strings"
)

// 数据目录 ACL 检测
//
// Token 与私钥使用机器作用域 DPAPI（CRYPTPROTECT_LOCAL_MACHINE）加密，
// 密文的机密性不再由 DPAPI 账户隔离提供，而完全依赖数据目录的文件系统 ACL：
// 任何能读到数据目录的账户都能解密其中的 Token 与私钥。因此需要检测数据目录
// 是否被授予了非管理员主体的访问权，弱 ACL 时输出告警（不阻断运行）。
//
// 判定按 SID 比较而非本地化组名，保证非英文 locale 下同样有效。

// aclEntry 目录 DACL 中的一条访问控制项（已物化的 Allow/Deny 授权）
type aclEntry struct {
	SID    string
	Allow  bool
	Rights uint32
}

// isPrivilegedSID 判断 SID 是否为期望持有数据目录访问权的可信主体
// （SYSTEM / Administrators / 对象所有者占位 / 服务主体），locale 无关。
func isPrivilegedSID(sid string) bool {
	switch sid {
	case "S-1-5-18", // LOCAL SYSTEM
		"S-1-5-32-544", // BUILTIN\Administrators
		"S-1-3-0",      // CREATOR OWNER（落定为对象所有者，管理员目录下即管理员）
		"S-1-3-1":      // CREATOR GROUP
		return true
	}
	// 服务/系统主体（TrustedInstaller S-1-5-80-... 等）视为可信
	if strings.HasPrefix(sid, "S-1-5-80-") {
		return true
	}
	return false
}

// weakACLPrincipals 从 DACL 项中筛出被授予访问权的非特权主体 SID（纯函数）。
// 返回非空表示 ACL 偏弱：这些主体能读取数据目录并解密其中的 Token 与私钥。
// Deny 项忽略；结果去重并保持出现顺序。
func weakACLPrincipals(entries []aclEntry) []string {
	var offenders []string
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.Allow {
			continue
		}
		if isPrivilegedSID(e.SID) {
			continue
		}
		if seen[e.SID] {
			continue
		}
		seen[e.SID] = true
		offenders = append(offenders, e.SID)
	}
	return offenders
}

// parseACLListing 解析 PowerShell 输出的 "SID|Allow或Deny|权限位" 行（纯函数）。
// 非法行（无 SID、格式不符）跳过，权限位解析失败按 0 处理。
func parseACLListing(output string) []aclEntry {
	var entries []aclEntry
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "|") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 2 {
			continue
		}
		sid := strings.TrimSpace(parts[0])
		// 仅接受 SID 字符串形态（Translate 失败时 PowerShell 可能输出组名，一律跳过按 SID 判定）
		if !strings.HasPrefix(sid, "S-1-") {
			continue
		}
		e := aclEntry{SID: sid, Allow: strings.EqualFold(strings.TrimSpace(parts[1]), "Allow")}
		if len(parts) == 3 {
			if v, err := strconv.ParseUint(strings.TrimSpace(parts[2]), 10, 32); err == nil {
				e.Rights = uint32(v)
			}
		}
		entries = append(entries, e)
	}
	return entries
}

// friendlySIDName 为常见 SID 附上英文名便于阅读；未知 SID 原样返回。
// 仅用于展示，不参与判定（判定始终按 SID）。
func friendlySIDName(sid string) string {
	names := map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-5-11":     "Authenticated Users",
		"S-1-5-7":      "Anonymous",
		"S-1-5-4":      "Interactive",
		"S-1-5-32-545": "Users",
		"S-1-5-32-546": "Guests",
		"S-1-5-32-547": "Power Users",
	}
	if n, ok := names[sid]; ok {
		return fmt.Sprintf("%s(%s)", n, sid)
	}
	return sid
}

// getAclScript 读取目录 DACL 并逐条输出 "SID|类型|权限位" 的 PowerShell 脚本。
// 路径经环境变量传入（避免命令注入），SID 通过 Translate 输出原始 SID 字符串保证 locale 无关。
const getAclScript = `$ErrorActionPreference='Stop'
$acl = Get-Acl -LiteralPath $env:SSLCTLW_ACL_PATH
foreach ($ace in $acl.Access) {
  $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { "$($ace.IdentityReference)" }
  '{0}|{1}|{2}' -f $sid, $ace.AccessControlType, [int]$ace.FileSystemRights
}`

// CheckDirectoryACL 读取目录 DACL，返回被授予访问权的非特权主体 SID 列表。
// locale 无关：PowerShell 输出原始 SID 字符串后按 SID 比较。
// 返回 error 表示无法判定（如 PowerShell 不可用），调用方应据此忽略而非误报。
func CheckDirectoryACL(path string) (offenders []string, err error) {
	output, err := RunPowerShellWithEnv(getAclScript, map[string]string{"SSLCTLW_ACL_PATH": path})
	if err != nil {
		return nil, fmt.Errorf("读取目录 ACL 失败: %w (输出: %s)", err, strings.TrimSpace(output))
	}
	return weakACLPrincipals(parseACLListing(output)), nil
}

// EvaluateDataDirACL 检测数据目录 ACL，返回告警列表（空表示健康或无法判定）。
// 无法判定（PowerShell 失败）时返回空，避免误报；弱 ACL 时给出可操作的收紧提示。
func EvaluateDataDirACL(path string) []string {
	offenders, err := CheckDirectoryACL(path)
	if err != nil || len(offenders) == 0 {
		return nil
	}
	names := make([]string, 0, len(offenders))
	for _, sid := range offenders {
		names = append(names, friendlySIDName(sid))
	}
	return []string{fmt.Sprintf(
		"数据目录 %s 的 ACL 允许非管理员主体访问 (%s)；机器作用域加密的 Token 与私钥可被这些主体解密，"+
			"请重新运行安装脚本或执行 icacls \"%s\" /inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\" 收紧权限",
		path, strings.Join(names, ", "), path)}
}
