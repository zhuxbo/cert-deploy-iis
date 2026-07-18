package util

import (
	"reflect"
	"strings"
	"testing"
)

// TestWeakACLPrincipals 弱 ACL 判定：Allow 授予非 SYSTEM/Administrators 主体即为弱
func TestWeakACLPrincipals(t *testing.T) {
	tests := []struct {
		name    string
		entries []aclEntry
		want    []string
	}{
		{
			name:    "仅 SYSTEM+Administrators 安全",
			entries: []aclEntry{{SID: "S-1-5-18", Allow: true}, {SID: "S-1-5-32-544", Allow: true}},
			want:    nil,
		},
		{
			name:    "Users 读权限视为弱",
			entries: []aclEntry{{SID: "S-1-5-18", Allow: true}, {SID: "S-1-5-32-545", Allow: true, Rights: 0x1200a9}},
			want:    []string{"S-1-5-32-545"},
		},
		{
			name:    "Everyone 视为弱",
			entries: []aclEntry{{SID: "S-1-1-0", Allow: true}},
			want:    []string{"S-1-1-0"},
		},
		{
			name:    "Authenticated Users 视为弱",
			entries: []aclEntry{{SID: "S-1-5-11", Allow: true}},
			want:    []string{"S-1-5-11"},
		},
		{
			name:    "具体用户 SID 视为弱",
			entries: []aclEntry{{SID: "S-1-5-21-1-2-3-1001", Allow: true}},
			want:    []string{"S-1-5-21-1-2-3-1001"},
		},
		{
			name:    "CREATOR OWNER 视为安全",
			entries: []aclEntry{{SID: "S-1-3-0", Allow: true}, {SID: "S-1-5-18", Allow: true}},
			want:    nil,
		},
		{
			name:    "TrustedInstaller/服务主体视为安全",
			entries: []aclEntry{{SID: "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", Allow: true}},
			want:    nil,
		},
		{
			name:    "Deny 项忽略",
			entries: []aclEntry{{SID: "S-1-5-32-545", Allow: false}, {SID: "S-1-5-18", Allow: true}},
			want:    nil,
		},
		{
			name:    "非特权主体去重",
			entries: []aclEntry{{SID: "S-1-5-32-545", Allow: true}, {SID: "S-1-5-32-545", Allow: true}},
			want:    []string{"S-1-5-32-545"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := weakACLPrincipals(tt.entries)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("weakACLPrincipals() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseACLListing 解析 PowerShell "SID|类型|权限位" 输出，跳过非法行
func TestParseACLListing(t *testing.T) {
	output := strings.Join([]string{
		"S-1-5-18|Allow|2032127",
		"S-1-5-32-544|Allow|2032127",
		"S-1-5-32-545|Allow|1179817",
		"garbage without pipe",
		`NT AUTHORITY\SYSTEM|Allow|x`, // Translate 失败回退组名，无 S-1- 前缀应跳过
		"S-1-1-0|Deny|2032127",
	}, "\n")

	entries := parseACLListing(output)
	if len(entries) != 4 {
		t.Fatalf("解析条目数 = %d, want 4: %+v", len(entries), entries)
	}
	if entries[0].SID != "S-1-5-18" || !entries[0].Allow || entries[0].Rights != 2032127 {
		t.Errorf("首条解析错误: %+v", entries[0])
	}
	if entries[3].SID != "S-1-1-0" || entries[3].Allow {
		t.Errorf("Deny 项应 Allow=false: %+v", entries[3])
	}

	// 端到端：解析后判定应仅报出 Users
	off := weakACLPrincipals(entries)
	if !reflect.DeepEqual(off, []string{"S-1-5-32-545"}) {
		t.Errorf("解析+判定 = %v, want [S-1-5-32-545]", off)
	}
}

// TestFriendlySIDName 展示名映射（不影响判定）
func TestFriendlySIDName(t *testing.T) {
	if got := friendlySIDName("S-1-5-32-545"); got != "Users(S-1-5-32-545)" {
		t.Errorf("friendlySIDName(Users) = %q", got)
	}
	if got := friendlySIDName("S-1-5-21-9-9-9-1005"); got != "S-1-5-21-9-9-9-1005" {
		t.Errorf("未知 SID 应原样返回, got %q", got)
	}
}

// TestIsPrivilegedSID 特权主体判定
func TestIsPrivilegedSID(t *testing.T) {
	priv := []string{"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-3-1", "S-1-5-80-abc"}
	for _, s := range priv {
		if !isPrivilegedSID(s) {
			t.Errorf("%s 应为特权主体", s)
		}
	}
	weak := []string{"S-1-5-32-545", "S-1-1-0", "S-1-5-11", "S-1-5-21-1-2-3-1001"}
	for _, s := range weak {
		if isPrivilegedSID(s) {
			t.Errorf("%s 不应为特权主体", s)
		}
	}
}
