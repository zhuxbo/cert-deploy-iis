// +build windows

package iis

import (
	"strings"
	"testing"
)

// TestScanSites_Live 测试扫描 IIS 站点（需要 IIS 已安装）
func TestScanSites_Live(t *testing.T) {
	// 检查 IIS 是否已安装
	if err := CheckIISInstalled(); err != nil {
		t.Skipf("跳过测试: IIS 未安装 - %v", err)
	}

	sites, err := ScanSites()
	if err != nil {
		t.Fatalf("ScanSites 失败: %v", err)
	}

	t.Logf("发现 %d 个站点", len(sites))
	for _, site := range sites {
		t.Logf("  站点: ID=%d, Name=%q, State=%s, Bindings=%d",
			site.ID, site.Name, site.State, len(site.Bindings))
	}

	// IIS 安装后通常至少有 Default Web Site
	if len(sites) == 0 {
		t.Log("警告: 没有发现任何站点（IIS 可能没有配置站点）")
	}
}

// TestListSSLBindings_Live 测试获取 SSL 绑定列表
func TestListSSLBindings_Live(t *testing.T) {
	bindings, err := ListSSLBindings()
	if err != nil {
		// netsh 可能需要管理员权限
		if strings.Contains(err.Error(), "拒绝访问") || strings.Contains(err.Error(), "Access") {
			t.Skipf("跳过测试: 需要管理员权限 - %v", err)
		}
		t.Fatalf("ListSSLBindings 失败: %v", err)
	}

	t.Logf("发现 %d 个 SSL 绑定", len(bindings))
	for _, b := range bindings {
		t.Logf("  绑定: %s, CertHash=%s, IsIP=%v",
			b.HostnamePort, b.CertHash, b.IsIPBinding)
	}
}

// TestGetIISMajorVersion_Live 测试获取 IIS 版本
func TestGetIISMajorVersion_Live(t *testing.T) {
	version, err := GetIISMajorVersion()
	if err != nil {
		t.Skipf("跳过测试: 无法获取 IIS 版本 - %v", err)
	}

	t.Logf("IIS 主版本: %d", version)

	// IIS 7+ 是 Windows 7/Server 2008 R2 及更高版本
	if version < 7 {
		t.Errorf("IIS 版本过低: %d", version)
	}
}

// TestIsIIS7_Live 测试 IIS7 检测
func TestIsIIS7_Live(t *testing.T) {
	result := IsIIS7()
	t.Logf("IsIIS7: %v", result)
}

// TestCheckIISInstalled_Live 测试 IIS 安装检测
func TestCheckIISInstalled_Live(t *testing.T) {
	err := CheckIISInstalled()
	if err != nil {
		t.Logf("IIS 未安装或不可用: %v", err)
	} else {
		t.Log("IIS 已安装")
	}
}

// TestGetSiteState_Live 测试获取站点状态
func TestGetSiteState_Live(t *testing.T) {
	if err := CheckIISInstalled(); err != nil {
		t.Skipf("跳过测试: IIS 未安装")
	}

	sites, err := ScanSites()
	if err != nil {
		t.Fatalf("ScanSites 失败: %v", err)
	}

	if len(sites) == 0 {
		t.Skip("没有站点可测试")
	}

	// 测试第一个站点
	site := sites[0]
	state, err := GetSiteState(site.Name)
	if err != nil {
		t.Fatalf("GetSiteState 失败: %v", err)
	}

	t.Logf("站点 %q 状态: %s", site.Name, state)

	// 验证状态是有效值
	validStates := map[string]bool{
		"Started": true,
		"Stopped": true,
		"Unknown": true,
	}
	if !validStates[state] {
		t.Errorf("无效的站点状态: %s", state)
	}
}
