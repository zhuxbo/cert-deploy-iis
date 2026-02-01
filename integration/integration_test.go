//go:build integration

package integration

import (
	"os"
	"testing"
)

// 测试配置
const (
	TestAPIBaseURL = "https://manager.test.pzo.cn/api/deploy"
	TestToken      = "sfZOLvxc0rIKyV7XMP0XGEP9D2AVrd6zUnKuXAE00Ql3E5eh602CCB0kovJHXX6H"
)

func TestMain(m *testing.M) {
	// 运行测试前的环境检查
	if !isAdmin() {
		println("警告: 非管理员权限运行，部分测试将被跳过")
	}

	os.Exit(m.Run())
}

// TestEnvironment 验证测试环境
func TestEnvironment(t *testing.T) {
	t.Run("CheckAdmin", func(t *testing.T) {
		if !isAdmin() {
			t.Skip("需要管理员权限")
		}
		t.Log("管理员权限: OK")
	})

	t.Run("CheckIIS", func(t *testing.T) {
		if !isIISInstalled() {
			t.Skip("IIS 未安装")
		}
		t.Log("IIS 安装: OK")
	})

	t.Run("CheckNetworkAccess", func(t *testing.T) {
		// 简单的网络连通性检查
		if err := checkNetworkAccess(TestAPIBaseURL); err != nil {
			t.Skipf("无法访问 API: %v", err)
		}
		t.Log("网络访问: OK")
	})
}
