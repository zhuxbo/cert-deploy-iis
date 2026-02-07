//go:build integration

package integration

import (
	"os"
	"testing"
)

// 测试配置 - 从环境变量获取，避免硬编码敏感信息
var (
	TestAPIBaseURL = getEnvOrDefault("TEST_API_BASE_URL", "https://manager.test.pzo.cn/api/deploy")
	TestToken      = os.Getenv("TEST_API_TOKEN") // 必须通过环境变量设置
)

// getEnvOrDefault 获取环境变量，如果不存在则返回默认值
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func TestMain(m *testing.M) {
	// 检查是否只运行本地测试
	localOnly := os.Getenv("TEST_LOCAL_ONLY") != ""

	// 检查必要的环境变量（本地测试模式跳过）
	if TestToken == "" && !localOnly {
		println("错误: 必须设置 TEST_API_TOKEN 环境变量")
		println("用法: set TEST_API_TOKEN=your_token && go test -tags=integration ./integration/...")
		println("")
		println("如果只运行本地测试（不需要 API），请设置:")
		println("  set TEST_LOCAL_ONLY=1 && go test -tags=integration ./integration/... -run \"TestIISLocal|TestUpgradeLocal\" -v")
		os.Exit(1)
	}

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
