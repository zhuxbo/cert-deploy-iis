package upgrade

import "testing"

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		// 基本版本比较
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.0", 1},
		{"2.0.0", "1.9.9", 1},

		// 不同长度版本号
		{"1.0", "1.0.0", 0},
		{"1.0.0", "1.0", 0},
		{"1.0.1", "1.0", 1},

		// 预发布版本 vs 正式版本
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-beta", "1.0.0", -1},

		// 预发布版本之间比较
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-alpha", 0},

		// 预发布版本数字比较（修复 beta10 < beta2 的问题）
		{"1.0.0-beta.2", "1.0.0-beta.10", -1},
		{"1.0.0-beta.10", "1.0.0-beta.2", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-rc.10", "1.0.0-rc.9", 1},

		// 复杂预发布版本
		{"1.0.0-alpha.1", "1.0.0-alpha.2", -1},
		{"1.0.0-alpha.2", "1.0.0-beta.1", -1},
		{"1.0.0-beta.1", "1.0.0-rc.1", -1},

		// 数字 vs 字符串（数字排在前面）
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-1", 1},

		// build metadata 不参与排序
		{"1.0.0+build1", "1.0.0+build2", 0},
		{"1.0.0", "1.0.0+build", 0},
		{"1.0.0-beta.1+abc", "1.0.0-beta.1+xyz", 0},
	}

	for _, tt := range tests {
		t.Run(tt.v1+"_vs_"+tt.v2, func(t *testing.T) {
			result := CompareVersion(tt.v1, tt.v2)
			if result != tt.expected {
				t.Errorf("CompareVersion(%q, %q) = %d, want %d", tt.v1, tt.v2, result, tt.expected)
			}
		})
	}
}

