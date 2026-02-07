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

func TestParseMetadata(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected map[string]string
	}{
		{
			name:     "empty body",
			body:     "",
			expected: map[string]string{},
		},
		{
			name:     "no metadata",
			body:     "This is a release note without metadata",
			expected: map[string]string{},
		},
		{
			name:     "single key-value",
			body:     "Release notes\n<!-- metadata: min_version=1.0.0 -->",
			expected: map[string]string{"min_version": "1.0.0"},
		},
		{
			name:     "multiple key-values",
			body:     "<!-- metadata: min_version=1.0.0; fingerprints=ABC123,DEF456 -->",
			expected: map[string]string{"min_version": "1.0.0", "fingerprints": "ABC123,DEF456"},
		},
		{
			name:     "with whitespace",
			body:     "<!--  metadata:  key1 = value1 ;  key2 = value2  -->",
			expected: map[string]string{"key1": "value1", "key2": "value2"},
		},
		{
			name:     "metadata in middle of text",
			body:     "Before\n<!-- metadata: test=value -->\nAfter",
			expected: map[string]string{"test": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMetadata(tt.body)
			if len(result) != len(tt.expected) {
				t.Errorf("parseMetadata() returned %d keys, want %d", len(result), len(tt.expected))
				return
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("parseMetadata()[%q] = %q, want %q", k, result[k], v)
				}
			}
		})
	}
}

func TestCleanReleaseNotes(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "no metadata",
			body:     "Release notes",
			expected: "Release notes",
		},
		{
			name:     "with metadata at end",
			body:     "Release notes\n<!-- metadata: key=value -->",
			expected: "Release notes",
		},
		{
			name:     "with metadata at start",
			body:     "<!-- metadata: key=value -->\nRelease notes",
			expected: "Release notes",
		},
		{
			name:     "metadata in middle",
			body:     "Before\n<!-- metadata: key=value -->\nAfter",
			expected: "Before\n\nAfter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanReleaseNotes(tt.body)
			if result != tt.expected {
				t.Errorf("cleanReleaseNotes() = %q, want %q", result, tt.expected)
			}
		})
	}
}
