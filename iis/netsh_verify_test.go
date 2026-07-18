package iis

import (
	"testing"
)

// TestVerifyBindingWithRetry verify 步瞬时失败重试一次再判定，避免误判触发回绑
func TestVerifyBindingWithRetry(t *testing.T) {
	const want = "abcd1234abcd1234abcd1234abcd1234abcd1234"

	t.Run("首次即命中不重试", func(t *testing.T) {
		calls := 0
		q := func() *capturedBinding {
			calls++
			return &capturedBinding{CertHash: want}
		}
		if !verifyBindingWithRetry(q, want, 0) {
			t.Fatal("首次命中应返回 true")
		}
		if calls != 1 {
			t.Errorf("首次命中不应重查, calls = %d", calls)
		}
	})

	t.Run("瞬时未命中重试后命中", func(t *testing.T) {
		calls := 0
		q := func() *capturedBinding {
			calls++
			if calls == 1 {
				return nil // 模拟 show 瞬时失败
			}
			return &capturedBinding{CertHash: want}
		}
		if !verifyBindingWithRetry(q, want, 0) {
			t.Fatal("重试后命中应返回 true")
		}
		if calls != 2 {
			t.Errorf("应恰好重查一次, calls = %d", calls)
		}
	})

	t.Run("两次均未命中判失败", func(t *testing.T) {
		calls := 0
		q := func() *capturedBinding {
			calls++
			return nil
		}
		if verifyBindingWithRetry(q, want, 0) {
			t.Fatal("两次均未命中应返回 false")
		}
		if calls != 2 {
			t.Errorf("最多重查一次, calls = %d", calls)
		}
	})

	t.Run("哈希不一致判失败", func(t *testing.T) {
		q := func() *capturedBinding {
			return &capturedBinding{CertHash: "0000000000000000000000000000000000000000"}
		}
		if verifyBindingWithRetry(q, want, 0) {
			t.Fatal("证书哈希不一致应返回 false")
		}
	})

	t.Run("大小写不敏感命中", func(t *testing.T) {
		q := func() *capturedBinding {
			return &capturedBinding{CertHash: want}
		}
		if !verifyBindingWithRetry(q, "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", 0) {
			t.Fatal("哈希比较应大小写不敏感")
		}
	})
}
