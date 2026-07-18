package iis

import (
	"errors"
	"testing"
)

// TestVerifyBindingWithRetry verify 步瞬时失败重试一次再判定，避免误判触发回绑
func TestVerifyBindingWithRetry(t *testing.T) {
	const want = "abcd1234abcd1234abcd1234abcd1234abcd1234"

	t.Run("首次即命中不重试", func(t *testing.T) {
		calls := 0
		q := func() (*capturedBinding, error) {
			calls++
			return &capturedBinding{CertHash: want}, nil
		}
		current, err := queryBindingWithRetry(q, want, 0)
		if err != nil || classifyBindingState(current, err, want) != bindingStateDesired {
			t.Fatalf("首次命中应返回目标绑定, current=%+v err=%v", current, err)
		}
		if calls != 1 {
			t.Errorf("首次命中不应重查, calls = %d", calls)
		}
	})

	t.Run("瞬时未命中重试后命中", func(t *testing.T) {
		calls := 0
		q := func() (*capturedBinding, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("瞬时查询失败")
			}
			return &capturedBinding{CertHash: want}, nil
		}
		current, err := queryBindingWithRetry(q, want, 0)
		if err != nil || classifyBindingState(current, err, want) != bindingStateDesired {
			t.Fatalf("重试后应返回目标绑定, current=%+v err=%v", current, err)
		}
		if calls != 2 {
			t.Errorf("应恰好重查一次, calls = %d", calls)
		}
	})

	t.Run("两次均确认不存在", func(t *testing.T) {
		calls := 0
		q := func() (*capturedBinding, error) {
			calls++
			return nil, nil
		}
		current, err := queryBindingWithRetry(q, want, 0)
		if classifyBindingState(current, err, want) != bindingStateAbsent {
			t.Fatalf("两次均未命中应确认不存在, current=%+v err=%v", current, err)
		}
		if calls != 2 {
			t.Errorf("最多重查一次, calls = %d", calls)
		}
	})

	t.Run("哈希不一致判失败", func(t *testing.T) {
		q := func() (*capturedBinding, error) {
			return &capturedBinding{CertHash: "0000000000000000000000000000000000000000"}, nil
		}
		current, err := queryBindingWithRetry(q, want, 0)
		if classifyBindingState(current, err, want) != bindingStateUnexpected {
			t.Fatalf("证书哈希不一致应判异常绑定, current=%+v err=%v", current, err)
		}
	})

	t.Run("大小写不敏感命中", func(t *testing.T) {
		q := func() (*capturedBinding, error) {
			return &capturedBinding{CertHash: want}, nil
		}
		current, err := queryBindingWithRetry(q, "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234", 0)
		if classifyBindingState(current, err, "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234") != bindingStateDesired {
			t.Fatal("哈希比较应大小写不敏感")
		}
	})

	t.Run("连续查询失败保持状态未知", func(t *testing.T) {
		calls := 0
		q := func() (*capturedBinding, error) {
			calls++
			return nil, errors.New("权限不足")
		}
		current, err := queryBindingWithRetry(q, want, 0)
		if classifyBindingState(current, err, want) != bindingStateUnknown {
			t.Fatalf("查询失败不得当成不存在, current=%+v err=%v", current, err)
		}
		if calls != 2 {
			t.Errorf("查询失败应重试一次, calls=%d", calls)
		}
	})
}
