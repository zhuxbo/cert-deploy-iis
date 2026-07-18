package iis

import (
	"errors"
	"reflect"
	"testing"
)

func TestClassifyBindingState(t *testing.T) {
	const desired = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

	tests := []struct {
		name    string
		current *capturedBinding
		err     error
		want    bindingState
	}{
		{"目标绑定已生效", &capturedBinding{CertHash: desired}, nil, bindingStateDesired},
		{"哈希大小写不敏感", &capturedBinding{CertHash: "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD"}, nil, bindingStateDesired},
		{"确认绑定不存在", nil, nil, bindingStateAbsent},
		{"存在异常绑定", &capturedBinding{CertHash: "0000000000000000000000000000000000000000"}, nil, bindingStateUnexpected},
		{"查询失败状态未知", nil, errors.New("httpapi 查询失败"), bindingStateUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyBindingState(tt.current, tt.err, desired); got != tt.want {
				t.Fatalf("classifyBindingState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBindingStateAllowsRecovery(t *testing.T) {
	tests := []struct {
		state bindingState
		want  bool
	}{
		{bindingStateDesired, false},
		{bindingStateUnknown, false},
		{bindingStateAbsent, true},
		{bindingStateUnexpected, true},
	}
	for _, tt := range tests {
		if got := bindingStateAllowsRecovery(tt.state); got != tt.want {
			t.Errorf("bindingStateAllowsRecovery(%v) = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestRestoreBinding(t *testing.T) {
	old := &capturedBinding{CertHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	unexpected := &capturedBinding{CertHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

	t.Run("异常绑定先删后恢复并验证", func(t *testing.T) {
		var calls []string
		err := restoreBinding(
			unexpected,
			old,
			func() error { calls = append(calls, "delete"); return nil },
			func() error { calls = append(calls, "add"); return nil },
			func() (*capturedBinding, error) {
				calls = append(calls, "query")
				return &capturedBinding{CertHash: old.CertHash}, nil
			},
		)
		if err != nil {
			t.Fatalf("restoreBinding() error = %v", err)
		}
		if want := []string{"delete", "add", "query"}; !reflect.DeepEqual(calls, want) {
			t.Fatalf("调用顺序 = %v, want %v", calls, want)
		}
	})

	t.Run("确认不存在时直接恢复", func(t *testing.T) {
		var calls []string
		err := restoreBinding(
			nil,
			old,
			func() error { calls = append(calls, "delete"); return nil },
			func() error { calls = append(calls, "add"); return nil },
			func() (*capturedBinding, error) {
				calls = append(calls, "query")
				return &capturedBinding{CertHash: old.CertHash}, nil
			},
		)
		if err != nil {
			t.Fatalf("restoreBinding() error = %v", err)
		}
		if want := []string{"add", "query"}; !reflect.DeepEqual(calls, want) {
			t.Fatalf("调用顺序 = %v, want %v", calls, want)
		}
	})

	t.Run("旧绑定已经存在无需变更", func(t *testing.T) {
		mutated := false
		err := restoreBinding(
			&capturedBinding{CertHash: old.CertHash},
			old,
			func() error { mutated = true; return nil },
			func() error { mutated = true; return nil },
			func() (*capturedBinding, error) { mutated = true; return nil, nil },
		)
		if err != nil {
			t.Fatalf("restoreBinding() error = %v", err)
		}
		if mutated {
			t.Fatal("旧绑定已存在时不应执行删除、添加或查询")
		}
	})

	t.Run("删除异常绑定失败时不得继续添加", func(t *testing.T) {
		added := false
		err := restoreBinding(
			unexpected,
			old,
			func() error { return errors.New("删除失败") },
			func() error { added = true; return nil },
			func() (*capturedBinding, error) { return nil, nil },
		)
		if err == nil {
			t.Fatal("删除失败应返回错误")
		}
		if added {
			t.Fatal("删除失败后不得继续添加旧绑定")
		}
	})
}
