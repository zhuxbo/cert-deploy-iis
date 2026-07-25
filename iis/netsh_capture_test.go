package iis

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"testing"
)

// netshRecorder 记录 netsh 调用序列并按脚本回放结果
type netshRecorder struct {
	calls   []string
	onQuery func(args []string) (string, error)
	onExec  func(args []string) (string, error)
}

// installNetshStub 用脚本化桩替换 netsh 与 httpapi 入口，测试结束自动还原。
// structured 为 httpapi 结构化查询结果；返回 error 表示 httpapi 不可用（走 netsh 降级）。
func installNetshStub(t *testing.T, r *netshRecorder, structured func(keyParam, keyValue string) (*capturedBinding, error)) {
	t.Helper()
	oldQuery, oldExec, oldFull, oldDelay := netshQuery, netshExec, queryFullBindingFn, bindVerifyRetryDelay
	t.Cleanup(func() {
		netshQuery, netshExec, queryFullBindingFn, bindVerifyRetryDelay = oldQuery, oldExec, oldFull, oldDelay
	})
	bindVerifyRetryDelay = 0
	netshQuery = func(args ...string) (string, error) {
		r.calls = append(r.calls, "query:"+strings.Join(args, " "))
		if r.onQuery != nil {
			return r.onQuery(args)
		}
		return "", errors.New("未配置 query 桩")
	}
	netshExec = func(args ...string) (string, error) {
		r.calls = append(r.calls, "exec:"+strings.Join(args, " "))
		if r.onExec != nil {
			return r.onExec(args)
		}
		return "", errors.New("未配置 exec 桩")
	}
	queryFullBindingFn = structured
}

func (r *netshRecorder) didDelete() bool {
	for _, c := range r.calls {
		if strings.Contains(c, "exec:http delete sslcert") {
			return true
		}
	}
	return false
}

func (r *netshRecorder) addCall() string {
	for _, c := range r.calls {
		if strings.Contains(c, "exec:http add sslcert") {
			return c
		}
	}
	return ""
}

// notRunErr 模拟 netsh 根本没跑起来（PATH 损坏 / 无法创建进程），
// 与“跑起来但退出码非零”（绑定不存在）是两回事。
var notRunErr = &exec.Error{Name: "netsh.exe", Err: errors.New("executable file not found in %PATH%")}

// exitErr 模拟 netsh 跑起来并以非零退出（精确查询命中“绑定不存在”）
func exitErr() error {
	cmd := exec.Command("cmd.exe", "/c", "exit", "1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		panic("构造 ExitError 失败")
	}
	return err
}

const stubHash = "aabbccddeeff00112233445566778899aabbccdd"
const oldHash = "1122334455667788990011223344556677889900"

// TestBindAndVerify_CaptureUnavailableMustNotDelete 坐实：
// 删除前无法确认现有绑定状态（httpapi 不可用 + netsh 无法执行）时，
// 绝不能先删后发现无快照可回绑——那会让站点 HTTPS 直接下线且无法恢复。
func TestBindAndVerify_CaptureUnavailableMustNotDelete(t *testing.T) {
	r := &netshRecorder{
		onQuery: func([]string) (string, error) { return "", notRunErr },
		onExec:  func([]string) (string, error) { return "", notRunErr },
	}
	installNetshStub(t, r, func(string, string) (*capturedBinding, error) {
		return nil, errors.New("httpapi 不可用")
	})

	unbindCalled := false
	err := bindAndVerify("hostnameport", "example.com:443", stubHash, func() error {
		unbindCalled = true
		return nil
	})
	if err == nil {
		t.Fatal("状态不可确认时必须返回错误")
	}
	if unbindCalled || r.didDelete() {
		t.Fatalf("捕获失败时不得执行删除，调用序列: %v", r.calls)
	}
	if !strings.Contains(err.Error(), "现有绑定状态") {
		t.Errorf("错误信息应说明中止原因, got %v", err)
	}
}

// TestBindAndVerify_FirstBindWhenAbsent 首次绑定（绑定确实不存在）必须放行，
// 不能因为 netsh 精确查询退出非零就误判为“状态未知”而拒绝工作。
func TestBindAndVerify_FirstBindWhenAbsent(t *testing.T) {
	added := false
	r := &netshRecorder{
		onQuery: func(args []string) (string, error) {
			if added {
				return fmt.Sprintf("Certificate Hash : %s\n", stubHash), nil
			}
			return "", exitErr() // netsh 跑了，退出非零 = 该键无绑定
		},
		onExec: func(args []string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "add sslcert") {
				added = true
			}
			return "", nil
		},
	}
	installNetshStub(t, r, func(string, string) (*capturedBinding, error) {
		return nil, errors.New("httpapi 不可用")
	})

	if err := bindAndVerify("hostnameport", "example.com:443", stubHash, func() error { return nil }); err != nil {
		t.Fatalf("绑定不存在时首次绑定应成功, got %v", err)
	}
}

// TestBindAndVerify_SuccessPreservesFullBinding 防止成功路径绕过完整快照，
// 导致 AppID、客户端证书协商、CTL 与吊销检查参数被恢复为 netsh 默认值。
func TestBindAndVerify_SuccessPreservesFullBinding(t *testing.T) {
	added := false
	old := &capturedBinding{
		CertHash:                oldHash,
		AppID:                   "{4dc3e181-e14b-4a21-b022-59fc669b0914}",
		CertStoreName:           "MY",
		full:                    true,
		certCheckMode:           certCheckModeNoVerifyRevocation | certCheckModeCachedRevocationOnly | certCheckModeNoUsageCheck,
		revocationFreshnessTime: 1234,
		urlRetrievalTimeout:     5678,
		sslCtlIdentifier:        "SslctlwLabCtl",
		sslCtlStoreName:         "CA",
		defaultFlags:            sslFlagUseDSMapper | sslFlagNegotiateClientCert,
	}
	r := &netshRecorder{
		onExec: func(args []string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "add sslcert") {
				added = true
			}
			return "", nil
		},
	}
	installNetshStub(t, r, func(string, string) (*capturedBinding, error) {
		if added {
			return &capturedBinding{CertHash: stubHash, full: true}, nil
		}
		return old, nil
	})

	if err := bindAndVerify("hostnameport", "example.com:443", stubHash, func() error { return nil }); err != nil {
		t.Fatalf("完整快照替换应成功, got %v", err)
	}
	want := "exec:http add sslcert hostnameport=example.com:443 certhash=" + stubHash +
		" appid={4dc3e181-e14b-4a21-b022-59fc669b0914} certstorename=MY" +
		" verifyclientcertrevocation=disable verifyrevocationwithcachedclientcertonly=enable" +
		" usagecheck=disable revocationfreshnesstime=1234 urlretrievaltimeout=5678" +
		" sslctlidentifier=SslctlwLabCtl sslctlstorename=CA" +
		" dsmapperusage=enable clientcertnegotiation=enable"
	if got := r.addCall(); got != want {
		t.Fatalf("成功路径必须复用完整快照\n got=%s\nwant=%s", got, want)
	}
}

// TestBindAndVerify_MinimalCapturePreservesAppIDAndWarns 防止降级捕获时
// 把已确认的 AppID 丢掉，同时必须显式告知高级参数无法保真；
// 新证书仍按安装器契约从 LocalMachine\My 查找。
func TestBindAndVerify_MinimalCapturePreservesAppIDAndWarns(t *testing.T) {
	added := false
	old := &capturedBinding{
		CertHash:      oldHash,
		AppID:         "{4dc3e181-e14b-4a21-b022-59fc669b0914}",
		CertStoreName: "WebHosting",
	}
	r := &netshRecorder{
		onExec: func(args []string) (string, error) {
			if strings.Contains(strings.Join(args, " "), "add sslcert") {
				added = true
			}
			return "", nil
		},
	}
	installNetshStub(t, r, func(string, string) (*capturedBinding, error) {
		if added {
			return &capturedBinding{CertHash: stubHash}, nil
		}
		return old, nil
	})

	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	if err := bindAndVerify("hostnameport", "example.com:443", stubHash, func() error { return nil }); err != nil {
		t.Fatalf("最小快照替换应维持现有可用性策略, got %v", err)
	}
	want := "exec:http add sslcert hostnameport=example.com:443 certhash=" + stubHash +
		" appid={4dc3e181-e14b-4a21-b022-59fc669b0914} certstorename=MY"
	if got := r.addCall(); got != want {
		t.Fatalf("降级路径应保留 AppID 且不生成高级参数\n got=%s\nwant=%s", got, want)
	}
	if !strings.Contains(logs.String(), "高级 SSL 参数无法保真") {
		t.Fatalf("降级路径必须记录保真告警, logs=%q", logs.String())
	}
}

// TestBindAndVerify_RollbackWhenAddFails 捕获到旧绑定、删除已生效但新证书添加失败时，
// 必须用捕获的快照把旧证书加回去，避免站点 HTTPS 下线。
func TestBindAndVerify_RollbackWhenAddFails(t *testing.T) {
	deleted, restored := false, false
	r := &netshRecorder{
		onQuery: func([]string) (string, error) {
			if restored || !deleted {
				return fmt.Sprintf("Certificate Hash : %s\n", oldHash), nil
			}
			return "", exitErr() // 已删除且新证书未加上：确认该键当前无绑定
		},
		onExec: func(args []string) (string, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "delete sslcert"):
				deleted = true
				return "", nil
			case strings.Contains(joined, "add sslcert") && strings.Contains(joined, oldHash):
				restored = true
				return "", nil
			default: // 添加新证书失败
				return "参数错误", errors.New("add 失败")
			}
		},
	}
	installNetshStub(t, r, func(string, string) (*capturedBinding, error) {
		return nil, errors.New("httpapi 不可用")
	})

	err := bindAndVerify("hostnameport", "example.com:443", stubHash, func() error {
		_, e := netshExec("http", "delete", "sslcert", "hostnameport=example.com:443")
		return e
	})
	if err == nil {
		t.Fatal("新绑定未生效应返回错误")
	}
	if !restored {
		t.Fatalf("应回绑旧证书, 调用序列: %v", r.calls)
	}
	if !strings.Contains(err.Error(), "已回绑旧证书") {
		t.Errorf("错误信息应说明已回绑, got %v", err)
	}
}
