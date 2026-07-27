package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseResponsePreservesStructuredError(t *testing.T) {
	_, err := parseResponse([]byte(`{
		"code": 0,
		"msg": "Deploy token rate limit exceeded",
		"errors": {"error_code": "rate_limited", "retry_after": 100}
	}`), http.StatusOK)
	if got := ErrorCodeOf(err); got != ErrorCodeRateLimited {
		t.Fatalf("ErrorCodeOf() = %q, want %q; err=%v", got, ErrorCodeRateLimited, err)
	}
	if got := RetryAfterOf(err); got != 100 {
		t.Fatalf("RetryAfterOf() = %d, want 100", got)
	}
	if !strings.Contains(err.Error(), ErrorCodeRateLimited) || !strings.Contains(err.Error(), "100") {
		t.Fatalf("错误文本必须携带 error_code/retry_after: %v", err)
	}
}

func TestParseResponseValidationBagRemainsUnclassified(t *testing.T) {
	_, err := parseResponse([]byte(`{
		"code": 0,
		"msg": "The order field is required.",
		"errors": {"order": ["The order field is required."]}
	}`), http.StatusOK)
	if got := ErrorCodeOf(err); got != "" {
		t.Fatalf("参数校验袋不得误判为结构化分类，got %q", got)
	}
}

func TestValidateOrderQuery(t *testing.T) {
	valid := []string{"0", "00", "1", "1,0", "1,2,300"}
	for _, query := range valid {
		if err := ValidateOrderQuery(query); err != nil {
			t.Errorf("ValidateOrderQuery(%q) error = %v", query, err)
		}
	}
	invalid := []string{"", "example.com", "1,example.com", "1,", ",1", " 1"}
	for _, query := range invalid {
		if got := ErrorCodeOf(ValidateOrderQuery(query)); got != ErrorCodeInvalidOrder {
			t.Errorf("ValidateOrderQuery(%q) code = %q, want %q", query, got, ErrorCodeInvalidOrder)
		}
	}
	tooMany := strings.TrimSuffix(strings.Repeat("1,", 101), ",")
	if got := ErrorCodeOf(ValidateOrderQuery(tooMany)); got != ErrorCodeInvalidOrder {
		t.Fatalf("101 个订单 code = %q, want %q", got, ErrorCodeInvalidOrder)
	}
}

func TestListCertsByQueryDoesNotPaginate(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.URL.Query().Get("order"); got != "1,2" {
			t.Errorf("order = %q, want 1,2", got)
		}
		if r.URL.Query().Has("page") || r.URL.Query().Has("page_size") {
			t.Errorf("查询不得携带分页参数: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"code":1,"msg":"ok","data":{"data":[],"renew_before_days":14}}`))
	}))
	defer server.Close()

	client := NewClient(server.URL, "token")
	if _, err := client.ListCertsByQuery(context.Background(), "1,2"); err != nil {
		t.Fatalf("ListCertsByQuery() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("请求次数 = %d, want 1", requests)
	}
}

func TestSubmitCSRDoesNotRetryUncertainTransport(t *testing.T) {
	calls := 0
	client := NewClient("http://127.0.0.1", "token")
	client.HTTPClient.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		// 请求可能已到达服务端，只是响应在客户端确认前断开。
		return nil, errors.New("connection reset after request write")
	})

	_, err := client.SubmitCSR(context.Background(), &UpdateRequest{
		OrderID: 1,
		CSR:     "same-csr",
		Domains: "example.com",
	})
	if err == nil || ErrorCodeOf(err) != "" {
		t.Fatalf("传输结果不确定应原样返回且不伪造业务码: %v", err)
	}
	if calls != 1 {
		t.Fatalf("CSR POST 请求次数 = %d, want 1", calls)
	}
}

func TestSubmitCSRRejectsNonPositiveOrderBeforeNetwork(t *testing.T) {
	calls := 0
	client := NewClient("http://127.0.0.1", "token")
	client.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("不应发起请求")
	})

	for _, orderID := range []int{0, -1} {
		_, err := client.SubmitCSR(context.Background(), &UpdateRequest{OrderID: orderID, CSR: "csr"})
		if got := ErrorCodeOf(err); got != ErrorCodeOrderNotFound {
			t.Errorf("SubmitCSR(order_id=%d) code = %q, want %q", orderID, got, ErrorCodeOrderNotFound)
		}
	}
	if calls != 0 {
		t.Fatalf("无效订单不得访问网络，calls=%d", calls)
	}
}

func TestGetCertByOrderIDRejectsNonPositiveOrderBeforeNetwork(t *testing.T) {
	calls := 0
	client := NewClient("http://127.0.0.1", "token")
	client.HTTPClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("不应发起请求")
	})

	for _, orderID := range []int{0, -1} {
		_, err := client.GetCertByOrderID(context.Background(), orderID)
		if got := ErrorCodeOf(err); got != ErrorCodeOrderNotFound {
			t.Errorf("GetCertByOrderID(%d) code = %q, want %q", orderID, got, ErrorCodeOrderNotFound)
		}
	}
	if calls != 0 {
		t.Fatalf("无效订单不得访问网络，calls=%d", calls)
	}
}
