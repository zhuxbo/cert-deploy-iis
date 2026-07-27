package deploy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sslctlw/api"
)

type authBlock struct {
	code       string
	retryAfter int
}

func (b authBlock) description() string {
	if b.retryAfter > 0 {
		return fmt.Sprintf("%s，约 %d 秒后可重试", b.code, b.retryAfter)
	}
	return b.code
}

// authGate 是一次自动部署轮次内的 (url, token) 黑名单。
// token 只作内存键，不记录、不落盘。
type authGate struct {
	blocked map[string]authBlock
	skipped int
}

func apiTokenKey(client *api.Client) string {
	return client.BaseURL + "\x00" + client.Token
}

func (g *authGate) blockedBy(client *api.Client) (authBlock, bool) {
	if g == nil {
		return authBlock{}, false
	}
	block, ok := g.blocked[apiTokenKey(client)]
	return block, ok
}

func (g *authGate) record(client *api.Client, err error) bool {
	if g == nil || client == nil {
		return false
	}
	code := api.ErrorCodeOf(err)
	if !api.IsAuthBlockErrorCode(code) {
		return false
	}
	if g.blocked == nil {
		g.blocked = make(map[string]authBlock)
	}
	key := apiTokenKey(client)
	if _, exists := g.blocked[key]; !exists {
		g.blocked[key] = authBlock{code: code, retryAfter: api.RetryAfterOf(err)}
	}
	return true
}

func (g *authGate) markSkipped() {
	if g != nil {
		g.skipped++
	}
}

func (g *authGate) summary() string {
	if g == nil || len(g.blocked) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(g.blocked))
	reasons := make([]string, 0, len(g.blocked))
	for _, block := range g.blocked {
		reason := block.description()
		if _, ok := seen[reason]; ok {
			continue
		}
		seen[reason] = struct{}{}
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	return fmt.Sprintf("本轮有 %d 个 API 凭据组被拒绝（%s），已跳过后续 %d 张证书；请按 error_code 检查 Token、账号、IP 白名单或限流状态",
		len(g.blocked), strings.Join(reasons, ", "), g.skipped)
}

type apiCallTracker struct {
	madeCall        bool
	authBlocked     bool
	trackNoProgress bool
}

// trackedAPIClient 统一记录实际 API 调用和整批共通错误，避免各状态分支漏记。
type trackedAPIClient struct {
	APIClient
	concrete        *api.Client
	gate            *authGate
	tracker         *apiCallTracker
	beforeFirstCall func()
	started         bool
}

func (c *trackedAPIClient) beforeCall() {
	if c.started {
		return
	}
	c.started = true
	if c.beforeFirstCall != nil {
		c.beforeFirstCall()
	}
}

func (c *trackedAPIClient) record(err error) {
	c.tracker.madeCall = true
	if c.gate.record(c.concrete, err) {
		c.tracker.authBlocked = true
	}
}

func (c *trackedAPIClient) GetCertByOrderID(ctx context.Context, orderID int) (*api.CertData, error) {
	c.beforeCall()
	result, err := c.APIClient.GetCertByOrderID(ctx, orderID)
	c.record(err)
	return result, err
}

func (c *trackedAPIClient) ListCertsByQuery(ctx context.Context, query string) ([]api.CertData, error) {
	c.beforeCall()
	result, err := c.APIClient.ListCertsByQuery(ctx, query)
	c.record(err)
	return result, err
}

func (c *trackedAPIClient) SubmitCSR(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error) {
	c.beforeCall()
	result, err := c.APIClient.SubmitCSR(ctx, req)
	c.record(err)
	return result, err
}
