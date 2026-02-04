//go:build integration

package integration

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"sslctlw/cert"
	"sslctlw/iis"
)

// isAdmin 检测是否以管理员权限运行
func isAdmin() bool {
	cmd := exec.Command("net", "session")
	err := cmd.Run()
	return err == nil
}

// RequireAdmin 要求管理员权限，否则跳过测试
func RequireAdmin(t *testing.T) {
	t.Helper()
	if !isAdmin() {
		t.Skip("此测试需要管理员权限")
	}
}

// isIISInstalled 检测 IIS 是否安装
func isIISInstalled() bool {
	cmd := exec.Command("sc", "query", "w3svc")
	output, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "RUNNING") ||
		strings.Contains(string(output), "STATE")
}

// RequireIIS 要求 IIS 已安装，否则跳过测试
func RequireIIS(t *testing.T) {
	t.Helper()
	if !isIISInstalled() {
		t.Skip("此测试需要 IIS 已安装")
	}
}

// checkNetworkAccess 检查网络访问
func checkNetworkAccess(url string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Head(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// CleanupCertificate 清理测试证书
func CleanupCertificate(thumbprint string) error {
	if thumbprint == "" {
		return nil
	}
	return cert.DeleteCertificate(thumbprint)
}

// CleanupBinding 清理 SSL 绑定
func CleanupBinding(hostname string, port int) error {
	return iis.UnbindCertificate(hostname, port)
}

// CleanupIPBinding 清理 IP SSL 绑定
func CleanupIPBinding(ip string, port int) error {
	return iis.UnbindCertificateByIP(ip, port)
}

// TestCleanup 测试清理辅助结构
type TestCleanup struct {
	t            *testing.T
	thumbprints  []string
	sniBindings  [][2]interface{} // [hostname, port]
	ipBindings   [][2]interface{} // [ip, port]
}

// NewTestCleanup 创建测试清理器
func NewTestCleanup(t *testing.T) *TestCleanup {
	return &TestCleanup{t: t}
}

// AddCertificate 添加需要清理的证书
func (c *TestCleanup) AddCertificate(thumbprint string) {
	if thumbprint != "" {
		c.thumbprints = append(c.thumbprints, thumbprint)
	}
}

// AddSNIBinding 添加需要清理的 SNI 绑定
func (c *TestCleanup) AddSNIBinding(hostname string, port int) {
	c.sniBindings = append(c.sniBindings, [2]interface{}{hostname, port})
}

// AddIPBinding 添加需要清理的 IP 绑定
func (c *TestCleanup) AddIPBinding(ip string, port int) {
	c.ipBindings = append(c.ipBindings, [2]interface{}{ip, port})
}

// Cleanup 执行清理
func (c *TestCleanup) Cleanup() {
	// 先解除绑定
	for _, b := range c.sniBindings {
		hostname := b[0].(string)
		port := b[1].(int)
		if err := CleanupBinding(hostname, port); err != nil {
			c.t.Logf("清理 SNI 绑定 %s:%d 失败: %v", hostname, port, err)
		}
	}

	for _, b := range c.ipBindings {
		ip := b[0].(string)
		port := b[1].(int)
		if err := CleanupIPBinding(ip, port); err != nil {
			c.t.Logf("清理 IP 绑定 %s:%d 失败: %v", ip, port, err)
		}
	}

	// 再删除证书
	for _, tp := range c.thumbprints {
		if err := CleanupCertificate(tp); err != nil {
			c.t.Logf("清理证书 %s 失败: %v", tp, err)
		}
	}
}

// verifyHTTPS 验证 HTTPS 访问
func verifyHTTPS(hostname string, port int) error {
	url := fmt.Sprintf("https://%s:%d/", hostname, port)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 测试环境允许自签名
			},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTPS 访问失败: %w", err)
	}
	defer resp.Body.Close()

	// 只要能建立 TLS 连接就算成功（不管 HTTP 状态码）
	return nil
}
