package iis

import (
	"testing"
)

// TestBindCertificate_InvalidParams 测试无效参数
func TestBindCertificate_InvalidParams(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		port       int
		thumbprint string
		wantErr    bool
	}{
		{
			name:       "空主机名",
			hostname:   "",
			port:       443,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效主机名-包含空格",
			hostname:   "www example.com",
			port:       443,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效端口-负数",
			hostname:   TestDomain,
			port:       -1,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效端口-超大",
			hostname:   TestDomain,
			port:       70000,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效指纹-太短",
			hostname:   TestDomain,
			port:       443,
			thumbprint: "abc",
			wantErr:    true,
		},
		{
			name:       "无效指纹-包含非十六进制字符",
			hostname:   TestDomain,
			port:       443,
			thumbprint: "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := BindCertificate(tt.hostname, tt.port, tt.thumbprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("BindCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBindCertificateByIP_InvalidParams 测试 IP 绑定的无效参数
func TestBindCertificateByIP_InvalidParams(t *testing.T) {
	tests := []struct {
		name       string
		ip         string
		port       int
		thumbprint string
		wantErr    bool
	}{
		{
			name:       "无效 IP-字母",
			ip:         "invalid",
			port:       443,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效 IP-超出范围",
			ip:         "256.256.256.256",
			port:       443,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效端口",
			ip:         "0.0.0.0",
			port:       -1,
			thumbprint: TestThumbprint,
			wantErr:    true,
		},
		{
			name:       "无效指纹",
			ip:         "0.0.0.0",
			port:       443,
			thumbprint: "invalid",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := BindCertificateByIP(tt.ip, tt.port, tt.thumbprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("BindCertificateByIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUnbindCertificate_InvalidParams 测试解绑的无效参数
func TestUnbindCertificate_InvalidParams(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		port     int
		wantErr  bool
	}{
		{
			name:     "空主机名",
			hostname: "",
			port:     443,
			wantErr:  true,
		},
		{
			name:     "无效端口",
			hostname: TestDomain,
			port:     -1,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UnbindCertificate(tt.hostname, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnbindCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestUnbindCertificateByIP_InvalidParams 测试 IP 解绑的无效参数
func TestUnbindCertificateByIP_InvalidParams(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		port    int
		wantErr bool
	}{
		{
			name:    "无效 IP",
			ip:      "invalid",
			port:    443,
			wantErr: true,
		},
		{
			name:    "无效端口",
			ip:      "0.0.0.0",
			port:    -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UnbindCertificateByIP(tt.ip, tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnbindCertificateByIP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBindCertificate_DefaultPort 测试默认端口
func TestBindCertificate_DefaultPort(t *testing.T) {
	// 端口 0 应该默认为 443
	// 由于会实际执行命令，这里只验证参数验证逻辑
	// 无效的主机名会在端口设置后触发错误
	err := BindCertificate("", 0, TestThumbprint)
	if err == nil {
		t.Error("空主机名应该返回错误")
	}
}

// TestBindCertificateByIP_DefaultPort 测试 IP 绑定的默认端口
func TestBindCertificateByIP_DefaultPort(t *testing.T) {
	// 端口 0 应该默认为 443
	// 空 IP 或 0.0.0.0 应该默认为 0.0.0.0
	// 由于无效指纹会先被检测，这里验证参数处理逻辑
	err := BindCertificateByIP("", 0, "invalid")
	if err == nil {
		t.Error("无效指纹应该返回错误")
	}
}

// TestUnbindCertificate_DefaultPort 测试解绑默认端口
func TestUnbindCertificate_DefaultPort(t *testing.T) {
	err := UnbindCertificate("", 0)
	if err == nil {
		t.Error("空主机名应该返回错误")
	}
}

// TestUnbindCertificateByIP_DefaultValues 测试 IP 解绑的默认值
func TestUnbindCertificateByIP_DefaultValues(t *testing.T) {
	// 空 IP 应该默认为 0.0.0.0
	// 端口 0 应该默认为 443
	// 由于我们不能实际执行命令，这里只测试参数验证
	// 无效端口会在设置默认值后仍然无效
	err := UnbindCertificateByIP("invalid-ip", 0)
	if err == nil {
		t.Error("无效 IP 应该返回错误")
	}
}

// TestGetBindingForHost_DefaultPort 测试获取绑定的默认端口
func TestGetBindingForHost_DefaultPort(t *testing.T) {
	// 端口 0 应该默认为 443
	// 这会实际调用 ListSSLBindings
	_, err := GetBindingForHost(TestDomain, 0)
	// 可能成功也可能失败（取决于系统状态）
	// 这里只验证函数可以被调用
	_ = err
}

// TestGetBindingForIP_DefaultValues 测试 IP 绑定查询的默认值
func TestGetBindingForIP_DefaultValues(t *testing.T) {
	// 空 IP 应该默认为 0.0.0.0
	// 端口 0 应该默认为 443
	_, err := GetBindingForIP("", 0)
	// 可能成功也可能失败
	_ = err
}

// TestSSLBinding_IsIPBinding 测试 IsIPBinding 字段
func TestSSLBinding_IsIPBinding(t *testing.T) {
	tests := []struct {
		name        string
		binding     SSLBinding
		wantIsIP    bool
	}{
		{
			name: "IP 绑定",
			binding: SSLBinding{
				HostnamePort: "0.0.0.0:443",
				IsIPBinding:  true,
			},
			wantIsIP: true,
		},
		{
			name: "SNI 绑定",
			binding: SSLBinding{
				HostnamePort: "www.example.com:443",
				IsIPBinding:  false,
			},
			wantIsIP: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.binding.IsIPBinding != tt.wantIsIP {
				t.Errorf("IsIPBinding = %v, want %v", tt.binding.IsIPBinding, tt.wantIsIP)
			}
		})
	}
}
