package util

import (
	"testing"
)

func TestValidateSiteName(t *testing.T) {
	tests := []struct {
		name     string
		siteName string
		wantErr  bool
	}{
		// 有效的站点名称
		{"简单英文", "Default Web Site", false},
		{"带数字", "Site123", false},
		{"带连字符", "my-site", false},
		{"带下划线", "my_site", false},
		{"带点", "site.example", false},
		{"中文名称", "中文站点", false},
		{"中英混合", "站点Site", false},
		{"纯数字", "123", false},

		// 无效的站点名称
		{"空字符串", "", true},
		{"包含单引号", "site'name", true},
		{"包含双引号", "site\"name", true},
		{"包含反引号", "site`name", true},
		{"包含美元符号", "site$name", true},
		{"包含分号", "site;name", true},
		{"包含和号", "site&name", true},
		{"包含管道", "site|name", true},
		{"包含小于号", "site<name", true},
		{"包含大于号", "site>name", true},
		{"包含换行", "site\nname", true},
		{"包含回车", "site\rname", true},
		{"包含制表符", "site\tname", true},
		{"包含斜杠", "site/name", true},
		{"包含反斜杠", "site\\name", true},
		{"包含星号", "site*name", true},
		{"包含问号", "site?name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSiteName(tt.siteName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSiteName(%q) error = %v, wantErr %v", tt.siteName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateSiteNameStrict(t *testing.T) {
	tests := []struct {
		name     string
		siteName string
		wantErr  bool
	}{
		// 有效的站点名称
		{"简单英文", "DefaultWebSite", false},
		{"带空格", "Default Web Site", false},
		{"带数字", "Site123", false},
		{"带连字符", "my-site", false},
		{"带下划线", "my_site", false},
		{"中文名称", "中文站点", false},

		// 在严格模式下无效的
		{"带点", "site.example", true}, // 严格模式不允许点
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSiteNameStrict(tt.siteName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSiteNameStrict(%q) error = %v, wantErr %v", tt.siteName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateThumbprint(t *testing.T) {
	tests := []struct {
		name       string
		thumbprint string
		wantErr    bool
	}{
		{"有效40位", "ABC123DEF456789012345678901234567890ABCD", false},
		{"有效40位小写", "abc123def456789012345678901234567890abcd", false},
		{"有效带空格", "ABC1 23DE F456 7890 1234 5678 9012 3456 7890 ABCD", false},
		{"有效带连字符", "ABC1-23DE-F456-7890-1234-5678-9012-3456-7890-ABCD", false},
		{"太短", "ABC123", true},
		{"太长", "ABC123DEF456789012345678901234567890ABCDEF", true},
		{"包含非十六进制", "XYZ123DEF456789012345678901234567890ABCD", true},
		{"空字符串", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateThumbprint(tt.thumbprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateThumbprint(%q) error = %v, wantErr %v", tt.thumbprint, err, tt.wantErr)
			}
		})
	}
}

func TestNormalizeThumbprint(t *testing.T) {
	tests := []struct {
		name       string
		thumbprint string
		want       string
		wantErr    bool
	}{
		{
			"已规范化",
			"ABC123DEF456789012345678901234567890ABCD",
			"ABC123DEF456789012345678901234567890ABCD",
			false,
		},
		{
			"小写转大写",
			"abc123def456789012345678901234567890abcd",
			"ABC123DEF456789012345678901234567890ABCD",
			false,
		},
		{
			"移除空格",
			"ABC1 23DE F456 7890 1234 5678 9012 3456 7890 ABCD",
			"ABC123DEF456789012345678901234567890ABCD",
			false,
		},
		{
			"移除连字符",
			"ABC1-23DE-F456-7890-1234-5678-9012-3456-7890-ABCD",
			"ABC123DEF456789012345678901234567890ABCD",
			false,
		},
		{
			"无效指纹",
			"invalid",
			"",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeThumbprint(tt.thumbprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("NormalizeThumbprint(%q) error = %v, wantErr %v", tt.thumbprint, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("NormalizeThumbprint(%q) = %v, want %v", tt.thumbprint, got, tt.want)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		// 有效域名
		{"简单域名", "example.com", false},
		{"带子域名", "www.example.com", false},
		{"多级子域名", "sub.www.example.com", false},
		{"通配符域名", "*.example.com", false},
		{"带数字", "example123.com", false},
		{"带连字符", "my-site.example.com", false},

		// 无效域名
		{"空字符串", "", true},
		{"双通配符", "**.example.com", true},
		{"中间通配符", "sub.*.example.com", true},
		{"以连字符开头", "-example.com", true},
		{"以连字符结尾", "example-.com", true},
		{"包含下划线", "my_site.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"端口 1", 1, false},
		{"端口 80", 80, false},
		{"端口 443", 443, false},
		{"端口 8080", 8080, false},
		{"端口 65535", 65535, false},
		{"端口 0", 0, true},
		{"端口 -1", -1, true},
		{"端口 65536", 65536, true},
		{"端口 100000", 100000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort(%d) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

func TestIsPathWithinBase(t *testing.T) {
	tests := []struct {
		name       string
		basePath   string
		targetPath string
		want       bool
	}{
		{"相同路径", "C:\\inetpub\\wwwroot", "C:\\inetpub\\wwwroot", true},
		{"子目录", "C:\\inetpub\\wwwroot", "C:\\inetpub\\wwwroot\\site", true},
		{"深层子目录", "C:\\inetpub\\wwwroot", "C:\\inetpub\\wwwroot\\a\\b\\c", true},
		{"同级目录", "C:\\inetpub\\wwwroot", "C:\\inetpub\\other", false},
		{"父目录", "C:\\inetpub\\wwwroot", "C:\\inetpub", false},
		{"完全不同的路径", "C:\\inetpub\\wwwroot", "D:\\data", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPathWithinBase(tt.basePath, tt.targetPath)
			if got != tt.want {
				t.Errorf("IsPathWithinBase(%q, %q) = %v, want %v", tt.basePath, tt.targetPath, got, tt.want)
			}
		})
	}
}

func TestValidateRelativePath(t *testing.T) {
	// 创建临时目录用于测试
	basePath := "C:\\inetpub\\wwwroot"

	tests := []struct {
		name         string
		basePath     string
		relativePath string
		wantErr      bool
	}{
		{"正常相对路径", basePath, ".well-known\\acme-challenge\\token", false},
		{"带前导斜杠", basePath, "\\.well-known\\acme-challenge\\token", false},
		{"路径遍历攻击", basePath, "..\\..\\etc\\passwd", true},
		{"隐藏路径遍历", basePath, ".well-known\\..\\..\\etc\\passwd", true},
		{"空基础路径", "", "test", true},
		{"空相对路径", basePath, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateRelativePath(tt.basePath, tt.relativePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRelativePath(%q, %q) error = %v, wantErr %v", tt.basePath, tt.relativePath, err, tt.wantErr)
			}
		})
	}
}

func TestEscapePowerShellString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"无特殊字符", "hello", "hello"},
		{"单引号", "it's", "it''s"},
		{"多个单引号", "it's a 'test'", "it''s a ''test''"},
		{"空字符串", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EscapePowerShellString(tt.input)
			if got != tt.want {
				t.Errorf("EscapePowerShellString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEscapePowerShellDoubleQuoteString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"无特殊字符", "hello", "hello"},
		{"反引号", "test`cmd", "test``cmd"},
		{"美元符号", "test$var", "test`$var"},
		{"双引号", "test\"value", "test`\"value"},
		{"多种字符", "test`$\"all", "test```$`\"all"},
		{"空字符串", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EscapePowerShellDoubleQuoteString(tt.input)
			if got != tt.want {
				t.Errorf("EscapePowerShellDoubleQuoteString(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  bool
	}{
		// 有效的主机名
		{"简单主机名", "example", false},
		{"带域名", "www.example.com", false},
		{"带数字", "server1.example.com", false},
		{"带连字符", "my-server.example.com", false},
		{"纯数字开头", "123server.com", false},

		// 无效的主机名
		{"空字符串", "", true},
		{"以连字符开头", "-example.com", true},
		{"以连字符结尾", "example-.com", true},
		{"包含下划线", "my_server.com", true},
		{"包含空格", "my server.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHostname(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname(%q) error = %v, wantErr %v", tt.hostname, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTaskName(t *testing.T) {
	tests := []struct {
		name     string
		taskName string
		wantErr  bool
	}{
		// 有效的任务名称
		{"简单名称", "CertDeployIIS", false},
		{"带数字", "Task123", false},
		{"带连字符", "my-task", false},
		{"带下划线", "my_task", false},
		{"带点", "my.task", false},
		{"纯数字", "123", false},

		// 无效的任务名称
		{"空字符串", "", true},
		{"带空格", "my task", true},
		{"带中文", "任务", true},
		{"带特殊字符", "task@name", true},
		{"带斜杠", "task/name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTaskName(tt.taskName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTaskName(%q) error = %v, wantErr %v", tt.taskName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateFriendlyName(t *testing.T) {
	tests := []struct {
		name         string
		friendlyName string
		wantErr      bool
	}{
		// 有效的友好名称
		{"简单名称", "My Certificate", false},
		{"带域名", "example.com SSL", false},
		{"带数字", "Cert2024", false},
		{"中文名称", "我的证书", false},

		// 无效的友好名称
		{"空字符串", "", true},
		{"带单引号", "My'Cert", true},
		{"带双引号", "My\"Cert", true},
		{"带反引号", "My`Cert", true},
		{"带美元符号", "My$Cert", true},
		{"带分号", "My;Cert", true},
		{"带和号", "My&Cert", true},
		{"带管道", "My|Cert", true},
		{"带小于号", "My<Cert", true},
		{"带大于号", "My>Cert", true},
		{"带换行", "My\nCert", true},
		{"带回车", "My\rCert", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFriendlyName(tt.friendlyName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFriendlyName(%q) error = %v, wantErr %v", tt.friendlyName, err, tt.wantErr)
			}
		})
	}
}

func TestValidateIPv4(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		// 有效的 IPv4 地址
		{"通配 IP", "0.0.0.0", false},
		{"本地回环", "127.0.0.1", false},
		{"私有地址", "192.168.1.1", false},
		{"公网地址", "8.8.8.8", false},
		{"最大地址", "255.255.255.255", false},

		// 无效的 IP
		{"空字符串", "", true},
		{"IPv6 地址", "2001:db8::1", true},
		{"无效格式", "256.1.1.1", true},
		{"非 IP 字符串", "not-an-ip", true},
		{"缺少部分", "192.168.1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv4(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPv4(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

func TestValidateDomain_LongDomain(t *testing.T) {
	// 测试超长域名
	longDomain := ""
	for i := 0; i < 260; i++ {
		longDomain += "a"
	}
	longDomain += ".com"

	err := ValidateDomain(longDomain)
	if err == nil {
		t.Error("ValidateDomain() 应该对超长域名返回错误")
	}
}

func TestValidateSiteName_LongName(t *testing.T) {
	// 测试超长站点名称
	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}

	err := ValidateSiteName(longName)
	if err == nil {
		t.Error("ValidateSiteName() 应该对超长名称返回错误")
	}
}

func TestValidateHostname_LongHostname(t *testing.T) {
	// 测试超长主机名
	longHostname := ""
	for i := 0; i < 260; i++ {
		longHostname += "a"
	}
	longHostname += ".com"

	err := ValidateHostname(longHostname)
	if err == nil {
		t.Error("ValidateHostname() 应该对超长主机名返回错误")
	}
}

// TestValidateIPv4_MoreCases 更多 IPv4 验证测试
func TestValidateIPv4_MoreCases(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		// 有效 IPv4
		{"通配 IP", "0.0.0.0", false},
		{"本地回环", "127.0.0.1", false},
		{"私有地址 A 类", "10.0.0.1", false},
		{"私有地址 B 类", "172.16.0.1", false},
		{"私有地址 C 类", "192.168.1.1", false},
		{"公网地址", "8.8.8.8", false},
		{"边界值最小", "0.0.0.1", false},
		{"边界值最大", "255.255.255.255", false},

		// 无效 IPv4
		{"空字符串", "", true},
		{"超出范围", "256.1.1.1", true},
		{"负数", "-1.1.1.1", true},
		{"字母", "a.b.c.d", true},
		{"IPv6", "::1", true},
		{"缺少部分", "192.168.1", true},
		{"多余部分", "192.168.1.1.1", true},
		{"带端口", "192.168.1.1:8080", true},
		{"带空格", "192.168.1. 1", true},
		{"前导零", "01.02.03.04", true}, // Go 的 net.ParseIP 不接受前导零
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIPv4(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIPv4(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

// TestEvalSymlinksPartial 测试部分路径解析
func TestEvalSymlinksPartial(t *testing.T) {
	// 测试存在的路径
	existingPath := "C:\\Windows"
	result, err := evalSymlinksPartial(existingPath)
	if err != nil {
		t.Skipf("evalSymlinksPartial(%q) error = %v（路径可能不存在）", existingPath, err)
	}
	if result == "" {
		t.Error("结果不应为空")
	}

	// 测试部分存在的路径
	partialPath := "C:\\Windows\\nonexistent\\path\\file.txt"
	result, err = evalSymlinksPartial(partialPath)
	if err != nil {
		t.Errorf("evalSymlinksPartial(%q) error = %v", partialPath, err)
	}
	// 结果应该包含 nonexistent/path/file.txt
	if result == "" {
		t.Error("结果不应为空")
	}
}

// TestIsPathWithinBase_MoreCases 更多路径检查测试
func TestIsPathWithinBase_MoreCases(t *testing.T) {
	tests := []struct {
		name       string
		basePath   string
		targetPath string
		want       bool
	}{
		// 正常情况
		{"相同路径", "C:\\test", "C:\\test", true},
		{"子目录", "C:\\test", "C:\\test\\sub", true},
		{"深层子目录", "C:\\test", "C:\\test\\a\\b\\c\\d", true},
		{"同名前缀但不同目录", "C:\\test", "C:\\testing", false},

		// 路径遍历
		{"路径遍历-简单", "C:\\test", "C:\\test\\..\\other", false},
		{"路径遍历-复杂", "C:\\test", "C:\\test\\sub\\..\\..\\other", false},

		// 大小写（Windows 实际上区分大小写的比较）
		{"大小写差异", "C:\\Test", "C:\\Test\\sub", true},

		// 相对路径
		{"相对路径", "test", "test\\sub", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPathWithinBase(tt.basePath, tt.targetPath)
			if got != tt.want {
				t.Errorf("IsPathWithinBase(%q, %q) = %v, want %v", tt.basePath, tt.targetPath, got, tt.want)
			}
		})
	}
}

// TestValidateRelativePath_MoreCases 更多相对路径验证测试
func TestValidateRelativePath_MoreCases(t *testing.T) {
	basePath := "C:\\inetpub\\wwwroot"

	tests := []struct {
		name         string
		basePath     string
		relativePath string
		wantErr      bool
	}{
		// 有效路径
		{"简单相对路径", basePath, "test.txt", false},
		{"带子目录", basePath, "subdir\\test.txt", false},
		{".well-known 路径", basePath, ".well-known\\acme-challenge\\token", false},
		{"带前导斜杠", basePath, "\\test.txt", false},
		{"带前导正斜杠", basePath, "/test.txt", false},

		// 无效路径
		{"空基础路径", "", "test.txt", true},
		{"空相对路径", basePath, "", true},
		{"路径遍历", basePath, "..\\test.txt", true},
		{"隐藏路径遍历", basePath, "sub\\..\\..\\test.txt", true},
		{"多重路径遍历", basePath, "..\\..\\..\\etc\\passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateRelativePath(tt.basePath, tt.relativePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRelativePath(%q, %q) error = %v, wantErr %v",
					tt.basePath, tt.relativePath, err, tt.wantErr)
			}
		})
	}
}

// TestValidateFriendlyName_MoreCases 更多友好名称测试
func TestValidateFriendlyName_MoreCases(t *testing.T) {
	tests := []struct {
		name         string
		friendlyName string
		wantErr      bool
	}{
		// 有效名称
		{"简单名称", "MyCert", false},
		{"带空格", "My Certificate", false},
		{"中文名称", "我的证书", false},
		{"带数字", "Cert2024", false},
		{"带点", "example.com SSL", false},
		{"带连字符", "my-cert", false},

		// 无效名称
		{"空字符串", "", true},
		{"单引号", "My'Cert", true},
		{"双引号", "My\"Cert", true},
		{"反引号", "My`Cert", true},
		{"美元符号", "My$Cert", true},
		{"分号", "My;Cert", true},
		{"换行", "My\nCert", true},
		{"管道", "My|Cert", true},
		{"小于号", "My<Cert", true},
		{"大于号", "My>Cert", true},
		{"和号", "My&Cert", true},
		{"回车", "My\rCert", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFriendlyName(tt.friendlyName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFriendlyName(%q) error = %v, wantErr %v",
					tt.friendlyName, err, tt.wantErr)
			}
		})
	}
}

// TestValidateFriendlyName_LongName 测试超长友好名称
func TestValidateFriendlyName_LongName(t *testing.T) {
	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}

	err := ValidateFriendlyName(longName)
	if err == nil {
		t.Error("ValidateFriendlyName() 应该对超长名称返回错误")
	}
}

// TestValidateTaskName_MoreCases 更多任务名称测试
func TestValidateTaskName_MoreCases(t *testing.T) {
	tests := []struct {
		name     string
		taskName string
		wantErr  bool
	}{
		// 有效名称
		{"简单名称", "MyTask", false},
		{"带数字", "Task123", false},
		{"带连字符", "my-task", false},
		{"带下划线", "my_task", false},
		{"带点", "my.task", false},
		{"纯数字", "123456", false},
		{"混合字符", "My_Task-1.0", false},

		// 无效名称
		{"空字符串", "", true},
		{"带空格", "My Task", true},
		{"中文", "我的任务", true},
		{"带斜杠", "task/name", true},
		{"带反斜杠", "task\\name", true},
		{"带特殊字符", "task@name", true},
		{"带星号", "task*name", true},
		{"带问号", "task?name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTaskName(tt.taskName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTaskName(%q) error = %v, wantErr %v",
					tt.taskName, err, tt.wantErr)
			}
		})
	}
}

// TestValidateTaskName_LongName 测试超长任务名称
func TestValidateTaskName_LongName(t *testing.T) {
	longName := ""
	for i := 0; i < 300; i++ {
		longName += "a"
	}

	err := ValidateTaskName(longName)
	if err == nil {
		t.Error("ValidateTaskName() 应该对超长名称返回错误")
	}
}

// TestValidatePort_AllRanges 测试所有端口范围
func TestValidatePort_AllRanges(t *testing.T) {
	tests := []struct {
		name    string
		port    int
		wantErr bool
	}{
		// 边界值
		{"最小有效端口", 1, false},
		{"最大有效端口", 65535, false},
		{"零端口", 0, true},
		{"超过最大", 65536, true},
		{"负数端口", -1, true},
		{"大负数", -65535, true},

		// 常用端口
		{"HTTP 端口", 80, false},
		{"HTTPS 端口", 443, false},
		{"SSH 端口", 22, false},
		{"FTP 端口", 21, false},
		{"MySQL 端口", 3306, false},
		{"PostgreSQL 端口", 5432, false},
		{"Redis 端口", 6379, false},
		{"高端口", 49152, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort(%d) error = %v, wantErr %v",
					tt.port, err, tt.wantErr)
			}
		})
	}
}
