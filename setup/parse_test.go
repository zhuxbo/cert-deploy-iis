package setup

import "testing"

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantURL     string
		wantToken   string
		wantOrder   string
		wantKeyPath string
		wantErr     bool
	}{
		{
			name:      "完整命令",
			input:     "sslctlw setup --url https://api.example.com --token abc123 --order 123",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123",
		},
		{
			name:      "带 order",
			input:     "sslctlw setup --url https://api.example.com --token abc123 --order 123,456",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123,456",
		},
		{
			name:      "sslctl 格式",
			input:     "sslctl setup --url https://api.example.com --token abc123 --order 123",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123",
		},
		{
			name:      "无程序名",
			input:     "--url https://api.example.com --token abc123 --order 123",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123",
		},
		{
			name:      "带引号的 token",
			input:     `sslctlw setup --url https://api.example.com --token "abc 123" --order 123`,
			wantURL:   "https://api.example.com",
			wantToken: "abc 123",
			wantOrder: "123",
		},
		{
			name:      "多行输入",
			input:     "sslctlw setup\n--url https://api.example.com\n--token abc123\n--order 123",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123",
		},
		{
			name:      "带 debug",
			input:     "sslctlw setup --debug --url https://api.example.com --token abc123 --order 123",
			wantURL:   "https://api.example.com",
			wantToken: "abc123",
			wantOrder: "123",
		},
		{
			name:    "空命令",
			input:   "",
			wantErr: true,
		},
		{
			name:    "缺少 url",
			input:   "sslctlw setup --token abc123",
			wantErr: true,
		},
		{
			name:    "缺少 token",
			input:   "sslctlw setup --url https://api.example.com",
			wantErr: true,
		},
		{
			name:    "未知参数",
			input:   "sslctlw setup --url https://api.example.com --token abc123 --unknown foo",
			wantErr: true,
		},
		{
			name:    "url 无值",
			input:   "sslctlw setup --url",
			wantErr: true,
		},
		{
			name:        "带 key",
			input:       "sslctlw setup --url https://api.example.com --token abc123 --order 123 --key /path/to/key.pem",
			wantURL:     "https://api.example.com",
			wantToken:   "abc123",
			wantOrder:   "123",
			wantKeyPath: "/path/to/key.pem",
		},
		{
			name:    "key 无值",
			input:   "sslctlw setup --url https://api.example.com --token abc123 --key",
			wantErr: true,
		},
		{
			name:      "URL 格式带 order",
			input:     "https://www.cnssl.com/api/deploy?token=abc123&order=12345",
			wantURL:   "https://www.cnssl.com/api/deploy",
			wantToken: "abc123",
			wantOrder: "12345",
		},
		{
			name:    "URL 格式无 order",
			input:   "https://www.cnssl.com/api/deploy?token=abc123",
			wantErr: true,
		},
		{
			name:    "URL 格式缺少 token",
			input:   "https://www.cnssl.com/api/deploy?order=12345",
			wantErr: true,
		},
		{
			name:    "命令格式 order 为零",
			input:   "sslctlw setup --url https://api.example.com --token abc123 --order 0",
			wantErr: true,
		},
		{
			name:    "URL 格式 order 为零",
			input:   "https://www.cnssl.com/api/deploy?token=abc123&order=0",
			wantErr: true,
		},
		{
			name:    "批量 order 含零",
			input:   "sslctlw setup --url https://api.example.com --token abc123 --order 1,0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := ParseCommand(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("期望错误，但成功了")
				}
				return
			}
			if err != nil {
				t.Fatalf("不期望错误: %v", err)
			}
			if opts.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", opts.URL, tt.wantURL)
			}
			if opts.Token != tt.wantToken {
				t.Errorf("Token = %q, want %q", opts.Token, tt.wantToken)
			}
			if opts.Order != tt.wantOrder {
				t.Errorf("Order = %q, want %q", opts.Order, tt.wantOrder)
			}
			if opts.KeyPath != tt.wantKeyPath {
				t.Errorf("KeyPath = %q, want %q", opts.KeyPath, tt.wantKeyPath)
			}
		})
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a b c", []string{"a", "b", "c"}},
		{`"hello world"`, []string{"hello world"}},
		{`a "b c" d`, []string{"a", "b c", "d"}},
		{"  spaces  ", []string{"spaces"}},
		{`'single quotes'`, []string{"single quotes"}},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := tokenize(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("tokenize(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("tokenize(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}
