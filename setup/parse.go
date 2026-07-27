package setup

import (
	"fmt"
	"net/url"
	"strings"

	"sslctlw/api"
)

// Options 一键部署选项
type Options struct {
	URL     string // API 地址
	Token   string // API Token
	Order   string // 逗号分隔的订单 ID（必填，最多 100 个）
	KeyPath string // 私钥文件路径（--key 参数）
}

func validateSetupOrderQuery(order string) error {
	if err := api.ValidateOrderQuery(order); err != nil {
		return err
	}
	for _, item := range strings.Split(order, ",") {
		if strings.TrimLeft(item, "0") == "" {
			return &api.APIError{
				Code:      0,
				Message:   "setup 只能配置已有的正整数订单 ID",
				ErrorCode: api.ErrorCodeInvalidOrder,
			}
		}
	}
	return nil
}

// ParseCommand 解析部署命令字符串
// 支持格式:
//
//	sslctlw setup --url <url> --token <token> --order <ids>
//	sslctl setup --url <url> --token <token> --order <ids>
//	--url <url> --token <token> --order <ids>
func ParseCommand(input string) (*Options, error) {
	// 合并多行为一行
	input = strings.ReplaceAll(input, "\r\n", " ")
	input = strings.ReplaceAll(input, "\n", " ")
	input = strings.TrimSpace(input)

	if input == "" {
		return nil, fmt.Errorf("命令为空")
	}

	// URL 格式：https://xxx?token=xxx&order=xxx
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		return parseURL(input)
	}

	// 命令格式：sslctlw setup --url <url> --token <token> ...
	args := tokenize(input)

	// 跳过程序名和 setup 子命令
	i := 0
	for i < len(args) {
		lower := strings.ToLower(args[i])
		if lower == "sslctlw" || lower == "sslctlw.exe" || lower == "sslctl" || lower == "setup" {
			i++
			continue
		}
		break
	}

	opts := &Options{}

	for i < len(args) {
		arg := args[i]
		switch arg {
		case "--url":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--url 需要参数")
			}
			i++
			opts.URL = args[i]
		case "--token":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--token 需要参数")
			}
			i++
			opts.Token = args[i]
		case "--order":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--order 需要参数")
			}
			i++
			opts.Order = args[i]
		case "--key":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--key 需要参数")
			}
			i++
			opts.KeyPath = args[i]
		case "--debug":
			// 忽略
		default:
			return nil, fmt.Errorf("未知参数: %s", arg)
		}
		i++
	}

	if opts.URL == "" {
		return nil, fmt.Errorf("缺少 --url 参数")
	}
	if opts.Token == "" {
		return nil, fmt.Errorf("缺少 --token 参数")
	}
	if opts.Order == "" {
		return nil, fmt.Errorf("缺少 --order 参数")
	}
	if err := validateSetupOrderQuery(opts.Order); err != nil {
		return nil, err
	}

	return opts, nil
}

// tokenize 将命令行字符串分割为 token（支持引号）
func tokenize(s string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == quoteChar {
				inQuote = false
			} else {
				current.WriteByte(c)
			}
		} else {
			if c == '"' || c == '\'' {
				inQuote = true
				quoteChar = c
			} else if c == ' ' || c == '\t' {
				if current.Len() > 0 {
					tokens = append(tokens, current.String())
					current.Reset()
				}
			} else {
				current.WriteByte(c)
			}
		}
	}

	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}

	return tokens
}

// parseURL 解析 URL 格式的部署链接
// 支持: https://xxx/api/deploy?token=xxx&order=xxx
func parseURL(input string) (*Options, error) {
	parsed, err := url.Parse(input)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("URL 格式无效")
	}

	query := parsed.Query()
	token := query.Get("token")
	if token == "" {
		return nil, fmt.Errorf("URL 缺少 token 参数")
	}

	// 基础 URL = scheme://host/path（不含查询参数）
	baseURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, parsed.Path)

	opts := &Options{
		URL:   baseURL,
		Token: token,
		Order: query.Get("order"),
	}
	if opts.Order == "" {
		return nil, fmt.Errorf("URL 缺少 order 参数")
	}
	if err := validateSetupOrderQuery(opts.Order); err != nil {
		return nil, err
	}

	return opts, nil
}
