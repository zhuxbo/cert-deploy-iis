package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"sslctlw/api"
)

// GitHubChecker GitHub Release 版本检测器
type GitHubChecker struct {
	apiURL     string
	httpClient *http.Client
}

// NewGitHubChecker 创建 GitHub Release 检测器
func NewGitHubChecker(apiURL string) *GitHubChecker {
	return &GitHubChecker{
		apiURL: apiURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ReleasesData releases.json 顶层结构（spec 6.1）
// 通道名做顶层 key：{"main": {...}, "dev": {...}}
type ReleasesData map[string]ChannelRelease

// ChannelRelease 单个通道的版本数据
type ChannelRelease struct {
	Latest   string         `json:"latest"`
	Versions []VersionEntry `json:"versions"`
}

// VersionEntry releases.json 中的版本条目（spec 6.1）
type VersionEntry struct {
	Version    string            `json:"version"`
	ReleasedAt string            `json:"released_at"`
	Checksums  map[string]string `json:"checksums"` // {filename: "sha256:..."}
}

// productFilename 构建当前平台的产物文件名（spec §8.1）
// 格式: {product}-{os}-{arch}.{ext}，版本在目录路径中体现
func productFilename() string {
	return "sslctlw-windows-amd64.exe"
}

// CheckUpdate 检查是否有可用更新（spec 6.1-6.3）
// 读取 releases.json，按 upgrade_channel 读取对应通道数据
func (c *GitHubChecker) CheckUpdate(ctx context.Context, channel string, currentVersion string) (*ReleaseInfo, error) {
	if c.apiURL == "" {
		return nil, fmt.Errorf("Release API 地址未配置")
	}
	if !ValidChannel(Channel(channel)) {
		return nil, fmt.Errorf("无效的升级通道: %q", channel)
	}

	// SSRF 防护（spec 10.1）
	if allowed, reason := api.IsAllowedAPIURL(c.apiURL); !allowed {
		return nil, fmt.Errorf("升级地址不允许: %s", reason)
	}

	releasesURL := strings.TrimRight(c.apiURL, "/") + "/releases.json"

	req, err := http.NewRequestWithContext(ctx, "GET", releasesURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "sslctlw-updater")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var releasesData ReleasesData
	if err := json.Unmarshal(body, &releasesData); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	// 读取对应通道数据（spec 6.2）
	channelData, ok := releasesData[channel]
	if !ok || channelData.Latest == "" {
		return nil, nil
	}

	if CompareVersion(channelData.Latest, currentVersion) <= 0 {
		return nil, nil
	}

	// 在 versions 中找到 latest 对应条目
	var entry *VersionEntry
	for i := range channelData.Versions {
		if channelData.Versions[i].Version == channelData.Latest {
			entry = &channelData.Versions[i]
			break
		}
	}
	if entry == nil {
		return nil, nil
	}

	// 拼出文件名，从 checksums 获取哈希（spec 6.3）
	filename := productFilename()
	checksum := entry.Checksums[filename]
	if checksum == "" {
		return nil, fmt.Errorf("版本 %s 缺少 %s 的 SHA256 校验值", entry.Version, filename)
	}

	// 下载 URL: {release_url}/{channel}/v{version}/{filename}（spec 6.3）
	baseURL := strings.TrimRight(c.apiURL, "/")
	downloadURL := baseURL + "/" + channel + "/v" + entry.Version + "/" + filename

	return &ReleaseInfo{
		Version:     entry.Version,
		Channel:     Channel(channel),
		DownloadURL: downloadURL,
		Checksum:    checksum,
	}, nil
}

// CompareVersion 比较两个版本号
// 返回: -1 (v1 < v2), 0 (v1 == v2), 1 (v1 > v2)
// 支持格式: "1.2.3", "1.2.3-beta", "1.2.3-rc.1"
func CompareVersion(v1, v2 string) int {
	// 分离主版本号和预发布标签
	v1Main, v1Pre := splitVersion(v1)
	v2Main, v2Pre := splitVersion(v2)

	// 比较主版本号
	v1Parts := parseVersionParts(v1Main)
	v2Parts := parseVersionParts(v2Main)

	// 补齐长度
	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}
	for len(v1Parts) < maxLen {
		v1Parts = append(v1Parts, 0)
	}
	for len(v2Parts) < maxLen {
		v2Parts = append(v2Parts, 0)
	}

	// 逐段比较
	for i := 0; i < maxLen; i++ {
		if v1Parts[i] < v2Parts[i] {
			return -1
		}
		if v1Parts[i] > v2Parts[i] {
			return 1
		}
	}

	// 主版本号相同，比较预发布标签
	// 有预发布标签的版本 < 无预发布标签的版本
	// 例如: 1.0.0-beta < 1.0.0
	if v1Pre != "" && v2Pre == "" {
		return -1
	}
	if v1Pre == "" && v2Pre != "" {
		return 1
	}
	if v1Pre != "" && v2Pre != "" {
		return comparePreRelease(v1Pre, v2Pre)
	}

	return 0
}

// comparePreRelease 按 semver 规则比较预发布标签
// 例如: alpha < beta < rc.1 < rc.2 < rc.10
func comparePreRelease(pre1, pre2 string) int {
	parts1 := strings.Split(pre1, ".")
	parts2 := strings.Split(pre2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 string
		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		// 空段 < 非空段（更少的段表示更早的版本）
		if p1 == "" && p2 != "" {
			return -1
		}
		if p1 != "" && p2 == "" {
			return 1
		}

		// 尝试解析为数字
		n1, err1 := strconv.Atoi(p1)
		n2, err2 := strconv.Atoi(p2)

		if err1 == nil && err2 == nil {
			// 两者都是数字，按数值比较
			if n1 < n2 {
				return -1
			}
			if n1 > n2 {
				return 1
			}
		} else if err1 == nil {
			// 数字 < 字符串
			return -1
		} else if err2 == nil {
			// 字符串 > 数字
			return 1
		} else {
			// 两者都是字符串，按字典序比较
			if p1 < p2 {
				return -1
			}
			if p1 > p2 {
				return 1
			}
		}
	}

	return 0
}

// splitVersion 分离主版本号和预发布标签
// 先剥离 build metadata（semver: +xxx 不参与排序），再切分 pre-release
func splitVersion(v string) (main, pre string) {
	if idx := strings.IndexByte(v, '+'); idx != -1 {
		v = v[:idx]
	}
	if idx := strings.IndexByte(v, '-'); idx != -1 {
		return v[:idx], v[idx+1:]
	}
	return v, ""
}

// parseVersionParts 解析版本号各部分为整数
func parseVersionParts(v string) []int {
	parts := strings.Split(v, ".")
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		n, _ := strconv.Atoi(p)
		result = append(result, n)
	}
	return result
}

