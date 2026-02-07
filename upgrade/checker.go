package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
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

// CheckUpdate 检查是否有可用更新
func (c *GitHubChecker) CheckUpdate(ctx context.Context, channel string, currentVersion string) (*ReleaseInfo, error) {
	if c.apiURL == "" {
		return nil, fmt.Errorf("Release API 地址未配置")
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "sslctlw-updater")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // 没有发布版本
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 限制 1MB
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var release ReleaseResponse
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	// 解析版本号（去掉 v 前缀）
	version := strings.TrimPrefix(release.TagName, "v")

	// 检查通道
	// stable 通道不接收 prerelease 版本
	// beta 通道接收所有版本
	if channel == string(ChannelStable) && release.Prerelease {
		return nil, nil
	}

	// 比较版本号
	cmp := CompareVersion(version, currentVersion)
	if cmp <= 0 {
		return nil, nil // 当前版本已是最新或更新
	}

	// 查找 Windows EXE 附件
	var downloadURL string
	var fileSize int64
	for _, asset := range release.Assets {
		if strings.HasSuffix(strings.ToLower(asset.Name), ".exe") {
			downloadURL = asset.BrowserDownloadURL
			fileSize = asset.Size
			break
		}
	}

	if downloadURL == "" {
		return nil, fmt.Errorf("未找到可下载的 EXE 文件")
	}

	// 解析发布说明中的元数据
	metadata := parseMetadata(release.Body)

	// 确定通道
	ch := ChannelStable
	if release.Prerelease {
		ch = ChannelBeta
	}

	info := &ReleaseInfo{
		Version:      version,
		Channel:      ch,
		DownloadURL:  downloadURL,
		FileSize:     fileSize,
		ReleaseNotes: cleanReleaseNotes(release.Body),
		MinVersion:   metadata["min_version"],
	}

	// 解析指纹列表
	if fps := metadata["fingerprints"]; fps != "" {
		info.Fingerprints = strings.Split(fps, ",")
		for i := range info.Fingerprints {
			info.Fingerprints[i] = strings.TrimSpace(info.Fingerprints[i])
		}
	}

	// 解析发布时间
	if t, err := time.Parse(time.RFC3339, release.PublishedAt); err == nil {
		info.ReleaseDate = t
	}

	return info, nil
}

// parseMetadata 从发布说明中解析元数据
// 格式: <!-- metadata: key=value; key2=value2 -->
func parseMetadata(body string) map[string]string {
	metadata := make(map[string]string)

	// 匹配 <!-- metadata: ... -->
	re := regexp.MustCompile(`<!--\s*metadata:\s*([^>]+)\s*-->`)
	matches := re.FindStringSubmatch(body)
	if len(matches) < 2 {
		return metadata
	}

	// 解析 key=value 对
	pairs := strings.Split(matches[1], ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			metadata[key] = value
		}
	}

	return metadata
}

// cleanReleaseNotes 清理发布说明（移除元数据注释）
func cleanReleaseNotes(body string) string {
	re := regexp.MustCompile(`<!--\s*metadata:[^>]+-->`)
	return strings.TrimSpace(re.ReplaceAllString(body, ""))
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
func splitVersion(v string) (main, pre string) {
	if idx := strings.IndexAny(v, "-+"); idx != -1 {
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

// GetUpgradePath 获取升级路径
func (c *GitHubChecker) GetUpgradePath(ctx context.Context, currentVersion, targetVersion string) (*UpgradePath, error) {
	if c.apiURL == "" {
		return nil, fmt.Errorf("Release API 地址未配置")
	}

	// 构建升级路径 API 地址
	// 格式: {apiURL}/path?from={currentVersion}&to={targetVersion}
	// 或者在同一 API 基础上添加查询参数
	pathURL := strings.TrimSuffix(c.apiURL, "/latest")
	pathURL = strings.TrimSuffix(pathURL, "/releases")
	pathURL = fmt.Sprintf("%s/upgrade-path?from=%s&to=%s", pathURL, currentVersion, targetVersion)

	req, err := http.NewRequestWithContext(ctx, "GET", pathURL, nil)
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
		// 没有升级路径，可能不需要链式升级
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var path UpgradePath
	if err := json.Unmarshal(body, &path); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if len(path.Steps) == 0 {
		return nil, nil
	}

	return &path, nil
}
