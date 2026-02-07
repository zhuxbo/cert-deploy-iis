package upgrade

import (
	"context"
	"io"
)

// ReleaseChecker 版本检测接口
type ReleaseChecker interface {
	// CheckUpdate 检查是否有可用更新
	// channel: "stable" 或 "beta"
	// currentVersion: 当前版本号（如 "1.2.3"）
	// 返回: 最新版本信息，如果没有更新返回 nil
	CheckUpdate(ctx context.Context, channel string, currentVersion string) (*ReleaseInfo, error)

	// GetUpgradePath 获取升级路径（用于链式跨版本升级）
	// currentVersion: 当前版本
	// targetVersion: 目标版本
	// 返回: 升级路径（包含中间版本），如果可以直接升级返回 nil
	GetUpgradePath(ctx context.Context, currentVersion, targetVersion string) (*UpgradePath, error)
}

// ProgressCallback 进度回调函数
// downloaded: 已下载字节数
// total: 总字节数（-1 表示未知）
// speed: 下载速度（字节/秒）
type ProgressCallback func(downloaded, total int64, speed float64)

// FileDownloader 文件下载接口
type FileDownloader interface {
	// Download 下载文件到指定路径
	Download(ctx context.Context, url string, destPath string, onProgress ProgressCallback) error

	// DownloadToWriter 下载到 Writer
	DownloadToWriter(ctx context.Context, url string, w io.Writer, onProgress ProgressCallback) error
}

// SignatureVerifier 签名验证接口
type SignatureVerifier interface {
	// Verify 验证文件签名
	// filePath: 文件路径
	// trustedFingerprints: 预埋的证书指纹白名单
	// fallbackConfig: 回退验证配置（指纹不匹配时使用）
	Verify(filePath string, trustedFingerprints []string, fallbackConfig *FallbackVerifyConfig) (*VerifyResult, error)
}

// FallbackVerifyConfig 回退验证配置
type FallbackVerifyConfig struct {
	TrustedOrg     string   // 可信组织名称（精确匹配）
	TrustedCountry string   // 可信国家代码（精确匹配）
	TrustedCAs     []string // 可信 CA 列表
}

// SelfUpdater 自我更新接口
type SelfUpdater interface {
	// PrepareUpdate 准备更新（备份当前版本）
	PrepareUpdate(ctx context.Context, newExePath string) (*UpdatePlan, error)

	// ApplyUpdate 应用更新（替换可执行文件）
	ApplyUpdate(plan *UpdatePlan) error

	// Rollback 回滚到备份版本
	Rollback(plan *UpdatePlan) error

	// Cleanup 清理临时文件和旧备份
	Cleanup(plan *UpdatePlan) error
}
