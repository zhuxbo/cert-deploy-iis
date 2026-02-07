package upgrade

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// HTTPDownloader HTTP 文件下载器
type HTTPDownloader struct {
	httpClient *http.Client
}

// NewHTTPDownloader 创建 HTTP 下载器
func NewHTTPDownloader() *HTTPDownloader {
	return &HTTPDownloader{
		httpClient: &http.Client{
			Timeout: 30 * time.Minute, // 大文件下载超时
		},
	}
}

// Download 下载文件到指定路径
func (d *HTTPDownloader) Download(ctx context.Context, downloadURL string, destPath string, onProgress ProgressCallback) error {
	// 验证 URL
	if err := validateDownloadURL(downloadURL); err != nil {
		return err
	}

	// 创建目标目录
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}

	// 创建临时文件
	tmpPath := destPath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}

	// 下载到临时文件
	downloadErr := d.DownloadToWriter(ctx, downloadURL, f, onProgress)
	closeErr := f.Close()

	if downloadErr != nil {
		os.Remove(tmpPath)
		return downloadErr
	}
	if closeErr != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("关闭临时文件失败: %w", closeErr)
	}

	// 删除已存在的目标文件（Windows 上 Rename 不会覆盖）
	os.Remove(destPath)

	// 重命名为目标文件
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("重命名文件失败: %w", err)
	}

	return nil
}

// DownloadToWriter 下载到 Writer
func (d *HTTPDownloader) DownloadToWriter(ctx context.Context, downloadURL string, w io.Writer, onProgress ProgressCallback) error {
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("User-Agent", "sslctlw-updater")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("下载请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: HTTP %d", resp.StatusCode)
	}

	total := resp.ContentLength // 可能为 -1

	// 创建进度报告 reader
	reader := &progressReader{
		reader:     resp.Body,
		total:      total,
		onProgress: onProgress,
		startTime:  time.Now(),
	}

	// 复制数据
	_, err = io.Copy(w, reader)
	if err != nil {
		return fmt.Errorf("下载数据失败: %w", err)
	}

	return nil
}

// progressReader 带进度报告的 Reader
type progressReader struct {
	reader     io.Reader
	total      int64
	downloaded int64
	onProgress ProgressCallback
	startTime  time.Time
	lastReport time.Time
}

func (r *progressReader) Read(p []byte) (n int, err error) {
	n, err = r.reader.Read(p)
	if n > 0 {
		r.downloaded += int64(n)

		// 限制报告频率（每 100ms 报告一次）
		now := time.Now()
		if r.onProgress != nil && now.Sub(r.lastReport) >= 100*time.Millisecond {
			elapsed := now.Sub(r.startTime).Seconds()
			speed := float64(0)
			if elapsed > 0 {
				speed = float64(r.downloaded) / elapsed
			}
			r.onProgress(r.downloaded, r.total, speed)
			r.lastReport = now
		}
	}

	// 下载完成时最后报告一次
	if err == io.EOF && r.onProgress != nil {
		elapsed := time.Since(r.startTime).Seconds()
		speed := float64(0)
		if elapsed > 0 {
			speed = float64(r.downloaded) / elapsed
		}
		r.onProgress(r.downloaded, r.total, speed)
	}

	return n, err
}

// validateDownloadURL 验证下载 URL
func validateDownloadURL(downloadURL string) error {
	parsed, err := url.Parse(downloadURL)
	if err != nil {
		return fmt.Errorf("无效的下载地址: %w", err)
	}

	// 必须是 HTTPS（除了 localhost）
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())

	if scheme == "https" {
		return nil
	}

	if scheme == "http" {
		if host == "localhost" || host == "127.0.0.1" {
			return nil
		}
		return fmt.Errorf("下载地址必须使用 HTTPS: %s", downloadURL)
	}

	return fmt.Errorf("不支持的协议: %s", scheme)
}
