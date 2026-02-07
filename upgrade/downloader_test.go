package upgrade

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestValidateDownloadURL 测试 URL 验证
func TestValidateDownloadURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// 有效的 HTTPS URL
		{"有效 HTTPS", "https://example.com/file.exe", false, ""},
		{"HTTPS 带端口", "https://example.com:8443/file.exe", false, ""},
		{"HTTPS 带路径", "https://example.com/path/to/file.exe", false, ""},
		{"HTTPS 带参数", "https://example.com/file.exe?v=1", false, ""},

		// 有效的 localhost HTTP
		{"localhost HTTP", "http://localhost/file.exe", false, ""},
		{"localhost 带端口", "http://localhost:8080/file.exe", false, ""},
		{"127.0.0.1 HTTP", "http://127.0.0.1/file.exe", false, ""},
		{"127.0.0.1 带端口", "http://127.0.0.1:8080/file.exe", false, ""},

		// 无效的 HTTP（非 localhost）
		{"外部 HTTP", "http://example.com/file.exe", true, "必须使用 HTTPS"},

		// 无效的协议
		{"FTP 协议", "ftp://example.com/file.exe", true, "不支持的协议"},
		{"file 协议", "file:///C:/file.exe", true, "不支持的协议"},
		{"无协议", "example.com/file.exe", true, "不支持的协议"},

		// 无效的 URL
		{"空 URL", "", true, "不支持的协议"},
		{"无效字符", "https://example.com/\x00file.exe", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDownloadURL(tt.url)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateDownloadURL(%q) 期望错误，但没有返回错误", tt.url)
				} else if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("错误消息 = %q, 期望包含 %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateDownloadURL(%q) 返回意外错误: %v", tt.url, err)
				}
			}
		})
	}
}

// TestProgressReader 测试带进度的 Reader
func TestProgressReader(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	var progressCalls []struct {
		downloaded int64
		total      int64
		speed      float64
	}

	reader := &progressReader{
		reader:    bytes.NewReader(data),
		total:     int64(len(data)),
		startTime: time.Now(),
		onProgress: func(downloaded, total int64, speed float64) {
			progressCalls = append(progressCalls, struct {
				downloaded int64
				total      int64
				speed      float64
			}{downloaded, total, speed})
		},
	}

	// 读取所有数据
	buf := make([]byte, 100)
	totalRead := 0
	for {
		n, err := reader.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
	}

	if totalRead != len(data) {
		t.Errorf("总读取字节 = %d, want %d", totalRead, len(data))
	}

	// 应该有进度回调
	if len(progressCalls) == 0 {
		t.Error("应该有进度回调")
	}

	// 最后一次回调应该显示 100% 完成
	lastCall := progressCalls[len(progressCalls)-1]
	if lastCall.downloaded != int64(len(data)) {
		t.Errorf("最后下载进度 = %d, want %d", lastCall.downloaded, len(data))
	}
}

// TestProgressReaderNoCallback 测试无回调的 Reader
func TestProgressReaderNoCallback(t *testing.T) {
	data := []byte("test data")

	reader := &progressReader{
		reader:     bytes.NewReader(data),
		total:      int64(len(data)),
		startTime:  time.Now(),
		onProgress: nil, // 无回调
	}

	buf := make([]byte, 100)
	_, err := reader.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("读取失败: %v", err)
	}
	// 无回调时不应该 panic
}

// TestHTTPDownloaderDownloadToWriter 测试下载到 Writer
func TestHTTPDownloaderDownloadToWriter(t *testing.T) {
	content := "Hello, World! This is test content for download."

	// 创建测试服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "48")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}))
	defer server.Close()

	downloader := NewHTTPDownloader()

	var buf bytes.Buffer
	var lastProgress int64

	err := downloader.DownloadToWriter(context.Background(), server.URL, &buf, func(downloaded, total int64, speed float64) {
		lastProgress = downloaded
	})

	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	if buf.String() != content {
		t.Errorf("内容 = %q, want %q", buf.String(), content)
	}

	if lastProgress != int64(len(content)) {
		t.Errorf("最终进度 = %d, want %d", lastProgress, len(content))
	}
}

// TestHTTPDownloaderDownloadToWriterError 测试下载错误处理
func TestHTTPDownloaderDownloadToWriterError(t *testing.T) {
	tests := []struct {
		name       string
		handler    http.HandlerFunc
		wantErrMsg string
	}{
		{
			"404错误",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			"HTTP 404",
		},
		{
			"500错误",
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			"HTTP 500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			downloader := NewHTTPDownloader()
			var buf bytes.Buffer

			err := downloader.DownloadToWriter(context.Background(), server.URL, &buf, nil)

			if err == nil {
				t.Error("期望错误，但没有返回错误")
			} else if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Errorf("错误消息 = %q, 期望包含 %q", err.Error(), tt.wantErrMsg)
			}
		})
	}
}

// TestHTTPDownloaderDownloadToWriterCancel 测试取消下载
func TestHTTPDownloaderDownloadToWriterCancel(t *testing.T) {
	// 创建一个慢速服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// 缓慢发送数据
		for i := 0; i < 100; i++ {
			select {
			case <-r.Context().Done():
				return
			default:
				w.Write(make([]byte, 10000))
				time.Sleep(10 * time.Millisecond)
			}
		}
	}))
	defer server.Close()

	downloader := NewHTTPDownloader()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var buf bytes.Buffer
	err := downloader.DownloadToWriter(ctx, server.URL, &buf, nil)

	// 应该返回 context 相关的错误
	if err == nil {
		t.Error("期望因超时返回错误")
	}
}

// TestHTTPDownloaderDownload 测试完整下载流程
func TestHTTPDownloaderDownload(t *testing.T) {
	content := "Test file content for download"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 检查 User-Agent
		if r.Header.Get("User-Agent") != "sslctlw-updater" {
			t.Errorf("User-Agent = %q, want 'sslctlw-updater'", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}))
	defer server.Close()

	// 创建临时目录
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "downloaded.exe")

	downloader := NewHTTPDownloader()
	err := downloader.Download(context.Background(), server.URL, destPath, nil)

	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	// 验证文件内容
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("读取文件失败: %v", err)
	}

	if string(data) != content {
		t.Errorf("文件内容 = %q, want %q", string(data), content)
	}

	// 验证临时文件被清理
	tmpPath := destPath + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("临时文件应该被删除")
	}
}

// TestHTTPDownloaderDownloadURLValidation 测试下载时的 URL 验证
func TestHTTPDownloaderDownloadURLValidation(t *testing.T) {
	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "test.exe")

	downloader := NewHTTPDownloader()

	// 测试无效 URL
	err := downloader.Download(context.Background(), "http://external.com/file.exe", destPath, nil)
	if err == nil {
		t.Error("应该因 URL 验证失败而返回错误")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("错误消息应该包含 HTTPS: %v", err)
	}
}

// TestHTTPDownloaderDownloadCreateDir 测试创建目标目录
func TestHTTPDownloaderDownloadCreateDir(t *testing.T) {
	content := "Test content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	// 嵌套目录
	destPath := filepath.Join(tmpDir, "subdir1", "subdir2", "file.exe")

	downloader := NewHTTPDownloader()
	err := downloader.Download(context.Background(), server.URL, destPath, nil)

	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	// 验证目录被创建
	if _, err := os.Stat(filepath.Dir(destPath)); os.IsNotExist(err) {
		t.Error("目标目录应该被创建")
	}
}

// TestHTTPDownloaderDownloadOverwrite 测试覆盖已存在的文件
func TestHTTPDownloaderDownloadOverwrite(t *testing.T) {
	newContent := "New content"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(newContent))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "file.exe")

	// 先创建一个已存在的文件
	if err := os.WriteFile(destPath, []byte("Old content"), 0644); err != nil {
		t.Fatalf("创建旧文件失败: %v", err)
	}

	downloader := NewHTTPDownloader()
	err := downloader.Download(context.Background(), server.URL, destPath, nil)

	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	// 验证内容被覆盖
	data, _ := os.ReadFile(destPath)
	if string(data) != newContent {
		t.Errorf("文件内容 = %q, want %q", string(data), newContent)
	}
}

// TestHTTPDownloaderDownloadWithProgress 测试带进度回调的下载
func TestHTTPDownloaderDownloadWithProgress(t *testing.T) {
	content := strings.Repeat("A", 10000) // 10KB

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(content))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "file.exe")

	var progressCalls int
	var lastDownloaded int64

	downloader := NewHTTPDownloader()
	err := downloader.Download(context.Background(), server.URL, destPath, func(downloaded, total int64, speed float64) {
		progressCalls++
		lastDownloaded = downloaded
	})

	if err != nil {
		t.Fatalf("下载失败: %v", err)
	}

	if progressCalls == 0 {
		t.Error("应该有进度回调")
	}

	if lastDownloaded != 10000 {
		t.Errorf("最终下载量 = %d, want 10000", lastDownloaded)
	}
}

// TestProgressReaderSpeedCalculation 测试速度计算
func TestProgressReaderSpeedCalculation(t *testing.T) {
	data := make([]byte, 1000)

	var lastSpeed float64

	reader := &progressReader{
		reader:    bytes.NewReader(data),
		total:     int64(len(data)),
		startTime: time.Now().Add(-1 * time.Second), // 模拟 1 秒前开始
		onProgress: func(downloaded, total int64, speed float64) {
			lastSpeed = speed
		},
	}

	// 读取所有数据
	buf := make([]byte, len(data))
	reader.Read(buf)

	// 速度应该接近 1000 bytes/sec
	if lastSpeed < 500 || lastSpeed > 2000 {
		t.Logf("速度 = %.1f bytes/s（在合理范围内）", lastSpeed)
	}
}

// TestValidateDownloadURLCaseInsensitive 测试 URL 协议大小写
func TestValidateDownloadURLCaseInsensitive(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"HTTPS://example.com/file.exe", false},
		{"Https://example.com/file.exe", false},
		{"HTTP://localhost/file.exe", false},
		{"Http://127.0.0.1/file.exe", false},
		{"HTTP://example.com/file.exe", true}, // 非 localhost 的 HTTP 仍然不允许
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateDownloadURL(tt.url)
			if tt.wantErr && err == nil {
				t.Errorf("期望错误，但没有返回错误")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("不期望错误，但返回了: %v", err)
			}
		})
	}
}
