package util

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitForFileRemoval 轮询等待文件被删除
func waitForFileRemoval(t *testing.T, path string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestCleanupTempFile_Empty(t *testing.T) {
	CleanupTempFile("")
}

func TestCleanupTempFile_NotExists(t *testing.T) {
	CleanupTempFile("/nonexistent/path/file.tmp")
}

func TestCleanupTempFile_Success(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cleanup_test_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	CleanupTempFile(tmpPath)

	if !waitForFileRemoval(t, tmpPath, 10*time.Second) {
		t.Error("临时文件应该被删除")
		os.Remove(tmpPath)
	}
}

func TestCleanupTempFiles(t *testing.T) {
	var paths []string
	for i := 0; i < 3; i++ {
		tmpFile, err := os.CreateTemp("", "cleanup_multi_*.tmp")
		if err != nil {
			t.Fatalf("创建临时文件失败: %v", err)
		}
		paths = append(paths, tmpFile.Name())
		tmpFile.Close()
	}

	CleanupTempFiles(paths...)

	for _, path := range paths {
		if !waitForFileRemoval(t, path, 10*time.Second) {
			t.Errorf("文件 %s 应该被删除", path)
			os.Remove(path)
		}
	}
}

func TestCleanupTempFileSync_Empty(t *testing.T) {
	result := CleanupTempFileSync("")
	if !result {
		t.Error("CleanupTempFileSync(\"\") 应该返回 true")
	}
}

func TestCleanupTempFileSync_NotExists(t *testing.T) {
	result := CleanupTempFileSync("/nonexistent/path/file.tmp")
	if !result {
		t.Error("CleanupTempFileSync() 对不存在的文件应该返回 true")
	}
}

func TestCleanupTempFileSync_Success(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cleanup_sync_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	result := CleanupTempFileSync(tmpPath)
	if !result {
		t.Error("CleanupTempFileSync() 应该返回 true")
	}

	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("临时文件应该被删除")
		os.Remove(tmpPath)
	}
}

func TestCleanupTempFileSync_Locked(t *testing.T) {
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "locked_file.tmp")

	f, err := os.Create(tmpPath)
	if err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}
	defer f.Close()

	// 在 Windows 上，打开的文件无法删除
	result := CleanupTempFileSync(tmpPath)
	if result {
		t.Error("CleanupTempFileSync() 应该对锁定的文件返回 false")
	}

	// 验证文件仍然存在
	if _, err := os.Stat(tmpPath); os.IsNotExist(err) {
		t.Error("锁定的文件不应该被删除")
	}
}

func TestCleanupTempFiles_Empty(t *testing.T) {
	CleanupTempFiles()
}

func TestCleanupTempFiles_Mixed(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cleanup_mixed_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	CleanupTempFiles("", "/nonexistent/path/file.tmp", tmpPath)

	if !waitForFileRemoval(t, tmpPath, 10*time.Second) {
		t.Error("文件应该被删除")
		os.Remove(tmpPath)
	}
}

func TestCleanupTempFile_DeletedByOther(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "cleanup_deleted_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	os.Remove(tmpPath)

	CleanupTempFile(tmpPath)
}
