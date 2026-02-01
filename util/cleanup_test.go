package util

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupTempFile_Empty(t *testing.T) {
	// 空路径应该直接返回，不报错
	CleanupTempFile("")
	// 只要不 panic 就算通过
}

func TestCleanupTempFile_NotExists(t *testing.T) {
	// 文件不存在应该直接返回
	CleanupTempFile("/nonexistent/path/file.tmp")
	// 只要不 panic 就算通过
}

func TestCleanupTempFile_Success(t *testing.T) {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "cleanup_test_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 验证文件存在
	if _, err := os.Stat(tmpPath); err != nil {
		t.Fatalf("临时文件应该存在: %v", err)
	}

	// 清理
	CleanupTempFile(tmpPath)

	// 等待一下，因为可能是异步删除
	time.Sleep(100 * time.Millisecond)

	// 验证文件被删除
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		// 如果仍存在，可能是因为异步删除，再等待一下
		time.Sleep(500 * time.Millisecond)
		if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
			t.Error("临时文件应该被删除")
			// 清理
			os.Remove(tmpPath)
		}
	}
}

func TestCleanupTempFiles(t *testing.T) {
	// 创建多个临时文件
	var paths []string
	for i := 0; i < 3; i++ {
		tmpFile, err := os.CreateTemp("", "cleanup_multi_*.tmp")
		if err != nil {
			t.Fatalf("创建临时文件失败: %v", err)
		}
		paths = append(paths, tmpFile.Name())
		tmpFile.Close()
	}

	// 批量清理
	CleanupTempFiles(paths...)

	// 等待异步删除
	time.Sleep(200 * time.Millisecond)

	// 验证所有文件被删除
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			time.Sleep(500 * time.Millisecond)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Errorf("文件 %s 应该被删除", path)
				os.Remove(path)
			}
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
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "cleanup_sync_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 同步清理
	result := CleanupTempFileSync(tmpPath)
	if !result {
		t.Error("CleanupTempFileSync() 应该返回 true")
	}

	// 验证文件被删除
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("临时文件应该被删除")
		os.Remove(tmpPath)
	}
}

func TestCleanupTempFileSync_Locked(t *testing.T) {
	// 创建临时文件并保持打开（锁定）
	tmpDir := t.TempDir()
	tmpPath := filepath.Join(tmpDir, "locked_file.tmp")

	// 创建文件
	f, err := os.Create(tmpPath)
	if err != nil {
		t.Fatalf("创建文件失败: %v", err)
	}
	defer f.Close()

	// 尝试删除被锁定的文件
	// 在 Windows 上，打开的文件可能无法删除
	// 这个测试主要验证函数不会崩溃

	// 由于文件被锁定，我们跳过实际的删除测试
	// 只验证函数能正常处理
	t.Skip("跳过：文件锁定测试依赖系统行为")
}

func TestCleanupTempFiles_Empty(t *testing.T) {
	// 空列表应该正常处理
	CleanupTempFiles()
	// 只要不 panic 就算通过
}

func TestCleanupTempFiles_Mixed(t *testing.T) {
	// 创建一个临时文件
	tmpFile, err := os.CreateTemp("", "cleanup_mixed_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 批量清理：包含空路径、不存在的路径、存在的路径
	CleanupTempFiles("", "/nonexistent/path/file.tmp", tmpPath)

	// 等待异步删除
	time.Sleep(200 * time.Millisecond)

	// 验证存在的文件被删除
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		time.Sleep(500 * time.Millisecond)
		if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
			t.Error("文件应该被删除")
			os.Remove(tmpPath)
		}
	}
}

func TestCleanupTempFile_DeletedByOther(t *testing.T) {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "cleanup_deleted_*.tmp")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// 手动删除文件
	os.Remove(tmpPath)

	// 再次调用清理，应该不会出错
	CleanupTempFile(tmpPath)
	// 只要不 panic 就算通过
}
