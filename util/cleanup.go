package util

import (
	"log"
	"os"
	"time"
)

// CleanupTempFile 清理临时文件（带重试机制）
// 如果文件被占用无法立即删除，会在后台尝试延迟删除
func CleanupTempFile(path string) {
	if path == "" {
		return
	}

	// 首次尝试删除
	if err := os.Remove(path); err == nil {
		return
	}

	// 如果文件不存在，无需处理
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return
	}

	// 延迟重试删除
	go func() {
		for i := 0; i < 3; i++ {
			// 指数退避：1s, 2s, 4s
			time.Sleep(time.Duration(1<<i) * time.Second)

			if err := os.Remove(path); err == nil {
				return
			}

			// 检查文件是否已被其他方式删除
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return
			}
		}
		log.Printf("警告: 无法删除临时文件 %s", path)
	}()
}

// CleanupTempFiles 批量清理临时文件
func CleanupTempFiles(paths ...string) {
	for _, path := range paths {
		CleanupTempFile(path)
	}
}

// CleanupTempFileSync 同步清理临时文件（带重试）
// 最多重试 3 次，每次间隔 1 秒
// 返回 true 表示删除成功或文件不存在
func CleanupTempFileSync(path string) bool {
	if path == "" {
		return true
	}

	for i := 0; i < 3; i++ {
		if i > 0 {
			time.Sleep(time.Second)
		}

		if err := os.Remove(path); err == nil {
			return true
		}

		// 检查文件是否已不存在
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
	}

	log.Printf("警告: 无法删除临时文件 %s", path)
	return false
}
