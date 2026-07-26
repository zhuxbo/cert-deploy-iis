package deploy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sslctlw/config"
	"sslctlw/iis"
)

const maxValidationFileSize = 1 << 20

const validationWebConfig = `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <staticContent>
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
  </system.webServer>
</configuration>`

type validationTokenPlacement struct {
	RelativePath string
	SHA256       string
	Created      bool
}

type validationTokenRemoveStatus int

const (
	validationTokenRemoved validationTokenRemoveStatus = iota
	validationTokenMissing
	validationTokenOwnershipChanged
)

type validationFileStore interface {
	PlaceToken(root iis.ValidationWebRoot, relativePath, content string) (validationTokenPlacement, error)
	RemoveToken(root iis.ValidationWebRoot, record config.ValidationFileRecord) (validationTokenRemoveStatus, error)
}

type defaultValidationFileStore struct{}

func validationFSError(operation string, err error) error {
	if os.IsNotExist(err) {
		return fmt.Errorf("%s: %w", operation, os.ErrNotExist)
	}
	if os.IsPermission(err) {
		return fmt.Errorf("%s: %w", operation, os.ErrPermission)
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %w", operation, pathErr.Err)
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func normalizeValidationRelativePath(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') {
		return "", fmt.Errorf("验证文件路径为空或包含 NUL")
	}
	if strings.Contains(value, "/") && strings.Contains(value, `\`) {
		return "", fmt.Errorf("验证文件路径混用分隔符")
	}
	if strings.HasPrefix(value, `\\`) || strings.HasPrefix(value, "//") {
		return "", fmt.Errorf("验证文件路径不得为 UNC 路径")
	}
	// Deploy API 使用 URL 根相对写法 "/.well-known/..."；只移除这一枚 URL 前导斜杠。
	if strings.HasPrefix(value, "/") {
		value = strings.TrimPrefix(value, "/")
	}
	value = strings.ReplaceAll(value, "/", string(os.PathSeparator))
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" || strings.Contains(value, ":") {
		return "", fmt.Errorf("验证文件路径必须为站点内相对路径")
	}
	parts := strings.Split(value, string(os.PathSeparator))
	if len(parts) < 2 || !strings.EqualFold(parts[0], ".well-known") {
		return "", fmt.Errorf("验证文件路径必须在 .well-known 目录下")
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("验证文件路径包含非法路径段")
		}
		if strings.TrimRight(part, ". ") != part {
			return "", fmt.Errorf("验证文件路径段不得以点或空格结尾")
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if isReservedWindowsName(base) {
			return "", fmt.Errorf("验证文件路径包含 Windows 保留名 %q", part)
		}
	}
	cleaned := filepath.Clean(filepath.Join(parts...))
	if cleaned == "." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("验证文件路径越界")
	}
	switch strings.ToLower(filepath.Ext(cleaned)) {
	case ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".asp", ".aspx", ".php":
		return "", fmt.Errorf("不允许创建危险扩展名的验证文件")
	}
	return cleaned, nil
}

func isReservedWindowsName(base string) bool {
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$",
		"COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³":
		return true
	}
	if len(base) == 4 {
		prefix, suffix := base[:3], base[3]
		return (prefix == "COM" || prefix == "LPT") && suffix >= '1' && suffix <= '9'
	}
	return false
}

func (defaultValidationFileStore) PlaceToken(
	root iis.ValidationWebRoot,
	rawRelativePath string,
	content string,
) (validationTokenPlacement, error) {
	relativePath, err := normalizeValidationRelativePath(rawRelativePath)
	if err != nil {
		return validationTokenPlacement{}, err
	}
	if content == "" {
		return validationTokenPlacement{}, fmt.Errorf("验证文件内容为空")
	}
	if len(content) > maxValidationFileSize {
		return validationTokenPlacement{}, fmt.Errorf("验证文件内容超过 %d 字节上限", maxValidationFileSize)
	}
	fullPath, err := validationPath(root.PhysicalPath, relativePath)
	if err != nil {
		return validationTokenPlacement{}, err
	}
	if err := ensureValidationDirectories(root.PhysicalPath, filepath.Dir(fullPath)); err != nil {
		return validationTokenPlacement{}, err
	}
	webConfigPath := filepath.Join(filepath.Dir(fullPath), "web.config")
	if err := ensureValidationWebConfig(webConfigPath); err != nil {
		return validationTokenPlacement{}, err
	}

	sum := sha256.Sum256([]byte(content))
	digest := hex.EncodeToString(sum[:])
	if existing, err := readSafeValidationFile(fullPath); err == nil {
		if string(existing) != content {
			return validationTokenPlacement{}, fmt.Errorf("验证文件已存在且内容不同，拒绝覆盖")
		}
		return validationTokenPlacement{RelativePath: relativePath, SHA256: digest}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return validationTokenPlacement{}, err
	}

	file, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		// 竞争方刚创建时，仅允许复用完全相同且安全的文件。
		if os.IsExist(err) {
			if existing, readErr := readSafeValidationFile(fullPath); readErr == nil && string(existing) == content {
				return validationTokenPlacement{RelativePath: relativePath, SHA256: digest}, nil
			}
		}
		return validationTokenPlacement{}, validationFSError("独占创建验证文件失败", err)
	}
	created := true
	if _, err = file.WriteString(content); err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		if created {
			_ = os.Remove(fullPath)
		}
		return validationTokenPlacement{}, validationFSError("写入验证文件失败", err)
	}
	if info, err := os.Lstat(fullPath); err != nil || !info.Mode().IsRegular() || isReparsePoint(info) {
		_ = os.Remove(fullPath)
		return validationTokenPlacement{}, fmt.Errorf("验证文件创建后类型不安全")
	}
	return validationTokenPlacement{RelativePath: relativePath, SHA256: digest, Created: true}, nil
}

func (defaultValidationFileStore) RemoveToken(
	root iis.ValidationWebRoot,
	record config.ValidationFileRecord,
) (validationTokenRemoveStatus, error) {
	if !strings.EqualFold(root.SiteName, record.SiteName) {
		return validationTokenOwnershipChanged, nil
	}
	relativePath, err := normalizeValidationRelativePath(record.RelativePath)
	if err != nil {
		return validationTokenOwnershipChanged, nil
	}
	fullPath, err := validationPath(root.PhysicalPath, relativePath)
	if err != nil {
		return validationTokenOwnershipChanged, nil
	}
	if err := ensureSafeExistingPath(root.PhysicalPath, fullPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return validationTokenMissing, nil
		}
		return validationTokenOwnershipChanged, nil
	}
	digest, err := hashSafeValidationFile(fullPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return validationTokenMissing, nil
		}
		return validationTokenOwnershipChanged, nil
	}
	if !strings.EqualFold(digest, record.SHA256) {
		return validationTokenOwnershipChanged, nil
	}
	if err := os.Remove(fullPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return validationTokenMissing, nil
		}
		return validationTokenOwnershipChanged, validationFSError("删除验证文件失败", err)
	}
	return validationTokenRemoved, nil
}

func validationPath(root, relativePath string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("站点物理根为空")
	}
	root = filepath.Clean(root)
	full := filepath.Join(root, relativePath)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("验证文件路径越出站点根")
	}
	return full, nil
}

func ensureValidationDirectories(root, dir string) error {
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil {
		return validationFSError("检查站点根失败", err)
	}
	if !info.IsDir() || isReparsePoint(info) {
		return fmt.Errorf("站点根不是安全普通目录")
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("验证目录越出站点根")
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0750); err != nil && !os.IsExist(err) {
				return validationFSError("创建验证目录失败", err)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return validationFSError("检查验证目录失败", err)
		}
		if !info.IsDir() || isReparsePoint(info) {
			return fmt.Errorf("验证目录包含 symlink/junction/reparse point")
		}
	}
	return nil
}

func ensureValidationWebConfig(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || isReparsePoint(info) {
			return fmt.Errorf("web.config 不是安全普通文件")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return validationFSError("检查 web.config 失败", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return ensureValidationWebConfig(path)
		}
		return validationFSError("创建 web.config 失败", err)
	}
	if _, err = file.WriteString(validationWebConfig); err == nil {
		err = file.Close()
	} else {
		_ = file.Close()
	}
	if err != nil {
		_ = os.Remove(path)
		return validationFSError("写入 web.config 失败", err)
	}
	return nil
}

func readSafeValidationFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, validationFSError("检查验证文件失败", err)
	}
	if !info.Mode().IsRegular() || isReparsePoint(info) {
		return nil, fmt.Errorf("验证文件不是安全普通文件")
	}
	if info.Size() > maxValidationFileSize {
		return nil, fmt.Errorf("验证文件超过 %d 字节上限", maxValidationFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, validationFSError("打开验证文件失败", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxValidationFileSize+1))
	if err != nil {
		return nil, validationFSError("读取验证文件失败", err)
	}
	if len(data) > maxValidationFileSize {
		return nil, fmt.Errorf("验证文件超过 %d 字节上限", maxValidationFileSize)
	}
	return data, nil
}

func hashSafeValidationFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", validationFSError("检查验证文件失败", err)
	}
	if !info.Mode().IsRegular() || isReparsePoint(info) {
		return "", fmt.Errorf("验证文件不是安全普通文件")
	}
	if info.Size() > maxValidationFileSize {
		return "", fmt.Errorf("验证文件超过 %d 字节上限", maxValidationFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", validationFSError("打开验证文件失败", err)
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxValidationFileSize+1))
	if err != nil {
		return "", validationFSError("读取验证文件失败", err)
	}
	if written > maxValidationFileSize {
		return "", fmt.Errorf("验证文件超过 %d 字节上限", maxValidationFileSize)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func ensureSafeExistingPath(root, fullPath string) error {
	root = filepath.Clean(root)
	rel, err := filepath.Rel(root, fullPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("验证文件路径越出站点根")
	}
	current := root
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		info, err := os.Lstat(current)
		if err != nil {
			return validationFSError("检查验证文件路径失败", err)
		}
		if isReparsePoint(info) {
			return fmt.Errorf("验证文件路径包含 symlink/junction/reparse point")
		}
		current = filepath.Join(current, part)
	}
	info, err := os.Lstat(fullPath)
	if err != nil {
		return validationFSError("检查验证文件失败", err)
	}
	if isReparsePoint(info) {
		return fmt.Errorf("验证文件是 symlink/junction/reparse point")
	}
	return nil
}
