package cert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewOrderStore(t *testing.T) {
	store := NewOrderStore()
	if store == nil {
		t.Fatal("NewOrderStore() 返回 nil")
	}
	if store.BaseDir == "" {
		t.Error("BaseDir 不应为空")
	}
}

func TestOrderStore_GetOrderPath(t *testing.T) {
	store := &OrderStore{BaseDir: "/test/orders"}
	path := store.GetOrderPath(123)
	expected := filepath.Join("/test/orders", "123")
	if path != expected {
		t.Errorf("GetOrderPath(123) = %q, want %q", path, expected)
	}
}

func TestOrderStore_EnsureOrderDir(t *testing.T) {
	// 使用临时目录
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	err := store.EnsureOrderDir(456)
	if err != nil {
		t.Fatalf("EnsureOrderDir() error = %v", err)
	}

	// 验证目录存在
	orderPath := store.GetOrderPath(456)
	info, err := os.Stat(orderPath)
	if err != nil {
		t.Fatalf("目录不存在: %v", err)
	}
	if !info.IsDir() {
		t.Error("路径应该是目录")
	}
}

func TestOrderStore_SaveAndLoadMeta(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	meta := &OrderMeta{
		OrderID:   123,
		Domain:    "example.com",
		Domains:   []string{"example.com", "www.example.com"},
		Status:    "active",
		ExpiresAt: "2025-12-31",
		CreatedAt: "2024-01-01",
	}

	// 保存
	err := store.SaveMeta(123, meta)
	if err != nil {
		t.Fatalf("SaveMeta() error = %v", err)
	}

	// 加载
	loaded, err := store.LoadMeta(123)
	if err != nil {
		t.Fatalf("LoadMeta() error = %v", err)
	}

	// 验证
	if loaded.OrderID != meta.OrderID {
		t.Errorf("OrderID = %d, want %d", loaded.OrderID, meta.OrderID)
	}
	if loaded.Domain != meta.Domain {
		t.Errorf("Domain = %q, want %q", loaded.Domain, meta.Domain)
	}
	if loaded.Status != meta.Status {
		t.Errorf("Status = %q, want %q", loaded.Status, meta.Status)
	}
	if len(loaded.Domains) != len(meta.Domains) {
		t.Errorf("Domains 长度 = %d, want %d", len(loaded.Domains), len(meta.Domains))
	}
}

func TestOrderStore_LoadMeta_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	_, err := store.LoadMeta(999)
	if err == nil {
		t.Error("LoadMeta() 应该对不存在的订单返回错误")
	}
}

func TestOrderStore_SaveAndLoadCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	certPEM := "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"
	chainPEM := "-----BEGIN CERTIFICATE-----\ntest chain\n-----END CERTIFICATE-----"

	// 保存
	err := store.SaveCertificate(123, certPEM, chainPEM)
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}

	// 加载
	loadedCert, loadedChain, err := store.LoadCertificate(123)
	if err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}

	if loadedCert != certPEM {
		t.Errorf("证书内容不匹配")
	}
	if loadedChain != chainPEM {
		t.Errorf("证书链内容不匹配")
	}
}

func TestOrderStore_SaveCertificate_NoChain(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	certPEM := "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"

	// 保存（无证书链）
	err := store.SaveCertificate(123, certPEM, "")
	if err != nil {
		t.Fatalf("SaveCertificate() error = %v", err)
	}

	// 加载
	loadedCert, loadedChain, err := store.LoadCertificate(123)
	if err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}

	if loadedCert != certPEM {
		t.Errorf("证书内容不匹配")
	}
	if loadedChain != "" {
		t.Errorf("证书链应为空，实际为: %q", loadedChain)
	}
}

func TestOrderStore_LoadCertificate_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	_, _, err := store.LoadCertificate(999)
	if err == nil {
		t.Error("LoadCertificate() 应该对不存在的订单返回错误")
	}
}

func TestOrderStore_ListOrders(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 创建几个订单目录
	store.EnsureOrderDir(100)
	store.EnsureOrderDir(200)
	store.EnsureOrderDir(300)

	// 创建一个非数字目录（应被忽略）
	os.MkdirAll(filepath.Join(tmpDir, "invalid"), 0755)

	orders, err := store.ListOrders()
	if err != nil {
		t.Fatalf("ListOrders() error = %v", err)
	}

	if len(orders) != 3 {
		t.Errorf("ListOrders() 返回 %d 个订单, want 3", len(orders))
	}

	// 验证包含正确的订单 ID
	expected := map[int]bool{100: true, 200: true, 300: true}
	for _, id := range orders {
		if !expected[id] {
			t.Errorf("意外的订单 ID: %d", id)
		}
	}
}

func TestOrderStore_ListOrders_Empty(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: filepath.Join(tmpDir, "nonexistent")}

	orders, err := store.ListOrders()
	if err != nil {
		t.Fatalf("ListOrders() error = %v", err)
	}

	if len(orders) != 0 {
		t.Errorf("ListOrders() 返回 %d 个订单, want 0", len(orders))
	}
}

func TestOrderStore_DeleteOrder(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 创建订单
	store.EnsureOrderDir(123)
	store.SaveMeta(123, &OrderMeta{OrderID: 123, Domain: "test.com"})

	// 验证存在
	orderPath := store.GetOrderPath(123)
	if _, err := os.Stat(orderPath); err != nil {
		t.Fatal("订单目录应该存在")
	}

	// 删除
	err := store.DeleteOrder(123)
	if err != nil {
		t.Fatalf("DeleteOrder() error = %v", err)
	}

	// 验证不存在
	if _, err := os.Stat(orderPath); !os.IsNotExist(err) {
		t.Error("订单目录应该被删除")
	}
}

func TestOrderStore_HasPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 不存在的订单
	if store.HasPrivateKey(999) {
		t.Error("HasPrivateKey() 应该对不存在的订单返回 false")
	}

	// 创建订单但不保存私钥
	store.EnsureOrderDir(123)
	if store.HasPrivateKey(123) {
		t.Error("HasPrivateKey() 应该对没有私钥的订单返回 false")
	}

	// 创建私钥文件
	keyPath := filepath.Join(store.GetOrderPath(123), "private.key")
	os.WriteFile(keyPath, []byte("dummy"), 0600)

	if !store.HasPrivateKey(123) {
		t.Error("HasPrivateKey() 应该对有私钥的订单返回 true")
	}
}

func TestOrderMeta_Fields(t *testing.T) {
	meta := &OrderMeta{
		OrderID:      123,
		Domain:       "example.com",
		Domains:      []string{"example.com", "www.example.com"},
		Status:       "active",
		ExpiresAt:    "2025-12-31",
		CreatedAt:    "2024-01-01",
		LastDeployed: "2024-06-01",
		Thumbprint:   "ABC123",
	}

	if meta.OrderID != 123 {
		t.Errorf("OrderID = %d, want 123", meta.OrderID)
	}
	if meta.Domain != "example.com" {
		t.Errorf("Domain = %q, want %q", meta.Domain, "example.com")
	}
	if len(meta.Domains) != 2 {
		t.Errorf("Domains 长度 = %d, want 2", len(meta.Domains))
	}
	if meta.Thumbprint != "ABC123" {
		t.Errorf("Thumbprint = %q, want %q", meta.Thumbprint, "ABC123")
	}
}

// TestEncryptDecryptPrivateKey 测试私钥加解密
func TestEncryptDecryptPrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyPEM  string
		wantErr bool
	}{
		{"空字符串", "", false},
		{"有效私钥", "-----BEGIN TEST KEY-----\ntest\n-----END TEST KEY-----", false},
		{"长私钥", string(make([]byte, 2048)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptPrivateKey(tt.keyPEM)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.keyPEM == "" {
				// 空字符串加密后也应该是空的
				if encrypted != "" {
					t.Errorf("空字符串加密后应该为空, got %q", encrypted)
				}
				return
			}

			// 解密
			decrypted, err := DecryptPrivateKey(encrypted)
			if err != nil {
				t.Fatalf("DecryptPrivateKey() error = %v", err)
			}

			if decrypted != tt.keyPEM {
				t.Errorf("解密后内容不匹配")
			}
		})
	}
}

// TestDecryptPrivateKey_InvalidFormat 测试无效格式解密
func TestDecryptPrivateKey_InvalidFormat(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		wantErr   bool
	}{
		{"空字符串", "", false},
		{"无效前缀", "invalid:data", true},
		{"错误前缀", "v2:dpapi:data", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptPrivateKey(tt.encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestOrderStore_SaveLoadPrivateKey 测试保存和加载私钥
func TestOrderStore_SaveLoadPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	testKey := "-----BEGIN TEST KEY-----\nMIItest...\n-----END TEST KEY-----"

	// 保存
	err := store.SavePrivateKey(123, testKey)
	if err != nil {
		t.Fatalf("SavePrivateKey() error = %v", err)
	}

	// 验证有私钥
	if !store.HasPrivateKey(123) {
		t.Error("HasPrivateKey() = false, want true")
	}

	// 加载
	loaded, err := store.LoadPrivateKey(123)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	if loaded != testKey {
		t.Error("加载的私钥与保存的不匹配")
	}
}

// TestOrderStore_LoadPrivateKey_NotExists 测试加载不存在的私钥
func TestOrderStore_LoadPrivateKey_NotExists(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	_, err := store.LoadPrivateKey(999)
	if err == nil {
		t.Error("LoadPrivateKey() 应该对不存在的私钥返回错误")
	}
}

// TestOrderStore_DeleteOrder_Twice 测试重复删除
func TestOrderStore_DeleteOrder_Twice(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 创建并删除
	store.EnsureOrderDir(123)
	err := store.DeleteOrder(123)
	if err != nil {
		t.Fatalf("第一次 DeleteOrder() error = %v", err)
	}

	// 第二次删除应该也不报错
	err = store.DeleteOrder(123)
	if err != nil {
		t.Errorf("第二次 DeleteOrder() error = %v", err)
	}
}

// TestOrderStore_MultipleOrders 测试多个订单
func TestOrderStore_MultipleOrders(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 创建多个订单
	orderIDs := []int{100, 200, 300, 400, 500}
	for _, id := range orderIDs {
		err := store.EnsureOrderDir(id)
		if err != nil {
			t.Fatalf("EnsureOrderDir(%d) error = %v", id, err)
		}

		meta := &OrderMeta{
			OrderID: id,
			Domain:  "example.com",
			Status:  "active",
		}
		err = store.SaveMeta(id, meta)
		if err != nil {
			t.Fatalf("SaveMeta(%d) error = %v", id, err)
		}
	}

	// 列出订单
	orders, err := store.ListOrders()
	if err != nil {
		t.Fatalf("ListOrders() error = %v", err)
	}

	if len(orders) != len(orderIDs) {
		t.Errorf("ListOrders() 返回 %d 个订单, want %d", len(orders), len(orderIDs))
	}

	// 验证每个订单都存在
	orderMap := make(map[int]bool)
	for _, id := range orders {
		orderMap[id] = true
	}
	for _, id := range orderIDs {
		if !orderMap[id] {
			t.Errorf("订单 %d 未在列表中找到", id)
		}
	}
}

// TestKeyEncryptionPrefix 测试私钥加密前缀常量
func TestKeyEncryptionPrefix(t *testing.T) {
	if KeyEncryptionPrefix != "v1:dpapi:" {
		t.Errorf("KeyEncryptionPrefix = %q, want %q", KeyEncryptionPrefix, "v1:dpapi:")
	}
}

// TestOrderStore_SaveMeta_Override 测试覆盖元数据
func TestOrderStore_SaveMeta_Override(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}

	// 保存第一次
	meta1 := &OrderMeta{
		OrderID: 123,
		Domain:  "old.example.com",
		Status:  "pending",
	}
	err := store.SaveMeta(123, meta1)
	if err != nil {
		t.Fatalf("SaveMeta() error = %v", err)
	}

	// 覆盖保存
	meta2 := &OrderMeta{
		OrderID: 123,
		Domain:  "new.example.com",
		Status:  "active",
	}
	err = store.SaveMeta(123, meta2)
	if err != nil {
		t.Fatalf("SaveMeta() 覆盖 error = %v", err)
	}

	// 验证是新的数据
	loaded, err := store.LoadMeta(123)
	if err != nil {
		t.Fatalf("LoadMeta() error = %v", err)
	}

	if loaded.Domain != "new.example.com" {
		t.Errorf("Domain = %q, want %q", loaded.Domain, "new.example.com")
	}
	if loaded.Status != "active" {
		t.Errorf("Status = %q, want %q", loaded.Status, "active")
	}
}
