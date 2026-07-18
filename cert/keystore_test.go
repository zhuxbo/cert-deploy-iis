package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
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

	// 动态生成测试用私钥，避免硬编码私钥触发 secret scanning
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("编码测试密钥失败: %v", err)
	}
	testKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}))

	// 保存
	err = store.SavePrivateKey(123, testKey)
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

func TestOrderStore_PendingPrivateKeyLifecycle(t *testing.T) {
	dataDir := t.TempDir()
	store := &OrderStore{BaseDir: filepath.Join(dataDir, "orders")}
	keyPEM := generateTestPrivateKey(t)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("test-csr")}))

	if err := store.SavePendingCSR("example.com-123", csrPEM); err != nil {
		t.Fatalf("SavePendingCSR() error = %v", err)
	}
	if err := store.SavePendingPrivateKey("example.com-123", keyPEM); err != nil {
		t.Fatalf("SavePendingPrivateKey() error = %v", err)
	}
	if !store.HasPendingPrivateKey("example.com-123") {
		t.Fatal("保存后应存在 pending 私钥")
	}
	loaded, err := store.LoadPendingPrivateKey("example.com-123")
	if err != nil {
		t.Fatalf("LoadPendingPrivateKey() error = %v", err)
	}
	if loaded != keyPEM {
		t.Fatal("pending 私钥与保存内容不一致")
	}
	loadedCSR, err := store.LoadPendingCSR("example.com-123")
	if err != nil {
		t.Fatalf("LoadPendingCSR() error = %v", err)
	}
	if loadedCSR != csrPEM {
		t.Fatal("pending CSR 与保存内容不一致")
	}

	if err := store.PromotePendingPrivateKey("example.com-123", 456, keyPEM); err != nil {
		t.Fatalf("PromotePendingPrivateKey() error = %v", err)
	}
	if store.HasPendingPrivateKey("example.com-123") {
		t.Fatal("转正成功后应删除 pending 私钥")
	}
	if _, err := store.LoadPendingCSR("example.com-123"); !os.IsNotExist(err) {
		t.Fatalf("转正成功后应删除 pending CSR，got error = %v", err)
	}
	formal, err := store.LoadPrivateKey(456)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if formal != keyPEM {
		t.Fatal("转正后的正式私钥内容不一致")
	}
}

func TestOrderStore_PendingMismatchPreservesBothKeys(t *testing.T) {
	dataDir := t.TempDir()
	store := &OrderStore{BaseDir: filepath.Join(dataDir, "orders")}
	formalKey := generateTestPrivateKey(t)
	pendingKey := generateTestPrivateKey(t)

	if err := store.SavePrivateKey(456, formalKey); err != nil {
		t.Fatalf("SavePrivateKey() error = %v", err)
	}
	if err := store.SavePendingPrivateKey("example.com-123", pendingKey); err != nil {
		t.Fatalf("SavePendingPrivateKey() error = %v", err)
	}
	if err := store.PromotePendingPrivateKey("example.com-123", 456, formalKey); err == nil {
		t.Fatal("pending 内容与已部署私钥不一致时应拒绝转正")
	}
	if !store.HasPendingPrivateKey("example.com-123") {
		t.Fatal("转正拒绝后应保留 pending 私钥")
	}
	loadedFormal, err := store.LoadPrivateKey(456)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if loadedFormal != formalKey {
		t.Fatal("转正拒绝后不应覆盖正式私钥")
	}
}

func TestOrderStore_PendingPrivateKeyRejectsUnsafeName(t *testing.T) {
	store := &OrderStore{BaseDir: filepath.Join(t.TempDir(), "orders")}
	if err := store.SavePendingPrivateKey("../escape", generateTestPrivateKey(t)); err == nil {
		t.Fatal("包含路径遍历的 cert_name 应被拒绝")
	}
}

func generateTestPrivateKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试私钥失败: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("编码测试私钥失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
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
	if KeyEncryptionPrefixMachine != "vm:dpapi:" {
		t.Errorf("KeyEncryptionPrefixMachine = %q, want %q", KeyEncryptionPrefixMachine, "vm:dpapi:")
	}
}

// genTestKeyPEM 生成测试用 EC 私钥 PEM（避免硬编码私钥触发 secret scanning）
func genTestKeyPEM(t *testing.T) string {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("编码测试密钥失败: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes}))
}

// TestKeyNeedsMigration 纯逻辑：识别需迁移的旧用户作用域私钥前缀
func TestKeyNeedsMigration(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		want      bool
	}{
		{"空串", "", false},
		{"机器作用域", KeyEncryptionPrefixMachine + "abc", false},
		{"旧用户作用域", KeyEncryptionPrefix + "abc", true},
		{"token 前缀非私钥", "v1:abc", false},
		{"无前缀", "abc", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyNeedsMigration(tt.encrypted); got != tt.want {
				t.Errorf("KeyNeedsMigration(%q) = %v, want %v", tt.encrypted, got, tt.want)
			}
		})
	}
}

// TestEncryptPrivateKey_MachinePrefix 验证加密输出机器作用域前缀且可解密（依赖 DPAPI，Windows 运行）
func TestEncryptPrivateKey_MachinePrefix(t *testing.T) {
	keyPEM := genTestKeyPEM(t)

	encrypted, err := EncryptPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}
	if !strings.HasPrefix(encrypted, KeyEncryptionPrefixMachine) {
		t.Fatalf("加密结果应以机器作用域前缀 %q 开头", KeyEncryptionPrefixMachine)
	}
	if KeyNeedsMigration(encrypted) {
		t.Errorf("机器作用域私钥不应被判定为需迁移")
	}

	decrypted, err := DecryptPrivateKey(encrypted)
	if err != nil {
		t.Fatalf("DecryptPrivateKey() error = %v", err)
	}
	if decrypted != keyPEM {
		t.Errorf("解密后私钥与原文不匹配")
	}
}

// TestDecryptPrivateKey_LegacyPrefixCompat 验证旧用户作用域私钥前缀仍可解密（依赖 DPAPI，Windows 运行）
func TestDecryptPrivateKey_LegacyPrefixCompat(t *testing.T) {
	keyPEM := genTestKeyPEM(t)

	encrypted, err := EncryptPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}
	// 换成旧前缀模拟历史数据（底层密文不变）
	legacy := KeyEncryptionPrefix + strings.TrimPrefix(encrypted, KeyEncryptionPrefixMachine)
	if !KeyNeedsMigration(legacy) {
		t.Fatalf("旧前缀应被判定为需迁移")
	}
	decrypted, err := DecryptPrivateKey(legacy)
	if err != nil {
		t.Fatalf("DecryptPrivateKey(旧前缀) error = %v", err)
	}
	if decrypted != keyPEM {
		t.Errorf("解密后私钥与原文不匹配")
	}
}

// TestLoadPrivateKey_MigratesLegacyScope 验证加载旧作用域私钥时透明迁移为机器作用域（依赖 DPAPI，Windows 运行）
func TestLoadPrivateKey_MigratesLegacyScope(t *testing.T) {
	tmpDir := t.TempDir()
	store := &OrderStore{BaseDir: tmpDir}
	keyPEM := genTestKeyPEM(t)

	// 构造旧用户作用域格式的私钥文件
	encrypted, err := EncryptPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}
	legacy := KeyEncryptionPrefix + strings.TrimPrefix(encrypted, KeyEncryptionPrefixMachine)
	if err := store.EnsureOrderDir(123); err != nil {
		t.Fatalf("EnsureOrderDir() error = %v", err)
	}
	keyPath := filepath.Join(store.GetOrderPath(123), "private.key")
	if err := os.WriteFile(keyPath, []byte(legacy), 0600); err != nil {
		t.Fatalf("写入旧私钥失败: %v", err)
	}

	// 加载应成功且内容正确
	loaded, err := store.LoadPrivateKey(123)
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}
	if loaded != keyPEM {
		t.Errorf("加载的私钥与原文不匹配")
	}

	// 加载后文件应已迁移为机器作用域前缀
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取迁移后私钥失败: %v", err)
	}
	if !strings.HasPrefix(string(data), KeyEncryptionPrefixMachine) {
		t.Errorf("加载后私钥应迁移为机器作用域前缀 %q", KeyEncryptionPrefixMachine)
	}
	if KeyNeedsMigration(string(data)) {
		t.Errorf("迁移后不应再被判定为需迁移")
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

// TestAtomicWriteKey_Success 原子写成功：替换已有内容且清理临时文件
func TestAtomicWriteKey_Success(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(keyPath, []byte("OLD-CIPHERTEXT"), 0600); err != nil {
		t.Fatalf("预置旧密文失败: %v", err)
	}

	if err := atomicWriteKey(keyPath, []byte("NEW-CIPHERTEXT")); err != nil {
		t.Fatalf("atomicWriteKey() error = %v", err)
	}

	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != "NEW-CIPHERTEXT" {
		t.Errorf("内容 = %q, want NEW-CIPHERTEXT", got)
	}
	if _, err := os.Stat(keyPath + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("临时文件应已清理")
	}
}

// TestAtomicWriteKey_WriteFail_PreservesExisting 临时文件写入失败时保留旧密文（迁移不丢唯一密文）
func TestAtomicWriteKey_WriteFail_PreservesExisting(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "private.key")
	if err := os.WriteFile(keyPath, []byte("OLD-CIPHERTEXT"), 0600); err != nil {
		t.Fatalf("预置旧密文失败: %v", err)
	}
	// 把 .tmp 造成目录，使 os.WriteFile(tmpPath) 失败，模拟迁移写入失败
	if err := os.Mkdir(keyPath+".tmp", 0700); err != nil {
		t.Fatalf("构造 .tmp 目录失败: %v", err)
	}

	if err := atomicWriteKey(keyPath, []byte("NEW-CIPHERTEXT")); err == nil {
		t.Fatal("临时文件写入失败应返回错误")
	}

	// 旧密文必须完好无损
	got, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("读取旧密文失败: %v", err)
	}
	if string(got) != "OLD-CIPHERTEXT" {
		t.Errorf("旧密文被破坏: %q, want OLD-CIPHERTEXT", got)
	}
}
