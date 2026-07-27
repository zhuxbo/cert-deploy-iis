package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sslctlw/api"
	"sslctlw/config"
	"sslctlw/iis"
)

func TestNormalizeValidationRelativePathRejectsUnsafeInput(t *testing.T) {
	bad := []string{
		`C:\inetpub\wwwroot\.well-known\token`,
		`\\server\share\.well-known\token`,
		`/.well-known/../secret`,
		`/.well-known/acme-challenge/token:ads`,
		"/.well-known/acme-challenge/NUL.txt",
		"/.well-known/acme-challenge/CONIN$",
		"/.well-known/acme-challenge/COM¹.txt",
		"/.well-known/acme-challenge/LPT³",
		"/.well-known/acme-challenge/token.",
		"/.well-known/acme-challenge/token ",
		"/.well-known/acme-challenge/malware.exe",
		"/.well-known\\acme-challenge/token",
		"/tmp/token",
		string([]byte{'/', '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', '/', 0, 'x'}),
	}
	for _, input := range bad {
		t.Run(strings.ReplaceAll(input, "/", "_"), func(t *testing.T) {
			if _, err := normalizeValidationRelativePath(input); err == nil {
				t.Fatalf("normalizeValidationRelativePath(%q) 应拒绝", input)
			}
		})
	}

	got, err := normalizeValidationRelativePath("/.well-known/acme-challenge/token")
	if err != nil {
		t.Fatalf("合法路径 error = %v", err)
	}
	if got != filepath.Join(".well-known", "acme-challenge", "token") {
		t.Fatalf("合法路径 = %q", got)
	}
}

func TestDefaultValidationFileStoreOwnership(t *testing.T) {
	store := defaultValidationFileStore{}
	root := iis.ValidationWebRoot{SiteName: "Default", PhysicalPath: t.TempDir()}
	path := "/.well-known/acme-challenge/token"

	placed, err := store.PlaceToken(root, path, "first")
	if err != nil {
		t.Fatalf("PlaceToken() error = %v", err)
	}
	if !placed.Created || placed.SHA256 == "" {
		t.Fatalf("新文件 placement = %+v", placed)
	}
	if _, err := os.Stat(filepath.Join(root.PhysicalPath, ".well-known", "acme-challenge", "web.config")); err != nil {
		t.Fatalf("token 前应创建 web.config: %v", err)
	}

	same, err := store.PlaceToken(root, path, "first")
	if err != nil {
		t.Fatalf("同内容预存应复用: %v", err)
	}
	if same.Created {
		t.Fatal("同内容预存不得取得所有权")
	}
	if _, err := store.PlaceToken(root, path, "different"); err == nil {
		t.Fatal("不同内容预存不得覆盖")
	}
	content, _ := os.ReadFile(filepath.Join(root.PhysicalPath, placed.RelativePath))
	if string(content) != "first" {
		t.Fatalf("不同内容调用覆盖了文件: %q", content)
	}

	changedPath := filepath.Join(root.PhysicalPath, placed.RelativePath)
	if err := os.WriteFile(changedPath, []byte("user changed"), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := store.RemoveToken(root, config.ValidationFileRecord{
		SiteName: root.SiteName, RelativePath: placed.RelativePath, SHA256: placed.SHA256,
	})
	if err != nil {
		t.Fatalf("RemoveToken(changed) error = %v", err)
	}
	if status != validationTokenOwnershipChanged {
		t.Fatalf("changed status = %v", status)
	}
	if _, err := os.Stat(changedPath); err != nil {
		t.Fatalf("所有权改变后必须保留: %v", err)
	}
}

func TestDefaultValidationFileStoreCreatesWebConfigBeforeToken(t *testing.T) {
	store := defaultValidationFileStore{}
	root := iis.ValidationWebRoot{SiteName: "Default", PhysicalPath: t.TempDir()}
	dir := filepath.Join(root.PhysicalPath, ".well-known", "acme-challenge")
	if err := os.MkdirAll(filepath.Join(dir, "web.config"), 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PlaceToken(root, "/.well-known/acme-challenge/token", "content"); err == nil {
		t.Fatal("web.config 无法创建时应失败")
	}
	if _, err := os.Stat(filepath.Join(dir, "token")); !os.IsNotExist(err) {
		t.Fatalf("web.config 失败后不得创建 token, err=%v", err)
	}
}

func TestDefaultValidationFileStoreBoundsExistingFileRead(t *testing.T) {
	store := defaultValidationFileStore{}
	root := iis.ValidationWebRoot{SiteName: "Default", PhysicalPath: t.TempDir()}
	dir := filepath.Join(root.PhysicalPath, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), make([]byte, maxValidationFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PlaceToken(root, "/.well-known/acme-challenge/token", "content"); err == nil {
		t.Fatal("超大现有文件必须有界拒绝")
	}
}

func TestDefaultValidationFileStoreErrorsDoNotExposePhysicalRoot(t *testing.T) {
	store := defaultValidationFileStore{}
	rootPath := filepath.Join(t.TempDir(), "private-site-root")
	root := iis.ValidationWebRoot{SiteName: "Secret", PhysicalPath: rootPath}
	_, err := store.PlaceToken(root, "/.well-known/acme-challenge/token", "content")
	if err == nil {
		t.Fatal("不存在的 root 应失败")
	}
	if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(rootPath)) {
		t.Fatalf("错误不得暴露 IIS PhysicalPath: %v", err)
	}
}

func TestDefaultValidationFileStoreRejectsSymlinkTraversal(t *testing.T) {
	store := defaultValidationFileStore{}
	rootDir := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(rootDir, ".well-known"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rootDir, ".well-known", "acme-challenge")); err != nil {
		t.Skipf("当前环境不能创建符号链接: %v", err)
	}
	root := iis.ValidationWebRoot{SiteName: "Default", PhysicalPath: rootDir}
	if _, err := store.PlaceToken(root, "/.well-known/acme-challenge/token", "content"); err == nil {
		t.Fatal("不得穿过 symlink/reparse point")
	}
}

func TestHandleProcessingOrderPersistsEachOwnedTokenAndResumes(t *testing.T) {
	d := NewMockDeployer()
	roots := []iis.ValidationWebRoot{
		{SiteName: "A", PhysicalPath: `C:\sites\a`},
		{SiteName: "B", PhysicalPath: `C:\sites\b`},
	}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func([]string, string) ([]iis.ValidationWebRoot, error) {
		return roots, nil
	}
	placeCalls := map[string]int{}
	failB := true
	d.ValidationFiles.(*MockValidationFileStore).PlaceTokenFunc = func(root iis.ValidationWebRoot, path, content string) (validationTokenPlacement, error) {
		placeCalls[root.SiteName]++
		if root.SiteName == "A" && placeCalls[root.SiteName] > 1 {
			relative, _ := normalizeValidationRelativePath(path)
			return validationTokenPlacement{RelativePath: relative, SHA256: strings.Repeat("a", 64)}, nil
		}
		if root.SiteName == "B" && failB {
			return validationTokenPlacement{}, errors.New("B root unavailable")
		}
		relative, _ := normalizeValidationRelativePath(path)
		return validationTokenPlacement{RelativePath: relative, SHA256: strings.Repeat(strings.ToLower(root.SiteName), 64), Created: true}, nil
	}
	cfg := &config.CertConfig{Domain: "example.com", Domains: []string{"example.com"}}
	data := &api.CertData{File: &api.FileValidation{
		Path: "/.well-known/acme-challenge/token", Content: "content",
	}}
	saveSnapshots := make([]int, 0)
	save := func() error {
		saveSnapshots = append(saveSnapshots, len(cfg.Metadata.ValidationFiles))
		return nil
	}

	if _, err := handleProcessingOrder(d, cfg, data, save); err == nil || !strings.Contains(err.Error(), "B root unavailable") {
		t.Fatalf("第二根失败应向上传播: %v", err)
	}
	if len(cfg.Metadata.ValidationFiles) != 1 || cfg.Metadata.ValidationFiles[0].SiteName != "A" {
		t.Fatalf("第一根记录必须已保留: %+v", cfg.Metadata.ValidationFiles)
	}
	if len(saveSnapshots) != 1 || saveSnapshots[0] != 1 {
		t.Fatalf("每个新增 token 应立即持久化: %v", saveSnapshots)
	}

	failB = false
	if _, err := handleProcessingOrder(d, cfg, data, save); err != nil {
		t.Fatalf("补齐第二根 error = %v", err)
	}
	if placeCalls["A"] != 2 || placeCalls["B"] != 2 {
		t.Fatalf("重试必须复验已有根并补缺失根: calls=%v", placeCalls)
	}
	if len(cfg.Metadata.ValidationFiles) != 2 {
		t.Fatalf("最终 records = %+v", cfg.Metadata.ValidationFiles)
	}
}

func TestHandleProcessingOrderExistingRecordRevalidatesAndPersistsRecreatedToken(t *testing.T) {
	d := NewMockDeployer()
	root := iis.ValidationWebRoot{SiteName: "A", PhysicalPath: `C:\sites\a`}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func([]string, string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{root}, nil
	}
	old := config.ValidationFileRecord{
		SiteName: "A", RelativePath: filepath.Join(".well-known", "acme-challenge", "token"),
		SHA256: "old",
	}
	cfg := &config.CertConfig{
		Domain:   "example.com",
		Metadata: config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{old}},
	}
	data := &api.CertData{File: &api.FileValidation{
		Path: "/.well-known/acme-challenge/token", Content: "new",
	}}
	placeCalls := 0
	d.ValidationFiles.(*MockValidationFileStore).PlaceTokenFunc = func(iis.ValidationWebRoot, string, string) (validationTokenPlacement, error) {
		placeCalls++
		return validationTokenPlacement{
			RelativePath: old.RelativePath, SHA256: "new", Created: true,
		}, nil
	}
	removeCalls := 0
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		removeCalls++
		return validationTokenRemoved, nil
	}
	saveCalls := 0
	if _, err := handleProcessingOrder(d, cfg, data, func() error { saveCalls++; return nil }); err != nil {
		t.Fatalf("重建 token error = %v", err)
	}
	if placeCalls != 1 || saveCalls != 1 || len(cfg.Metadata.ValidationFiles) != 1 ||
		cfg.Metadata.ValidationFiles[0].SHA256 != "new" {
		t.Fatalf("重建应复验、原位更新并保存: place=%d save=%d records=%+v",
			placeCalls, saveCalls, cfg.Metadata.ValidationFiles)
	}

	cfg.Metadata.ValidationFiles[0] = old
	saveCalls = 0
	if _, err := handleProcessingOrder(d, cfg, data, func() error {
		saveCalls++
		return errors.New("save failed")
	}); err == nil {
		t.Fatal("重建后的保存失败必须返回错误")
	}
	if removeCalls != 1 || cfg.Metadata.ValidationFiles[0] != old {
		t.Fatalf("保存失败只回滚重建 token 并恢复旧 record: remove=%d record=%+v",
			removeCalls, cfg.Metadata.ValidationFiles[0])
	}
}

func TestHandleProcessingOrderExistingRecordSameContentDoesNotSave(t *testing.T) {
	d := NewMockDeployer()
	root := iis.ValidationWebRoot{SiteName: "A", PhysicalPath: `C:\sites\a`}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func([]string, string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{root}, nil
	}
	record := config.ValidationFileRecord{
		SiteName: "A", RelativePath: filepath.Join(".well-known", "acme-challenge", "token"), SHA256: "same",
	}
	cfg := &config.CertConfig{
		Domain:   "example.com",
		Metadata: config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{record}},
	}
	d.ValidationFiles.(*MockValidationFileStore).PlaceTokenFunc = func(iis.ValidationWebRoot, string, string) (validationTokenPlacement, error) {
		return validationTokenPlacement{RelativePath: record.RelativePath, SHA256: record.SHA256}, nil
	}
	saveCalls := 0
	if _, err := handleProcessingOrder(d, cfg, &api.CertData{File: &api.FileValidation{
		Path: "/.well-known/acme-challenge/token", Content: "same",
	}}, func() error { saveCalls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if saveCalls != 0 || len(cfg.Metadata.ValidationFiles) != 1 {
		t.Fatalf("同内容复验不得新增或保存: save=%d records=%+v", saveCalls, cfg.Metadata.ValidationFiles)
	}
}

func TestResolveValidationRootsIncludesExplicitAndAutomaticRules(t *testing.T) {
	resolver := &MockValidationWebRootResolver{}
	calls := make([]string, 0)
	resolver.ResolveFunc = func(_ []string, site string) ([]iis.ValidationWebRoot, error) {
		calls = append(calls, site)
		name := site
		if name == "" {
			name = "Auto"
		}
		return []iis.ValidationWebRoot{{SiteName: name, PhysicalPath: `C:\sites\` + name}}, nil
	}
	cfg := &config.CertConfig{
		Domain: "example.com",
		BindRules: []config.BindRule{
			{Domain: "example.com", SiteName: "Explicit"},
			{Domain: "www.example.com"},
		},
	}
	roots, err := resolveValidationRoots(resolver, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0] != "" || calls[1] != "Explicit" || len(roots) != 2 {
		t.Fatalf("混合规则必须同时解析自动与显式站点: calls=%v roots=%+v", calls, roots)
	}
}

func TestDefaultValidationFileStoreRemoveUncertainStatePreservesOwnership(t *testing.T) {
	store := defaultValidationFileStore{}
	root := iis.ValidationWebRoot{SiteName: "Default", PhysicalPath: t.TempDir()}
	tests := []config.ValidationFileRecord{
		{SiteName: "Default", RelativePath: `..\outside`, SHA256: "x"},
		{SiteName: "Default", RelativePath: filepath.Join(".well-known", "token"), SHA256: "x"},
	}
	if err := os.MkdirAll(filepath.Join(root.PhysicalPath, ".well-known", "token"), 0750); err != nil {
		t.Fatal(err)
	}
	for _, record := range tests {
		status, err := store.RemoveToken(root, record)
		if err != nil || status != validationTokenOwnershipChanged {
			t.Fatalf("不确定 record=%+v 应保留所有权: status=%v err=%v", record, status, err)
		}
	}
}

func TestHandleProcessingOrderSaveFailureRollsBackOnlyNewToken(t *testing.T) {
	d := NewMockDeployer()
	root := iis.ValidationWebRoot{SiteName: "A", PhysicalPath: `C:\sites\a`}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func([]string, string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{root}, nil
	}
	d.ValidationFiles.(*MockValidationFileStore).PlaceTokenFunc = func(iis.ValidationWebRoot, string, string) (validationTokenPlacement, error) {
		return validationTokenPlacement{
			RelativePath: filepath.Join(".well-known", "acme-challenge", "token"),
			SHA256:       strings.Repeat("a", 64),
			Created:      true,
		}, nil
	}
	removeCalls := 0
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		removeCalls++
		return validationTokenRemoved, nil
	}
	cfg := &config.CertConfig{Domain: "example.com"}
	data := &api.CertData{File: &api.FileValidation{
		Path: "/.well-known/acme-challenge/token", Content: "content",
	}}
	if _, err := handleProcessingOrder(d, cfg, data, func() error { return errors.New("config disk full") }); err == nil {
		t.Fatal("metadata 保存失败必须向上传播")
	}
	if removeCalls != 1 || len(cfg.Metadata.ValidationFiles) != 0 {
		t.Fatalf("只应回滚本次新建 token: remove=%d records=%+v", removeCalls, cfg.Metadata.ValidationFiles)
	}

	removeCalls = 0
	if _, err := handleProcessingOrder(d, cfg, data); err == nil || !strings.Contains(err.Error(), "持久化") {
		t.Fatalf("缺少 persister 时新建 token 必须失败: %v", err)
	}
	if removeCalls != 1 {
		t.Fatalf("缺少 persister 也必须回滚 token, remove=%d", removeCalls)
	}

	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		return validationTokenOwnershipChanged, errors.New("rollback denied")
	}
	_, joinedErr := handleProcessingOrder(d, cfg, data, func() error { return errors.New("save denied") })
	if joinedErr == nil || !strings.Contains(joinedErr.Error(), "save denied") || !strings.Contains(joinedErr.Error(), "rollback denied") {
		t.Fatalf("保存与回滚失败必须同时保留: %v", joinedErr)
	}
}

func TestSubmitPendingCSRPersistsNewOrderBeforePlacingToken(t *testing.T) {
	d := NewMockDeployer()
	root := iis.ValidationWebRoot{SiteName: "A", PhysicalPath: `C:\sites\a`}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func([]string, string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{root}, nil
	}
	events := make([]string, 0)
	d.ValidationFiles.(*MockValidationFileStore).PlaceTokenFunc = func(iis.ValidationWebRoot, string, string) (validationTokenPlacement, error) {
		events = append(events, "place")
		if len(events) < 2 || events[len(events)-2] != "persist:42" {
			return validationTokenPlacement{}, errors.New("token 在新订单状态持久化前写入")
		}
		return validationTokenPlacement{
			RelativePath: filepath.Join(".well-known", "acme-challenge", "token"),
			SHA256:       strings.Repeat("a", 64),
			Created:      true,
		}, nil
	}
	client := NewMockClient()
	client.SubmitCSRFunc = func(_ context.Context, _ *api.UpdateRequest) (*api.UpdateResponse, error) {
		events = append(events, "post")
		return &api.UpdateResponse{Data: api.UpdateResponseData{CertData: api.CertData{
			OrderID: 42, Status: "processing",
			File: &api.FileValidation{Path: "/.well-known/acme-challenge/token", Content: "content"},
		}}}, nil
	}
	cfg := &config.CertConfig{Domain: "example.com", Domains: []string{"example.com"}}
	persist := func() error {
		events = append(events, fmt.Sprintf("persist:%d", cfg.OrderID))
		return nil
	}
	if _, _, _, err := submitPendingCSR(d, client, cfg, validTestCSR(t), persist); err != nil {
		t.Fatalf("submitPendingCSR() error = %v, events=%v", err, events)
	}
	if len(cfg.Metadata.ValidationFiles) != 1 {
		t.Fatalf("token 所有权未持久化: %+v", cfg.Metadata.ValidationFiles)
	}
}

func TestCleanupOwnedValidationFilesPreservesUncertainOwnership(t *testing.T) {
	d := NewMockDeployer()
	roots := map[string]iis.ValidationWebRoot{
		"A": {SiteName: "A", PhysicalPath: `C:\sites\a`},
		"B": {SiteName: "B", PhysicalPath: `C:\sites\b`},
	}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func(domains []string, site string) ([]iis.ValidationWebRoot, error) {
		if len(domains) != 1 || domains[0] != "example.com" {
			return nil, errors.New("cleanup 未回退使用主域名")
		}
		return []iis.ValidationWebRoot{roots[site]}, nil
	}
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(root iis.ValidationWebRoot, _ config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		if root.SiteName == "B" {
			return validationTokenOwnershipChanged, nil
		}
		return validationTokenRemoved, nil
	}
	cfg := &config.CertConfig{
		Domain: "example.com",
		Metadata: config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{
			{SiteName: "A", RelativePath: filepath.Join(".well-known", "a"), SHA256: "a"},
			{SiteName: "B", RelativePath: filepath.Join(".well-known", "b"), SHA256: "b"},
		}},
	}
	supplemental := &runSupplemental{}
	saveCalls := 0
	cleanupOwnedValidationFiles(d, cfg, func() error { saveCalls++; return nil }, supplemental)
	if saveCalls != 1 || len(cfg.Metadata.ValidationFiles) != 1 || cfg.Metadata.ValidationFiles[0].SiteName != "B" {
		t.Fatalf("cleanup records=%+v saveCalls=%d", cfg.Metadata.ValidationFiles, saveCalls)
	}
	if len(supplemental.Warnings) != 1 || len(supplemental.Errors) != 0 {
		t.Fatalf("所有权不确定只告警并保留: %+v", supplemental)
	}
}

func TestCleanupOwnedValidationFilesMissingClearsRecordButSaveFailureRestoresIt(t *testing.T) {
	d := NewMockDeployer()
	root := iis.ValidationWebRoot{SiteName: "A", PhysicalPath: `C:\sites\a`}
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func(_ []string, _ string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{root}, nil
	}
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		return validationTokenMissing, nil
	}
	record := config.ValidationFileRecord{
		SiteName: "A", RelativePath: filepath.Join(".well-known", "token"), SHA256: "a",
	}
	cfg := &config.CertConfig{
		Domain:   "example.com",
		Domains:  []string{"example.com"},
		Metadata: config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{record}},
	}
	supplemental := &runSupplemental{}
	cleanupOwnedValidationFiles(d, cfg, func() error { return errors.New("disk full") }, supplemental)
	if len(cfg.Metadata.ValidationFiles) != 1 || cfg.Metadata.ValidationFiles[0] != record {
		t.Fatalf("保存失败必须恢复 record: %+v", cfg.Metadata.ValidationFiles)
	}
	if len(supplemental.Errors) != 1 || !strings.Contains(supplemental.Errors[0].Error(), "disk full") {
		t.Fatalf("保存失败必须进入 supplemental Errors: %+v", supplemental)
	}
}

func TestRunAutoDeployCleanupFailureDoesNotChangeSuccessCallback(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "cleanup.example.com")
	callbackStatus := ""
	callbackCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/callback" {
			var req api.CallbackRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			callbackStatus = req.Status
			callbackCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data": []api.CertData{{
					OrderID: 901, Domains: "cleanup.example.com", Status: "active",
					ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
					Certificate: certPEM, PrivateKey: keyPEM, CACert: testCACertPEM,
				}},
				"currentPage": 1, "pageSize": 20, "total": 1,
			},
		})
	}))
	defer server.Close()

	certAPI := config.CertAPIConfig{URL: server.URL}
	if err := certAPI.SetToken("token"); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Certificates = []config.CertConfig{{
		OrderID: 901, Domain: "cleanup.example.com", Domains: []string{"cleanup.example.com"},
		Enabled: true, API: certAPI,
		BindRules: []config.BindRule{{Domain: "cleanup.example.com", Port: 443}},
		Metadata: config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{{
			SiteName: "A", RelativePath: filepath.Join(".well-known", "token"), SHA256: "a",
		}}},
	}}
	d := NewMockDeployer()
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func(_ []string, _ string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{{SiteName: "A", PhysicalPath: `C:\sites\a`}}, nil
	}
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		return validationTokenOwnershipChanged, errors.New("access denied")
	}

	report := runAutoDeploy(cfg, d, RunOptions{}, successfulAutoDeployDependencies(nil))
	if callbackStatus != "success" || callbackCount != 1 {
		t.Fatalf("cleanup 失败不得改变一次成功 callback: status=%q count=%d", callbackStatus, callbackCount)
	}
	if len(report.Errors) != 1 || len(report.Results) == 0 || !report.Results[0].Success {
		t.Fatalf("cleanup 失败应是 supplemental error，部署结果保持成功: %+v", report)
	}
}

func TestRunAutoDeployCleanupSaveFailureIsSupplemental(t *testing.T) {
	certPEM, keyPEM := genSelfSignedPair(t, "cleanup-save.example.com")
	callbackCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/callback" {
			callbackCount++
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "ok"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code": 1, "msg": "ok", "data": map[string]any{
				"data": []api.CertData{{
					OrderID: 902, Domains: "cleanup-save.example.com", Status: "active",
					ExpiresAt:   time.Now().AddDate(0, 0, 5).Format("2006-01-02"),
					Certificate: certPEM, PrivateKey: keyPEM, CACert: testCACertPEM,
				}},
				"currentPage": 1, "pageSize": 20, "total": 1,
			},
		})
	}))
	defer server.Close()
	certAPI := config.CertAPIConfig{URL: server.URL}
	if err := certAPI.SetToken("token"); err != nil {
		t.Fatal(err)
	}
	record := config.ValidationFileRecord{
		SiteName: "A", RelativePath: filepath.Join(".well-known", "token"), SHA256: "a",
	}
	cfg := config.DefaultConfig()
	cfg.Certificates = []config.CertConfig{{
		OrderID: 902, Domain: "cleanup-save.example.com", Domains: []string{"cleanup-save.example.com"},
		Enabled: true, API: certAPI,
		BindRules: []config.BindRule{{Domain: "cleanup-save.example.com", Port: 443}},
		Metadata:  config.CertMetadata{ValidationFiles: []config.ValidationFileRecord{record}},
	}}
	d := NewMockDeployer()
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func(_ []string, _ string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{{SiteName: "A", PhysicalPath: `C:\sites\a`}}, nil
	}
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		return validationTokenRemoved, nil
	}
	saveCalls := 0
	deps := successfulAutoDeployDependencies(func(*config.Config) error {
		saveCalls++
		if saveCalls == 3 {
			return errors.New("cleanup metadata save denied")
		}
		return nil
	})
	report := runAutoDeploy(cfg, d, RunOptions{}, deps)
	if callbackCount != 1 || len(report.Results) == 0 || !report.Results[0].Success {
		t.Fatalf("cleanup save 失败不得改变部署/callback: count=%d report=%+v", callbackCount, report)
	}
	if len(report.Errors) != 1 || !strings.Contains(report.Errors[0].Error(), "cleanup metadata save denied") {
		t.Fatalf("cleanup save 失败必须进入 RunReport.Errors: %+v", report.Errors)
	}
	if len(cfg.Certificates[0].Metadata.ValidationFiles) != 1 {
		t.Fatalf("cleanup save 失败必须恢复 record: %+v", cfg.Certificates[0].Metadata.ValidationFiles)
	}
}

func TestStalledValidationCleanupRetriesBeforeCappedGate(t *testing.T) {
	record := config.ValidationFileRecord{
		SiteName: "A", RelativePath: filepath.Join(".well-known", "token"), SHA256: "a",
	}
	cfg := config.DefaultConfig()
	cfg.Certificates = []config.CertConfig{{
		CertName: "stalled.example.com-903", OrderID: 903,
		Domain: "stalled.example.com", Domains: []string{"stalled.example.com"}, Enabled: true,
		Metadata: config.CertMetadata{
			LastIssueState: config.IssueStateCapped,
			CapPhase:       config.CapPhaseStalled,
			ValidationFiles: []config.ValidationFileRecord{
				record,
			},
		},
	}}
	d := NewMockDeployer()
	d.ValidationRoots.(*MockValidationWebRootResolver).ResolveFunc = func(_ []string, _ string) ([]iis.ValidationWebRoot, error) {
		return []iis.ValidationWebRoot{{SiteName: "A", PhysicalPath: `C:\sites\a`}}, nil
	}
	removeCalls := 0
	d.ValidationFiles.(*MockValidationFileStore).RemoveTokenFunc = func(iis.ValidationWebRoot, config.ValidationFileRecord) (validationTokenRemoveStatus, error) {
		removeCalls++
		if removeCalls == 1 {
			return validationTokenOwnershipChanged, errors.New("access denied")
		}
		return validationTokenRemoved, nil
	}

	first := &runSupplemental{}
	_, _ = processOneCertWithSaveAndGate(cfg, d, 0, nil, func() error { return nil }, nil, nil, first)
	if len(first.Errors) != 1 || len(cfg.Certificates[0].Metadata.ValidationFiles) != 1 {
		t.Fatalf("首次失败必须保留记录供重试: errors=%+v records=%+v",
			first.Errors, cfg.Certificates[0].Metadata.ValidationFiles)
	}

	second := &runSupplemental{}
	_, _ = processOneCertWithSaveAndGate(cfg, d, 0, nil, func() error { return nil }, nil, nil, second)
	if len(second.Errors) != 0 || len(cfg.Certificates[0].Metadata.ValidationFiles) != 0 || removeCalls != 2 {
		t.Fatalf("下轮应在 CAPPED 门禁前收敛: errors=%+v records=%+v calls=%d",
			second.Errors, cfg.Certificates[0].Metadata.ValidationFiles, removeCalls)
	}
}
