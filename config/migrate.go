package config

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// migrateAction 迁移操作类型
type migrateAction int

const (
	actionRename migrateAction = iota + 1 // 重命名字段（path 下 field→target）
	actionDelete                          // 删除字段（path 下的 field）
	actionMove                            // 扁平字段移入子对象（目标已存在则不覆盖）
	actionSpread                          // 顶层字段分发到数组元素（合并语义，不覆盖已有值）
)

// migrateRule 声明式迁移规则
// 路径格式: "." 表示根，"certificates[]" 表示遍历数组元素，可嵌套如 "certificates[].bindings[]"
type migrateRule struct {
	action migrateAction
	path   string // 操作目标路径
	field  string // 源字段名
	target string // rename→新字段名; move→目标路径（如 "schedule.renew_before_days"）; spread→目标路径
}

// migrateRules 所有迁移规则（按添加顺序执行）
// 新增规则追加到末尾；每条规则必须幂等
var migrateRules = []migrateRule{
	// renew_days（顶层）→ schedule.renew_before_days
	{actionMove, ".", "renew_days", "schedule.renew_before_days"},
	// expires_at → metadata.cert_expires_at
	{actionMove, "certificates[]", "expires_at", "metadata.cert_expires_at"},
	// serial_number → metadata.cert_serial
	{actionMove, "certificates[]", "serial_number", "metadata.cert_serial"},
}

// customMigrations 自定义迁移函数（声明式规则无法表达的转换）
// 在 migrateRules 之后执行
var customMigrations = []func(map[string]interface{}) bool{
	migrateUseLocalKey,
	migrateCertName,
	migrateUpgradeChannel,
	migrateAPIToken,
	migrateTokenScope,
}

// migrateUseLocalKey 将 use_local_key bool 转换为 renew_mode string
func migrateUseLocalKey(raw map[string]interface{}) bool {
	certs := getSlice(raw, "certificates")
	if len(certs) == 0 {
		return false
	}
	changed := false
	for _, elem := range certs {
		node, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		val, has := node["use_local_key"]
		if !has {
			continue
		}
		// 仅当 renew_mode 不存在时才设置
		if _, hasNew := node["renew_mode"]; !hasNew {
			if b, ok := val.(bool); ok && b {
				node["renew_mode"] = "local"
			}
			// false 或非 bool → 不设置 renew_mode（继承全局）
		}
		delete(node, "use_local_key")
		changed = true
	}
	return changed
}

// migrateCertName 为缺少 cert_name 的证书自动生成
func migrateCertName(raw map[string]interface{}) bool {
	certs := getSlice(raw, "certificates")
	if len(certs) == 0 {
		return false
	}
	changed := false
	for _, elem := range certs {
		node, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		if _, has := node["cert_name"]; has {
			continue
		}
		domain, _ := node["domain"].(string)
		orderID, _ := node["order_id"].(float64) // JSON numbers are float64
		if domain != "" && orderID > 0 {
			node["cert_name"] = fmt.Sprintf("%s-%d", domain, int(orderID))
			changed = true
		}
	}
	return changed
}

// migrateUpgradeChannel 将旧通道值 stable→main、beta→dev
func migrateUpgradeChannel(raw map[string]interface{}) bool {
	ch, ok := raw["upgrade_channel"].(string)
	if !ok {
		return false
	}
	switch ch {
	case "stable":
		raw["upgrade_channel"] = "main"
		return true
	case "beta":
		raw["upgrade_channel"] = "dev"
		return true
	}
	return false
}

// encryptTokenFn 明文 Token 加密函数，可在测试中替换以注入加密失败
var encryptTokenFn = EncryptToken

// migrateAPIToken 将明文 api.token 加密迁移为 encrypted_token
// 加密失败时保留原明文字段不动、记警告日志，下次加载再试迁移，
// 避免丢弃用户唯一凭据导致被迫重录（与 vm:/v1: 前缀迁移逻辑幂等协同）
func migrateAPIToken(raw map[string]interface{}) bool {
	certs := getSlice(raw, "certificates")
	if len(certs) == 0 {
		return false
	}
	changed := false
	for _, elem := range certs {
		node, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		apiObj, ok := getMap(node, "api")
		if !ok {
			continue
		}
		token, hasToken := apiObj["token"].(string)
		if !hasToken || token == "" {
			continue
		}
		// 已有密文：明文冗余，安全删除
		if _, hasEncrypted := apiObj["encrypted_token"].(string); hasEncrypted {
			delete(apiObj, "token")
			changed = true
			continue
		}
		// 加密失败：保留明文，不删除、不置换，下次加载重试；切勿丢弃唯一凭据
		encrypted, err := encryptTokenFn(token)
		if err != nil {
			log.Printf("警告: 迁移 API Token 加密失败，保留明文待下次重试: %v", err)
			continue
		}
		// 成功才替换：写入密文并删除明文
		apiObj["encrypted_token"] = encrypted
		delete(apiObj, "token")
		changed = true
	}
	return changed
}

// migrateTokenScope 将旧用户作用域的 encrypted_token 透明迁移为机器作用域
// 仅当能成功解密（当前为加密时的交互账户）才重新加密落盘，实现幂等迁移；
// 无法解密（例如密文由其他账户加密）时保留原值，由 GetToken 显式报错提示重录
func migrateTokenScope(raw map[string]interface{}) bool {
	certs := getSlice(raw, "certificates")
	if len(certs) == 0 {
		return false
	}
	changed := false
	for _, elem := range certs {
		node, ok := elem.(map[string]interface{})
		if !ok {
			continue
		}
		apiObj, ok := getMap(node, "api")
		if !ok {
			continue
		}
		enc, ok := apiObj["encrypted_token"].(string)
		if !ok || !TokenNeedsMigration(enc) {
			continue
		}
		plain, err := DecryptToken(enc)
		if err != nil {
			continue // 无法解密，保留原值
		}
		reEncrypted, err := EncryptToken(plain)
		if err != nil {
			continue
		}
		apiObj["encrypted_token"] = reEncrypted
		changed = true
	}
	return changed
}

// mergeFile 旧文件合并规则
type mergeFile struct {
	name   string // 旧文件名（相对于配置目录）
	target string // 合并目标路径（"." 表示根级合并）
}

// mergeFiles 旧文件合并规则（按添加顺序执行）
// sslctlw 当前无旧文件需要合并，规则表为空
var mergeFiles []mergeFile

// migrateFields 对 raw JSON map 执行所有迁移规则 + 自定义迁移
func migrateFields(raw map[string]interface{}) bool {
	changed := false
	for _, rule := range migrateRules {
		if applyRule(raw, rule) {
			changed = true
		}
	}
	for _, fn := range customMigrations {
		if fn(raw) {
			changed = true
		}
	}
	return changed
}

// migrateConfig 便捷入口：接收原始 JSON bytes，返回迁移后的 bytes
// 仅执行规则迁移，不包含默认值填充和旧文件合并
func migrateConfig(data []byte) ([]byte, bool, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return data, false, err
	}

	if !migrateFields(raw) {
		return data, false, nil
	}

	newData, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return data, false, err
	}
	return newData, true, nil
}

// applyRule 分发执行迁移规则
func applyRule(root map[string]interface{}, rule migrateRule) bool {
	switch rule.action {
	case actionRename:
		return applyRename(root, rule.path, rule.field, rule.target)
	case actionDelete:
		return applyDelete(root, rule.path, rule.field)
	case actionMove:
		return applyMove(root, rule.path, rule.field, rule.target)
	case actionSpread:
		return applySpread(root, rule.field, rule.target)
	}
	return false
}

// applyRename 在 path 匹配的所有节点上，将 oldKey 重命名为 newKey
func applyRename(root map[string]interface{}, path, oldKey, newKey string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[oldKey]
		if !has {
			continue
		}
		if _, hasNew := node[newKey]; !hasNew {
			node[newKey] = val
		}
		delete(node, oldKey)
		changed = true
	}
	return changed
}

// applyDelete 在 path 匹配的所有节点上，删除 key
func applyDelete(root map[string]interface{}, path, key string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		if _, has := node[key]; has {
			delete(node, key)
			changed = true
		}
	}
	return changed
}

// applyMove 将 path 下的 field 移入 target 指定的子对象路径
// target 是相对于源节点的路径（如 "schedule.renew_before_days"）
// 目标已存在则不覆盖，源字段始终删除
func applyMove(root map[string]interface{}, path, field, target string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[field]
		if !has {
			continue
		}

		// 解析目标路径
		targetParent, targetField := splitTargetPath(target)
		parent := ensurePath(node, targetParent)
		if parent != nil {
			if _, hasTarget := parent[targetField]; !hasTarget {
				parent[targetField] = val
			}
		}

		delete(node, field)
		changed = true
	}
	return changed
}

// applySpread 将根节点的 sourceKey 字段分发到 targetPath 指向的每个数组元素
// 合并语义：仅补全目标节点中缺失的字段，不覆盖已有值
// 分发完成后删除源字段
func applySpread(root map[string]interface{}, sourceKey, targetPath string) bool {
	source, ok := root[sourceKey]
	if !ok {
		return false
	}
	sourceMap, ok := source.(map[string]interface{})
	if !ok {
		delete(root, sourceKey)
		return true
	}
	if len(sourceMap) == 0 {
		delete(root, sourceKey)
		return true
	}

	parentPath, field := splitTargetPath(targetPath)
	nodes := resolvePath(root, parentPath)

	for _, node := range nodes {
		existing, hasExisting := node[field]
		if !hasExisting {
			node[field] = copyMap(sourceMap)
			continue
		}
		existingMap, ok := existing.(map[string]interface{})
		if !ok {
			continue
		}
		for k, v := range sourceMap {
			if _, has := existingMap[k]; !has {
				existingMap[k] = v
			}
		}
	}

	delete(root, sourceKey)
	return true
}

// --- 路径解析 ---

// resolvePath 解析路径，返回所有匹配的 map 节点
// 路径格式: "." = 根节点，"key[]" = 遍历数组，"key" = 进入子 map，用 "." 分隔
func resolvePath(root map[string]interface{}, path string) []map[string]interface{} {
	if path == "." {
		return []map[string]interface{}{root}
	}

	current := []map[string]interface{}{root}
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		var next []map[string]interface{}
		if strings.HasSuffix(part, "[]") {
			key := strings.TrimSuffix(part, "[]")
			for _, node := range current {
				for _, elem := range getSlice(node, key) {
					if m, ok := elem.(map[string]interface{}); ok {
						next = append(next, m)
					}
				}
			}
		} else {
			for _, node := range current {
				if m, ok := getMap(node, part); ok {
					next = append(next, m)
				}
			}
		}
		current = next
	}
	return current
}

// splitTargetPath 拆分目标路径为父路径和字段名
// "schedule.renew_before_days" → ("schedule", "renew_before_days")
// "certificates[].api" → ("certificates[]", "api")
// "api" → (".", "api")
func splitTargetPath(target string) (parentPath, field string) {
	idx := strings.LastIndex(target, ".")
	if idx < 0 {
		return ".", target
	}
	return target[:idx], target[idx+1:]
}

// ensurePath 沿路径导航，不存在的中间对象自动创建
// 仅支持简单 key 路径（不支持数组遍历 []）
// 返回 nil 表示路径冲突（中间节点不是 map）
func ensurePath(node map[string]interface{}, path string) map[string]interface{} {
	if path == "." {
		return node
	}
	current := node
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		child, ok := current[part]
		if !ok {
			newChild := make(map[string]interface{})
			current[part] = newChild
			current = newChild
			continue
		}
		childMap, ok := child.(map[string]interface{})
		if !ok {
			return nil
		}
		current = childMap
	}
	return current
}

// --- 辅助函数 ---

func getSlice(m map[string]interface{}, key string) []interface{} {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}

func getMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	result, ok := v.(map[string]interface{})
	return result, ok
}

func copyMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// deepCopy 深拷贝 JSON 值（map/slice 递归，原始类型直接返回）
func deepCopy(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		dst := make(map[string]interface{}, len(val))
		for k, v := range val {
			dst[k] = deepCopy(v)
		}
		return dst
	case []interface{}:
		dst := make([]interface{}, len(val))
		for i, v := range val {
			dst[i] = deepCopy(v)
		}
		return dst
	default:
		return v
	}
}

// --- 默认值填充 ---

// applyDefaults 递归对比 raw 与 defaults，补齐 raw 中缺失的字段
// 仅填充缺失的键，不覆盖已有值；嵌套 map 递归处理
func applyDefaults(raw, defaults map[string]interface{}) bool {
	changed := false
	for key, defVal := range defaults {
		curVal, exists := raw[key]
		if !exists {
			raw[key] = deepCopy(defVal)
			changed = true
			continue
		}
		// 两者都是 map 时递归
		defMap, defIsMap := defVal.(map[string]interface{})
		curMap, curIsMap := curVal.(map[string]interface{})
		if defIsMap && curIsMap {
			if applyDefaults(curMap, defMap) {
				changed = true
			}
		}
	}
	return changed
}

// defaultConfigRaw 将 DefaultConfig() 序列化为 raw JSON map
func defaultConfigRaw() map[string]interface{} {
	data, _ := json.Marshal(DefaultConfig())
	var raw map[string]interface{}
	_ = json.Unmarshal(data, &raw)
	return raw
}

// --- 旧文件合并 ---

// mergeInto 将 source 数据合并到 raw 的指定 target 路径
// 仅补全缺失字段，不覆盖已有值
func mergeInto(raw map[string]interface{}, target string, source map[string]interface{}) bool {
	node := ensurePath(raw, target)
	if node == nil {
		return false
	}
	changed := false
	for k, v := range source {
		if _, has := node[k]; !has {
			node[k] = v
			changed = true
		}
	}
	return changed
}
