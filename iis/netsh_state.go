package iis

import (
	"fmt"
	"strings"
	"time"
)

// capturedBinding 回绑旧证书所需的绑定参数快照。
// 最小三字段（CertHash/AppID/CertStoreName）始终可用；
// full=true 时（经 httpapi 结构化查询）携带完整高级 SSL 参数，回绑可完整还原。
type capturedBinding struct {
	CertHash      string
	AppID         string
	CertStoreName string

	// 以下高级参数仅在 full=true 时有效（HttpQueryServiceConfiguration 结构化查询结果）
	full                    bool
	certCheckMode           uint32 // DefaultCertCheckMode 位掩码
	revocationFreshnessTime uint32 // DefaultRevocationFreshnessTime（秒）
	urlRetrievalTimeout     uint32 // DefaultRevocationUrlRetrievalTimeout（毫秒）
	sslCtlIdentifier        string // pDefaultSslCtlIdentifier
	sslCtlStoreName         string // pDefaultSslCtlStoreName
	defaultFlags            uint32 // DefaultFlags 位掩码
}

// bindingState 是绑定变更后可确认的实际状态。
type bindingState uint8

const (
	bindingStateUnknown bindingState = iota
	bindingStateDesired
	bindingStateAbsent
	bindingStateUnexpected
)

// classifyBindingState 将查询结果分类，避免把“查询失败”与“确认不存在”混为一谈。
func classifyBindingState(current *capturedBinding, queryErr error, desiredHash string) bindingState {
	if queryErr != nil {
		return bindingStateUnknown
	}
	if current == nil {
		return bindingStateAbsent
	}
	if strings.EqualFold(current.CertHash, desiredHash) {
		return bindingStateDesired
	}
	return bindingStateUnexpected
}

// bindingStateAllowsRecovery 仅允许在确认不存在或确认存在异常绑定时执行破坏性回滚。
func bindingStateAllowsRecovery(state bindingState) bool {
	return state == bindingStateAbsent || state == bindingStateUnexpected
}

// queryBindingWithRetry 查询并判断目标绑定；首次未命中或查询失败后重试一次。
// 返回最后一次查询的真实结果与错误，由调用方区分“不存在”“异常绑定”和“状态未知”。
func queryBindingWithRetry(query func() (*capturedBinding, error), desiredHash string, retryDelay time.Duration) (*capturedBinding, error) {
	current, err := query()
	if classifyBindingState(current, err, desiredHash) == bindingStateDesired {
		return current, nil
	}
	if retryDelay > 0 {
		time.Sleep(retryDelay)
	}
	return query()
}

// restoreBinding 将当前已确认的绑定状态恢复为旧快照。
// 当前存在异常绑定时必须先删除再添加；当前已是旧绑定时不做任何变更。
func restoreBinding(
	current *capturedBinding,
	old *capturedBinding,
	deleteCurrent func() error,
	addOld func() error,
	queryCurrent func() (*capturedBinding, error),
) error {
	if current != nil && strings.EqualFold(current.CertHash, old.CertHash) {
		return nil
	}
	if current != nil {
		if err := deleteCurrent(); err != nil {
			return fmt.Errorf("删除当前异常绑定失败: %w", err)
		}
	}

	addErr := addOld()
	restored, queryErr := queryCurrent()
	if queryErr != nil {
		return fmt.Errorf("恢复后查询旧绑定失败: %w (添加错误: %v)", queryErr, addErr)
	}
	if restored != nil && strings.EqualFold(restored.CertHash, old.CertHash) {
		return nil
	}
	return fmt.Errorf("旧绑定未恢复 (添加错误: %v)", addErr)
}
