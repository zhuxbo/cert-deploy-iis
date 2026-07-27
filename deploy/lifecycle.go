package deploy

import (
	"fmt"
	"log"
	"time"

	"sslctlw/api"
	"sslctlw/config"
)

type orderClass int

const (
	orderClassActive orderClass = iota + 1
	orderClassWaiting
	orderClassTerminal
	orderClassChainAnomaly
	orderClassUnknown
)

// classifyOrderStatus 显式分类服务端全部已知状态；未知新增状态保守等待。
func classifyOrderStatus(status string) orderClass {
	switch status {
	case config.OrderStatusActive:
		return orderClassActive
	case config.OrderStatusPending, config.OrderStatusProcessing, config.OrderStatusApproving,
		config.OrderStatusUnpaid, config.OrderStatusCancelling:
		return orderClassWaiting
	case config.OrderStatusFailed, config.OrderStatusCancelled, config.OrderStatusRevoked, config.OrderStatusExpired:
		return orderClassTerminal
	case config.OrderStatusRenewed, config.OrderStatusReissued:
		return orderClassChainAnomaly
	default:
		return orderClassUnknown
	}
}

func trackOrderStatus(certCfg *config.CertConfig, status string) bool {
	if certCfg.Metadata.LastOrderStatus == status {
		return false
	}
	certCfg.Metadata.LastOrderStatus = status
	return true
}

func trackAPIOrderError(certCfg *config.CertConfig, err error) bool {
	code := api.ErrorCodeOf(err)
	if code == "" || api.IsAuthBlockErrorCode(code) {
		return false
	}
	return trackOrderStatus(certCfg, code)
}

type progressMark struct {
	orderID        int
	lastDeployAt   string
	certExpiresAt  string
	certSerial     string
	csrSubmittedAt string
}

func snapshotProgress(certCfg *config.CertConfig) progressMark {
	return progressMark{
		orderID:        certCfg.OrderID,
		lastDeployAt:   certCfg.Metadata.LastDeployAt,
		certExpiresAt:  certCfg.Metadata.CertExpiresAt,
		certSerial:     certCfg.Metadata.CertSerial,
		csrSubmittedAt: certCfg.Metadata.CSRSubmittedAt,
	}
}

// settleNoProgress 只对实际 API 请求结算；本地跳过与 token 黑名单跳过不参与。
func settleNoProgress(certCfg *config.CertConfig, before progressMark, madeAPICall bool, now time.Time) {
	if !madeAPICall {
		return
	}
	if snapshotProgress(certCfg) != before {
		certCfg.Metadata.NoProgressSince = ""
		return
	}
	if certCfg.Metadata.NoProgressSince == "" {
		certCfg.Metadata.NoProgressSince = now.Format(time.RFC3339)
	}
}

// stalledTooLong 判断无进展计时是否到达边界。
// 损坏、回拨或超过可信时间差时重锚，避免错误停车。
func stalledTooLong(certCfg *config.CertConfig, now time.Time) bool {
	value := certCfg.Metadata.NoProgressSince
	if value == "" {
		return false
	}
	since, err := time.Parse(time.RFC3339, value)
	if err != nil {
		certCfg.Metadata.NoProgressSince = now.Format(time.RFC3339)
		return false
	}
	elapsed := now.Sub(since)
	if elapsed < 0 || elapsed > time.Duration(config.ClockSanityMaxDays)*24*time.Hour {
		certCfg.Metadata.NoProgressSince = now.Format(time.RFC3339)
		return false
	}
	return elapsed >= time.Duration(config.MaxNoProgressDays)*24*time.Hour
}

func markStalled(
	d *Deployer,
	certCfg *config.CertConfig,
	save func() error,
	supplementals ...*runSupplemental,
) {
	log.Printf("证书 %s 连续 %d 天无进展，进入 CAPPED（停更）", certCfg.Domain, config.MaxNoProgressDays)
	var supplemental *runSupplemental
	if len(supplementals) > 0 {
		supplemental = supplementals[0]
	}

	// 先把终态可靠落盘，再做不可逆的文件清理。否则保存失败或进程崩溃时，
	// 磁盘仍是 processing，但与服务端证书唯一配对的 pending 私钥已丢失。
	certCfg.Metadata.NoProgressSince = ""
	certCfg.Metadata.DeployStartedAt = ""
	certCfg.Metadata.PendingCleanup = true
	certCfg.Metadata.MarkCapped(config.CapPhaseStalled)
	if save == nil {
		if supplemental != nil {
			supplemental.Errors = append(supplemental.Errors,
				fmt.Errorf("保存证书 %s 停更状态失败，已保留在途产物: 缺少持久化函数", certCfg.Domain))
		}
		return
	}
	if err := save(); err != nil {
		if supplemental != nil {
			supplemental.Errors = append(supplemental.Errors,
				fmt.Errorf("保存证书 %s 停更状态失败，已保留在途产物: %w", certCfg.Domain, err))
		}
		return
	}

	pendingRemoved := true
	if err := d.Store.RemovePendingArtifacts(certCfg.CertName); err != nil {
		pendingRemoved = false
		if supplemental != nil {
			supplemental.Warnings = append(supplemental.Warnings,
				fmt.Sprintf("清理证书 %s 在途私钥失败: %v", certCfg.Domain, err))
		}
	}
	cleanupOwnedValidationFiles(d, certCfg, save, supplemental)
	if pendingRemoved {
		certCfg.Metadata.CSRSubmittedAt = ""
		certCfg.Metadata.LastCSRHash = ""
		certCfg.Metadata.PendingCleanup = false
	}
	if pendingRemoved {
		if err := save(); err != nil && supplemental != nil {
			supplemental.Errors = append(supplemental.Errors,
				fmt.Errorf("保存证书 %s 在途产物清理结果失败: %w", certCfg.Domain, err))
		}
	}
}
