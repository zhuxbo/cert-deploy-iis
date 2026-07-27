package deploy

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sslctlw/api"
	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
)

// RunOptions 控制一次自动部署运行的范围与节奏。
type RunOptions struct {
	ScatterDelay    bool
	OnlyOrderID     int
	MaxCertificates int
}

// CertAttention 表示需要人工处理、但不应令本次运行报错的证书状态。
type CertAttention struct {
	OrderID int
	Domain  string
	Reason  string
}

// RunReport 汇总一次自动部署运行的结构化结果。
type RunReport struct {
	Results        []Result
	Errors         []error
	Warnings       []string
	Attention      []CertAttention
	AlreadyRunning bool
}

// Err 聚合失败结果与运行级错误；warning、attention 和正常锁占用不属于错误。
func (r RunReport) Err() error {
	errs := make([]error, 0, len(r.Results)+len(r.Errors))
	for _, result := range r.Results {
		if result.Success {
			continue
		}
		key := result.Message
		if key == "" {
			key = "部署失败"
		}
		identity := result.Domain
		if identity == "" {
			identity = fmt.Sprintf("订单 %d", result.OrderID)
		}
		errs = append(errs, fmt.Errorf("%s: %s", identity, key))
	}
	for _, err := range r.Errors {
		if err == nil {
			continue
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// CertConverter 证书转换接口
type CertConverter interface {
	// PEMToPFX 将 PEM 格式证书转换为 PFX 格式
	// 返回 PFX 文件路径
	PEMToPFX(certPEM, keyPEM, intermediatePEM, password string) (string, error)
}

// CertInstaller 证书安装接口
type CertInstaller interface {
	// InstallPFX 安装 PFX 证书到 Windows 证书存储
	InstallPFX(pfxPath, password string) (*cert.InstallResult, error)
	// SetFriendlyName 设置证书友好名称
	SetFriendlyName(thumbprint, friendlyName string) error
}

// IISBinder IIS 绑定接口
type IISBinder interface {
	// BindCertificate 使用 SNI 模式绑定证书
	BindCertificate(hostname string, port int, certHash string) error
	// BindCertificateByIP 使用 IP 模式绑定证书
	BindCertificateByIP(ip string, port int, certHash string) error
	// FindBindingsForDomains 查找域名匹配的绑定
	FindBindingsForDomains(domains []string) ([]iis.SSLBinding, error)
}

// ValidationWebRootResolver 只负责解析文件验证可写入的 IIS 站点根。
type ValidationWebRootResolver interface {
	ResolveValidationWebRoots(domains []string, explicitSiteName string) ([]iis.ValidationWebRoot, error)
}

// APIClient API 客户端接口
type APIClient interface {
	// GetCertByOrderID 按订单 ID 获取证书
	GetCertByOrderID(ctx context.Context, orderID int) (*api.CertData, error)
	// ListCertsByQuery 批量按订单 ID 查询证书
	ListCertsByQuery(ctx context.Context, query string) ([]api.CertData, error)
	// SubmitCSR 提交 CSR
	SubmitCSR(ctx context.Context, req *api.UpdateRequest) (*api.UpdateResponse, error)
	// Callback 发送部署回调
	Callback(ctx context.Context, req *api.CallbackRequest) error
}

// OrderStore 订单存储接口（私钥和证书文件操作，metadata 已移入 Config）
type OrderStore interface {
	// HasPrivateKey 检查是否有私钥
	HasPrivateKey(orderID int) bool
	// LoadPrivateKey 加载私钥
	LoadPrivateKey(orderID int) (string, error)
	// SavePrivateKey 保存私钥
	SavePrivateKey(orderID int, keyPEM string) error
	// HasPendingPrivateKey 检查是否有待确认私钥
	HasPendingPrivateKey(certName string) bool
	// LoadPendingPrivateKey 加载待确认私钥
	LoadPendingPrivateKey(certName string) (string, error)
	// SavePendingPrivateKey 保存待确认私钥
	SavePendingPrivateKey(certName, keyPEM string) error
	// SavePendingCSR 保存与待确认私钥配对、供 query-first 归属判断的 CSR
	SavePendingCSR(certName, csrPEM string) error
	// LoadPendingCSR 加载 pending CSR（不用于重放 POST）
	LoadPendingCSR(certName string) (string, error)
	// RemovePendingArtifacts 清理在途私钥与 CSR
	RemovePendingArtifacts(certName string) error
	// PromotePendingPrivateKey 将本次已成功部署的待确认私钥转正
	PromotePendingPrivateKey(certName string, orderID int, deployedKey string) error
	// SaveCertificate 保存证书
	SaveCertificate(orderID int, certPEM, chainPEM string) error
	// LoadCertificate 加载证书
	LoadCertificate(orderID int) (certPEM, chainPEM string, err error)
	// ListOrders 列出所有订单 ID
	ListOrders() ([]int, error)
	// DeleteOrder 删除订单
	DeleteOrder(orderID int) error
}

// Deployer 部署器，聚合所有依赖（不含 API Client，每个证书独立创建）
type Deployer struct {
	Converter        CertConverter
	Installer        CertInstaller
	Binder           IISBinder
	Store            OrderStore
	ValidationRoots  ValidationWebRootResolver
	ValidationFiles  validationFileStore
	callbackWg       sync.WaitGroup
	callbackMu       sync.Mutex
	callbackSeq      uint64
	renewSeq         uint64
	renewDays        int
	callbackWarnings []string
}

// WaitCallbacks 等待所有回调完成，返回并清空本轮 warning。
func (d *Deployer) WaitCallbacks() []string {
	d.callbackWg.Wait()
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	warnings := append([]string(nil), d.callbackWarnings...)
	d.callbackWarnings = nil
	return warnings
}

func (d *Deployer) recordCallbackWarning(warning string) {
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	d.callbackWarnings = append(d.callbackWarnings, warning)
}

func (d *Deployer) nextCallbackSequence() uint64 {
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	d.callbackSeq++
	return d.callbackSeq
}

func (d *Deployer) recordCallbackRenewBeforeDays(seq uint64, days int) {
	if days <= 0 || days > config.MaxRenewBeforeDays {
		return
	}
	d.callbackMu.Lock()
	defer d.callbackMu.Unlock()
	if seq >= d.renewSeq {
		d.renewSeq = seq
		d.renewDays = days
	}
}

// ApplyCallbackRenewBeforeDays 将已完成回调中最后一条有效响应应用到本地配置。
func (d *Deployer) ApplyCallbackRenewBeforeDays(cfg *config.Config) {
	d.callbackMu.Lock()
	days := d.renewDays
	d.callbackMu.Unlock()
	updateRenewBeforeDaysValue(cfg, days)
}
