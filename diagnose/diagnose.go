package diagnose

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/iis"
	"sslctlw/util"
)

func printHeader() {
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Println("========================================")
	fmt.Println("  sslctlw 诊断报告")
	fmt.Printf("  生成时间: %s\n", now)
	fmt.Println("========================================")
}

func printFooter() {
	fmt.Println("\n========================================")
	fmt.Println("  诊断完成")
	fmt.Println("========================================")
}

func printSection(label, title string) {
	fmt.Printf("\n[%s] %s\n", label, title)
	fmt.Println("---")
}

func printKV(key, value string) {
	fmt.Printf("  %-12s%s\n", key+":", value)
}

func printError(context string, err error) {
	fmt.Printf("[错误] %s: %v\n", context, err)
}

func truncHash(hash string) string {
	if len(hash) > 10 {
		return hash[:10] + "..."
	}
	return hash
}

// Run 运行诊断信息收集
func Run(version string) {
	printHeader()
	cfg := collectProgramInfo(version)
	collectWindowsInfo()
	sslBindings := collectIISInfo()
	collectCertInfo(cfg, sslBindings)
	collectTaskInfo(cfg)
	printFooter()
}

func collectProgramInfo(version string) *config.Config {
	printSection("A", "程序信息")

	printKV("版本", version)
	printKV("Go 版本", runtime.Version())

	if exe, err := os.Executable(); err == nil {
		printKV("程序路径", exe)
	}
	printKV("数据目录", config.GetDataDir())
	printKV("配置文件", config.GetConfigPath())
	printKV("日志目录", config.GetLogDir())

	cfg, err := config.Load()
	if err != nil {
		printError("加载配置", err)
		return nil
	}

	enabled := 0
	disabled := 0
	for _, c := range cfg.Certificates {
		if c.Enabled {
			enabled++
		} else {
			disabled++
		}
	}
	printKV("证书数量", fmt.Sprintf("%d (启用 %d, 禁用 %d)", len(cfg.Certificates), enabled, disabled))

	if cfg.AutoCheckEnabled {
		printKV("自动部署", "已启用 (每天一次)")
	} else {
		printKV("自动部署", "未启用")
	}
	if cfg.LastCheck != "" {
		printKV("上次检查", cfg.LastCheck)
	}

	if cfg.UpgradeEnabled {
		printKV("升级检查", fmt.Sprintf("已启用 (%s 通道)", cfg.UpgradeChannel))
	} else {
		printKV("升级检查", "未启用")
	}

	if len(cfg.Certificates) > 0 {
		fmt.Println("\n已配置证书:")
		for i, c := range cfg.Certificates {
			status := "启用"
			if !c.Enabled {
				status = "禁用"
			}
			mode := c.RenewMode
			if mode == "" {
				mode = "pull"
			}
			api := "无"
			if c.API.URL != "" {
				api = "已配置"
			}
			fmt.Printf("  #%-2d %-28s 订单:%-8d 过期:%-12s %s  %s  API:%s\n",
				i+1, c.Domain, c.OrderID, c.Metadata.CertExpiresAt, status, mode, api)
		}
	}

	return cfg
}

func collectWindowsInfo() {
	printSection("B", "Windows 系统")

	osVer, err := util.RunPowerShell(`
$os = Get-CimInstance Win32_OperatingSystem
$os.Caption.Trim() + ' ' + $os.Version
`)
	if err != nil {
		printError("OS 版本", err)
	} else {
		printKV("OS 版本", strings.TrimSpace(osVer))
	}

	// 管理员权限检测
	_, err = util.RunCmd(util.ResolveSystem32Exe("net.exe"), "session")
	if err != nil {
		printKV("管理员权限", "否")
	} else {
		printKV("管理员权限", "是")
	}

	psVer, err := util.RunPowerShell("$PSVersionTable.PSVersion.ToString()")
	if err != nil {
		printError("PowerShell 版本", err)
	} else {
		printKV("PowerShell", strings.TrimSpace(psVer))
	}
}

func collectIISInfo() []iis.SSLBinding {
	printSection("C", "IIS 状态")

	if err := iis.CheckIISInstalled(); err != nil {
		printKV("IIS 安装", "否")
		return nil
	}
	printKV("IIS 安装", "是")

	ver, err := iis.GetIISMajorVersion()
	if err != nil {
		printError("IIS 版本", err)
	} else {
		printKV("IIS 版本", fmt.Sprintf("%d", ver))
	}

	// 站点列表
	sites, err := iis.ScanSites()
	if err != nil {
		printError("扫描站点", err)
	} else if len(sites) > 0 {
		fmt.Println("\nIIS 站点:")
		for _, s := range sites {
			var bindings []string
			for _, b := range s.Bindings {
				info := fmt.Sprintf("%s/%s:%d", b.Protocol, b.Host, b.Port)
				if b.HasSSL {
					info += " [SSL]"
				}
				bindings = append(bindings, info)
			}
			fmt.Printf("  %-30s ID:%-5d %s  %s\n",
				s.Name, s.ID, strings.Join(bindings, ", "), s.State)
		}
	} else {
		fmt.Println("  (无站点)")
	}

	// SSL 绑定
	sslBindings, err := iis.ListSSLBindings()
	if err != nil {
		printError("SSL 绑定", err)
		return nil
	}
	if len(sslBindings) > 0 {
		fmt.Println("\nSSL 绑定 (netsh):")
		for _, b := range sslBindings {
			bindType := ""
			if b.IsIPBinding {
				bindType = " [IP绑定]"
			}
			fmt.Printf("  %-35s 证书:%s  存储:%s%s\n",
				b.HostnamePort, truncHash(b.CertHash), b.CertStoreName, bindType)
		}
	} else {
		fmt.Println("\nSSL 绑定 (netsh): (无)")
	}

	return sslBindings
}

func collectCertInfo(cfg *config.Config, sslBindings []iis.SSLBinding) {
	printSection("D", "证书状态")

	// 证书存储
	certs, err := cert.ListCertificates()
	if err != nil {
		printError("读取证书存储", err)
		certs = nil
	}

	// 建立指纹索引
	hashToCert := make(map[string]*cert.CertInfo)
	if len(certs) > 0 {
		fmt.Println("Windows 证书存储 (LocalMachine\\My):")
		for i := range certs {
			c := &certs[i]
			hashToCert[strings.ToUpper(c.Thumbprint)] = c
			privKey := "无私钥"
			if c.HasPrivKey {
				privKey = "有私钥"
			}
			fmt.Printf("  %s  %-24s %-8s %s  %s\n",
				truncHash(c.Thumbprint),
				cert.GetCertDisplayName(c),
				cert.GetCertStatus(c),
				c.NotAfter.Format("2006-01-02"),
				privKey)
		}
	} else if err == nil {
		fmt.Println("Windows 证书存储 (LocalMachine\\My): (空)")
	}

	// 交叉验证
	if cfg != nil && len(cfg.Certificates) > 0 {
		results := crossValidate(cfg.Certificates, sslBindings, hashToCert)
		fmt.Println("\n交叉验证:")
		for _, r := range results {
			fmt.Printf("  %s\n", r)
		}
	}

	// 本地订单
	store := cert.NewOrderStore()
	orderIDs, err := store.ListOrders()
	if err != nil {
		printError("读取本地订单", err)
		return
	}
	if len(orderIDs) > 0 {
		fmt.Println("\n本地订单:")
		for _, id := range orderIDs {
			meta, err := store.LoadMeta(id)
			if err != nil {
				fmt.Printf("  订单 %-8d [错误] %v\n", id, err)
				continue
			}
			hasKey := "无私钥"
			if store.HasPrivateKey(id) {
				hasKey = "有私钥"
			}
			fmt.Printf("  订单 %-8d %-24s %-8s 过期:%-12s %s\n",
				meta.OrderID, meta.Domain, meta.Status, meta.ExpiresAt, hasKey)
		}
	}
}

func collectTaskInfo(cfg *config.Config) {
	printSection("E", "计划任务")

	taskName := config.DefaultTaskName
	if cfg != nil && cfg.TaskName != "" {
		taskName = cfg.TaskName
	}

	printKV("任务名称", taskName)

	if !util.IsTaskExists(taskName) {
		printKV("状态", "未创建")
		if cfg != nil && cfg.AutoCheckEnabled {
			fmt.Println("  [警告] 自动部署已启用但计划任务不存在")
		}
		return
	}

	printKV("状态", "已创建")

	info, err := util.GetTaskInfo(taskName)
	if err != nil {
		printError("获取任务详情", err)
		return
	}

	fmt.Println("\n详细信息:")
	for line := range strings.SplitSeq(strings.TrimSpace(info), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			fmt.Printf("  %s\n", line)
		}
	}
}

// crossValidate 交叉验证配置证书与 SSL 绑定、证书存储的一致性
func crossValidate(configCerts []config.CertConfig, sslBindings []iis.SSLBinding, hashToCert map[string]*cert.CertInfo) []string {
	// 建立绑定索引：域名 → SSLBinding
	bindingByHost := make(map[string]*iis.SSLBinding)
	for i := range sslBindings {
		b := &sslBindings[i]
		host := iis.ParseHostFromBinding(b.HostnamePort)
		if host != "" {
			bindingByHost[strings.ToLower(host)] = b
		}
	}

	var results []string
	for _, cc := range configCerts {
		domain := strings.ToLower(cc.Domain)
		binding := bindingByHost[domain]

		if binding == nil {
			results = append(results, fmt.Sprintf("[警告] %s (订单 %d) → 未找到 SSL 绑定", cc.Domain, cc.OrderID))
			continue
		}

		bindHash := strings.ToUpper(binding.CertHash)
		storeCert := hashToCert[bindHash]
		if storeCert == nil {
			results = append(results, fmt.Sprintf("[错误] %s (订单 %d) → 绑定 %s → 证书 %s 不在存储中",
				cc.Domain, cc.OrderID, binding.HostnamePort, truncHash(binding.CertHash)))
			continue
		}

		status := cert.GetCertStatus(storeCert)
		if status == "已过期" {
			results = append(results, fmt.Sprintf("[错误] %s (订单 %d) → 绑定 %s → 证书已过期 (%s)",
				cc.Domain, cc.OrderID, binding.HostnamePort, storeCert.NotAfter.Format("2006-01-02")))
		} else {
			results = append(results, fmt.Sprintf("[正常] %s (订单 %d) → 绑定 %s → 证书 %s %s",
				cc.Domain, cc.OrderID, binding.HostnamePort, truncHash(binding.CertHash), status))
		}
	}
	return results
}
