package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sslctlw/cert"
	"sslctlw/config"
	"sslctlw/deploy"
	"sslctlw/diagnose"
	"sslctlw/iis"
	"sslctlw/setup"
	"sslctlw/ui"
	"sslctlw/upgrade"
	"sslctlw/util"
)

var version = "dev"

func main() {
	// 无参数 → GUI 模式
	if len(os.Args) <= 1 {
		util.HideConsole()
		ui.SetVersion(version)
		runGUISafe()
		return
	}

	args := os.Args[1:]

	// --debug 仅用于 GUI 模式
	if len(args) > 0 && args[0] == "--debug" {
		args = args[1:]
		if len(args) == 0 {
			util.HideConsole()
			ui.EnableDebugMode()
			ui.SetVersion(version)
			runGUISafe()
			return
		}
	}

	cmd := strings.ToLower(args[0])
	cmdArgs := args[1:]

	switch cmd {
	case "setup":
		runSetup(cmdArgs)
	case "scan":
		runScan(cmdArgs)
	case "deploy":
		runDeploy(cmdArgs)
	case "status":
		runStatus()
	case "upgrade":
		runUpgrade(cmdArgs)
	case "diagnose":
		diagnose.Run(version)
	case "uninstall":
		runUninstall(cmdArgs)
	case "version":
		fmt.Printf("sslctlw v%s\n", version)
	case "help", "--help", "-help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// runSetup 执行一键部署
func runSetup(args []string) {
	if err := setup.RunCLI(args); err != nil {
		fmt.Fprintf(os.Stderr, "setup 失败: %v\n", err)
		os.Exit(1)
	}
}

// runScan 扫描 IIS 站点
func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	sslOnly := fs.Bool("ssl-only", false, "仅显示已配置 SSL 的站点")
	fs.Parse(args)

	sites, err := iis.ScanSites()
	if err != nil {
		fmt.Fprintf(os.Stderr, "扫描 IIS 站点失败: %v\n", err)
		os.Exit(1)
	}

	if len(sites) == 0 {
		fmt.Println("未找到 IIS 站点")
		return
	}

	for _, site := range sites {
		hasSSL := false
		var bindingStrs []string
		for _, b := range site.Bindings {
			info := fmt.Sprintf("%s/%s:%d", b.Protocol, b.Host, b.Port)
			bindingStrs = append(bindingStrs, info)
			if b.HasSSL {
				hasSSL = true
			}
		}

		if *sslOnly && !hasSSL {
			continue
		}

		ssl := ""
		if hasSSL {
			ssl = " [SSL]"
		}
		fmt.Printf("%-30s ID:%-5d %s%s\n", site.Name, site.ID, strings.Join(bindingStrs, ", "), ssl)
	}
}

// runDeploy 部署证书
func runDeploy(args []string) {
	fs := flag.NewFlagSet("deploy", flag.ExitOnError)
	all := fs.Bool("all", false, "部署所有已配置的证书")
	certID := fs.Int("cert", 0, "部署指定订单 ID 的证书")
	fs.Parse(args)

	if *all {
		// deploy --all: 自动部署所有
		setupDeployLog()
		log.Printf("========== 开始自动部署 ==========")
		reportOut := io.MultiWriter(os.Stdout, log.Writer())
		if err := deployAllWithRunner(deploy.CheckAndDeploy, reportOut); err != nil {
			log.Printf("部署失败: %v", err)
			fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
			os.Exit(1)
		}
		log.Printf("========== 自动部署完成 ==========")
	} else if *certID > 0 {
		// deploy --cert <id>: 部署单个证书
		if err := deploySingleCert(*certID); err != nil {
			fmt.Fprintf(os.Stderr, "部署失败: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "请指定 --all 或 --cert <order_id>")
		os.Exit(1)
	}
}

// deploySingleCert 部署单个证书
func deploySingleCert(orderID int) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("加载配置失败: %v", err)
	}

	store := cert.NewOrderStore()
	deployer := deploy.DefaultDeployer(cfg, store)
	return deploySingleCertWith(cfg, deployer, orderID)
}

func deploySingleCertWith(cfg *config.Config, deployer *deploy.Deployer, orderID int) error {
	return deploySingleCertWithRunner(cfg, deployer, orderID, deploy.AutoDeploy, os.Stdout)
}

type singleCertRunner func(*config.Config, *deploy.Deployer, deploy.RunOptions) deploy.RunReport

func deploySingleCertWithRunner(cfg *config.Config, deployer *deploy.Deployer, orderID int, run singleCertRunner, out io.Writer) error {
	matchCount := 0
	var target *config.CertConfig
	for i := range cfg.Certificates {
		if cfg.Certificates[i].OrderID == orderID {
			matchCount++
			target = &cfg.Certificates[i]
		}
	}
	if matchCount == 0 {
		return fmt.Errorf("未找到订单 %d 的配置", orderID)
	}
	if matchCount > 1 {
		return fmt.Errorf("订单 %d 存在 %d 条配置，无法确定单证书部署目标", orderID, matchCount)
	}
	if !target.Enabled {
		return fmt.Errorf("订单 %d 已禁用，无法执行部署", orderID)
	}

	report := run(cfg, deployer, deploy.RunOptions{OnlyOrderID: orderID})
	reportErr := writeRunReport(out, report)

	var attentionErrors []error
	for _, attention := range report.Attention {
		attentionErrors = append(attentionErrors,
			fmt.Errorf("订单 %d 需要人工处理: %s", attention.OrderID, attention.Reason))
	}
	return errors.Join(reportErr, errors.Join(attentionErrors...))
}

func deployAllWithRunner(run func() deploy.RunReport, out io.Writer) error {
	return writeRunReport(out, run())
}

func writeRunReport(out io.Writer, report deploy.RunReport) error {
	for _, r := range report.Results {
		if r.Success {
			fmt.Fprintf(out, "[成功] %s: %s\n", r.Domain, r.Message)
		} else {
			fmt.Fprintf(out, "[失败] %s: %s\n", r.Domain, r.Message)
		}
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(out, "[警告] %s\n", warning)
	}
	for _, attention := range report.Attention {
		fmt.Fprintf(out, "[需人工处理] 订单 %d %s: %s\n",
			attention.OrderID, attention.Domain, attention.Reason)
	}
	for _, runErr := range report.Errors {
		if runErr != nil {
			fmt.Fprintf(out, "[错误] %v\n", runErr)
		}
	}
	if report.AlreadyRunning {
		fmt.Fprintln(out, "已有部署正在运行，本次跳过")
	}
	if len(report.Results) == 0 && len(report.Errors) == 0 &&
		len(report.Warnings) == 0 && len(report.Attention) == 0 &&
		!report.AlreadyRunning {
		fmt.Fprintln(out, "本次无需部署")
	}
	return report.Err()
}

// runStatus 显示状态
func runStatus() {
	fmt.Printf("sslctlw v%s\n\n", version)

	// 数据目录 ACL 安全检查：机器作用域加密的机密性依赖数据目录仅限管理员访问
	for _, w := range util.EvaluateDataDirACL(config.GetDataDir()) {
		fmt.Printf("[安全告警] %s\n\n", w)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	if len(cfg.Certificates) == 0 {
		fmt.Println("未配置任何证书")
		return
	}

	fmt.Printf("已配置 %d 个证书:\n", len(cfg.Certificates))
	for _, c := range cfg.Certificates {
		status := "禁用"
		if c.Enabled {
			status = "启用"
		}
		mode := c.RenewMode
		if mode == "" {
			mode = "pull"
		}
		hasAPI := "无"
		if c.API.URL != "" {
			hasAPI = "已配置"
		}
		tokenHealth := certTokenHealth(&c.API)
		fmt.Printf("  %-30s 订单:%-8d 过期:%s 状态:%s 模式:%s API:%s Token:%s\n",
			c.Domain, c.OrderID, c.Metadata.CertExpiresAt, status, mode, hasAPI, tokenHealth)
	}

	// 计划任务状态
	fmt.Println()
	taskName := cfg.TaskName
	if taskName == "" {
		taskName = config.DefaultTaskName
	}
	_ = writeTaskHealthStatus(os.Stdout, cfg.AutoCheckEnabled, taskName, time.Now(), util.GetTaskHealth)
}

func writeTaskHealthStatus(
	out io.Writer,
	enabled bool,
	taskName string,
	now time.Time,
	query func(string) (*util.TaskHealth, error),
) error {
	if !enabled {
		fmt.Fprintf(out, "计划任务: %s (不健康)\n", taskName)
		fmt.Fprintln(out, "  [告警] 自动部署已停止")
		return nil
	}

	health, err := query(taskName)
	if err != nil {
		fmt.Fprintf(out, "计划任务: %s (不健康)\n", taskName)
		fmt.Fprintf(out, "  [告警] 任务运行信息查询失败: %v\n", err)
		return err
	}

	warnings := util.EvaluateTaskHealth(health, now)
	state := "健康"
	if len(warnings) > 0 {
		state = "不健康"
	}
	fmt.Fprintf(out, "计划任务: %s (%s)\n", taskName, state)

	if health.HasRun {
		fmt.Fprintf(out, "  上次运行: %s (结果: 0x%X)\n",
			health.LastRunTime.Format("2006-01-02 15:04:05"), health.LastTaskResult)
	} else {
		fmt.Fprintln(out, "  上次运行: 从未运行")
	}
	for _, warning := range warnings {
		fmt.Fprintf(out, "  [告警] %s\n", warning)
	}
	return nil
}

// certTokenHealth 返回证书 API Token 的健康描述
// 用于 status 命令呈现 Token 是否可解密（解密失败通常是配置由其他账户加密）
func certTokenHealth(apiCfg *config.CertAPIConfig) string {
	if apiCfg.EncryptedToken == "" {
		return "未配置"
	}
	if _, err := apiCfg.GetToken(); err != nil {
		return "解密失败(请重新 setup 重录)"
	}
	return "正常"
}

// runUpgrade 升级
func runUpgrade(args []string) {
	fs := flag.NewFlagSet("upgrade", flag.ExitOnError)
	check := fs.Bool("check", false, "仅检查更新")
	fs.Parse(args)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	upgradeCfg := cfg.GetUpgradeConfig()
	defaultCfg := upgrade.DefaultConfig()
	uCfg := &upgrade.Config{
		Enabled:        upgradeCfg.Enabled,
		Channel:        upgrade.Channel(upgradeCfg.Channel),
		CheckInterval:  upgradeCfg.CheckInterval,
		LastCheck:      upgradeCfg.LastCheck,
		ReleaseURL:     upgradeCfg.ReleaseURL,
		TrustedOrg:     defaultCfg.TrustedOrg,
		TrustedCountry: defaultCfg.TrustedCountry,
		TrustedCAs:     defaultCfg.TrustedCAs,
	}
	upgrader := upgrade.NewUpgrader(uCfg)

	ctx := context.Background()
	info, err := upgrader.CheckForUpdate(ctx, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "检查更新失败: %v\n", err)
		os.Exit(1)
	}

	if info == nil {
		fmt.Println("当前已是最新版本")
		return
	}

	fmt.Printf("发现新版本: %s\n", info.Version)
	if *check {
		return
	}

	fmt.Println("正在下载更新...")
	newExePath, _, err := upgrader.DownloadAndVerify(ctx, info)
	if err != nil {
		fmt.Fprintf(os.Stderr, "下载失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("正在安装更新...")
	if err := upgrader.ApplyUpdate(ctx, newExePath, info.Version); err != nil {
		fmt.Fprintf(os.Stderr, "安装失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("更新成功，请重启程序")
}

// runUninstall 卸载
func runUninstall(args []string) {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "同时删除配置文件和数据")
	fs.Parse(args)

	// 删除计划任务
	taskName := config.DefaultTaskName
	if util.IsTaskExists(taskName) {
		if err := util.DeleteTask(taskName); err != nil {
			fmt.Fprintf(os.Stderr, "删除计划任务失败: %v\n", err)
		} else {
			fmt.Println("已删除计划任务:", taskName)
		}
	}

	if *purge {
		dataDir := config.GetDataDir()
		if err := os.RemoveAll(dataDir); err != nil {
			fmt.Fprintf(os.Stderr, "删除数据目录失败: %v\n", err)
		} else {
			fmt.Println("已删除数据目录:", dataDir)
		}
	}

	fmt.Println("卸载完成")
}

// setupDeployLog 设置部署日志
func setupDeployLog() {
	logPath := filepath.Join(config.GetLogDir(), "deploy.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法打开日志文件 %s: %v\n", logPath, err)
		return
	}
	// 如果是新文件，写入 UTF-8 BOM
	info, statErr := logFile.Stat()
	if statErr == nil && info != nil && info.Size() == 0 {
		logFile.Write([]byte{0xEF, 0xBB, 0xBF})
	}
	log.SetOutput(logFile)
}

// printUsage 打印帮助
func printUsage() {
	fmt.Printf(`IIS 证书部署工具 v%s

用法:
  sslctlw <command> [options]

命令:
  setup           一键部署
  scan            扫描 IIS 站点
  deploy          部署证书
  status          显示状态
  diagnose        诊断信息收集
  upgrade         升级工具
  uninstall       卸载工具
  version         显示版本
  help            显示帮助

无参数运行进入 GUI 模式。

一键部署:
  sslctlw setup --url <url> --token <token>
  sslctlw setup --url <url> --token <token> --order <id>
  sslctlw setup --url <url> --token <token> --order "123,456"
  sslctlw setup --url <url> --token <token> --key key.pem

扫描:
  sslctlw scan
  sslctlw scan --ssl-only

部署:
  sslctlw deploy --all
  sslctlw deploy --cert <order_id>

诊断:
  sslctlw diagnose
  sslctlw diagnose > diag.txt

升级:
  sslctlw upgrade
  sslctlw upgrade --check

卸载:
  sslctlw uninstall
  sslctlw uninstall --purge

`, version)
}

// runGUISafe 带 panic 恢复的 GUI 启动，崩溃信息写入 crash.log
func runGUISafe() {
	defer func() {
		if r := recover(); r != nil {
			crashPath := filepath.Join(config.GetDataDir(), "crash.log")
			msg := fmt.Sprintf("GUI panic: %v\n", r)
			os.WriteFile(crashPath, []byte(msg), 0600)
			// 也尝试弹 MessageBox 让用户看到
			util.ShowErrorMessageBox("启动失败", fmt.Sprintf("GUI 初始化失败: %v\n\n详见: %s", r, crashPath))
		}
	}()
	ui.RunApp()
}
