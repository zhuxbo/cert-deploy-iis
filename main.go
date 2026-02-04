package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"sslctlw/config"
	"sslctlw/deploy"
	"sslctlw/ui"
)

var (
	version = "1.0.0"
)

func main() {
	// 命令行参数
	autoMode := flag.Bool("auto", false, "自动部署模式（用于计划任务）")
	debugMode := flag.Bool("debug", false, "启用调试模式（输出到 debug.log）")
	showVersion := flag.Bool("version", false, "显示版本号")
	showHelp := flag.Bool("help", false, "显示帮助")

	flag.Parse()

	if *showVersion {
		fmt.Printf("sslctlw v%s\n", version)
		return
	}

	if *showHelp {
		printUsage()
		return
	}

	if *autoMode {
		// 自动部署模式
		runAutoDeploy()
		return
	}

	// 启用调试模式
	if *debugMode {
		ui.EnableDebugMode()
	}

	// GUI 模式
	ui.RunApp()
}

// runAutoDeploy 运行自动部署
func runAutoDeploy() {
	// 设置日志到配置目录（权限 0600 - 仅所有者可读写）
	logPath := filepath.Join(config.GetLogDir(), "deploy.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		// 如果是新文件，写入 UTF-8 BOM
		info, _ := logFile.Stat()
		if info != nil && info.Size() == 0 {
			logFile.Write([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
		}
		log.SetOutput(logFile)
		defer logFile.Close()
	}

	log.Printf("========== 开始自动部署 ==========")

	if err := deploy.CheckAndDeploy(); err != nil {
		log.Printf("部署失败: %v", err)
		os.Exit(1)
	}

	log.Printf("========== 自动部署完成 ==========")
}

// printUsage 打印使用说明
func printUsage() {
	fmt.Printf(`IIS 证书部署工具 v%s

用法:
  sslctlw.exe [选项]

选项:
  -auto      自动部署模式（用于计划任务）
  -debug     启用调试模式（输出到 debug.log）
  -version   显示版本号
  -help      显示帮助

GUI 模式:
  直接运行 sslctlw.exe 进入图形界面

自动部署模式:
  sslctlw.exe -auto

  自动部署模式会读取配置文件，检查所有启用的站点：
  - 如果证书在配置的天数内过期，自动从部署接口获取新证书并部署
  - 部署结果记录到日志文件

  可配合 Windows 任务计划程序定时执行

配置目录:
  程序同目录下的 sslctlw 文件夹
  - 配置文件: sslctlw/config.json
  - 日志目录: sslctlw/logs/

创建计划任务:
  schtasks /create /tn "SSLCtlW" /tr "C:\path\to\sslctlw.exe -auto" /sc daily /st 03:00 /ru SYSTEM

`, version)
}
