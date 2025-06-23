package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LubyRuffy/tcpdumper"
)

func main() {
	// 解析命令行参数
	var iface string
	var pcapFile string
	var bpfFilter string

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help":
			printHelp()
			return
		case "-f", "--file":
			if len(os.Args) < 3 {
				log.Fatal("请提供pcap文件路径")
			}
			pcapFile = os.Args[2]
		case "-i", "--interface":
			if len(os.Args) < 3 {
				log.Fatal("请提供网络接口名称")
			}
			iface = os.Args[2]
		default:
			// 默认作为接口名称处理
			iface = os.Args[1]
		}
	} else {
		// 默认使用lo0接口
		iface = "lo0"
	}

	// 设置BPF过滤器
	if len(os.Args) > 3 && os.Args[3] != "" {
		bpfFilter = os.Args[3]
	} else {
		bpfFilter = "tcp" // 默认只捕获TCP流量
	}

	// 创建捕获选项
	var dumper *tcpdumper.TCPDumper
	if pcapFile != "" {
		// 从文件读取
		fmt.Printf("从pcap文件读取: %s\n", pcapFile)
		options := &tcpdumper.CaptureOptions{
			PcapFile:  pcapFile,
			BPFFilter: bpfFilter,
			SnapLen:   65536,
		}
		dumper = tcpdumper.NewDumper(options)
	} else {
		// 实时抓包
		fmt.Printf("监听网络接口: %s\n", iface)
		options := &tcpdumper.CaptureOptions{
			Interface:   iface,
			BPFFilter:   bpfFilter,
			SnapLen:     65536,
			Promiscuous: true,
			Timeout:     time.Millisecond * 30, // 毫秒超时，减少数据包接收延迟
		}
		dumper = tcpdumper.NewDumper(options)
	}

	// 不注册任何协议，只使用默认处理器
	dumper.SetDefaultProcessor(CreateDefaultRawProcessorFactory())

	fmt.Printf("BPF过滤器: %s\n", bpfFilter)
	fmt.Println("不注册任何协议，所有TCP流都将被默认处理器处理")
	fmt.Println("按 Ctrl+C 停止捕获")
	fmt.Println(strings.Repeat("-", 60))

	// 启动捕获
	err := dumper.Start()
	if err != nil {
		log.Fatalf("启动捕获失败: %v", err)
	}

	// 设置信号处理，优雅退出
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 定期打印统计信息
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// 如果是文件模式，等待处理完成
	if pcapFile != "" {
		// 给文件处理一些时间
		time.Sleep(2 * time.Second)
		dumper.Stop()
		printFinalStats(dumper)
		return
	}

	// 实时模式的主循环
	for {
		select {
		case <-sigChan:
			fmt.Println("\n收到停止信号，正在关闭...")
			dumper.Stop()
			printFinalStats(dumper)
			return

		case <-ticker.C:
			printStats(dumper)
		}
	}
}

// printHelp 打印帮助信息
func printHelp() {
	fmt.Println("Raw TCP Dumper - 基础TCP流信息打印工具")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  rawtcpdumper [选项] [接口名] [BPF过滤器]")
	fmt.Println()
	fmt.Println("选项:")
	fmt.Println("  -h, --help              显示帮助信息")
	fmt.Println("  -f, --file <文件>       从pcap文件读取")
	fmt.Println("  -i, --interface <接口>  指定网络接口")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  rawtcpdumper                    # 使用默认接口lo0，捕获所有TCP流量")
	fmt.Println("  rawtcpdumper eth0               # 监听eth0接口")
	fmt.Println("  rawtcpdumper eth0 \"tcp port 80\" # 监听eth0接口的HTTP流量")
	fmt.Println("  rawtcpdumper -f capture.pcap    # 从pcap文件读取")
	fmt.Println()
	fmt.Println("功能:")
	fmt.Println("  - 不注册任何协议处理器")
	fmt.Println("  - 使用默认RAW处理器处理所有TCP流")
	fmt.Println("  - 显示TCP流的基本信息和数据摘要")
	fmt.Println("  - 实时统计信息")
}

// printStats 打印当前统计信息
func printStats(dumper *tcpdumper.TCPDumper) {
	packets, tcpStreams, errors, unknownFlows := dumper.GetStats()
	fmt.Printf("[%s] 统计: %d 包, %d TCP流, %d 错误, %d 未知协议流\n",
		time.Now().Format("15:04:05"), packets, tcpStreams, errors, unknownFlows)
}

// printFinalStats 打印最终统计信息
func printFinalStats(dumper *tcpdumper.TCPDumper) {
	fmt.Println(strings.Repeat("-", 60))
	packets, tcpStreams, errors, unknownFlows := dumper.GetStats()
	fmt.Printf("最终统计:\n")
	fmt.Printf("  处理的数据包: %d\n", packets)
	fmt.Printf("  TCP流数量: %d\n", tcpStreams)
	fmt.Printf("  错误数量: %d\n", errors)
	fmt.Printf("  未知协议流: %d\n", unknownFlows)
	fmt.Println("捕获完成")
}
