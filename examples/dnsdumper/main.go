package main

import (
	"fmt"
	"log"
	"time"

	"github.com/LubyRuffy/tcpdumper"
	"github.com/google/gopacket/reassembly"
)

// DNSProcessor DNS协议处理器实现
type DNSProcessor struct {
	ident string
}

func (dp *DNSProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	if len(data) < 2 {
		return nil
	}

	// DNS over TCP: 前2字节是消息长度
	msgLen := int(data[0])<<8 | int(data[1])
	fmt.Printf("DNS/%s [%s]: DNS message (%d bytes)\n", dp.ident, dir, msgLen)

	return nil
}

func (dp *DNSProcessor) Close() error {
	fmt.Printf("DNS/%s: Connection closed\n", dp.ident)
	return nil
}

func (dp *DNSProcessor) GetProtocolName() string {
	return "DNS"
}

// DNSDetector DNS协议检测器
type DNSDetector struct{}

func (dd *DNSDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
	// DNS over TCP格式检查
	if len(data) < 12 { // DNS头部至少12字节
		return 0
	}

	// 检查DNS over TCP的长度前缀（前2字节）
	if len(data) >= 2 {
		msgLen := int(data[0])<<8 | int(data[1])
		if msgLen > 0 && msgLen <= 512 && len(data) >= msgLen+2 {
			// 检查DNS头部的合理性
			if len(data) >= 14 { // 2字节长度 + 12字节DNS头部
				// 简单检查DNS头部字段
				flags := int(data[4])<<8 | int(data[5])
				if (flags&0x8000) == 0 || (flags&0x8000) != 0 { // QR位可以是0或1
					return 80
				}
			}
		}
	}

	return 0
}

func (dd *DNSDetector) Name() string {
	return "DNS"
}

func (dd *DNSDetector) CreateProcessor(streamInfo tcpdumper.StreamInfo) tcpdumper.ProtocolProcessor {
	return &DNSProcessor{ident: streamInfo.Ident}
}

func main() {
	// 创建TCP捕获器
	options := &tcpdumper.CaptureOptions{
		Interface: "en0",
		BPFFilter: "tcp port 53",
		SnapLen:   1024,
		Timeout:   30,
	}
	dumper := tcpdumper.NewDumper(options)

	// 注册DNS协议检测器
	dumper.RegisterProtocolDetector(&DNSDetector{})

	// 显示已注册的协议
	protocols := dumper.GetRegisteredProtocols()
	fmt.Printf("已注册协议: %v\n", protocols)

	// 启动捕获
	fmt.Println("启动DNS over TCP流量捕获...")
	err := dumper.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer dumper.Stop()

	// 运行30秒
	fmt.Println("捕获DNS流量中... (30秒)")
	time.Sleep(30 * time.Second)

	// 获取统计信息
	packets, streams, errors, unknownFlows := dumper.GetStats()
	fmt.Printf("统计信息: %d 个数据包, %d 个TCP流, %d 个错误, %d 个未知协议流\n",
		packets, streams, errors, unknownFlows)
}
