// Package tcpdumper 提供TCP数据包捕获和协议解析的核心功能
package tcpdumper

import (
	"github.com/google/gopacket/reassembly"
)

// ProtocolProcessor TCP协议处理器接口
// 上层应用需要实现此接口来处理特定协议的数据
type ProtocolProcessor interface {
	// ProcessData 处理TCP流数据
	// data: 数据内容
	// dir: 数据流方向 (ClientToServer/ServerToClient)
	// start: 是否为流的开始
	// end: 是否为流的结束
	ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error

	// Close 关闭处理器，清理资源
	Close() error

	// GetProtocolName 获取协议名称
	GetProtocolName() string
}

// ProtocolDetector 协议检测器接口
// 用于检测TCP流中的应用层协议
type ProtocolDetector interface {
	// Detect 检测协议，返回置信度 (0-100)
	// 置信度越高表示越可能是该协议
	// 只有置信度>50才会被选中
	Detect(data []byte, dir reassembly.TCPFlowDirection) int

	// Name 获取协议名称
	Name() string

	// CreateProcessor 创建协议处理器
	CreateProcessor(streamInfo StreamInfo) ProtocolProcessor
}

// StreamInfo TCP流信息
type StreamInfo struct {
	SrcIP   string // 源IP地址
	SrcPort string // 源端口
	DstIP   string // 目标IP地址
	DstPort string // 目标端口
	Ident   string // 流标识符
}

// DefaultProcessorFactory 默认处理器工厂函数类型
// 当没有任何协议匹配时，使用此工厂创建默认处理器
type DefaultProcessorFactory func(streamInfo StreamInfo) ProtocolProcessor

// CaptureOptions 抓包配置选项
type CaptureOptions struct {
	Interface   string // 网络接口名称，如 "eth0", "lo0"
	PcapFile    string // pcap文件路径，如果指定则从文件读取
	SnapLen     int    // 每个数据包的最大捕获长度
	Promiscuous bool   // 是否启用混杂模式
	Timeout     int    // 超时时间（毫秒）
	BPFFilter   string // BPF过滤器表达式，如 "tcp port 80"
}

// DefaultCaptureOptions 返回默认的抓包配置
func DefaultCaptureOptions() *CaptureOptions {
	return &CaptureOptions{
		Interface:   "lo0",
		SnapLen:     65536,
		Promiscuous: true,
		Timeout:     30,
	}
}
