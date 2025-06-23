package tcpdumper_test

import (
	"fmt"

	"github.com/LubyRuffy/tcpdumper"
	"github.com/google/gopacket/reassembly"
)

// 示例：基本使用
func ExampleNewSimpleDumper() {
	// 创建简单的TCP捕获器
	dumper := tcpdumper.NewSimpleDumper()

	// 显示已注册的协议
	protocols := dumper.GetRegisteredProtocols()
	fmt.Printf("Registered protocols: %v\n", protocols)

	// 注意：实际使用时需要调用dumper.Start()和dumper.Stop()
	// Output: Registered protocols: []
}

// 示例：从pcap文件读取
func ExampleNewFileDumper() {
	// 从pcap文件创建捕获器
	dumper := tcpdumper.NewFileDumper("capture.pcap")

	// 显示配置信息
	protocols := dumper.GetRegisteredProtocols()
	fmt.Printf("File dumper created with %d protocols\n", len(protocols))

	// 启动处理（在实际环境中）
	// err := dumper.Start()
	// if err != nil {
	//     log.Fatal(err)
	// }
	// defer dumper.Stop()

	// Output: File dumper created with 0 protocols
}

// 示例：自定义协议处理器
func ExampleTCPDumper_RegisterSimpleProtocol() {
	dumper := tcpdumper.NewSimpleDumper()

	// 注册自定义的Echo协议
	dumper.RegisterSimpleProtocol("Echo", "ECHO:", func(ident string) tcpdumper.ProtocolProcessor {
		return &EchoProcessor{ident: ident}
	})

	protocols := dumper.GetRegisteredProtocols()
	fmt.Printf("Protocols after registration: %v\n", protocols)
	// Output: Protocols after registration: [Echo]
}

// 示例：复杂的协议检测
func ExampleTCPDumper_RegisterProtocolDetector() {
	dumper := tcpdumper.NewSimpleDumper()

	// 创建自定义协议检测器
	detector := &CustomProtocolDetector{}
	dumper.RegisterProtocolDetector(detector)

	fmt.Println("Custom protocol detector registered")
	// Output: Custom protocol detector registered
}

// 示例：完整的使用流程
func ExampleTCPDumper_complete() {
	// 创建配置
	options := &tcpdumper.CaptureOptions{
		Interface: "lo0",
		BPFFilter: "tcp port 80",
		SnapLen:   1024,
	}

	// 创建捕获器
	dumper := tcpdumper.NewDumper(options)

	// 注册自定义协议
	dumper.RegisterSimpleProtocol("MyProtocol", "MYPROT", func(ident string) tcpdumper.ProtocolProcessor {
		return &MyProtocolProcessor{ident: ident}
	})

	// 在实际使用中：
	// err := dumper.Start()
	// if err != nil {
	//     log.Fatal(err)
	// }
	//
	// // 运行一段时间
	// time.Sleep(10 * time.Second)
	//
	// // 停止并获取统计信息
	// dumper.Stop()
	// packets, streams, errors := dumper.GetStats()
	// fmt.Printf("Stats: %d packets, %d streams, %d errors\n", packets, streams, errors)

	fmt.Println("Complete example setup")
	// Output: Complete example setup
}

/*
 * 示例协议处理器实现
 */

// EchoProcessor 简单的Echo协议处理器
type EchoProcessor struct {
	ident string
}

func (ep *EchoProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	fmt.Printf("Echo/%s [%s]: %s\n", ep.ident, dir, string(data))
	return nil
}

func (ep *EchoProcessor) Close() error {
	fmt.Printf("Echo/%s: Connection closed\n", ep.ident)
	return nil
}

func (ep *EchoProcessor) GetProtocolName() string {
	return "Echo"
}

// MyProtocolProcessor 自定义协议处理器
type MyProtocolProcessor struct {
	ident string
}

func (mp *MyProtocolProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	fmt.Printf("MyProtocol/%s [%s]: Processing %d bytes\n", mp.ident, dir, len(data))
	return nil
}

func (mp *MyProtocolProcessor) Close() error {
	return nil
}

func (mp *MyProtocolProcessor) GetProtocolName() string {
	return "MyProtocol"
}

// CustomProtocolDetector 自定义协议检测器
type CustomProtocolDetector struct{}

func (cpd *CustomProtocolDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
	// 检测特定的二进制头部
	if len(data) >= 4 && data[0] == 0xCA && data[1] == 0xFE {
		return 95 // 高置信度
	}
	return 0
}

func (cpd *CustomProtocolDetector) Name() string {
	return "CustomBinary"
}

func (cpd *CustomProtocolDetector) CreateProcessor(ident string) tcpdumper.ProtocolProcessor {
	return &CustomBinaryProcessor{ident: ident}
}

// CustomBinaryProcessor 自定义二进制协议处理器
type CustomBinaryProcessor struct {
	ident string
}

func (cbp *CustomBinaryProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	fmt.Printf("CustomBinary/%s [%s]: Binary data (%d bytes)\n", cbp.ident, dir, len(data))
	return nil
}

func (cbp *CustomBinaryProcessor) Close() error {
	return nil
}

func (cbp *CustomBinaryProcessor) GetProtocolName() string {
	return "CustomBinary"
}
