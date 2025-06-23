// Package tcpdumper 提供简单易用的TCP数据包捕获和协议解析功能
package tcpdumper

// NewDumper 创建新的TCP数据包捕获器
// 这是包的主要入口点，上层调用者通过此函数开始使用
func NewDumper(options *CaptureOptions) *TCPDumper {
	dumper := NewTCPDumper(options)

	// 不再自动注册内置协议，让用户根据需要自行注册
	// 用户可以参考 examples/ 目录中的示例代码

	return dumper
}

// NewSimpleDumper 创建简单的TCP数据包捕获器，使用默认配置
func NewSimpleDumper() *TCPDumper {
	return NewDumper(nil)
}

// NewFileDumper 创建从pcap文件读取的捕获器
func NewFileDumper(filename string) *TCPDumper {
	options := DefaultCaptureOptions()
	options.PcapFile = filename
	return NewDumper(options)
}

// NewInterfaceDumper 创建从网络接口抓包的捕获器
func NewInterfaceDumper(iface string) *TCPDumper {
	options := DefaultCaptureOptions()
	options.Interface = iface
	return NewDumper(options)
}
