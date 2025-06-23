package tcpdumper

import (
	"testing"

	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/assert"
)

// 测试协议注册表
func TestProtocolRegistry(t *testing.T) {
	registry := NewProtocolRegistry()

	// 注册测试协议
	RegisterSimpleProtocol(registry, "Test", "TEST", func(streamInfo StreamInfo) ProtocolProcessor {
		return &testProcessor{ident: streamInfo.Ident}
	})

	// 检查协议是否注册成功
	protocols := registry.GetRegisteredProtocols()
	assert.Contains(t, protocols, "Test")

	// 测试协议检测
	detector := registry.DetectProtocol([]byte("TEST data"), reassembly.TCPDirClientToServer)
	assert.NotNil(t, detector)
	assert.Equal(t, "Test", detector.Name())

	// 测试创建处理器
	streamInfo := StreamInfo{
		SrcIP:   "127.0.0.1",
		SrcPort: "12345",
		DstIP:   "127.0.0.1",
		DstPort: "80",
		Ident:   "test-stream",
	}
	processor := detector.CreateProcessor(streamInfo)
	assert.NotNil(t, processor)
	assert.Equal(t, "Test", processor.GetProtocolName())
}

// 测试TCPDumper创建
func TestTCPDumperCreation(t *testing.T) {
	// 测试默认配置
	dumper := NewSimpleDumper()
	assert.NotNil(t, dumper)

	// 默认情况下不应该有任何内置协议
	protocols := dumper.GetRegisteredProtocols()
	assert.Empty(t, protocols)

	// 测试自定义配置
	options := &CaptureOptions{
		Interface: "eth0",
		SnapLen:   1024,
		BPFFilter: "tcp port 80",
	}
	dumper2 := NewDumper(options)
	assert.NotNil(t, dumper2)
	assert.Equal(t, "eth0", dumper2.options.Interface)
	assert.Equal(t, 1024, dumper2.options.SnapLen)
}

// 测试文件捕获器创建
func TestFileDumper(t *testing.T) {
	dumper := NewFileDumper("test.pcap")
	assert.NotNil(t, dumper)
	assert.Equal(t, "test.pcap", dumper.options.PcapFile)
}

// 测试接口捕获器创建
func TestInterfaceDumper(t *testing.T) {
	dumper := NewInterfaceDumper("lo0")
	assert.NotNil(t, dumper)
	assert.Equal(t, "lo0", dumper.options.Interface)
}

// 测试自定义协议注册
func TestCustomProtocolRegistration(t *testing.T) {
	dumper := NewSimpleDumper()

	// 注册自定义协议
	dumper.RegisterSimpleProtocol("Echo", "ECHO:", func(streamInfo StreamInfo) ProtocolProcessor {
		return &testProcessor{ident: streamInfo.Ident}
	})

	protocols := dumper.GetRegisteredProtocols()
	assert.Contains(t, protocols, "Echo")
}

// 测试处理器
type testProcessor struct {
	ident string
}

func (tp *testProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	return nil
}

func (tp *testProcessor) Close() error {
	return nil
}

func (tp *testProcessor) GetProtocolName() string {
	return "Test"
}

// 基准测试 - 协议检测性能
func BenchmarkProtocolDetection(b *testing.B) {
	registry := NewProtocolRegistry()
	RegisterSimpleProtocol(registry, "HTTP", "GET ", func(streamInfo StreamInfo) ProtocolProcessor {
		return &testProcessor{ident: streamInfo.Ident}
	})
	RegisterSimpleProtocol(registry, "Test", "TEST", func(streamInfo StreamInfo) ProtocolProcessor {
		return &testProcessor{ident: streamInfo.Ident}
	})

	testData := []byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.DetectProtocol(testData, reassembly.TCPDirClientToServer)
	}
}
