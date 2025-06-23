package main

import (
	"testing"

	"github.com/LubyRuffy/tcpdumper"
	"github.com/google/gopacket/reassembly"
	"github.com/stretchr/testify/assert"
)

// 测试默认处理器
func TestDefaultProcessor(t *testing.T) {
	dumper := tcpdumper.NewSimpleDumper()

	// 设置默认处理器
	dumper.SetDefaultProcessor(CreateDefaultRawProcessorFactory())

	// 测试统计信息初始状态
	packets, tcpStreams, errors, unknownFlows := dumper.GetStats()
	assert.Equal(t, uint64(0), packets)
	assert.Equal(t, uint64(0), tcpStreams)
	assert.Equal(t, uint64(0), errors)
	assert.Equal(t, uint64(0), unknownFlows)
}

// 测试原始数据处理器
func TestRawProcessor(t *testing.T) {
	processor := NewRawProcessor("test-stream")
	assert.NotNil(t, processor)
	assert.Equal(t, "RAW", processor.GetProtocolName())

	// 测试数据处理
	testData := []byte("unknown protocol data")
	err := processor.ProcessData(testData, reassembly.TCPDirClientToServer, true, false)
	assert.NoError(t, err)

	// 测试关闭
	err = processor.Close()
	assert.NoError(t, err)
}

// 测试默认处理器工厂
func TestDefaultProcessorFactory(t *testing.T) {
	factory := CreateDefaultRawProcessorFactory()
	assert.NotNil(t, factory)

	processor := factory("test-stream")
	assert.NotNil(t, processor)
	assert.Equal(t, "RAW", processor.GetProtocolName())
}
