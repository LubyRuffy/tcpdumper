package main

import (
	"encoding/hex"
	"fmt"

	"github.com/LubyRuffy/tcpdumper"
	"github.com/google/gopacket/reassembly"
)

// RawProcessor 原始数据处理器，用于处理未知协议的TCP流
type RawProcessor struct {
	ident       string
	totalBytes  int64
	packetCount int64
}

// ProcessData 处理原始TCP数据
func (rp *RawProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	rp.packetCount++
	rp.totalBytes += int64(len(data))

	dirStr := "C->S"
	if dir == reassembly.TCPDirServerToClient {
		dirStr = "S->C"
	}

	// 只在开始时记录流信息
	if start {
		fmt.Printf("[RAW] New unknown protocol stream: %s\n", rp.ident)
	}

	// 记录数据摘要（前32字节的十六进制）
	if len(data) > 0 {
		preview := data
		if len(preview) > 32 {
			preview = preview[:32]
		}
		fmt.Printf("[RAW] %s [%s] %d bytes: \n%s\n", rp.ident, dirStr, len(data), hex.Dump(preview))
	}

	if end {
		fmt.Printf("[RAW] Stream %s closed. Total: %d packets, %d bytes\n",
			rp.ident, rp.packetCount, rp.totalBytes)
	}

	return nil
}

// Close 关闭处理器
func (rp *RawProcessor) Close() error {
	fmt.Printf("[RAW] Closing stream %s. Final stats: %d packets, %d bytes\n",
		rp.ident, rp.packetCount, rp.totalBytes)
	return nil
}

// GetProtocolName 获取协议名称
func (rp *RawProcessor) GetProtocolName() string {
	return "RAW"
}

// NewRawProcessor 创建原始数据处理器
func NewRawProcessor(ident string) tcpdumper.ProtocolProcessor {
	return &RawProcessor{
		ident: ident,
	}
}

// CreateDefaultRawProcessorFactory 创建默认的原始数据处理器工厂
func CreateDefaultRawProcessorFactory() tcpdumper.DefaultProcessorFactory {
	return func(ident string) tcpdumper.ProtocolProcessor {
		return NewRawProcessor(ident)
	}
}
