package tcpdumper

import (
	"sync"

	"github.com/google/gopacket/reassembly"
)

// ProtocolRegistry 协议注册表
// 管理所有已注册的协议检测器
type ProtocolRegistry struct {
	detectors []ProtocolDetector
	mu        sync.RWMutex
}

// NewProtocolRegistry 创建新的协议注册表
func NewProtocolRegistry() *ProtocolRegistry {
	return &ProtocolRegistry{
		detectors: make([]ProtocolDetector, 0),
	}
}

// Register 注册协议检测器
func (pr *ProtocolRegistry) Register(detector ProtocolDetector) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.detectors = append(pr.detectors, detector)
}

// DetectProtocol 检测协议，返回最匹配的协议检测器
func (pr *ProtocolRegistry) DetectProtocol(data []byte, dir reassembly.TCPFlowDirection) ProtocolDetector {
	if len(pr.detectors) == 0 {
		return nil
	}

	pr.mu.RLock()
	defer pr.mu.RUnlock()

	var bestDetector ProtocolDetector
	bestConfidence := 0

	for _, detector := range pr.detectors {
		confidence := detector.Detect(data, dir)
		if confidence > bestConfidence {
			bestConfidence = confidence
			bestDetector = detector
		}
	}

	// 只有置信度大于50才认为检测成功
	if bestConfidence > 50 {
		return bestDetector
	}

	return nil
}

// GetRegisteredProtocols 获取所有已注册的协议名称
func (pr *ProtocolRegistry) GetRegisteredProtocols() []string {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	protocols := make([]string, len(pr.detectors))
	for i, detector := range pr.detectors {
		protocols[i] = detector.Name()
	}
	return protocols
}

// CreateProcessor 根据协议名创建处理器
func (pr *ProtocolRegistry) CreateProcessor(protocolName string, ident string) ProtocolProcessor {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	for _, detector := range pr.detectors {
		if detector.Name() == protocolName {
			return detector.CreateProcessor(ident)
		}
	}
	return nil
}

/*
 * 简化开发的便捷函数
 */

// SimpleProtocolDetector 简单协议检测器实现
type SimpleProtocolDetector struct {
	name             string
	detectFunc       func([]byte, reassembly.TCPFlowDirection) int
	processorFactory func(string) ProtocolProcessor
}

// NewSimpleProtocolDetector 创建简单协议检测器
func NewSimpleProtocolDetector(
	name string,
	detectFunc func([]byte, reassembly.TCPFlowDirection) int,
	processorFactory func(string) ProtocolProcessor,
) *SimpleProtocolDetector {
	return &SimpleProtocolDetector{
		name:             name,
		detectFunc:       detectFunc,
		processorFactory: processorFactory,
	}
}

func (spd *SimpleProtocolDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
	return spd.detectFunc(data, dir)
}

func (spd *SimpleProtocolDetector) Name() string {
	return spd.name
}

func (spd *SimpleProtocolDetector) CreateProcessor(ident string) ProtocolProcessor {
	return spd.processorFactory(ident)
}

// RegisterProtocol 便捷的协议注册函数
func RegisterProtocol(
	registry *ProtocolRegistry,
	name string,
	detectFunc func([]byte, reassembly.TCPFlowDirection) int,
	processorFactory func(string) ProtocolProcessor,
) {
	detector := NewSimpleProtocolDetector(name, detectFunc, processorFactory)
	registry.Register(detector)
}

// RegisterSimpleProtocol 更简单的协议注册函数（基于字符串前缀匹配）
func RegisterSimpleProtocol(
	registry *ProtocolRegistry,
	name string,
	pattern string,
	processorFactory func(string) ProtocolProcessor,
) {
	detectFunc := func(data []byte, dir reassembly.TCPFlowDirection) int {
		if len(data) < len(pattern) {
			return 0
		}
		if string(data[:len(pattern)]) == pattern {
			return 95 // 高置信度
		}
		return 0
	}

	RegisterProtocol(registry, name, detectFunc, processorFactory)
}

// RegisterPatternProtocol 基于方向敏感模式匹配的协议注册
func RegisterPatternProtocol(
	registry *ProtocolRegistry,
	name string,
	clientPattern string, // 客户端到服务器的模式
	serverPattern string, // 服务器到客户端的模式
	processorFactory func(string) ProtocolProcessor,
) {
	detectFunc := func(data []byte, dir reassembly.TCPFlowDirection) int {
		var pattern string
		if dir == reassembly.TCPDirClientToServer {
			pattern = clientPattern
		} else {
			pattern = serverPattern
		}

		if pattern == "" {
			return 0 // 该方向不支持此协议
		}

		if len(data) < len(pattern) {
			return 0
		}

		if string(data[:len(pattern)]) == pattern {
			return 95 // 高置信度
		}
		return 0
	}

	RegisterProtocol(registry, name, detectFunc, processorFactory)
}
