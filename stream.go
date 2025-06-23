package tcpdumper

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"
)

// tcpStreamFactory TCP流工厂
type tcpStreamFactory struct {
	registry                *ProtocolRegistry
	defaultProcessorFactory DefaultProcessorFactory
	dumper                  *TCPDumper // 用于更新统计信息
	mu                      sync.Mutex
	wg                      sync.WaitGroup
}

// New 创建新的TCP流
func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	// 创建流标识符
	srcIP, dstIP := net.Endpoints()
	srcPort, dstPort := transport.Endpoints()
	ident := fmt.Sprintf("%s:%s - %s:%s", srcIP, srcPort.String(), dstIP, dstPort.String())

	log.Println("New tcpStreamFactory", ident)

	stream := &tcpStream{
		net:       net,
		transport: transport,
		ident:     ident,
		registry:  factory.registry,
		factory:   factory,
	}

	factory.mu.Lock()
	factory.wg.Add(1)
	factory.mu.Unlock()

	return stream
}

// WaitGoRoutines 等待所有TCP流处理完成
func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

// tcpStream TCP流处理器
type tcpStream struct {
	net, transport gopacket.Flow
	ident          string
	registry       *ProtocolRegistry
	factory        *tcpStreamFactory
	processor      ProtocolProcessor
	detected       bool
	mu             sync.Mutex
}

// Accept 接受TCP数据包
func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// 简化的接受逻辑，接受所有数据包
	return true
}

// ReassembledSG 处理重组后的TCP数据
func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	// log.Println("ReassembledSG", t.ident)
	dir, start, end, skip := sg.Info()
	length, _ := sg.Lengths()

	// 跳过丢失的数据
	if skip != 0 {
		return
	}

	// 获取数据
	data := sg.Fetch(length)
	if len(data) == 0 {
		return
	}

	// 协议检测（只在第一次有数据时进行）
	if !t.detected && len(data) > 0 {
		t.mu.Lock()
		if !t.detected { // 双重检查
			detector := t.registry.DetectProtocol(data, dir)
			if detector != nil {
				t.processor = detector.CreateProcessor(t.ident)
				t.detected = true
			} else {
				// 没有匹配的协议，使用默认处理器
				if t.factory.defaultProcessorFactory != nil {
					t.processor = t.factory.defaultProcessorFactory(t.ident)
					// 更新未知流统计
					if t.factory.dumper != nil {
						t.factory.dumper.mu.Lock()
						t.factory.dumper.stats.unknownFlows++
						t.factory.dumper.mu.Unlock()
					}
				}
				t.detected = true // 标记为已检测，避免重复检测
			}
		}
		t.mu.Unlock()
	}

	// 如果有协议处理器，则处理数据
	if t.processor != nil {
		err := t.processor.ProcessData(data, dir, start, end)
		if err != nil {
			// 记录错误但不中断处理
			fmt.Printf("Error processing %s data: %v\n", t.processor.GetProtocolName(), err)
		}
	}
}

// ReassemblyComplete TCP流重组完成
func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	// 关闭协议处理器
	if t.processor != nil {
		t.processor.Close()
	}

	// 通知工厂一个流处理完成
	t.factory.mu.Lock()
	t.factory.wg.Done()
	t.factory.mu.Unlock()

	return true // 移除流
}
