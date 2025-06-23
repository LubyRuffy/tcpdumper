package tcpdumper

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"
)

// TCPDumper TCP数据包捕获和协议解析器
type TCPDumper struct {
	registry *ProtocolRegistry
	options  *CaptureOptions
	handle   *pcap.Handle

	// TCP重组相关
	assembler *reassembly.Assembler
	factory   *tcpStreamFactory

	// 默认处理器
	defaultProcessorFactory DefaultProcessorFactory

	// 控制相关
	stopChan chan struct{}
	wg       sync.WaitGroup

	// 统计信息
	stats struct {
		packets      uint64
		tcpStreams   uint64
		errors       uint64
		unknownFlows uint64 // 未知协议流的数量
	}
	mu sync.RWMutex
}

// NewTCPDumper 创建新的TCP数据包捕获器
func NewTCPDumper(options *CaptureOptions) *TCPDumper {
	if options == nil {
		options = DefaultCaptureOptions()
	} else if options.Timeout == 0 {
		options.Timeout = pcap.BlockForever
	}

	dumper := &TCPDumper{
		registry: NewProtocolRegistry(),
		options:  options,
		stopChan: make(chan struct{}),
	}

	// 创建TCP流工厂
	dumper.factory = &tcpStreamFactory{
		registry:                dumper.registry,
		defaultProcessorFactory: dumper.defaultProcessorFactory,
		dumper:                  dumper,
	}

	// 创建TCP重组器
	streamPool := reassembly.NewStreamPool(dumper.factory)
	dumper.assembler = reassembly.NewAssembler(streamPool)

	return dumper
}

// RegisterProtocolDetector 注册协议检测器
func (td *TCPDumper) RegisterProtocolDetector(detector ProtocolDetector) {
	td.registry.Register(detector)
}

// RegisterSimpleProtocol 注册简单协议（基于字符串前缀匹配）
func (td *TCPDumper) RegisterSimpleProtocol(name, pattern string, processorFactory func(StreamInfo) ProtocolProcessor) {
	RegisterSimpleProtocol(td.registry, name, pattern, processorFactory)
}

// RegisterPatternProtocol 注册方向敏感的协议
func (td *TCPDumper) RegisterPatternProtocol(name, clientPattern, serverPattern string, processorFactory func(StreamInfo) ProtocolProcessor) {
	RegisterPatternProtocol(td.registry, name, clientPattern, serverPattern, processorFactory)
}

// SetDefaultProcessor 设置默认处理器工厂
// 当没有任何协议匹配时，将使用此工厂创建处理器来处理TCP流
func (td *TCPDumper) SetDefaultProcessor(factory DefaultProcessorFactory) {
	td.defaultProcessorFactory = factory
	if td.factory != nil {
		td.factory.defaultProcessorFactory = factory
	}
}

// Start 开始捕获数据包
func (td *TCPDumper) Start() error {
	var err error

	// 打开数据源
	if td.options.PcapFile != "" {
		// 从文件读取
		td.handle, err = pcap.OpenOffline(td.options.PcapFile)
	} else {
		// 实时抓包
		td.handle, err = pcap.OpenLive(
			td.options.Interface,
			int32(td.options.SnapLen),
			td.options.Promiscuous,
			td.options.Timeout,
		)
	}

	if err != nil {
		return fmt.Errorf("failed to open pcap: %v", err)
	}

	// 设置BPF过滤器
	if td.options.BPFFilter != "" {
		err = td.handle.SetBPFFilter(td.options.BPFFilter)
		if err != nil {
			td.handle.Close()
			return fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	// 启动数据包处理goroutine
	td.wg.Add(1)
	go td.packetLoop()

	return nil
}

// Stop 停止捕获数据包
func (td *TCPDumper) Stop() {
	close(td.stopChan)
	td.wg.Wait()

	if td.handle != nil {
		td.handle.Close()
	}

	// 等待所有TCP流处理完成
	td.factory.WaitGoRoutines()
}

// GetStats 获取统计信息
func (td *TCPDumper) GetStats() (packets, tcpStreams, errors, unknownFlows uint64) {
	td.mu.RLock()
	defer td.mu.RUnlock()
	return td.stats.packets, td.stats.tcpStreams, td.stats.errors, td.stats.unknownFlows
}

// GetRegisteredProtocols 获取已注册的协议列表
func (td *TCPDumper) GetRegisteredProtocols() []string {
	return td.registry.GetRegisteredProtocols()
}

// packetLoop 数据包处理循环
func (td *TCPDumper) packetLoop() {
	defer td.wg.Done()

	// 创建IPv4碎片整理器
	var defragger *ip4defrag.IPv4Defragmenter
	// defragger := ip4defrag.NewIPv4Defragmenter()

	// 创建数据包源
	packetSource := gopacket.NewPacketSource(td.handle, td.handle.LinkType())
	packets := packetSource.Packets()

	// 定期清理过期的TCP流
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	log.Println("packetLoop")

	for {
		select {
		case <-td.stopChan:
			return

		case <-ticker.C:
			// 清理过期的TCP流和碎片
			td.assembler.FlushCloseOlderThan(time.Now().Add(-2 * time.Minute))
			if defragger != nil {
				defragger.DiscardOlderThan(time.Now().Add(-10 * time.Second))
			}

		case packet := <-packets:
			if packet == nil {
				return // 数据源结束
			}

			td.processPacket(packet, defragger)
		}
	}
}

// processPacket 处理单个数据包
func (td *TCPDumper) processPacket(packet gopacket.Packet, defragger *ip4defrag.IPv4Defragmenter) {
	td.mu.Lock()
	td.stats.packets++
	td.mu.Unlock()

	// 处理IPv4碎片
	if defragger != nil {
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			newipv4, err := defragger.DefragIPv4(ipv4)
			if err != nil {
				log.Printf("Error defragmenting IPv4 packet: %v", err)
				td.mu.Lock()
				td.stats.errors++
				td.mu.Unlock()
				return
			} else if newipv4 == nil {
				// 碎片还没有完整，等待更多碎片
				return
			}

			// 使用整理后的IPv4包创建新的数据包
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				return
			}
			nextDecoder := newipv4.NextLayerType()
			nextDecoder.Decode(newipv4.Payload, pb)
		}
	}

	// 处理TCP层
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			// 将数据包交给TCP重组器
			td.assembler.AssembleWithContext(
				netLayer.NetworkFlow(),
				tcp,
				&Context{CaptureInfo: packet.Metadata().CaptureInfo},
			)
		}
	}
}

// Context 重组器上下文
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}
