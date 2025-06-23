# TCPDumper

TCPDumper 是一个简单易用的Go语言TCP数据包捕获和协议解析库。它封装了pcap抓包和TCP重组的复杂性，让开发者能够快速扩展自定义的TCP协议处理器。

## 特性

- 🚀 **简单易用** - 只需几行代码即可开始TCP数据包分析
- 🔧 **高度可扩展** - 轻松添加自定义协议处理器
- 📦 **丰富示例** - 提供HTTP、DNS等协议处理器示例
- 🎯 **智能检测** - 基于数据内容的协议自动识别
- 🔄 **TCP重组** - 自动处理TCP分片和重组
- 📊 **统计信息** - 实时的数据包和流统计
- 🎛️ **灵活配置** - 支持实时抓包和pcap文件分析

## 快速开始

### 安装

```bash
go get github.com/LubyRuffy/tcpdumper
```

### 基本使用

```go
package main

import (
    "log"
    "time"
    
    "github.com/LubyRuffy/tcpdumper"
)

func main() {
    // 创建简单的TCP捕获器
    dumper := tcpdumper.NewSimpleDumper()

    // todo: 注册自定义协议处理器
    
    // 启动捕获
    err := dumper.Start()
    if err != nil {
        log.Fatal(err)
    }
    defer dumper.Stop()
    
    // 运行10秒
    time.Sleep(10 * time.Second)
    
    // 获取统计信息
    packets, streams, errors := dumper.GetStats()
    log.Printf("处理了 %d 个数据包, %d 个TCP流, %d 个错误", packets, streams, errors)
}
```

### 从pcap文件分析

```go
dumper := tcpdumper.NewFileDumper("capture.pcap")
err := dumper.Start()
if err != nil {
    log.Fatal(err)
}
dumper.Stop() // 文件处理完成后自动停止
```

### 指定网络接口

```go
dumper := tcpdumper.NewInterfaceDumper("eth0")
err := dumper.Start()
if err != nil {
    log.Fatal(err)
}
defer dumper.Stop()
```

## 自定义协议处理

### 简单协议注册

最简单的方式是基于字符串前缀匹配：

```go
dumper := tcpdumper.NewSimpleDumper()

// 注册Echo协议（以"ECHO:"开头）
dumper.RegisterSimpleProtocol("Echo", "ECHO:", func(ident string) tcpdumper.ProtocolProcessor {
    return &EchoProcessor{ident: ident}
})
```

### 方向敏感协议

支持客户端和服务器不同的协议模式：

```go
// Redis协议：客户端命令以"*"开头，服务器响应以"+"开头
dumper.RegisterPatternProtocol("Redis", "*", "+", func(ident string) tcpdumper.ProtocolProcessor {
    return &RedisProcessor{ident: ident}
})
```

### 自定义协议检测器

对于复杂的协议检测逻辑：

```go
type MyProtocolDetector struct{}

func (mpd *MyProtocolDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
    // 检测特定的二进制头部
    if len(data) >= 4 && data[0] == 0xCA && data[1] == 0xFE {
        return 95 // 高置信度
    }
    return 0
}

func (mpd *MyProtocolDetector) Name() string {
    return "MyProtocol"
}

func (mpd *MyProtocolDetector) CreateProcessor(streamInfo tcpdumper.StreamInfo) tcpdumper.ProtocolProcessor {
    return &MyProtocolProcessor{ident: streamInfo.Ident}
}

// 注册自定义检测器
dumper.RegisterProtocolDetector(&MyProtocolDetector{})
```

### 实现协议处理器

所有协议处理器都需要实现 `ProtocolProcessor` 接口：

```go
type MyProtocolProcessor struct {
    ident string
}

func (mp *MyProtocolProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
    fmt.Printf("MyProtocol/%s [%s]: 处理 %d 字节数据\n", mp.ident, dir, len(data))
    
    // 在这里实现你的协议解析逻辑
    // dir 参数表示数据流方向：
    // - reassembly.TCPDirClientToServer: 客户端到服务器
    // - reassembly.TCPDirServerToClient: 服务器到客户端
    
    return nil
}

func (mp *MyProtocolProcessor) Close() error {
    fmt.Printf("MyProtocol/%s: 连接关闭\n", mp.ident)
    return nil
}

func (mp *MyProtocolProcessor) GetProtocolName() string {
    return "MyProtocol"
}
```

## 高级配置

### 自定义捕获选项

```go
options := &tcpdumper.CaptureOptions{
    Interface:   "eth0",           // 网络接口
    PcapFile:    "",               // pcap文件路径（为空则实时抓包）
    SnapLen:     65536,            // 每个数据包的最大捕获长度
    Promiscuous: true,             // 混杂模式
    Timeout:     30,               // 超时时间（毫秒）
    BPFFilter:   "tcp port 80",    // BPF过滤器
}

dumper := tcpdumper.NewDumper(options)
```

### BPF过滤器示例

```go
// 只捕获HTTP流量
options.BPFFilter = "tcp port 80 or tcp port 443"

// 只捕获特定IP的流量
options.BPFFilter = "host 192.168.1.100"

// 组合条件
options.BPFFilter = "tcp and (port 80 or port 443) and host 192.168.1.100"
```

## 协议示例

TCPDumper 不内置任何协议处理器，但提供了丰富的示例代码供参考：

### HTTP协议示例

参见 `examples/httpdumper/` 目录：

- 完整的HTTP协议检测和处理实现
- 支持所有标准HTTP方法（GET, POST, PUT等）
- 特殊处理CONNECT方法（代理模式）
- 方向敏感检测（请求 vs 响应）

### DNS协议示例

参见 `examples/dnsdumper/` 目录：

- DNS over TCP协议的完整实现
- 自动检测DNS消息格式
- 处理DNS查询和响应
- 支持标准DNS消息结构

## 协议检测机制

### 置信度系统

协议检测基于置信度（0-100）：

- **0-50**: 低置信度，不会被选中
- **51-80**: 中等置信度，可能的协议匹配
- **81-100**: 高置信度，很可能是该协议

### 多协议竞争

当多个协议都能检测到同一数据时：

1. 计算每个协议的置信度
2. 选择置信度最高的协议
3. 只有置信度>50才会被选中

## 默认处理器

### 处理未知协议

当TCP流没有匹配到任何已注册的协议时，可以使用默认处理器来处理：

```go
dumper := tcpdumper.NewSimpleDumper()

// 或者使用自定义默认处理器
dumper.SetDefaultProcessor(func(ident string) tcpdumper.ProtocolProcessor {
    return &MyDefaultProcessor{ident: ident}
})
```

### 自定义默认处理器

```go
type MyDefaultProcessor struct {
    ident string
    file  *os.File
}

func (mdp *MyDefaultProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
    // 将原始数据保存到文件
    if start && mdp.file == nil {
        var err error
        mdp.file, err = os.Create(fmt.Sprintf("unknown_%s.bin", 
            strings.ReplaceAll(mdp.ident, ":", "_")))
        if err != nil {
            return err
        }
    }
    
    if mdp.file != nil {
        mdp.file.Write(data)
    }
    
    return nil
}

func (mdp *MyDefaultProcessor) Close() error {
    if mdp.file != nil {
        return mdp.file.Close()
    }
    return nil
}

func (mdp *MyDefaultProcessor) GetProtocolName() string {
    return "Unknown"
}
```

### 统计信息

启用默认处理器后，`GetStats()`方法会返回额外的统计信息：

```go
packets, tcpStreams, errors, unknownFlows := dumper.GetStats()
fmt.Printf("统计: %d 包, %d 流, %d 错误, %d 未知协议流\n", 
    packets, tcpStreams, errors, unknownFlows)
```

## API参考

### 主要类型

```go
// 创建捕获器的便捷函数
func NewSimpleDumper() *TCPDumper
func NewFileDumper(filename string) *TCPDumper  
func NewInterfaceDumper(iface string) *TCPDumper
func NewDumper(options *CaptureOptions) *TCPDumper

// TCPDumper 主要方法
func (td *TCPDumper) Start() error
func (td *TCPDumper) Stop()
func (td *TCPDumper) GetStats() (packets, tcpStreams, errors, unknownFlows uint64)
func (td *TCPDumper) GetRegisteredProtocols() []string
func (td *TCPDumper) RegisterSimpleProtocol(name, pattern string, factory func(string) ProtocolProcessor)
func (td *TCPDumper) RegisterPatternProtocol(name, clientPattern, serverPattern string, factory func(string) ProtocolProcessor)
func (td *TCPDumper) RegisterProtocolDetector(detector ProtocolDetector)
func (td *TCPDumper) SetDefaultProcessor(factory DefaultProcessorFactory)
```

### 接口定义

```go
type ProtocolProcessor interface {
    ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error
    Close() error
    GetProtocolName() string
}

type ProtocolDetector interface {
    Detect(data []byte, dir reassembly.TCPFlowDirection) int
    Name() string
    	CreateProcessor(streamInfo StreamInfo) ProtocolProcessor
}

type DefaultProcessorFactory func(ident string) ProtocolProcessor
```

## 性能考虑

- **内存使用**: 自动清理过期的TCP流和IPv4碎片
- **并发安全**: 协议注册表支持并发访问
- **零拷贝**: 最小化数据拷贝操作
- **高效检测**: 基于置信度的快速协议匹配

## 使用场景

- 🔍 **网络流量分析** - 分析网络中的各种协议流量
- 🛡️ **安全监控** - 检测异常的网络行为
- 🐛 **网络调试** - 诊断网络连接问题  
- 📊 **协议统计** - 收集协议使用统计信息
- 🔬 **协议逆向** - 分析未知的网络协议
- 🧪 **协议开发** - 测试新的网络协议实现

## 完整示例

```go
package main

import (
    "fmt"
    "log"
    "time"
    
    "github.com/LubyRuffy/tcpdumper"
    "github.com/google/gopacket/reassembly"
)

// 自定义协议处理器
type TelnetProcessor struct {
    ident string
}

func (tp *TelnetProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
    fmt.Printf("Telnet/%s [%s]: %s\n", tp.ident, dir, string(data))
    return nil
}

func (tp *TelnetProcessor) Close() error {
    fmt.Printf("Telnet/%s: 连接关闭\n", tp.ident)
    return nil
}

func (tp *TelnetProcessor) GetProtocolName() string {
    return "Telnet"
}

func main() {
    // 创建捕获器
    options := &tcpdumper.CaptureOptions{
        Interface: "lo0",
        BPFFilter: "tcp",
        SnapLen:   1024,
    }
    dumper := tcpdumper.NewDumper(options)
    
    // 注册自定义Telnet协议
    dumper.RegisterSimpleProtocol("Telnet", "login:", func(ident string) tcpdumper.ProtocolProcessor {
        return &TelnetProcessor{ident: ident}
    })
    
    // 显示已注册的协议
    protocols := dumper.GetRegisteredProtocols()
    fmt.Printf("已注册协议: %v\n", protocols)
    fmt.Println("默认处理器: 已启用")
    
    // 启动捕获
    err := dumper.Start()
    if err != nil {
        log.Fatal(err)
    }
    defer dumper.Stop()
    
    // 运行30秒
    fmt.Println("开始捕获TCP流量...")
    time.Sleep(30 * time.Second)
    
    // 获取统计信息
    packets, streams, errors, unknownFlows := dumper.GetStats()
    fmt.Printf("统计信息: %d 个数据包, %d 个TCP流, %d 个错误, %d 个未知协议流\n", 
        packets, streams, errors, unknownFlows)
}
```

## 许可证

本项目采用与主项目相同的许可证。 