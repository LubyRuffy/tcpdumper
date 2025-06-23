# TCPDumper 协议处理器示例

这个目录包含了各种协议处理器的示例实现，展示如何使用TCPDumper库来解析不同的TCP协议。

## 可用示例

### [HTTP协议处理器](httpdumper/)

完整的HTTP协议检测和处理实现：

- 支持所有标准HTTP方法
- 特殊处理CONNECT方法（代理隧道模式）
- 方向敏感的协议检测
- 适用于Web流量分析

**运行方式：**
```bash
cd httpdumper
sudo go run main.go
```

### [DNS协议处理器](dnsdumper/)

DNS over TCP协议的完整实现：

- 检测DNS消息格式
- 解析DNS消息长度前缀
- 验证DNS头部合理性
- 适用于DNS流量监控

**运行方式：**
```bash
cd dnsdumper
sudo go run main.go
```

### [Raw TCP流监控器](rawtcpdumper/)

基础TCP流信息打印工具：

- 不注册任何协议处理器
- 使用默认Raw处理器处理所有TCP流
- 显示TCP流基本信息和数据摘要
- 支持实时统计和文件分析
- 适用于网络流量监控和协议分析

**运行方式：**
```bash
cd rawtcpdumper
sudo go run main.go
# 或者从pcap文件读取
go run main.go -f capture.pcap
```

## 如何使用示例

1. **选择示例**：根据你的需求选择相应的协议示例
2. **进入目录**：`cd examples/协议名dumper/`
3. **安装依赖**：`go mod tidy`（如果需要）
4. **运行示例**：`sudo go run main.go`（需要root权限进行网络抓包）

## 自定义协议开发

基于这些示例，你可以开发自己的协议处理器：

### 1. 实现协议检测器

```go
type MyProtocolDetector struct{}

func (d *MyProtocolDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
    // 实现你的协议检测逻辑
    // 返回0-100的置信度
    return 0
}

func (d *MyProtocolDetector) Name() string {
    return "MyProtocol"
}

func (d *MyProtocolDetector) CreateProcessor(ident string) tcpdumper.ProtocolProcessor {
    return &MyProtocolProcessor{ident: ident}
}
```

### 2. 实现协议处理器

```go
type MyProtocolProcessor struct {
    ident string
}

func (p *MyProtocolProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
    // 处理协议数据
    return nil
}

func (p *MyProtocolProcessor) Close() error {
    // 清理资源
    return nil
}

func (p *MyProtocolProcessor) GetProtocolName() string {
    return "MyProtocol"
}
```

### 3. 注册协议

```go
dumper := tcpdumper.NewSimpleDumper()
dumper.RegisterProtocolDetector(&MyProtocolDetector{})
```

## 开发指南

### 协议检测最佳实践

1. **准确性**：确保检测逻辑准确，避免误报
2. **性能**：检测逻辑应该高效，避免复杂计算
3. **置信度**：合理设置置信度，避免与其他协议冲突
4. **边界检查**：始终检查数据长度，避免越界访问

### 协议处理最佳实践

1. **错误处理**：妥善处理各种异常情况
2. **内存管理**：及时释放资源，避免内存泄漏
3. **日志记录**：提供有用的调试信息
4. **状态管理**：正确维护连接状态

## 贡献示例

欢迎贡献新的协议处理器示例！请确保：

1. 提供完整的实现代码
2. 包含详细的README文档
3. 添加适当的注释
4. 遵循Go语言最佳实践
5. 提供使用示例和测试用例

## 常见问题

**Q: 为什么需要root权限？**
A: 网络抓包需要访问网络接口的原始数据，这在大多数系统上需要管理员权限。

**Q: 如何调试协议检测？**
A: 可以在检测函数中添加日志输出，观察数据内容和检测逻辑。

**Q: 协议冲突怎么办？**
A: 调整置信度设置，或者改进检测逻辑使其更加精确。

**Q: 如何处理加密协议？**
A: 对于加密协议，通常只能检测握手阶段的明文部分，或基于流量模式进行分析。 