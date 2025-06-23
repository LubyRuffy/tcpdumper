# 性能和实时性配置说明

## pcap超时参数详解

### 问题描述

在使用rawtcpdumper进行网络抓包时，你可能会遇到数据包接收延迟的问题。例如，当你执行 `curl` 请求时，可能需要等待30秒才能看到相应的数据包输出。

### 原因分析

这个延迟是由pcap库的**超时参数**（Timeout）引起的。在 `main.go` 中：

```go
options := &tcpdumper.CaptureOptions{
    Interface:   iface,
    BPFFilter:   bpfFilter,
    SnapLen:     65536,
    Promiscuous: true,
    Timeout:     1, // 这个参数控制数据包读取的超时时间
}
```

### pcap超时机制

pcap的超时参数控制着 `pcap_next_ex()` 或 `ReadPacketData()` 函数的行为：

1. **阻塞模式**: 当没有数据包到达时，pcap会阻塞等待
2. **超时机制**: 最多等待指定的超时时间
3. **批量处理**: pcap可能会缓冲多个数据包一起返回

### 超时时间的影响

| 超时时间 | 实时性 | CPU使用率 | 适用场景 |
|---------|--------|-----------|----------|
| 30秒    | 很差   | 很低      | 文件分析 |
| 5秒     | 较差   | 低        | 批量处理 |
| 1秒     | 好     | 中等      | 实时监控 |
| 100毫秒 | 很好   | 较高      | 高实时性要求 |
| 10毫秒  | 极好   | 高        | 低延迟应用 |

### 推荐配置

#### 实时监控场景
```go
Timeout: 1, // 1秒，平衡实时性和性能
```

#### 高实时性要求
```go
Timeout: 0.1, // 100毫秒，需要修改为毫秒单位
```

在代码中应该这样设置：
```go
options := &tcpdumper.CaptureOptions{
    Interface:   iface,
    BPFFilter:   bpfFilter,
    SnapLen:     65536,
    Promiscuous: true,
    Timeout:     1, // 1秒 = 1000毫秒
}
```

#### 低延迟配置示例
如果需要更低的延迟，可以修改为：
```go
Timeout: 0, // 非阻塞模式，立即返回
```

但这会显著增加CPU使用率。

### 性能调优建议

#### 1. 调整超时时间
根据你的需求调整超时时间：
- **网络调试**: 100毫秒 - 1秒
- **安全监控**: 1-5秒
- **流量分析**: 5-30秒

#### 2. 优化BPF过滤器
使用精确的BPF过滤器减少不必要的数据包处理：
```bash
# 精确过滤
"tcp port 80 and host 192.168.1.100"

# 避免过于宽泛的过滤
"tcp"  # 会捕获所有TCP流量
```

#### 3. 调整缓冲区大小
```go
SnapLen: 1500, // 只捕获以太网帧大小，而不是65536
```

#### 4. 使用合适的网络接口
- 本地测试: `lo0` 或 `localhost`
- 生产环境: 实际的网络接口如 `eth0`

### 测试实时性

使用提供的测试脚本：
```bash
sudo ./test_curl.sh
```

观察输出中的时间戳，确认数据包接收的实时性。

### 常见问题排查

#### 1. 延迟仍然存在
- 检查BPF过滤器是否正确
- 确认网络接口是否活跃
- 尝试更小的超时值

#### 2. CPU使用率过高
- 增加超时时间
- 使用更精确的BPF过滤器
- 减少SnapLen大小

#### 3. 丢包问题
- 增加系统缓冲区
- 优化数据包处理逻辑
- 考虑使用多线程处理

### 代码示例

完整的低延迟配置示例：

```go
options := &tcpdumper.CaptureOptions{
    Interface:   "eth0",
    BPFFilter:   "tcp port 80",
    SnapLen:     1500,        // 标准以太网帧大小
    Promiscuous: true,
    Timeout:     1,           // 1秒超时，实时性较好
}
```

极低延迟配置（高CPU使用率）：
```go
options := &tcpdumper.CaptureOptions{
    Interface:   "eth0",
    BPFFilter:   "tcp port 80 and host 192.168.1.100",
    SnapLen:     1500,
    Promiscuous: true,
    Timeout:     0,           // 非阻塞模式
}
```

### 监控和调试

添加性能监控代码：
```go
start := time.Now()
// ... 数据包处理 ...
duration := time.Since(start)
if duration > time.Millisecond*100 {
    log.Printf("数据包处理耗时: %v", duration)
}
``` 