# Raw TCP Dumper - 基础TCP流信息打印工具

这个示例展示了如何使用TCPDumper库创建一个不注册任何协议处理器的基础TCP流监控工具。所有TCP流都将由默认的Raw处理器处理，显示基本的流信息和数据摘要。

## 功能特性

- 🚫 **无协议处理器** - 不注册任何特定协议的处理器
- 📊 **默认处理器** - 使用内置的Raw处理器处理所有TCP流
- 🔍 **数据摘要** - 显示每个数据包的十六进制摘要（前32字节）
- 📈 **实时统计** - 每10秒显示一次统计信息
- 🎛️ **灵活配置** - 支持不同的网络接口和BPF过滤器
- 📁 **文件支持** - 可以从pcap文件读取数据

## 使用方法

### 基本用法

```bash
# 进入示例目录
cd examples/rawtcpdumper

# 使用默认配置（监听lo0接口的所有TCP流量）
sudo go run main.go

# 监听指定网络接口
sudo go run main.go eth0

# 使用BPF过滤器
sudo go run main.go eth0 "tcp port 80"
```

### 命令行选项

```bash
# 显示帮助信息
go run main.go -h

# 从pcap文件读取
go run main.go -f capture.pcap

# 指定网络接口
sudo go run main.go -i eth0

# 指定网络接口和过滤器
sudo go run main.go -i eth0 "tcp port 443"
```

### 使用示例

```bash
# 监听所有TCP流量
sudo go run main.go

# 监听HTTP流量
sudo go run main.go lo0 "tcp port 80"

# 监听HTTPS流量
sudo go run main.go eth0 "tcp port 443"

# 监听特定IP的流量
sudo go run main.go eth0 "tcp and host 192.168.1.100"

# 从文件分析
go run main.go -f /path/to/capture.pcap
```

## 输出示例

### 启动信息
```
监听网络接口: lo0
BPF过滤器: tcp
不注册任何协议，所有TCP流都将被默认处理器处理
按 Ctrl+C 停止捕获
------------------------------------------------------------
```

### TCP流信息
```
[RAW] New unknown protocol stream: 127.0.0.1:12345 - 127.0.0.1:8080
[RAW] 127.0.0.1:12345 - 127.0.0.1:8080 [C->S] 64 bytes: 474554202f20485454502f312e310d0a486f73743a206c6f63616c686f73740d0a
[RAW] 127.0.0.1:12345 - 127.0.0.1:8080 [S->C] 156 bytes: 485454502f312e31203230302d4f4b0d0a436f6e74656e742d547970653a20746578742f68746d6c
[RAW] Stream 127.0.0.1:12345 - 127.0.0.1:8080 closed. Total: 3 packets, 220 bytes
```

### 统计信息
```
[15:04:05] 统计: 25 包, 5 TCP流, 0 错误, 5 未知协议流
[15:04:15] 统计: 47 包, 8 TCP流, 0 错误, 8 未知协议流
```

### 最终统计
```
------------------------------------------------------------
最终统计:
  处理的数据包: 156
  TCP流数量: 23
  错误数量: 0
  未知协议流: 23
捕获完成
```

## 配置说明

### 默认配置
- **网络接口**: `lo0` (本地回环接口)
- **BPF过滤器**: `tcp` (所有TCP流量)
- **捕获长度**: `65536` 字节
- **混杂模式**: `true` (实时抓包时)
- **超时时间**: `1` 秒 (pcap读取超时，影响数据包接收实时性)

### BPF过滤器示例

```bash
# 只捕获HTTP流量
"tcp port 80"

# 捕获HTTP和HTTPS流量
"tcp port 80 or tcp port 443"

# 捕获特定主机的流量
"tcp and host 192.168.1.100"

# 捕获特定端口范围
"tcp portrange 8000-8999"

# 组合条件
"tcp and (port 80 or port 443) and host 192.168.1.100"
```

## 输出格式说明

### 流标识格式
```
[RAW] 源IP:源端口 - 目标IP:目标端口 [方向] 字节数: 十六进制数据
```

### 方向标识
- `[C->S]`: 客户端到服务器
- `[S->C]`: 服务器到客户端

### 数据摘要
- 显示每个数据包的前32字节的十六进制表示
- 如果数据包小于32字节，显示全部内容
- 用于快速识别数据内容和协议类型

## 使用场景

1. **网络流量监控** - 监控网络中的TCP连接活动
2. **协议分析** - 分析未知协议的数据格式
3. **网络调试** - 调试TCP连接问题
4. **安全监控** - 检测异常的网络行为
5. **性能分析** - 分析网络流量模式
6. **学习工具** - 学习TCP协议和网络抓包

## 注意事项

1. **权限要求** - 实时抓包需要root权限
2. **性能影响** - 高流量环境下可能影响系统性能
3. **存储空间** - 长时间运行会产生大量输出
4. **网络接口** - 确保指定的网络接口存在且活跃
5. **BPF语法** - 使用正确的BPF过滤器语法
6. **实时性配置** - 超时时间设置为1秒，确保数据包能够实时处理而不会延迟

## 扩展建议

基于这个示例，你可以进行以下扩展：

1. **日志文件** - 将输出保存到文件
2. **数据统计** - 添加更详细的流量统计
3. **过滤功能** - 添加基于内容的过滤
4. **可视化** - 添加图形化的流量展示
5. **告警功能** - 添加异常流量告警
6. **数据导出** - 支持导出为不同格式

## 故障排除

### 常见问题

**Q: 提示权限不足？**
A: 网络抓包需要root权限，请使用`sudo`运行程序。

**Q: 找不到网络接口？**
A: 使用`ifconfig`或`ip link`命令查看可用的网络接口。

**Q: 没有输出？**
A: 检查BPF过滤器是否正确，或者尝试更宽松的过滤条件。

**Q: 输出太多？**
A: 使用更具体的BPF过滤器来限制捕获的流量。

**Q: 数据包接收有延迟？**
A: 检查超时配置，默认设置为30毫秒。如果仍有延迟，可以在main.go中将Timeout设置为更小的值（如10毫秒）。

**Q: 如何测试实时性？**
A: 运行 `sudo ./test_curl.sh` 脚本进行实时性测试。 