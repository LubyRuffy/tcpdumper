# DNS协议处理器示例

这个示例展示了如何使用TCPDumper库创建一个DNS over TCP协议处理器。

## 功能特性

- 检测DNS over TCP消息
- 解析DNS消息长度前缀
- 验证DNS头部格式的合理性
- 支持DNS查询和响应的处理

## 运行示例

```bash
# 进入示例目录
cd examples/dnsdumper

# 运行示例（需要root权限进行网络抓包）
sudo go run main.go
```

## 配置说明

示例程序配置为：
- 监听本地回环接口 `lo0`
- 过滤TCP端口 53 的流量（DNS标准端口）
- 捕获数据包大小限制为1024字节

你可以修改 `main.go` 中的配置来适应你的需求：

```go
options := &tcpdumper.CaptureOptions{
    Interface: "eth0",       // 修改为你的网络接口
    BPFFilter: "tcp port 53", // 保持DNS端口过滤
    SnapLen:   1024,         // 修改捕获长度
}
```

## 协议检测逻辑

DNS协议检测器使用以下规则：

### DNS over TCP格式检查
1. **最小长度检查**：数据至少12字节（DNS头部长度）
2. **长度前缀验证**：
   - 前2字节表示DNS消息长度
   - 消息长度应在合理范围内（1-512字节）
   - 实际数据长度应匹配声明的长度
3. **DNS头部验证**：
   - 检查DNS头部的flags字段格式
   - 验证QR位（查询/响应标志）
4. **置信度**：80

## DNS over TCP格式说明

DNS over TCP与DNS over UDP的主要区别：
- TCP版本在DNS消息前添加2字节的长度前缀
- 格式：`[2字节长度][DNS消息]`
- 长度字段采用网络字节序（大端序）

## 输出示例

```
已注册协议: [DNS]
启动DNS over TCP流量捕获...
捕获DNS流量中... (30秒)
DNS/192.168.1.100:12345 - 8.8.8.8:53 [C->S]: DNS message (45 bytes)
DNS/192.168.1.100:12345 - 8.8.8.8:53 [S->C]: DNS message (61 bytes)
DNS/192.168.1.100:12345 - 8.8.8.8:53: Connection closed
统计信息: 8 个数据包, 1 个TCP流, 0 个错误, 0 个未知协议流
```

## 使用场景

DNS over TCP通常在以下情况下使用：
1. **大型DNS响应**：当DNS响应超过UDP数据包大小限制时
2. **DNS安全**：某些DNS安全机制要求使用TCP
3. **防火墙环境**：某些网络环境只允许TCP连接
4. **DNS隧道**：恶意软件可能使用DNS over TCP进行数据传输

## 扩展说明

你可以基于这个示例进行扩展：

1. **完整DNS解析**：解析DNS查询类型、域名、响应记录等
2. **DNS安全检测**：检测异常的DNS请求模式
3. **DNS隧道检测**：识别可能的DNS隧道行为
4. **性能监控**：监控DNS查询的响应时间和成功率
5. **日志记录**：将DNS查询记录保存到日志文件

## 注意事项

- DNS over TCP相对较少见，大多数DNS查询使用UDP
- 如果要监控所有DNS流量，建议同时监控UDP端口53
- 某些DNS服务器可能不支持TCP连接 