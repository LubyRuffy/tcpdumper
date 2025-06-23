# HTTP协议处理器示例

这个示例展示了如何使用TCPDumper库创建一个HTTP协议处理器。

## 功能特性

- 检测HTTP请求和响应
- 支持所有标准HTTP方法（GET, POST, PUT, HEAD, DELETE, PATCH, OPTIONS, TRACE）
- 特殊处理CONNECT方法（代理隧道模式）
- 方向敏感的协议检测（区分客户端请求和服务器响应）

## 运行示例

```bash
# 进入示例目录
cd examples/httpdumper

# 运行示例（需要root权限进行网络抓包）
sudo go run main.go
```

## 配置说明

示例程序配置为：
- 监听本地回环接口 `lo0`
- 过滤TCP端口 80、443、8080 的流量
- 捕获数据包大小限制为1024字节

你可以修改 `main.go` 中的配置来适应你的需求：

```go
options := &tcpdumper.CaptureOptions{
    Interface: "eth0",        // 修改为你的网络接口
    BPFFilter: "tcp port 80", // 修改BPF过滤器
    SnapLen:   1024,          // 修改捕获长度
}
```

## 协议检测逻辑

HTTP协议检测器使用以下规则：

### 客户端到服务器（请求）
- 检测标准HTTP方法前缀：`GET `, `POST`, `PUT `, `HEAD`, `DELE`, `PATC`, `OPTI`, `TRAC`
- 置信度：90
- 特殊处理：`CONNECT ` 方法置信度为85

### 服务器到客户端（响应）
- 检测HTTP响应前缀：`HTTP/1.`, `HTTP/2`
- 置信度：90

## 输出示例

```
已注册协议: [HTTP]
启动HTTP流量捕获...
捕获HTTP流量中... (30秒)
HTTP/192.168.1.100:12345 - 192.168.1.200:80 [C->S]: GET / HTTP/1.1
HTTP/192.168.1.100:12345 - 192.168.1.200:80 [S->C]: HTTP/1.1 200 OK
HTTP/192.168.1.100:12345 - 192.168.1.200:80: Connection closed
统计信息: 15 个数据包, 3 个TCP流, 0 个错误, 0 个未知协议流
```

## 扩展说明

你可以基于这个示例进行扩展：

1. **增强HTTP解析**：解析HTTP头部、请求体等详细信息
2. **添加HTTPS支持**：处理TLS握手后的HTTP/2流量
3. **性能优化**：对于高流量场景进行优化
4. **日志记录**：将HTTP流量保存到文件或数据库
5. **统计分析**：收集HTTP请求的统计信息 