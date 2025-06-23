#!/bin/bash

# 测试curl请求的实时捕获脚本

echo "=== Raw TCP Dumper 实时性测试 ==="
echo

# 检查是否有root权限
if [ "$EUID" -ne 0 ]; then
    echo "错误: 需要root权限运行网络抓包"
    echo "请使用: sudo $0"
    exit 1
fi

# 编译程序
echo "1. 编译rawtcpdumper..."
go build -o rawtcpdumper main.go default.go
if [ $? -ne 0 ]; then
    echo "编译失败"
    exit 1
fi

echo "2. 启动rawtcpdumper (监听lo0接口的HTTP流量)..."
echo "   注意观察数据包接收的时间戳"
echo

# 在后台启动rawtcpdumper
./rawtcpdumper lo0 "tcp port 80" &
DUMPER_PID=$!

# 等待dumper启动
sleep 2

echo "3. 发送curl请求测试..."
echo "   时间戳: $(date '+%H:%M:%S')"

# 启动一个简单的HTTP服务器
python3 -m http.server 8080 > /dev/null 2>&1 &
SERVER_PID=$!

sleep 1

# 发送HTTP请求
echo "   发送GET请求到 http://localhost:8080"
curl -s http://localhost:8080 > /dev/null

echo "   请求完成时间: $(date '+%H:%M:%S')"
echo

echo "4. 等待5秒观察输出..."
sleep 5

echo "5. 清理进程..."
kill $DUMPER_PID 2>/dev/null
kill $SERVER_PID 2>/dev/null

echo
echo "=== 测试完成 ==="
echo "如果看到数据包输出的时间戳与curl请求时间相近，说明延迟问题已解决" 