package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LubyRuffy/tcpdumper"
	"github.com/google/gopacket/reassembly"
)

// HTTPProcessor HTTP协议处理器实现
type HTTPProcessor struct {
	ident     string
	isConnect bool

	mutex    sync.Mutex
	requests []*http.Request // 请求列表
	reqIndex int             // 当前读取的偏移

	requestBuf  *bytes.Buffer
	responseBuf *bytes.Buffer
}

func (hp *HTTPProcessor) appendRequest(req *http.Request) {
	hp.mutex.Lock()
	defer hp.mutex.Unlock()
	hp.requests = append(hp.requests, req)
}

func (hp *HTTPProcessor) getLastRequest() *http.Request {
	hp.mutex.Lock()
	defer hp.mutex.Unlock()

	// 收到了response但是还没有request
	if len(hp.requests) < hp.reqIndex+1 {
		return nil
	}

	req := hp.requests[hp.reqIndex]
	hp.reqIndex++
	return req
}

func (hp *HTTPProcessor) ProcessData(data []byte, dir reassembly.TCPFlowDirection, start, end bool) error {
	dataStr := string(data)

	// 检查是否是CONNECT方法
	if dir == reassembly.TCPDirClientToServer && strings.HasPrefix(dataStr, "CONNECT ") {
		hp.isConnect = true
		fmt.Printf("HTTP/%s [%s]: CONNECT method detected, switching to tunnel mode\n", hp.ident, dir)
		return nil
	}

	// 如果是CONNECT模式，跳过HTTP解析
	if hp.isConnect {
		fmt.Printf("HTTP/%s [%s]: Tunnel data (%d bytes)\n", hp.ident, dir, len(data))
		return nil
	}

	// 正常HTTP处理
	if dir == reassembly.TCPDirClientToServer {
		hp.mutex.Lock()
		hp.requestBuf.Write(data)
		hp.mutex.Unlock()
	} else {
		hp.mutex.Lock()
		hp.responseBuf.Write(data)
		hp.mutex.Unlock()
	}

	return nil
}

func (hp *HTTPProcessor) Close() error {
	fmt.Printf("HTTP/%s: Connection closed\n", hp.ident)
	return nil
}

func (hp *HTTPProcessor) GetProtocolName() string {
	return "HTTP"
}

func (hp *HTTPProcessor) Run() {
	go func() {
		buf := bufio.NewReader(hp.requestBuf)
		for {
			_, err := buf.Peek(1)
			if err != nil {
				return
			}

			req, err := http.ReadRequest(buf)
			if err != nil {
				log.Println("ReadRequest error:", err)
				return
			}
			io.Copy(io.Discard, req.Body)
			req.Body.Close()

			hp.appendRequest(req)
			fmt.Println(req)
		}
	}()

	go func() {
		buf := bufio.NewReader(hp.responseBuf)
		for {
			_, err := buf.Peek(1)
			if err != nil {
				return
			}

			req := hp.getLastRequest()

			resp, err := http.ReadResponse(buf, req)
			if err != nil {
				log.Println("ReadResponse error:", err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			fmt.Println(resp)
		}
	}()
}

// HTTPDetector HTTP协议检测器
type HTTPDetector struct{}

func (hd *HTTPDetector) Detect(data []byte, dir reassembly.TCPFlowDirection) int {
	if len(data) < 4 {
		return 0
	}

	dataStr := string(data)

	if dir == reassembly.TCPDirClientToServer {
		// 检测HTTP请求
		httpMethods := []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "TRAC"}
		for _, method := range httpMethods {
			if strings.HasPrefix(dataStr, method) {
				return 90
			}
		}

		// 检测CONNECT方法但返回较低置信度（特殊处理）
		if strings.HasPrefix(dataStr, "CONNECT ") {
			return 85
		}
	} else {
		// 检测HTTP响应
		if strings.HasPrefix(dataStr, "HTTP/1.") || strings.HasPrefix(dataStr, "HTTP/2") {
			return 90
		}
	}

	return 0
}

func (hd *HTTPDetector) Name() string {
	return "HTTP"
}

func (hd *HTTPDetector) CreateProcessor(streamInfo tcpdumper.StreamInfo) tcpdumper.ProtocolProcessor {
	hp := &HTTPProcessor{
		ident:       streamInfo.Ident,
		requestBuf:  &bytes.Buffer{},
		responseBuf: &bytes.Buffer{},
	}
	hp.Run()
	return hp
}

func main() {
	// 创建TCP捕获器
	options := &tcpdumper.CaptureOptions{
		Interface: "lo0",
		BPFFilter: "tcp port 1234",
		SnapLen:   1024,
	}
	dumper := tcpdumper.NewDumper(options)

	// 注册HTTP协议检测器
	dumper.RegisterProtocolDetector(&HTTPDetector{})

	// 显示已注册的协议
	protocols := dumper.GetRegisteredProtocols()
	fmt.Printf("已注册协议: %v\n", protocols)

	// 启动捕获
	fmt.Println("启动HTTP流量捕获...")
	err := dumper.Start()
	if err != nil {
		log.Fatal(err)
	}
	defer dumper.Stop()

	// 运行30秒
	fmt.Println("捕获HTTP流量中... (30秒)")
	time.Sleep(30 * time.Second)

	// 获取统计信息
	packets, streams, errors, unknownFlows := dumper.GetStats()
	fmt.Printf("统计信息: %d 个数据包, %d 个TCP流, %d 个错误, %d 个未知协议流\n",
		packets, streams, errors, unknownFlows)
}
