package collector

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	probing "github.com/prometheus-community/pro-bing"

	"github.com/wybroot/sentinel/internal/protocol"
)

// MonitorCollector 监控采集器
type MonitorCollector struct {
	httpClient *http.Client
}

// NewMonitorCollector 创建监控采集器
func NewMonitorCollector() *MonitorCollector {
	// 创建自定义的 HTTP 客户端，支持跳过 TLS 验证
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 允许自签名证书
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 限制重定向次数为 10
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	return &MonitorCollector{
		httpClient: httpClient,
	}
}

// Collect 采集所有监控项数据
func (c *MonitorCollector) Collect(items []protocol.MonitorItem) []protocol.MonitorData {
	if len(items) == 0 {
		return nil
	}

	results := make([]protocol.MonitorData, 0, len(items))

	for _, item := range items {
		var result protocol.MonitorData

		switch strings.ToLower(item.Type) {
		case "http", "https":
			result = c.checkHTTP(item)
		case "tcp":
			result = c.checkTCP(item)
		case "icmp", "ping":
			result = c.checkICMP(item)
		default:
			result = protocol.MonitorData{
				MonitorId: item.ID,
				Type:      item.Type,
				Target:    item.Target,
				Status:    "down",
				Error:     fmt.Sprintf("unsupported monitor type: %s", item.Type),
				CheckedAt: time.Now().UnixMilli(),
			}
		}

		results = append(results, result)
	}

	return results
}

// checkHTTP 检查 HTTP/HTTPS 服务
func (c *MonitorCollector) checkHTTP(item protocol.MonitorItem) protocol.MonitorData {
	result := protocol.MonitorData{
		MonitorId: item.ID,
		Type:      item.Type,
		Target:    item.Target,
		CheckedAt: time.Now().UnixMilli(),
	}

	// 获取配置，使用默认值
	httpCfg := item.HTTPConfig
	if httpCfg == nil {
		httpCfg = &protocol.HTTPMonitorConfig{
			Method:             "GET",
			ExpectedStatusCode: 200,
			Timeout:            60,
		}
	}

	// 设置默认值
	method := httpCfg.Method
	if method == "" {
		method = "GET"
	}

	timeout := httpCfg.Timeout
	if timeout <= 0 {
		timeout = 60
	}

	expectedStatus := httpCfg.ExpectedStatusCode
	if expectedStatus == 0 {
		expectedStatus = 200
	}

	// 创建请求
	var bodyReader io.Reader
	if httpCfg.Body != "" {
		bodyReader = strings.NewReader(httpCfg.Body)
	}

	// 为请求创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// 为请求添加上下文
	req, err := http.NewRequestWithContext(ctx, method, item.Target, bodyReader)
	if err != nil {
		result.Status = "down"
		result.Error = fmt.Sprintf("create request failed: %v", err)
		return result
	}

	// 设置请求头
	if httpCfg.Headers != nil {
		for key, value := range httpCfg.Headers {
			req.Header.Set(key, value)
		}
	}

	// 发送请求并计时
	startTime := time.Now()
	resp, err := c.httpClient.Do(req)
	responseTime := time.Since(startTime).Milliseconds()
	result.ResponseTime = responseTime

	if err != nil {
		result.Status = "down"
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// 检查状态码
	if resp.StatusCode != expectedStatus {
		result.Status = "down"
		result.Error = fmt.Sprintf("status code mismatch: expected %d, got %d", expectedStatus, resp.StatusCode)
		result.Message = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result
	}

	// 检查响应内容（如果有配置）
	if httpCfg.ExpectedContent != "" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			result.Status = "down"
			result.Error = fmt.Sprintf("read response body failed: %v", err)
			return result
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, httpCfg.ExpectedContent) {
			result.Status = "down"
			result.Error = fmt.Sprintf("content does not contain expected string: %s", httpCfg.ExpectedContent)
			result.ContentMatch = false
			return result
		}
		result.ContentMatch = true
	}

	// 获取 HTTPS 证书信息
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		// 获取第一个证书（服务器证书）
		cert := resp.TLS.PeerCertificates[0]

		// 证书过期时间
		expiryTime := cert.NotAfter
		result.CertExpiryTime = expiryTime.UnixMilli()

		// 计算剩余天数
		daysLeft := int(time.Until(expiryTime).Hours() / 24)
		result.CertDaysLeft = daysLeft
	}

	// 检查成功
	result.Status = "up"
	result.Message = fmt.Sprintf("HTTP %d - %dms", resp.StatusCode, responseTime)
	return result
}

// checkTCP 检查 TCP 端口
func (c *MonitorCollector) checkTCP(item protocol.MonitorItem) protocol.MonitorData {
	result := protocol.MonitorData{
		MonitorId: item.ID,
		Type:      item.Type,
		Target:    item.Target,
		CheckedAt: time.Now().UnixMilli(),
	}

	// 获取配置，使用默认值
	tcpCfg := item.TCPConfig
	timeout := 10 // 默认 10 秒
	if tcpCfg != nil && tcpCfg.Timeout > 0 {
		timeout = tcpCfg.Timeout
	}

	// 连接并计时
	startTime := time.Now()
	conn, err := net.DialTimeout("tcp", item.Target, time.Duration(timeout)*time.Second)
	responseTime := time.Since(startTime).Milliseconds()
	result.ResponseTime = responseTime

	if err != nil {
		result.Status = "down"
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()

	// 连接成功
	result.Status = "up"
	result.Message = fmt.Sprintf("TCP connected - %dms", responseTime)
	return result
}

// checkICMP 检查 ICMP (Ping)
func (c *MonitorCollector) checkICMP(item protocol.MonitorItem) protocol.MonitorData {
	result := protocol.MonitorData{
		MonitorId: item.ID,
		Type:      item.Type,
		Target:    item.Target,
		CheckedAt: time.Now().UnixMilli(),
	}

	// 获取配置，使用默认值
	icmpCfg := item.ICMPConfig
	timeout := 5 // 默认 5 秒
	count := 4   // 默认 Ping 4 次
	if icmpCfg != nil {
		if icmpCfg.Timeout > 0 {
			timeout = icmpCfg.Timeout
		}
		if icmpCfg.Count > 0 {
			count = icmpCfg.Count
		}
	}

	// 创建 Pinger
	pinger, err := probing.NewPinger(item.Target)
	if err != nil {
		result.Status = "down"
		result.Error = fmt.Sprintf("create pinger failed: %v", err)
		return result
	}

	// 配置 Pinger
	pinger.Count = count
	pinger.Timeout = time.Duration(timeout) * time.Second
	pinger.Interval = 100 * time.Millisecond

	// 尝试以非特权模式运行（使用 UDP）
	pinger.SetPrivileged(false)

	// 执行 Ping
	err = pinger.Run()
	if err != nil {
		// 如果非特权模式失败，尝试特权模式（需要 root 权限或 CAP_NET_RAW）
		pinger.SetPrivileged(true)
		err = pinger.Run()
		if err != nil {
			result.Status = "down"
			result.Error = fmt.Sprintf("ping failed: %v", err)
			return result
		}
	}

	// 获取统计信息
	stats := pinger.Statistics()

	// 检查是否有成功的包
	if stats.PacketsRecv > 0 {
		result.Status = "up"
		result.ResponseTime = stats.AvgRtt.Milliseconds()
		packetLoss := int(stats.PacketLoss)
		result.Message = fmt.Sprintf("ICMP Echo Reply - %d/%d packets, %dms avg, %d%% loss",
			stats.PacketsRecv, stats.PacketsSent, stats.AvgRtt.Milliseconds(), packetLoss)
	} else {
		result.Status = "down"
		result.Error = fmt.Sprintf("all %d ping attempts failed (timeout: %ds)", count, timeout)
		result.Message = "100% packet loss"
	}

	return result
}
