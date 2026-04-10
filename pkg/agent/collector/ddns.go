package collector

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/wybroot/sentinel/internal/protocol"
)

// 默认 IPv4 API 列表
var defaultIPv4APIs = []string{
	"https://myip.ipip.net",
	"https://ddns.oray.com/checkip",
	"https://ip.3322.net",
	"https://4.ipw.cn",
	"https://v4.yinghualuo.cn/bejson",
}

// 默认 IPv6 API 列表
var defaultIPv6APIs = []string{
	"https://speed.neu6.edu.cn/getIP.php",
	"https://v6.ident.me",
	"https://6.ipw.cn",
	"https://v6.yinghualuo.cn/bejson",
}

// IPv4 正则表达式
var ipv4Regex = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// IPv6 正则表达式
var ipv6Regex = regexp.MustCompile(`([0-9a-fA-F:]+:+[0-9a-fA-F:]+)`)

// DDNSCollector DDNS IP 地址采集器
type DDNSCollector struct {
	config *protocol.DDNSConfigData
}

// NewDDNSCollector 创建 DDNS 采集器
func NewDDNSCollector(config *protocol.DDNSConfigData) *DDNSCollector {
	return &DDNSCollector{
		config: config,
	}
}

// UpdateConfig 更新配置
func (d *DDNSCollector) UpdateConfig(config *protocol.DDNSConfigData) {
	d.config = config
}

// Collect 采集 IP 地址
func (d *DDNSCollector) Collect() (*protocol.DDNSIPReportData, error) {
	if d.config == nil || !d.config.Enabled {
		return nil, fmt.Errorf("DDNS 未启用")
	}

	data := &protocol.DDNSIPReportData{}

	// 采集 IPv4
	if d.config.EnableIPv4 {
		ipv4, err := d.getIP(d.config.IPv4GetMethod, d.config.IPv4GetValue, false)
		if err == nil && ipv4 != "" {
			data.IPv4 = ipv4
		}
	}

	// 采集 IPv6
	if d.config.EnableIPv6 {
		ipv6, err := d.getIP(d.config.IPv6GetMethod, d.config.IPv6GetValue, true)
		if err == nil && ipv6 != "" {
			data.IPv6 = ipv6
		}
	}

	return data, nil
}

// getIP 根据配置获取 IP 地址
func (d *DDNSCollector) getIP(method, value string, isIPv6 bool) (string, error) {
	switch method {
	case "api":
		return d.GetIPFromAPI(value, isIPv6)
	case "interface":
		return d.GetIPFromInterface(value, isIPv6)
	default:
		return "", fmt.Errorf("不支持的获取方式: %s", method)
	}
}

// GetIPFromAPI 通过 API 获取 IP 地址（支持轮询多个 API）
func (d *DDNSCollector) GetIPFromAPI(apiURL string, isIPv6 bool) (string, error) {
	var apiList []string

	if apiURL == "" {
		// 使用默认 API 列表
		if isIPv6 {
			apiList = defaultIPv6APIs
		} else {
			apiList = defaultIPv4APIs
		}
	} else {
		// 使用指定的 API
		apiList = []string{apiURL}
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var lastErr error
	// 轮询 API 列表，直到成功获取 IP
	for _, api := range apiList {
		ip, err := d.fetchIPFromAPI(client, api, isIPv6)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return "", fmt.Errorf("所有 API 请求均失败，最后错误: %w", lastErr)
	}
	return "", fmt.Errorf("未能获取 IP 地址")
}

// fetchIPFromAPI 从单个 API 获取 IP 地址
func (d *DDNSCollector) fetchIPFromAPI(client *http.Client, apiURL string, isIPv6 bool) (string, error) {
	resp, err := client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API 返回错误状态: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	// 使用正则表达式提取 IP 地址
	var regex *regexp.Regexp
	if isIPv6 {
		regex = ipv6Regex
	} else {
		regex = ipv4Regex
	}

	matches := regex.FindStringSubmatch(string(body))
	if len(matches) < 2 {
		return "", fmt.Errorf("响应中未找到有效的 IP 地址: %s", string(body))
	}

	ip := strings.TrimSpace(matches[1])

	// 验证 IP 格式
	if !isValidIP(ip, isIPv6) {
		return "", fmt.Errorf("无效的 IP 地址: %s", ip)
	}

	return ip, nil
}

// GetIPFromInterface 从网卡获取 IP 地址
func (d *DDNSCollector) GetIPFromInterface(interfaceName string, isIPv6 bool) (string, error) {
	if interfaceName == "" {
		return "", fmt.Errorf("网卡名称不能为空")
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return "", fmt.Errorf("获取网卡失败: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("获取网卡地址失败: %w", err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}

		ip := ipNet.IP
		// 过滤本地回环地址
		if ip.IsLoopback() {
			continue
		}

		// 根据 IPv4/IPv6 筛选
		if isIPv6 {
			if ip.To4() == nil && ip.To16() != nil {
				// 过滤链路本地地址
				if !ip.IsLinkLocalUnicast() {
					return ip.String(), nil
				}
			}
		} else {
			if ip.To4() != nil {
				return ip.String(), nil
			}
		}
	}

	return "", fmt.Errorf("未找到符合条件的 IP 地址")
}

// isValidIP 验证 IP 地址格式
func isValidIP(ipStr string, isIPv6 bool) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	if isIPv6 {
		return ip.To4() == nil && ip.To16() != nil
	}
	return ip.To4() != nil
}
