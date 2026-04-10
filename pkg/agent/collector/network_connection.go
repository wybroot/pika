package collector

import (
	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/shirou/gopsutil/v4/net"
)

// NetworkConnectionCollector 网络连接统计采集器
type NetworkConnectionCollector struct {
}

// NewNetworkConnectionCollector 创建网络连接统计采集器
func NewNetworkConnectionCollector() *NetworkConnectionCollector {
	return &NetworkConnectionCollector{}
}

// Collect 采集网络连接统计数据
func (n *NetworkConnectionCollector) Collect() (*protocol.NetworkConnectionData, error) {
	// 获取所有网络连接
	connections, err := net.Connections("all")
	if err != nil {
		return nil, err
	}

	// 统计各状态的连接数
	data := &protocol.NetworkConnectionData{}
	for _, conn := range connections {
		data.Total++
		switch conn.Status {
		case "ESTABLISHED":
			data.Established++
		case "SYN_SENT":
			data.SynSent++
		case "SYN_RECV":
			data.SynRecv++
		case "FIN_WAIT1":
			data.FinWait1++
		case "FIN_WAIT2":
			data.FinWait2++
		case "TIME_WAIT":
			data.TimeWait++
		case "CLOSE":
			data.Close++
		case "CLOSE_WAIT":
			data.CloseWait++
		case "LAST_ACK":
			data.LastAck++
		case "LISTEN":
			data.Listen++
		case "CLOSING":
			data.Closing++
		}
	}

	return data, nil
}
