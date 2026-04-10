package metric

import (
	"github.com/wybroot/sentinel/internal/models"
	"github.com/wybroot/sentinel/internal/protocol"
)

// DiskSummary 磁盘汇总数据
type DiskSummary struct {
	UsagePercent float64 `json:"usagePercent"` // 平均使用率
	TotalDisks   int     `json:"totalDisks"`   // 磁盘数量
	Total        uint64  `json:"total"`        // 总容量(字节)
	Used         uint64  `json:"used"`         // 已使用(字节)
	Free         uint64  `json:"free"`         // 空闲(字节)
}

// NetworkSummary 网络汇总数据
type NetworkSummary struct {
	TotalBytesSentRate  uint64 `json:"totalBytesSentRate"`  // 总发送速率(字节/秒)
	TotalBytesRecvRate  uint64 `json:"totalBytesRecvRate"`  // 总接收速率(字节/秒)
	TotalBytesSentTotal uint64 `json:"totalBytesSentTotal"` // 累计总发送流量
	TotalBytesRecvTotal uint64 `json:"totalBytesRecvTotal"` // 累计总接收流量
	TotalInterfaces     int    `json:"totalInterfaces"`     // 网卡数量
}

// LatestMetrics 最新指标数据（用于API响应）
type LatestMetrics struct {
	CPU               *protocol.CPUData               `json:"cpu,omitempty"`
	Memory            *protocol.MemoryData            `json:"memory,omitempty"`
	Disk              *DiskSummary                    `json:"disk,omitempty"`
	Network           *NetworkSummary                 `json:"network,omitempty"`
	NetworkConnection *protocol.NetworkConnectionData `json:"networkConnection,omitempty"`
	Host              *models.HostMetric              `json:"host,omitempty"`
	GPU               []protocol.GPUData              `json:"gpu,omitempty"`
	Temp              []protocol.TemperatureData      `json:"temperature,omitempty"`
	Monitors          []protocol.MonitorData          `json:"monitors,omitempty"`
}
