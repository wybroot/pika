package collector

import (
	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/shirou/gopsutil/v4/mem"
)

// MemoryCollector 内存监控采集器
type MemoryCollector struct {
}

// NewMemoryCollector 创建内存采集器
func NewMemoryCollector() *MemoryCollector {
	return &MemoryCollector{}
}

// Collect 采集内存数据(返回完整数据,包括静态和动态信息)
func (m *MemoryCollector) Collect() (*protocol.MemoryData, error) {
	// 获取虚拟内存信息
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	memData := &protocol.MemoryData{
		Total:        vmStat.Total,
		Used:         vmStat.Used,
		Free:         vmStat.Free,
		Available:    vmStat.Available,
		UsagePercent: vmStat.UsedPercent,
	}

	// 尝试获取更详细的内存信息(Linux 特有)
	if vmStat.Cached > 0 {
		memData.Cached = vmStat.Cached
	}
	if vmStat.Buffers > 0 {
		memData.Buffers = vmStat.Buffers
	}

	// 获取 Swap 信息
	swapStat, err := mem.SwapMemory()
	if err == nil {
		memData.SwapTotal = swapStat.Total
		memData.SwapUsed = swapStat.Used
		memData.SwapFree = swapStat.Free
	}

	return memData, nil
}
