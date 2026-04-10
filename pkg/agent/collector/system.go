package collector

import (
	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/shirou/gopsutil/v4/host"
)

// HostCollector 主机信息采集器
type HostCollector struct{}

// NewHostCollector 创建主机信息采集器
func NewHostCollector() *HostCollector {
	return &HostCollector{}
}

// Collect 采集主机信息（定期采集以检测主机名等变化）
func (h *HostCollector) Collect() (*protocol.HostInfoData, error) {
	hostInfo, err := host.Info()
	if err != nil {
		return nil, err
	}

	hostData := &protocol.HostInfoData{
		Hostname:        hostInfo.Hostname,
		Uptime:          hostInfo.Uptime,
		BootTime:        hostInfo.BootTime,
		Procs:           hostInfo.Procs,
		OS:              hostInfo.OS,
		Platform:        hostInfo.Platform,
		PlatformFamily:  hostInfo.PlatformFamily,
		PlatformVersion: hostInfo.PlatformVersion,
		KernelVersion:   hostInfo.KernelVersion,
		KernelArch:      hostInfo.KernelArch,
	}

	// 尝试获取虚拟化信息
	if hostInfo.VirtualizationSystem != "" {
		hostData.VirtualizationSystem = hostInfo.VirtualizationSystem
		hostData.VirtualizationRole = hostInfo.VirtualizationRole
	}

	return hostData, nil
}
