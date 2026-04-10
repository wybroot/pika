package collector

import (
	"time"

	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/shirou/gopsutil/v4/disk"
)

// DiskIOCollector 磁盘 IO 监控采集器
type DiskIOCollector struct {
}

// NewDiskIOCollector 创建磁盘 IO 采集器
func NewDiskIOCollector() *DiskIOCollector {
	return &DiskIOCollector{}
}

// Collect 采集磁盘 IO 数据(间隔1秒采集两次计算速率)
func (d *DiskIOCollector) Collect() ([]protocol.DiskIOData, error) {
	// 第一次采集
	firstCounters, err := d.collectOnce()
	if err != nil {
		return nil, err
	}

	// 间隔1秒
	time.Sleep(1 * time.Second)

	// 第二次采集
	secondCounters, err := d.collectOnce()
	if err != nil {
		return nil, err
	}

	// 创建第一次采集的统计数据映射
	firstStatsMap := make(map[string]disk.IOCountersStat)
	for device, counter := range firstCounters {
		firstStatsMap[device] = counter
	}

	// 计算速率(基于两次采集的差值)
	var diskIODataList []protocol.DiskIOData
	for device, counter := range secondCounters {
		diskIOData := protocol.DiskIOData{
			Device:         device,
			ReadCount:      counter.ReadCount,
			WriteCount:     counter.WriteCount,
			ReadBytes:      counter.ReadBytes,
			WriteBytes:     counter.WriteBytes,
			ReadTime:       counter.ReadTime,
			WriteTime:      counter.WriteTime,
			IoTime:         counter.IoTime,
			IopsInProgress: counter.IopsInProgress,
		}

		// 计算速率(如果第一次采集有数据)
		if firstStat, exists := firstStatsMap[device]; exists {
			readBytesDelta := safeDelta(counter.ReadBytes, firstStat.ReadBytes)
			writeBytesDelta := safeDelta(counter.WriteBytes, firstStat.WriteBytes)
			// 间隔固定为1秒
			diskIOData.ReadBytesRate = readBytesDelta
			diskIOData.WriteBytesRate = writeBytesDelta
		} else {
			// 如果第一次采集没有该设备数据,速率为0
			diskIOData.ReadBytesRate = 0
			diskIOData.WriteBytesRate = 0
		}

		diskIODataList = append(diskIODataList, diskIOData)
	}

	return diskIODataList, nil
}

// collectOnce 执行一次磁盘 IO 数据采集
func (d *DiskIOCollector) collectOnce() (map[string]disk.IOCountersStat, error) {
	ioCounters, err := disk.IOCounters()
	if err != nil {
		return nil, err
	}
	return ioCounters, nil
}
