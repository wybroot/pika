package collector

import (
	"runtime"
	"sync"
	"time"

	"github.com/wybroot/sentinel/internal/protocol"

	"github.com/shirou/gopsutil/v4/cpu"
)

// CPUCollector CPU 监控采集器
type CPUCollector struct {
	// 缓存不常变化的信息
	logicalCores  int
	physicalCores int
	modelName     string
	initOnce      sync.Once
}

// NewCPUCollector 创建 CPU 采集器
func NewCPUCollector() *CPUCollector {
	return &CPUCollector{}
}

// init 初始化缓存数据(只执行一次)
func (c *CPUCollector) init() {
	c.initOnce.Do(func() {
		// 获取逻辑核心数
		logicalCores, err := cpu.Counts(true)
		if err != nil {
			logicalCores = runtime.NumCPU()
		}
		c.logicalCores = logicalCores

		// 获取物理核心数
		physicalCores, err := cpu.Counts(false)
		if err != nil {
			physicalCores = logicalCores / 2 // 粗略估算
		}
		c.physicalCores = physicalCores

		// 获取 CPU 信息
		cpuInfos, err := cpu.Info()
		if err == nil && len(cpuInfos) > 0 {
			c.modelName = cpuInfos[0].ModelName
		}
	})
}

// Collect 采集 CPU 数据(返回完整数据,包括静态和动态信息)
func (c *CPUCollector) Collect() (*protocol.CPUData, error) {
	c.init()

	// 获取 CPU 总体使用率
	percentages, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}

	cpuPercent := 0.0
	if len(percentages) > 0 {
		cpuPercent = percentages[0]
	}

	return &protocol.CPUData{
		LogicalCores:  c.logicalCores,
		PhysicalCores: c.physicalCores,
		ModelName:     c.modelName,
		UsagePercent:  cpuPercent,
	}, nil
}
