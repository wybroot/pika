package models

import (
	"context"
	"fmt"
	"log"

	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/wybroot/sentinel/internal/vmclient"
	"gorm.io/gorm"
)

const (
	// 每批处理的数据量
	batchSize = 1000
)

// Migrate 执行数据迁移：将 PostgreSQL 中的历史指标数据迁移到 VictoriaMetrics
func Migrate(db *gorm.DB, client *vmclient.VMClient) error {
	ctx := context.Background()
	log.Println("开始迁移历史指标数据到 VictoriaMetrics...")

	// 迁移各类型的指标数据
	migrationTasks := []struct {
		name        string
		tableName   string
		migrateFunc func(context.Context, *gorm.DB, *vmclient.VMClient) error
	}{
		{"CPU指标", "cpu_metrics", migrateCPUMetrics},
		{"内存指标", "memory_metrics", migrateMemoryMetrics},
		{"磁盘指标", "disk_metrics", migrateDiskMetrics},
		{"网络指标", "network_metrics", migrateNetworkMetrics},
		{"网络连接指标", "network_connection_metrics", migrateNetworkConnectionMetrics},
		{"磁盘IO指标", "disk_io_metrics", migrateDiskIOMetrics},
		{"GPU指标", "gpu_metrics", migrateGPUMetrics},
		{"温度指标", "temperature_metrics", migrateTemperatureMetrics},
		{"监控指标", "monitor_metrics", migrateMonitorMetrics},
	}

	var errors []string
	for _, task := range migrationTasks {
		log.Printf("开始迁移 %s...", task.name)
		if err := task.migrateFunc(ctx, db, client); err != nil {
			errMsg := fmt.Sprintf("迁移 %s 失败: %v", task.name, err)
			log.Println(errMsg)
			errors = append(errors, errMsg)
			continue // 继续迁移其他类型的数据
		}
		log.Printf("✓ %s 迁移完成", task.name)
	}

	if len(errors) > 0 {
		log.Printf("迁移过程中遇到 %d 个错误，但已尽可能完成迁移", len(errors))
		return fmt.Errorf("迁移过程中遇到 %d 个错误", len(errors))
	}

	log.Println("✓ 数据迁移完成！")
	return nil
}

// migrateCPUMetrics 迁移CPU指标
func migrateCPUMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&CPUMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有CPU数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条CPU记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []CPUMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		var vmMetrics []vmclient.Metric
		for _, m := range metrics {
			cpuData := &protocol.CPUData{
				UsagePercent:  m.UsagePercent,
				LogicalCores:  m.LogicalCores,
				PhysicalCores: m.PhysicalCores,
				ModelName:     m.ModelName,
			}

			converted := convertToMetrics(m.AgentID, string(protocol.MetricTypeCPU), cpuData, m.Timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		// 批量写入 VictoriaMetrics
		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入CPU数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		// 打印进度
		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateMemoryMetrics 迁移内存指标
func migrateMemoryMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&MemoryMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有内存数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条内存记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []MemoryMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		var vmMetrics []vmclient.Metric
		for _, m := range metrics {
			memData := &protocol.MemoryData{
				Total:        m.Total,
				Used:         m.Used,
				Free:         m.Free,
				Available:    m.Available,
				UsagePercent: m.UsagePercent,
				SwapTotal:    m.SwapTotal,
				SwapUsed:     m.SwapUsed,
				SwapFree:     m.SwapFree,
			}

			converted := convertToMetrics(m.AgentID, string(protocol.MetricTypeMemory), memData, m.Timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入内存数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateDiskMetrics 迁移磁盘指标
func migrateDiskMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&DiskMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有磁盘数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条磁盘记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []DiskMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]protocol.DiskData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentID, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], protocol.DiskData{
				MountPoint:   m.MountPoint,
				Total:        m.Total,
				Used:         m.Used,
				Free:         m.Free,
				UsagePercent: m.UsagePercent,
			})
		}

		var vmMetrics []vmclient.Metric
		for key, diskDataList := range groupedMetrics {
			// 从 key 中提取 agentID 和 timestamp
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeDisk), diskDataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入磁盘数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateNetworkMetrics 迁移网络指标
func migrateNetworkMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&NetworkMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有网络数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条网络记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []NetworkMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]protocol.NetworkData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentID, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], protocol.NetworkData{
				Interface:      m.Interface,
				BytesSentRate:  m.BytesSentRate,
				BytesRecvRate:  m.BytesRecvRate,
				BytesSentTotal: m.BytesSentTotal,
				BytesRecvTotal: m.BytesRecvTotal,
			})
		}

		var vmMetrics []vmclient.Metric
		for key, netDataList := range groupedMetrics {
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeNetwork), netDataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入网络数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateNetworkConnectionMetrics 迁移网络连接指标
func migrateNetworkConnectionMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&NetworkConnectionMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有网络连接数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条网络连接记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []NetworkConnectionMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		var vmMetrics []vmclient.Metric
		for _, m := range metrics {
			connData := &protocol.NetworkConnectionData{
				Established: m.Established,
				SynSent:     m.SynSent,
				SynRecv:     m.SynRecv,
				TimeWait:    m.TimeWait,
				CloseWait:   m.CloseWait,
				Total:       m.Total,
			}

			converted := convertToMetrics(m.AgentID, string(protocol.MetricTypeNetworkConnection), connData, m.Timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入网络连接数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateDiskIOMetrics 迁移磁盘IO指标
func migrateDiskIOMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&DiskIOMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有磁盘IO数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条磁盘IO记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []DiskIOMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]*protocol.DiskIOData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentID, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], &protocol.DiskIOData{
				Device:         m.Device,
				ReadCount:      m.ReadCount,
				WriteCount:     m.WriteCount,
				ReadBytes:      m.ReadBytes,
				WriteBytes:     m.WriteBytes,
				ReadBytesRate:  m.ReadBytesRate,
				WriteBytesRate: m.WriteBytesRate,
				ReadTime:       m.ReadTime,
				WriteTime:      m.WriteTime,
				IoTime:         m.IoTime,
				IopsInProgress: m.IopsInProgress,
			})
		}

		var vmMetrics []vmclient.Metric
		for key, diskIODataList := range groupedMetrics {
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeDiskIO), diskIODataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入磁盘IO数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateGPUMetrics 迁移GPU指标
func migrateGPUMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&GPUMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有GPU数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条GPU记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []GPUMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]protocol.GPUData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentID, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], protocol.GPUData{
				Index:       m.Index,
				Name:        m.Name,
				Utilization: m.Utilization,
				MemoryTotal: m.MemoryTotal,
				MemoryUsed:  m.MemoryUsed,
				MemoryFree:  m.MemoryFree,
				Temperature: m.Temperature,
				PowerUsage:  m.PowerDraw,
				FanSpeed:    m.FanSpeed,
			})
		}

		var vmMetrics []vmclient.Metric
		for key, gpuDataList := range groupedMetrics {
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeGPU), gpuDataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入GPU数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateTemperatureMetrics 迁移温度指标
func migrateTemperatureMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&TemperatureMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有温度数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条温度记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []TemperatureMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]protocol.TemperatureData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentID, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], protocol.TemperatureData{
				SensorKey:   m.SensorKey,
				Temperature: m.Temperature,
				Type:        m.SensorLabel,
			})
		}

		var vmMetrics []vmclient.Metric
		for key, tempDataList := range groupedMetrics {
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeTemperature), tempDataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入温度数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// migrateMonitorMetrics 迁移监控指标
func migrateMonitorMetrics(ctx context.Context, db *gorm.DB, client *vmclient.VMClient) error {
	var totalCount int64
	if err := db.Model(&MonitorMetric{}).Count(&totalCount).Error; err != nil {
		return err
	}

	if totalCount == 0 {
		log.Println("  没有监控数据需要迁移")
		return nil
	}

	log.Printf("  找到 %d 条监控记录", totalCount)

	offset := 0
	migratedCount := 0

	for {
		var metrics []MonitorMetric
		if err := db.Offset(offset).Limit(batchSize).Order("timestamp ASC").Find(&metrics).Error; err != nil {
			return err
		}

		if len(metrics) == 0 {
			break
		}

		// 按 agent_id + timestamp 分组
		groupedMetrics := make(map[string][]protocol.MonitorData)
		for _, m := range metrics {
			key := fmt.Sprintf("%s_%d", m.AgentId, m.Timestamp)
			groupedMetrics[key] = append(groupedMetrics[key], protocol.MonitorData{
				AgentId:        m.AgentId,
				MonitorId:      m.MonitorId,
				Type:           m.Type,
				Target:         m.Target,
				Status:         m.Status,
				StatusCode:     m.StatusCode,
				ResponseTime:   m.ResponseTime,
				Error:          m.Error,
				Message:        m.Message,
				ContentMatch:   m.ContentMatch,
				CertExpiryTime: m.CertExpiryTime,
				CertDaysLeft:   m.CertDaysLeft,
				CheckedAt:      m.Timestamp, // 使用 timestamp 作为 CheckedAt
			})
		}

		var vmMetrics []vmclient.Metric
		for key, monitorDataList := range groupedMetrics {
			var agentID string
			var timestamp int64
			fmt.Sscanf(key, "%s_%d", &agentID, &timestamp)

			converted := convertToMetrics(agentID, string(protocol.MetricTypeMonitor), monitorDataList, timestamp)
			vmMetrics = append(vmMetrics, converted...)
		}

		if err := client.Write(ctx, vmMetrics); err != nil {
			log.Printf("  警告: 写入监控数据失败 (offset=%d): %v", offset, err)
		}

		migratedCount += len(metrics)
		offset += batchSize

		if migratedCount%10000 == 0 || migratedCount == int(totalCount) {
			log.Printf("  进度: %d/%d (%.1f%%)", migratedCount, totalCount, float64(migratedCount)/float64(totalCount)*100)
		}
	}

	return nil
}

// DropOldTables 删除旧的指标数据表
func DropOldTables(db *gorm.DB) error {
	// 要删除的表列表（除了 host_metrics，它仍然需要保留）
	tables := []string{
		"cpu_metrics",
		"memory_metrics",
		"disk_metrics",
		"network_metrics",
		"network_connection_metrics",
		"disk_io_metrics",
		"gpu_metrics",
		"temperature_metrics",
		"monitor_metrics",
		// 聚合表也删除
		"cpu_metrics_aggs",
		"memory_metrics_aggs",
		"disk_metrics_aggs",
		"network_metrics_aggs",
		"network_connection_metrics_aggs",
		"disk_io_metrics_aggs",
		"gpu_metrics_aggs",
		"temperature_metrics_aggs",
		"monitor_metrics_aggs",
		"aggregation_progress",
		// 统计表
		"monitor_stats",
	}

	for _, table := range tables {
		// 检查表是否存在
		if !db.Migrator().HasTable(table) {
			log.Printf("  表 %s 不存在，跳过", table)
			continue
		}

		log.Printf("  删除表: %s", table)
		if err := db.Migrator().DropTable(table); err != nil {
			log.Printf("  警告: 删除表 %s 失败: %v", table, err)
			continue
		}
	}

	return nil
}

// convertToMetrics 将指标数据转换为 VictoriaMetrics Metric 对象
// 这个函数复制自 internal/service/metric_converter.go，避免循环依赖
func convertToMetrics(agentID string, metricType string, data interface{}, timestamp int64) []vmclient.Metric {
	var metrics []vmclient.Metric

	switch protocol.MetricType(metricType) {
	case protocol.MetricTypeCPU:
		cpuData := data.(*protocol.CPUData)
		metrics = append(metrics, createMetric("pika_cpu_usage_percent", agentID, nil, cpuData.UsagePercent, timestamp))
		metrics = append(metrics, createMetric("pika_cpu_cores_logical", agentID, nil, float64(cpuData.LogicalCores), timestamp))
		metrics = append(metrics, createMetric("pika_cpu_cores_physical", agentID, nil, float64(cpuData.PhysicalCores), timestamp))

	case protocol.MetricTypeMemory:
		memData := data.(*protocol.MemoryData)
		metrics = append(metrics, createMetric("pika_memory_usage_percent", agentID, nil, memData.UsagePercent, timestamp))
		metrics = append(metrics, createMetric("pika_memory_total_bytes", agentID, nil, float64(memData.Total), timestamp))
		metrics = append(metrics, createMetric("pika_memory_used_bytes", agentID, nil, float64(memData.Used), timestamp))
		metrics = append(metrics, createMetric("pika_memory_available_bytes", agentID, nil, float64(memData.Available), timestamp))
		metrics = append(metrics, createMetric("pika_memory_swap_total_bytes", agentID, nil, float64(memData.SwapTotal), timestamp))
		metrics = append(metrics, createMetric("pika_memory_swap_used_bytes", agentID, nil, float64(memData.SwapUsed), timestamp))

	case protocol.MetricTypeDisk:
		diskDataList := data.([]protocol.DiskData)
		for _, diskData := range diskDataList {
			labels := map[string]string{"mount_point": diskData.MountPoint}
			metrics = append(metrics, createMetric("pika_disk_usage_percent", agentID, labels, diskData.UsagePercent, timestamp))
			metrics = append(metrics, createMetric("pika_disk_total_bytes", agentID, labels, float64(diskData.Total), timestamp))
			metrics = append(metrics, createMetric("pika_disk_used_bytes", agentID, labels, float64(diskData.Used), timestamp))
			metrics = append(metrics, createMetric("pika_disk_free_bytes", agentID, labels, float64(diskData.Free), timestamp))
		}

	case protocol.MetricTypeNetwork:
		networkDataList := data.([]protocol.NetworkData)
		for _, netData := range networkDataList {
			labels := map[string]string{"interface": netData.Interface}
			metrics = append(metrics, createMetric("pika_network_sent_bytes_rate", agentID, labels, float64(netData.BytesSentRate), timestamp))
			metrics = append(metrics, createMetric("pika_network_recv_bytes_rate", agentID, labels, float64(netData.BytesRecvRate), timestamp))
			metrics = append(metrics, createMetric("pika_network_sent_bytes_total", agentID, labels, float64(netData.BytesSentTotal), timestamp))
			metrics = append(metrics, createMetric("pika_network_recv_bytes_total", agentID, labels, float64(netData.BytesRecvTotal), timestamp))
		}

	case protocol.MetricTypeNetworkConnection:
		connData := data.(*protocol.NetworkConnectionData)
		metrics = append(metrics, createMetric("pika_network_conn_established", agentID, nil, float64(connData.Established), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_syn_sent", agentID, nil, float64(connData.SynSent), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_syn_recv", agentID, nil, float64(connData.SynRecv), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_time_wait", agentID, nil, float64(connData.TimeWait), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_close_wait", agentID, nil, float64(connData.CloseWait), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_listen", agentID, nil, float64(connData.Listen), timestamp))
		metrics = append(metrics, createMetric("pika_network_conn_total", agentID, nil, float64(connData.Total), timestamp))

	case protocol.MetricTypeDiskIO:
		diskIODataList := data.([]*protocol.DiskIOData)
		// 汇总所有磁盘的 IO
		var totalReadRate, totalWriteRate uint64
		for _, diskIOData := range diskIODataList {
			totalReadRate += diskIOData.ReadBytesRate
			totalWriteRate += diskIOData.WriteBytesRate
		}
		metrics = append(metrics, createMetric("pika_disk_read_bytes_rate", agentID, nil, float64(totalReadRate), timestamp))
		metrics = append(metrics, createMetric("pika_disk_write_bytes_rate", agentID, nil, float64(totalWriteRate), timestamp))

	case protocol.MetricTypeGPU:
		gpuDataList := data.([]protocol.GPUData)
		for _, gpuData := range gpuDataList {
			labels := map[string]string{
				"gpu_index": fmt.Sprintf("%d", gpuData.Index),
				"gpu_name":  gpuData.Name,
			}
			metrics = append(metrics, createMetric("pika_gpu_utilization_percent", agentID, labels, gpuData.Utilization, timestamp))
			metrics = append(metrics, createMetric("pika_gpu_memory_total_bytes", agentID, labels, float64(gpuData.MemoryTotal), timestamp))
			metrics = append(metrics, createMetric("pika_gpu_memory_used_bytes", agentID, labels, float64(gpuData.MemoryUsed), timestamp))
			metrics = append(metrics, createMetric("pika_gpu_temperature_celsius", agentID, labels, gpuData.Temperature, timestamp))
			metrics = append(metrics, createMetric("pika_gpu_power_draw_watts", agentID, labels, gpuData.PowerUsage, timestamp))
		}

	case protocol.MetricTypeTemperature:
		tempDataList := data.([]protocol.TemperatureData)
		for _, tempData := range tempDataList {
			labels := map[string]string{
				"sensor_label": tempData.Type,
			}
			metrics = append(metrics, createMetric("pika_temperature_celsius", agentID, labels, tempData.Temperature, timestamp))
		}

	case protocol.MetricTypeMonitor:
		monitorDataList := data.([]protocol.MonitorData)
		for _, monitorData := range monitorDataList {
			labels := map[string]string{
				"monitor_id":   monitorData.MonitorId,
				"monitor_type": monitorData.Type,
				"target":       monitorData.Target,
			}
			metrics = append(metrics, createMetric("pika_monitor_response_time_ms", agentID, labels, float64(monitorData.ResponseTime), timestamp))
		}
	}

	return metrics
}

// createMetric 创建 VictoriaMetrics Metric 对象
func createMetric(metricName, agentID string, extraLabels map[string]string, value float64, timestamp int64) vmclient.Metric {
	labels := make(map[string]string)
	labels["__name__"] = metricName
	labels["agent_id"] = agentID

	if extraLabels != nil {
		for k, v := range extraLabels {
			labels[k] = v
		}
	}

	return vmclient.Metric{
		Metric:     labels,
		Values:     []float64{value},
		Timestamps: []int64{timestamp},
	}
}
