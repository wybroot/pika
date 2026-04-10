package repo

import (
	"context"

	"github.com/wybroot/sentinel/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type MetricRepo struct {
	db *gorm.DB
}

func NewMetricRepo(db *gorm.DB) *MetricRepo {
	return &MetricRepo{
		db: db,
	}
}

// SaveHostMetric 保存主机信息指标（按 agent 覆盖，避免先删后插的空窗）
func (r *MetricRepo) SaveHostMetric(ctx context.Context, metric *models.HostMetric) error {
	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "agent_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"os", "platform", "platform_version", "kernel_version", "kernel_arch", "uptime", "boot_time", "procs", "timestamp"}),
		}).
		Create(metric).Error
}

// DeleteAgentMetrics 删除指定探针的所有指标数据
func (r *MetricRepo) DeleteAgentMetrics(ctx context.Context, agentID string) error {
	if err := r.db.WithContext(ctx).Where("agent_id = ?", agentID).Delete(&models.HostMetric{}).Error; err != nil {
		return err
	}
	return nil
}
