package repo

import (
	"context"

	"github.com/wybroot/sentinel/internal/models"
	"github.com/go-orz/orz"
	"gorm.io/gorm"
)

type DDNSRecordRepo struct {
	orz.Repository[models.DDNSRecord, string]
	db *gorm.DB
}

func NewDDNSRecordRepo(db *gorm.DB) *DDNSRecordRepo {
	return &DDNSRecordRepo{
		Repository: orz.NewRepository[models.DDNSRecord, string](db),
		db:         db,
	}
}

// ListByConfigID 根据配置ID列出DDNS更新记录
func (r *DDNSRecordRepo) ListByConfigID(ctx context.Context, configID string, limit int) ([]models.DDNSRecord, error) {
	var records []models.DDNSRecord
	query := r.db.WithContext(ctx).
		Where("config_id = ?", configID).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&records).Error
	return records, err
}

// ListByAgentID 根据探针ID列出DDNS更新记录
func (r *DDNSRecordRepo) ListByAgentID(ctx context.Context, agentID string, limit int) ([]models.DDNSRecord, error) {
	var records []models.DDNSRecord
	query := r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Order("created_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&records).Error
	return records, err
}

// DeleteByConfigID 删除配置相关的所有记录
func (r *DDNSRecordRepo) DeleteByConfigID(ctx context.Context, configID string) error {
	return r.db.WithContext(ctx).
		Where("config_id = ?", configID).
		Delete(&models.DDNSRecord{}).Error
}

// DeleteByAgentID 删除探针相关的所有记录
func (r *DDNSRecordRepo) DeleteByAgentID(ctx context.Context, agentID string) error {
	return r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Delete(&models.DDNSRecord{}).Error
}
