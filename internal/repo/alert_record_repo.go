package repo

import (
	"context"

	"github.com/wybroot/sentinel/internal/models"
	"github.com/go-orz/orz"
	"gorm.io/gorm"
)

type AlertRecordRepo struct {
	orz.Repository[models.AlertRecord, int64]
	db *gorm.DB
}

func NewAlertRecordRepo(db *gorm.DB) *AlertRecordRepo {
	return &AlertRecordRepo{
		Repository: orz.NewRepository[models.AlertRecord, int64](db),
		db:         db,
	}
}

// CreateAlertRecord 创建告警记录
func (r *AlertRecordRepo) CreateAlertRecord(ctx context.Context, record *models.AlertRecord) error {
	return r.db.WithContext(ctx).Create(record).Error
}

// UpdateAlertRecord 更新告警记录
func (r *AlertRecordRepo) UpdateAlertRecord(ctx context.Context, record *models.AlertRecord) error {
	return r.db.WithContext(ctx).Save(record).Error
}

// GetAlertRecordByID 根据记录ID获取告警记录
func (r *AlertRecordRepo) GetAlertRecordByID(ctx context.Context, id int64) (*models.AlertRecord, error) {
	var record models.AlertRecord
	err := r.db.WithContext(ctx).
		Where("id = ?", id).
		First(&record).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

// GetLatestAlertRecord 获取最新的告警记录
func (r *AlertRecordRepo) GetLatestAlertRecord(ctx context.Context, configID string, alertType string) (*models.AlertRecord, error) {
	var record models.AlertRecord
	err := r.db.WithContext(ctx).
		Where("config_id = ? AND alert_type = ? AND status = ?", configID, alertType, "firing").
		Order("fired_at DESC").
		First(&record).Error
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (r *AlertRecordRepo) Clear(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("1=1").Delete(&models.AlertRecord{}).Error
}
