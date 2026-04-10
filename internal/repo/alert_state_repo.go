package repo

import (
	"context"
	"time"

	"github.com/wybroot/sentinel/internal/models"
	"gorm.io/gorm"
)

type AlertStateRepo struct {
	db *gorm.DB
}

func NewAlertStateRepo(db *gorm.DB) *AlertStateRepo {
	return &AlertStateRepo{
		db: db,
	}
}

// GetAlertState 获取告警状态
func (r *AlertStateRepo) GetAlertState(ctx context.Context, id string) (*models.AlertState, error) {
	var state models.AlertState
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&state).Error
	if err != nil {
		return nil, err
	}
	return &state, nil
}

// SaveAlertState 保存告警状态
func (r *AlertStateRepo) SaveAlertState(ctx context.Context, state *models.AlertState) error {
	if state.CreatedAt == 0 {
		state.CreatedAt = time.Now().UnixMilli()
	}
	return r.db.WithContext(ctx).Save(state).Error
}

// DeleteAlertState 删除告警状态
func (r *AlertStateRepo) DeleteAlertState(ctx context.Context, id string) error {
	return r.db.WithContext(ctx).Delete(&models.AlertState{}, "id = ?", id).Error
}

// DeleteAlertStatesByConfigID 删除配置相关的所有告警状态
func (r *AlertStateRepo) DeleteAlertStatesByConfigID(ctx context.Context, configID string) error {
	return r.db.WithContext(ctx).Where("config_id = ?", configID).Delete(&models.AlertState{}).Error
}

// LoadAllStates 加载所有告警状态
func (r *AlertStateRepo) LoadAllStates(ctx context.Context) ([]models.AlertState, error) {
	var states []models.AlertState
	err := r.db.WithContext(ctx).Find(&states).Error
	return states, err
}

// CleanupOldStates 清理旧的告警状态（超过24小时未更新的）
func (r *AlertStateRepo) CleanupOldStates(ctx context.Context) error {
	cutoffTime := time.Now().Add(-24 * time.Hour).UnixMilli()
	return r.db.WithContext(ctx).
		Where("updated_at < ?", cutoffTime).
		Delete(&models.AlertState{}).Error
}

func (r *AlertStateRepo) Clear(ctx context.Context) error {
	return r.db.WithContext(ctx).Where("1=1").Delete(&models.AlertState{}).Error
}
