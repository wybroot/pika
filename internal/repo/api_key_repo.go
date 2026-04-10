package repo

import (
	"context"

	"github.com/wybroot/sentinel/internal/models"
	"github.com/go-orz/orz"
	"gorm.io/gorm"
)

type ApiKeyRepo struct {
	orz.Repository[models.ApiKey, string]
	db *gorm.DB
}

func NewApiKeyRepo(db *gorm.DB) *ApiKeyRepo {
	return &ApiKeyRepo{
		Repository: orz.NewRepository[models.ApiKey, string](db),
		db:         db,
	}
}

// FindByKey 根据密钥查找
func (r *ApiKeyRepo) FindByKey(ctx context.Context, key string) (*models.ApiKey, error) {
	var apiKey models.ApiKey
	err := r.db.WithContext(ctx).
		Where("key = ?", key).
		First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// FindEnabledByKey 根据密钥查找启用的密钥
func (r *ApiKeyRepo) FindEnabledByKey(ctx context.Context, key string) (*models.ApiKey, error) {
	var apiKey models.ApiKey
	err := r.db.WithContext(ctx).
		Where("key = ? AND enabled = ?", key, true).
		First(&apiKey).Error
	if err != nil {
		return nil, err
	}
	return &apiKey, nil
}

// ListByUser 列出用户创建的所有密钥
func (r *ApiKeyRepo) ListByUser(ctx context.Context, userID string, page, pageSize int) ([]models.ApiKey, int64, error) {
	var apiKeys []models.ApiKey
	var total int64

	offset := (page - 1) * pageSize

	err := r.db.WithContext(ctx).
		Model(&models.ApiKey{}).
		Where("created_by = ?", userID).
		Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = r.db.WithContext(ctx).
		Where("created_by = ?", userID).
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&apiKeys).Error

	return apiKeys, total, err
}

// ListAll 列出所有密钥
func (r *ApiKeyRepo) ListAll(ctx context.Context, page, pageSize int) ([]models.ApiKey, int64, error) {
	var apiKeys []models.ApiKey
	var total int64

	offset := (page - 1) * pageSize

	err := r.db.WithContext(ctx).
		Model(&models.ApiKey{}).
		Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = r.db.WithContext(ctx).
		Order("created_at DESC").
		Limit(pageSize).
		Offset(offset).
		Find(&apiKeys).Error

	return apiKeys, total, err
}

// UpdateName 更新密钥名称
func (r *ApiKeyRepo) UpdateName(ctx context.Context, id, name string) error {
	return r.db.WithContext(ctx).
		Model(&models.ApiKey{}).
		Where("id = ?", id).
		Update("name", name).Error
}

// UpdateEnabled 更新密钥启用状态
func (r *ApiKeyRepo) UpdateEnabled(ctx context.Context, id string, enabled bool) error {
	return r.db.WithContext(ctx).
		Model(&models.ApiKey{}).
		Where("id = ?", id).
		Update("enabled", enabled).Error
}
