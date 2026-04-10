package repo

import (
	"context"

	"github.com/wybroot/sentinel/internal/models"
	"github.com/go-orz/orz"
	"gorm.io/gorm"
)

type DDNSConfigRepo struct {
	orz.Repository[models.DDNSConfig, string]
	db *gorm.DB
}

func NewDDNSConfigRepo(db *gorm.DB) *DDNSConfigRepo {
	return &DDNSConfigRepo{
		Repository: orz.NewRepository[models.DDNSConfig, string](db),
		db:         db,
	}
}

// FindByAgentID 根据探针ID查找DDNS配置
func (r *DDNSConfigRepo) FindByAgentID(ctx context.Context, agentID string) (*models.DDNSConfig, error) {
	var config models.DDNSConfig
	err := r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		First(&config).Error
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// FindEnabledByAgentID 根据探针ID查找已启用的DDNS配置
func (r *DDNSConfigRepo) FindEnabledByAgentID(ctx context.Context, agentID string) (*models.DDNSConfig, error) {
	var config models.DDNSConfig
	err := r.db.WithContext(ctx).
		Where("agent_id = ? AND enabled = ?", agentID, true).
		First(&config).Error
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// ListByAgentID 列出探针的所有DDNS配置
func (r *DDNSConfigRepo) ListByAgentID(ctx context.Context, agentID string) ([]models.DDNSConfig, error) {
	var configs []models.DDNSConfig
	err := r.db.WithContext(ctx).
		Where("agent_id = ?", agentID).
		Order("created_at DESC").
		Find(&configs).Error
	return configs, err
}

// FindAllEnabled 查找所有已启用的DDNS配置
func (r *DDNSConfigRepo) FindAllEnabled(ctx context.Context) ([]models.DDNSConfig, error) {
	var configs []models.DDNSConfig
	err := r.db.WithContext(ctx).
		Where("enabled = ?", true).
		Find(&configs).Error
	return configs, err
}
