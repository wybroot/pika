package repo

import (
	"github.com/wybroot/sentinel/internal/models"
	"github.com/go-orz/orz"
	"gorm.io/gorm"
)

type PropertyRepo struct {
	orz.Repository[models.Property, string]
	db *gorm.DB
}

func NewPropertyRepo(db *gorm.DB) *PropertyRepo {
	return &PropertyRepo{
		Repository: orz.NewRepository[models.Property, string](db),
		db:         db,
	}
}
