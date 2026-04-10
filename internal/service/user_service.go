package service

import (
	"context"
	"errors"

	"github.com/wybroot/sentinel/internal/config"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// UserService User 认证服务
type UserService struct {
	logger *zap.Logger
	users  map[string]string // 用户名 -> bcrypt加密的密码
}

// NewUserService 创建 User 服务
func NewUserService(logger *zap.Logger, appConfig *config.AppConfig) *UserService {
	return &UserService{
		logger: logger,
		users:  appConfig.Users,
	}
}

// ValidateCredentials 验证用户名和密码
func (s *UserService) ValidateCredentials(ctx context.Context, username, password string) error {
	// 从配置中获取用户的bcrypt密码哈希
	hashedPassword, exists := s.users[username]
	if !exists {
		s.logger.Debug("用户不存在", zap.String("username", username))
		return errors.New("用户名或密码错误")
	}

	// 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		s.logger.Debug("密码验证失败", zap.String("username", username), zap.Error(err))
		return errors.New("用户名或密码错误")
	}

	s.logger.Info("User 认证成功", zap.String("username", username))
	return nil
}

// GetUsername 获取用户名（如果认证成功）
func (s *UserService) GetUsername(ctx context.Context, username string) (string, error) {
	if _, exists := s.users[username]; !exists {
		return "", errors.New("用户不存在")
	}
	return username, nil
}

// IsEnabled 检查 User 是否配置
func (s *UserService) IsEnabled() bool {
	return len(s.users) > 0
}
