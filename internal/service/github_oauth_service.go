package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/wybroot/sentinel/internal/config"
	"go.uber.org/zap"
)

// GitHubOAuthService GitHub OAuth 认证服务
type GitHubOAuthService struct {
	logger     *zap.Logger
	config     *config.GitHubOAuthConfig
	stateStore map[string]time.Time // 简单的 state 存储（生产环境应使用 Redis 等）
	httpClient *http.Client
}

// GitHubUserInfo GitHub 用户信息
type GitHubUserInfo struct {
	Login     string `json:"login"`      // GitHub 用户名
	Name      string `json:"name"`       // 显示名称
	Email     string `json:"email"`      // 邮箱
	AvatarURL string `json:"avatar_url"` // 头像
}

// GitHubAccessTokenResponse GitHub Access Token 响应
type GitHubAccessTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// NewGitHubOAuthService 创建 GitHub OAuth 服务
func NewGitHubOAuthService(logger *zap.Logger, appConfig *config.AppConfig) *GitHubOAuthService {
	if appConfig.GitHub == nil || !appConfig.GitHub.Enabled {
		logger.Info("GitHub OAuth 认证未启用")
		return &GitHubOAuthService{
			logger: logger,
			config: nil,
		}
	}

	githubConfig := appConfig.GitHub

	// 验证配置
	if githubConfig.ClientID == "" || githubConfig.ClientSecret == "" {
		logger.Error("GitHub OAuth 配置不完整，GitHub 认证将被禁用")
		return &GitHubOAuthService{
			logger: logger,
			config: nil,
		}
	}

	logger.Info("GitHub OAuth 服务初始化成功")

	return &GitHubOAuthService{
		logger:     logger,
		config:     githubConfig,
		stateStore: make(map[string]time.Time),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// IsEnabled 检查 GitHub OAuth 是否启用
func (s *GitHubOAuthService) IsEnabled() bool {
	return s.config != nil && s.config.Enabled
}

// GenerateAuthURL 生成 GitHub 认证 URL
func (s *GitHubOAuthService) GenerateAuthURL() (string, string, error) {
	if !s.IsEnabled() {
		return "", "", errors.New("GitHub OAuth 未启用")
	}

	// 生成随机 state
	state, err := s.generateState()
	if err != nil {
		return "", "", fmt.Errorf("生成 state 失败: %w", err)
	}

	// 存储 state（有效期 10 分钟）
	s.stateStore[state] = time.Now().Add(10 * time.Minute)

	// 清理过期的 state
	s.cleanExpiredStates()

	// 构建 GitHub 授权 URL
	authURL := fmt.Sprintf("https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s&state=%s&scope=user:email",
		url.QueryEscape(s.config.ClientID),
		url.QueryEscape(s.config.RedirectURL),
		url.QueryEscape(state),
	)

	return authURL, state, nil
}

// ExchangeCode 交换授权码获取 access token 和用户信息
func (s *GitHubOAuthService) ExchangeCode(ctx context.Context, code, state string) (string, string, error) {
	if !s.IsEnabled() {
		return "", "", errors.New("GitHub OAuth 未启用")
	}

	// 验证 state
	if !s.validateState(state) {
		return "", "", errors.New("无效的 state")
	}

	// 删除已使用的 state
	delete(s.stateStore, state)

	// 交换 code 获取 access token
	accessToken, err := s.getAccessToken(ctx, code)
	if err != nil {
		return "", "", fmt.Errorf("获取 access token 失败: %w", err)
	}

	// 使用 access token 获取用户信息
	userInfo, err := s.getUserInfo(ctx, accessToken)
	if err != nil {
		return "", "", fmt.Errorf("获取用户信息失败: %w", err)
	}

	// 确定用户标识
	username := userInfo.Login
	if username == "" {
		return "", "", errors.New("无法获取 GitHub 用户名")
	}

	// 检查用户是否在白名单中
	if !s.isUserAllowed(username) {
		s.logger.Warn("GitHub 用户不在白名单中，拒绝登录",
			zap.String("username", username))
		return "", "", fmt.Errorf("用户 %s 不在允许登录的白名单中", username)
	}

	nickname := userInfo.Name
	if nickname == "" {
		nickname = username
	}

	s.logger.Info("GitHub OAuth 认证成功",
		zap.String("username", username),
		zap.String("nickname", nickname),
		zap.String("email", userInfo.Email))

	return username, nickname, nil
}

// getAccessToken 获取 access token
func (s *GitHubOAuthService) getAccessToken(ctx context.Context, code string) (string, error) {
	// 构建请求
	data := url.Values{}
	data.Set("client_id", s.config.ClientID)
	data.Set("client_secret", s.config.ClientSecret)
	data.Set("code", code)
	data.Set("redirect_uri", s.config.RedirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", "https://github.com/login/oauth/access_token", nil)
	if err != nil {
		return "", err
	}

	req.URL.RawQuery = data.Encode()
	req.Header.Set("Accept", "application/json")

	// 发送请求
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API 返回错误: %d, %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var tokenResp GitHubAccessTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if tokenResp.AccessToken == "" {
		return "", errors.New("未获取到 access token")
	}

	return tokenResp.AccessToken, nil
}

// getUserInfo 获取用户信息
func (s *GitHubOAuthService) getUserInfo(ctx context.Context, accessToken string) (*GitHubUserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API 返回错误: %d, %s", resp.StatusCode, string(body))
	}

	var userInfo GitHubUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// generateState 生成随机 state
func (s *GitHubOAuthService) generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// validateState 验证 state
func (s *GitHubOAuthService) validateState(state string) bool {
	expiresAt, exists := s.stateStore[state]
	if !exists {
		return false
	}
	return time.Now().Before(expiresAt)
}

// cleanExpiredStates 清理过期的 state
func (s *GitHubOAuthService) cleanExpiredStates() {
	now := time.Now()
	for state, expiresAt := range s.stateStore {
		if now.After(expiresAt) {
			delete(s.stateStore, state)
		}
	}
}

// isUserAllowed 检查用户是否在白名单中
func (s *GitHubOAuthService) isUserAllowed(username string) bool {
	// 如果未配置白名单，则允许所有用户
	if len(s.config.AllowedUsers) == 0 {
		return true
	}

	// 检查用户是否在白名单中
	for _, allowedUser := range s.config.AllowedUsers {
		if allowedUser == username {
			return true
		}
	}

	return false
}
