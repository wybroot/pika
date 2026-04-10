package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/wybroot/sentinel/internal/ddns"
	"github.com/wybroot/sentinel/internal/models"
	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/wybroot/sentinel/internal/repo"
	"github.com/wybroot/sentinel/internal/websocket"

	"github.com/go-orz/toolkit/syncx"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// ipCacheData IP 缓存数据
type ipCacheData struct {
	IPv4 string
	IPv6 string
}

type DDNSService struct {
	logger          *zap.Logger
	ConfigRepo      *repo.DDNSConfigRepo // 导出用于 handler 的 PageBuilder
	recordRepo      *repo.DDNSRecordRepo
	propertyService *PropertyService
	wsManager       *websocket.Manager
	ipCache         *syncx.SafeMap[string, *ipCacheData] // 使用内存缓存存储 IP
}

func NewDDNSService(
	logger *zap.Logger,
	configRepo *repo.DDNSConfigRepo,
	recordRepo *repo.DDNSRecordRepo,
	propertyService *PropertyService,
	wsManager *websocket.Manager,
) *DDNSService {
	s := &DDNSService{
		logger:          logger,
		ConfigRepo:      configRepo,
		recordRepo:      recordRepo,
		propertyService: propertyService,
		wsManager:       wsManager,
		ipCache:         syncx.NewSafeMap[string, *ipCacheData](),
	}

	// 初始化 IP 缓存：从 DNS 服务商查询当前记录
	go s.initIPCache()

	return s
}

// initIPCache 初始化 IP 缓存：从 DNS 服务商查询所有启用配置的当前 IP 记录
func (s *DDNSService) initIPCache() {
	ctx := context.Background()

	// 查询所有启用的 DDNS 配置
	configs, err := s.ConfigRepo.FindAllEnabled(ctx)
	if err != nil {
		s.logger.Error("初始化 IP 缓存失败：查询配置出错", zap.Error(err))
		return
	}

	if len(configs) == 0 {
		s.logger.Info("没有启用的 DDNS 配置，跳过 IP 缓存初始化")
		return
	}

	s.logger.Info("开始初始化 IP 缓存", zap.Int("配置数量", len(configs)))

	for _, config := range configs {
		// 创建 DNS 提供商客户端
		provider, err := s.createProvider(ctx, &config)
		if err != nil {
			s.logger.Error("初始化 IP 缓存失败：创建 DNS 提供商失败",
				zap.String("agentId", config.AgentID),
				zap.String("provider", config.Provider),
				zap.Error(err))
			continue
		}

		cacheData := &ipCacheData{}

		// 查询 IPv4 记录
		if config.EnableIPv4 && len(config.DomainsIPv4) > 0 {
			// 使用第一个域名查询
			domain := config.DomainsIPv4[0]
			ipv4, err := provider.GetRecord(ctx, domain, ddns.RecordTypeA)
			if err != nil {
				s.logger.Warn("查询 IPv4 记录失败",
					zap.String("agentId", config.AgentID),
					zap.String("domain", domain),
					zap.Error(err))
			} else {
				cacheData.IPv4 = ipv4
				s.logger.Info("成功查询 IPv4 记录",
					zap.String("agentId", config.AgentID),
					zap.String("domain", domain),
					zap.String("ipv4", ipv4))
			}
		}

		// 查询 IPv6 记录
		if config.EnableIPv6 && len(config.DomainsIPv6) > 0 {
			// 使用第一个域名查询
			domain := config.DomainsIPv6[0]
			ipv6, err := provider.GetRecord(ctx, domain, ddns.RecordTypeAAAA)
			if err != nil {
				s.logger.Warn("查询 IPv6 记录失败",
					zap.String("agentId", config.AgentID),
					zap.String("domain", domain),
					zap.Error(err))
			} else {
				cacheData.IPv6 = ipv6
				s.logger.Info("成功查询 IPv6 记录",
					zap.String("agentId", config.AgentID),
					zap.String("domain", domain),
					zap.String("ipv6", ipv6))
			}
		}

		// 如果查询到了任何 IP，就放入缓存
		if cacheData.IPv4 != "" || cacheData.IPv6 != "" {
			s.ipCache.Set(config.AgentID, cacheData)
		}
	}

	s.logger.Info("IP 缓存初始化完成")
}

// HandleIPReport 处理客户端上报的 IP 地址
func (s *DDNSService) HandleIPReport(ctx context.Context, agentID string, ipData *protocol.DDNSIPReportData) error {
	// 获取该探针的 DDNS 配置
	config, err := s.ConfigRepo.FindEnabledByAgentID(ctx, agentID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// 没有配置或未启用，直接返回
			return nil
		}
		return fmt.Errorf("获取 DDNS 配置失败: %w", err)
	}

	// 获取缓存的 IP
	cachedIP, _ := s.ipCache.Get(agentID)

	var oldIPv4, oldIPv6 string
	if cachedIP != nil {
		oldIPv4 = cachedIP.IPv4
		oldIPv6 = cachedIP.IPv6
	}

	// 检查 IP 是否变化
	ipv4Changed := config.EnableIPv4 && ipData.IPv4 != "" && oldIPv4 != ipData.IPv4
	ipv6Changed := config.EnableIPv6 && ipData.IPv6 != "" && oldIPv6 != ipData.IPv6

	if !ipv4Changed && !ipv6Changed {
		// IP 没有变化，无需更新
		s.logger.Info("IP 未变化，无需更新",
			zap.String("agentId", agentID),
			zap.Bool("ipv4Changed", ipv4Changed),
			zap.Bool("ipv6Changed", ipv6Changed),
			zap.String("oldIPv4", oldIPv4),
			zap.String("newIPv4", ipData.IPv4),
			zap.String("oldIPv6", oldIPv6),
			zap.String("newIPv6", ipData.IPv6),
		)
		return nil
	}

	s.logger.Info("检测到 IP 变化",
		zap.String("agentId", agentID),
		zap.Bool("ipv4Changed", ipv4Changed),
		zap.Bool("ipv6Changed", ipv6Changed),
		zap.String("oldIPv4", oldIPv4),
		zap.String("newIPv4", ipData.IPv4),
		zap.String("oldIPv6", oldIPv6),
		zap.String("newIPv6", ipData.IPv6),
	)

	// 创建 DNS 提供商客户端
	provider, err := s.createProvider(ctx, config)
	if err != nil {
		return fmt.Errorf("创建 DNS 提供商失败: %w", err)
	}

	// 更新 DNS 记录
	// 处理 IPv4 域名
	if ipv4Changed {
		for _, domain := range config.DomainsIPv4 {
			if err := s.updateRecord(ctx, provider, config, domain, ddns.RecordTypeA, ipData.IPv4, oldIPv4); err != nil {
				s.logger.Error("更新 IPv4 域名记录失败",
					zap.String("agentId", agentID),
					zap.String("domain", domain),
					zap.Error(err))
			}
		}
	}

	// 处理 IPv6 域名
	if ipv6Changed {
		for _, domain := range config.DomainsIPv6 {
			if err := s.updateRecord(ctx, provider, config, domain, ddns.RecordTypeAAAA, ipData.IPv6, oldIPv6); err != nil {
				s.logger.Error("更新 IPv6 域名记录失败",
					zap.String("agentId", agentID),
					zap.String("domain", domain),
					zap.Error(err))
			}
		}
	}

	// 更新内存缓存
	s.ipCache.Set(agentID, &ipCacheData{IPv4: ipData.IPv4, IPv6: ipData.IPv6})

	return nil
}

// updateRecord 更新单条 DNS 记录
func (s *DDNSService) updateRecord(
	ctx context.Context,
	provider ddns.Provider,
	config *models.DDNSConfig,
	domain, recordType, newIP, oldIP string,
) error {
	err := provider.UpdateRecord(ctx, domain, recordType, newIP)

	// 记录更新结果
	record := &models.DDNSRecord{
		ID:         uuid.New().String(),
		ConfigID:   config.ID,
		AgentID:    config.AgentID,
		Domain:     domain,
		RecordType: recordType,
		OldIP:      oldIP,
		NewIP:      newIP,
		CreatedAt:  time.Now().UnixMilli(),
	}

	if err != nil {
		record.Status = "failed"
		record.ErrorMessage = err.Error()
		s.logger.Error("更新 DNS 记录失败",
			zap.String("domain", domain),
			zap.String("recordType", recordType),
			zap.String("newIP", newIP),
			zap.Error(err))
	} else {
		record.Status = "success"
		s.logger.Info("DNS 记录更新成功",
			zap.String("domain", domain),
			zap.String("recordType", recordType),
			zap.String("oldIP", oldIP),
			zap.String("newIP", newIP))
	}

	// 保存更新记录
	if saveErr := s.recordRepo.Create(ctx, record); saveErr != nil {
		s.logger.Error("保存 DDNS 更新记录失败", zap.Error(saveErr))
	}

	return err
}

// createProvider 创建 DNS 提供商
func (s *DDNSService) createProvider(ctx context.Context, config *models.DDNSConfig) (ddns.Provider, error) {
	// 从 PropertyService 获取 DNS Provider 配置
	dnsProvider, err := s.propertyService.GetDNSProviderByType(ctx, config.Provider)
	if err != nil {
		return nil, fmt.Errorf("获取 DNS Provider 配置失败: %w", err)
	}

	if !dnsProvider.Enabled {
		return nil, fmt.Errorf("DNS Provider %s 未启用", config.Provider)
	}

	// 将 Config (map[string]interface{}) 转换为 map[string]string
	providerConfig := make(map[string]string)
	for k, v := range dnsProvider.Config {
		if str, ok := v.(string); ok {
			providerConfig[k] = str
		}
	}

	return ddns.NewProvider(config.Provider, providerConfig)
}

// GetConfigByAgentID 获取探针的 DDNS 配置
func (s *DDNSService) GetConfigByAgentID(ctx context.Context, agentID string) (*models.DDNSConfig, error) {
	return s.ConfigRepo.FindByAgentID(ctx, agentID)
}

// GetDDNSConfig 将数据库配置转换为协议配置（下发给客户端）
func (s *DDNSService) GetDDNSConfig(config *models.DDNSConfig) (*protocol.DDNSConfigData, error) {
	return &protocol.DDNSConfigData{
		Enabled:       config.Enabled,
		EnableIPv4:    config.EnableIPv4,
		EnableIPv6:    config.EnableIPv6,
		IPv4GetMethod: config.IPv4GetMethod,
		IPv6GetMethod: config.IPv6GetMethod,
		IPv4GetValue:  config.IPv4GetValue,
		IPv6GetValue:  config.IPv6GetValue,
	}, nil
}

// ListConfigsByAgentID 列出探针的所有 DDNS 配置
func (s *DDNSService) ListConfigsByAgentID(ctx context.Context, agentID string) ([]models.DDNSConfig, error) {
	return s.ConfigRepo.ListByAgentID(ctx, agentID)
}

// ListRecords 列出 DDNS 更新记录
func (s *DDNSService) ListRecords(ctx context.Context, configID string, limit int) ([]models.DDNSRecord, error) {
	return s.recordRepo.ListByConfigID(ctx, configID, limit)
}

// ListRecordsByAgentID 列出探针的 DDNS 更新记录
func (s *DDNSService) ListRecordsByAgentID(ctx context.Context, agentID string, limit int) ([]models.DDNSRecord, error) {
	return s.recordRepo.ListByAgentID(ctx, agentID, limit)
}

// CreateConfig 创建 DDNS 配置
func (s *DDNSService) CreateConfig(ctx context.Context, config *models.DDNSConfig) error {
	return s.ConfigRepo.Create(ctx, config)
}

// UpdateConfig 更新 DDNS 配置
func (s *DDNSService) UpdateConfig(ctx context.Context, config *models.DDNSConfig) error {
	return s.ConfigRepo.Save(ctx, config)
}

func (s *DDNSService) UpdateEnabled(ctx context.Context, id string, enabled bool) error {
	return s.ConfigRepo.UpdateColumnsById(ctx, id, map[string]interface{}{
		"enabled": enabled,
	})
}

// GetConfig 获取 DDNS 配置
func (s *DDNSService) GetConfig(ctx context.Context, id string) (*models.DDNSConfig, error) {
	config, err := s.ConfigRepo.FindById(ctx, id)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// DeleteConfig 删除 DDNS 配置
func (s *DDNSService) DeleteConfig(ctx context.Context, id string) error {
	// 先删除相关记录
	if err := s.recordRepo.DeleteByConfigID(ctx, id); err != nil {
		return err
	}
	// 删除配置
	return s.ConfigRepo.DeleteById(ctx, id)
}

// Run 启动 DDNS 定时任务
func (s *DDNSService) Run(ctx context.Context) {
	// DDNS 配置检查 ticker (1 分钟)
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	s.logger.Info("DDNS 定时任务已启动")

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("DDNS 定时任务已停止")
			return
		case <-ticker.C:
			s.checkDDNS()
		}
	}
}

// checkDDNS 定时检查并下发启用的 DDNS 配置
func (s *DDNSService) checkDDNS() {
	ctx := context.Background()

	// 查询所有启用的 DDNS 配置
	configs, err := s.ConfigRepo.FindAllEnabled(ctx)
	if err != nil {
		s.logger.Error("查询启用的 DDNS 配置失败", zap.Error(err))
		return
	}

	// 并发向每个配置对应的在线探针发送 DDNS 配置
	for _, config := range configs {
		agentID := config.AgentID
		go func(id string) {
			if err := s.sendDDNSConfigToAgent(&config); err != nil {
				s.logger.Debug("发送 DDNS 配置失败",
					zap.String("agentID", id),
					zap.Error(err))
			}
		}(agentID)
	}
}

// sendDDNSConfigToAgent 向指定探针发送 DDNS 配置
func (s *DDNSService) sendDDNSConfigToAgent(config *models.DDNSConfig) error {
	// 获取探针的 DDNS 配置
	configData, err := s.GetDDNSConfig(config)
	if err != nil {
		return err
	}

	msgData, err := json.Marshal(protocol.OutboundMessage{
		Type: protocol.MessageTypeDDNSConfig,
		Data: configData,
	})
	if err != nil {
		return err
	}

	return s.wsManager.SendToClient(config.AgentID, msgData)
}
