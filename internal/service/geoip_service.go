package service

import (
	"fmt"
	"net"
	"sync"

	"github.com/wybroot/sentinel/internal/config"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"
)

type GeoIPService struct {
	logger *zap.Logger
	config *config.GeoIPConfig
	db     *geoip2.Reader
	mu     sync.RWMutex
}

func NewGeoIPService(logger *zap.Logger, appCfg *config.AppConfig) (*GeoIPService, error) {
	cfg := appCfg.GeoIP
	s := &GeoIPService{
		logger: logger,
		config: cfg,
	}

	// 如果启用了 GeoIP 且配置了数据库路径
	if cfg != nil && cfg.Enabled && cfg.DBPath != "" {
		if err := s.loadDatabase(); err != nil {
			logger.Warn("failed to load GeoIP database, service will be disabled",
				zap.String("path", cfg.DBPath),
				zap.Error(err))
			// 不返回错误，只是禁用服务
			return s, nil
		}
		logger.Info("GeoIP service initialized successfully", zap.String("dbPath", cfg.DBPath))
	} else {
		logger.Info("GeoIP service is disabled")
	}

	return s, nil
}

// loadDatabase 加载 GeoIP 数据库
func (s *GeoIPService) loadDatabase() error {
	db, err := geoip2.Open(s.config.DBPath)
	if err != nil {
		return fmt.Errorf("open GeoIP database failed: %w", err)
	}
	s.db = db
	return nil
}

// LookupIP 查询 IP 归属地
func (s *GeoIPService) LookupIP(ip string) string {
	// 如果服务未启用或数据库未加载
	if s.config == nil || !s.config.Enabled || s.db == nil {
		return ""
	}

	// 跳过私有IP
	if isPrivateIP(ip) {
		return "内网IP"
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return ""
	}

	record, err := s.db.City(parsedIP)
	if err != nil {
		s.logger.Debug("failed to lookup IP",
			zap.String("ip", ip),
			zap.Error(err))
		return ""
	}

	// 获取语言设置，默认使用中文
	lang := "zh-CN"
	if s.config.DBLanguage != "" {
		lang = s.config.DBLanguage
	}

	// 构建位置信息：国家-省份-城市
	var location string

	// 国家
	if country, ok := record.Country.Names[lang]; ok && country != "" {
		location = country
	} else if record.Country.Names["en"] != "" {
		location = record.Country.Names["en"]
	}

	// 省份/州
	if len(record.Subdivisions) > 0 {
		if subdivision, ok := record.Subdivisions[0].Names[lang]; ok && subdivision != "" {
			if location != "" {
				location += "-" + subdivision
			} else {
				location = subdivision
			}
		} else if record.Subdivisions[0].Names["en"] != "" {
			if location != "" {
				location += "-" + record.Subdivisions[0].Names["en"]
			} else {
				location = record.Subdivisions[0].Names["en"]
			}
		}
	}

	// 城市
	if city, ok := record.City.Names[lang]; ok && city != "" {
		if location != "" {
			location += "-" + city
		} else {
			location = city
		}
	} else if record.City.Names["en"] != "" {
		if location != "" {
			location += "-" + record.City.Names["en"]
		} else {
			location = record.City.Names["en"]
		}
	}

	return location
}

// Close 关闭数据库连接
func (s *GeoIPService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// isPrivateIP 检查是否为私有IP
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// 检查是否为私有IP段
	privateIPBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}

	for _, block := range privateIPBlocks {
		_, subnet, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if subnet.Contains(parsedIP) {
			return true
		}
	}

	return false
}
