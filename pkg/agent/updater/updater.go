package updater

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/wybroot/sentinel/pkg/agent/config"
	"github.com/minio/selfupdate"
)

// VersionInfo 版本信息
type VersionInfo struct {
	Version string `json:"version"`
}

// Updater 自动更新器
type Updater struct {
	cfg            *config.Config
	currentVer     string
	httpClient     *http.Client
	executablePath string
}

// New 创建更新器
func New(cfg *config.Config, currentVer string) (*Updater, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	// 创建 HTTP 客户端，根据配置决定是否跳过证书验证
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}
	if cfg.Server.InsecureSkipVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	return &Updater{
		cfg:            cfg,
		currentVer:     currentVer,
		httpClient:     httpClient,
		executablePath: execPath,
	}, nil
}

// Start 启动自动更新检查
func (u *Updater) Start(ctx context.Context) {
	if !u.cfg.AutoUpdate.Enabled {
		log.Println("自动更新已禁用")
		return
	}

	log.Printf("自动更新已启用，检查间隔: %v", u.cfg.GetUpdateCheckInterval())

	// 立即检查一次
	u.CheckAndUpdate()

	// 定时检查
	ticker := time.NewTicker(u.cfg.GetUpdateCheckInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			u.CheckAndUpdate()
		case <-ctx.Done():
			log.Println("停止自动更新检查")
			return
		}
	}
}

// CheckAndUpdate 检查并更新
func (u *Updater) CheckAndUpdate() {
	log.Println("🔍 检查更新...")

	// 获取最新版本信息
	versionInfo, err := u.fetchLatestVersion()
	if err != nil {
		log.Printf("⚠️  获取版本信息失败: %v", err)
		return
	}

	// 比较版本
	if versionInfo.Version == u.currentVer {
		log.Printf("✅ 当前已是最新版本: %s", u.currentVer)
		return
	}

	log.Printf("🆕 发现新版本: %s (当前版本: %s)", versionInfo.Version, u.currentVer)

	// 下载新版本
	if err := u.downloadAndUpdate(versionInfo); err != nil {
		log.Printf("❌ 更新失败: %v", err)
		return
	}

	log.Println("✅ 更新成功，将在下次重启时生效")
}

// fetchLatestVersion 获取最新版本信息
func (u *Updater) fetchLatestVersion() (*VersionInfo, error) {
	latestVersionURL := u.cfg.GetLatestVersionURL()
	return u.checkUpdateWithClient(latestVersionURL)
}

// checkUpdateWithClient 使用实例的 httpClient 检查更新
func (u *Updater) checkUpdateWithClient(latestVersionURL string) (*VersionInfo, error) {
	resp, err := u.httpClient.Get(latestVersionURL)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP 状态码: %d", resp.StatusCode)
	}

	var versionInfo VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&versionInfo); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	return &versionInfo, nil
}

// downloadAndUpdate 下载并更新
func (u *Updater) downloadAndUpdate(versionInfo *VersionInfo) error {
	log.Printf("📥 下载新版本: %s", versionInfo.Version)

	downloadURL := u.cfg.GetDownloadURL()

	// 下载文件
	resp, err := u.httpClient.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP 状态码: %d", resp.StatusCode)
	}

	// 使用 selfupdate 应用更新
	if err := selfupdate.Apply(resp.Body, selfupdate.Options{}); err != nil {
		return fmt.Errorf("应用更新失败: %w", err)
	}

	log.Printf("✅ 更新成功，进程即将退出，等待系统服务重启...")

	// 退出当前进程，让系统服务管理器（systemd/supervisor等）自动重启
	// 注意：这要求服务配置了自动重启（如 systemd 的 Restart=always）
	os.Exit(1)

	return nil
}
