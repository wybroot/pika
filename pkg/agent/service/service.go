package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/wybroot/sentinel/pkg/agent/config"
	"github.com/wybroot/sentinel/pkg/agent/sysutil"
	"github.com/wybroot/sentinel/pkg/agent/updater"
	"github.com/kardianos/service"
)

// program 实现 service.Interface
type program struct {
	cfg    *config.Config
	agent  *Agent
	ctx    context.Context
	cancel context.CancelFunc
}

// configureICMP 配置 ICMP 权限（抽取通用逻辑）
func configureICMP() {
	if err := sysutil.ConfigureICMPPermissions(); err != nil {
		log.Printf("⚠️  配置 ICMP 权限失败: %v", err)
		log.Println("   提示: ICMP 监控可能需要 root 权限运行，或手动执行:")
		log.Println("   sudo sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"")
	}
}

// startAgent 启动 Agent 和自动更新（抽取通用逻辑）
func startAgent(ctx context.Context, cfg *config.Config) *Agent {
	// 创建 Agent 实例
	agent := New(cfg)

	// 启动自动更新（如果启用）
	if cfg.AutoUpdate.Enabled {
		upd, err := updater.New(cfg, GetVersion())
		if err != nil {
			log.Printf("⚠️  创建更新器失败: %v", err)
		} else {
			go upd.Start(ctx)
		}
	}

	// 在后台启动 Agent
	go func() {
		if err := agent.Start(ctx); err != nil {
			log.Printf("⚠️  探针运行出错: %v", err)
		}
	}()

	return agent
}

// Start 启动服务
func (p *program) Start(s service.Service) error {
	log.Println("✅ Sentinel Agent 服务启动中...")

	// 初始化系统配置（Linux ICMP 权限等）
	configureICMP()

	// 创建 context
	p.ctx, p.cancel = context.WithCancel(context.Background())

	// 启动 Agent
	p.agent = startAgent(p.ctx, p.cfg)

	return nil
}

// Stop 停止服务
func (p *program) Stop(s service.Service) error {
	log.Println("📴 Sentinel Agent 服务停止中...")

	if p.cancel != nil {
		p.cancel()
	}

	if p.agent != nil {
		p.agent.Stop()
	}

	log.Println("✅ Sentinel Agent 服务已停止")
	return nil
}

// ServiceManager 服务管理器
type ServiceManager struct {
	cfg     *config.Config
	service service.Service
}

// NewServiceManager 创建服务管理器
func NewServiceManager(cfg *config.Config) (*ServiceManager, error) {
	// 获取可执行文件路径
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取可执行文件路径失败: %w", err)
	}

	// 配置服务
	svcConfig := &service.Config{
		Name:        "pika-agent",
		DisplayName: "Sentinel Agent",
		Description: "Sentinel 监控探针 - 采集系统性能指标并上报到服务端",
		Arguments:   []string{"run", "--config", cfg.Path},
		Executable:  execPath,
		Option: service.KeyValue{
			// Linux systemd 配置
			"Restart":            "always",  // 总是重启
			"RestartSec":         "10",      // 重启前等待 10 秒
			"StartLimitInterval": "0",       // 无限制重启次数
			"KillMode":           "process", // 只杀主进程

			// Windows 配置
			"OnFailure":    "restart", // 失败时重启
			"ResetPeriod":  86400,     // 重置失败计数周期 (秒)
			"RestartDelay": 10000,     // 重启延迟 (毫秒)

			// 其他 Unix 系统 (upstart/launchd)
			"KeepAlive": true, // 保持运行
			"RunAtLoad": true, // 启动时运行
		},
	}

	// 创建 program
	prg := &program{
		cfg: cfg,
	}

	// 创建服务
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("创建服务失败: %w", err)
	}

	return &ServiceManager{
		cfg:     cfg,
		service: s,
	}, nil
}

// Install 安装服务
func (m *ServiceManager) Install() error {
	return m.service.Install()
}

// Uninstall 卸载服务
func (m *ServiceManager) Uninstall() error {
	// 先停止服务
	_ = m.service.Stop()

	return m.service.Uninstall()
}

// Start 启动服务
func (m *ServiceManager) Start() error {
	return m.service.Start()
}

// Stop 停止服务
func (m *ServiceManager) Stop() error {
	return m.service.Stop()
}

// Restart 重启服务
func (m *ServiceManager) Restart() error {
	return m.service.Restart()
}

// Status 查看服务状态
func (m *ServiceManager) Status() (string, error) {
	status, err := m.service.Status()
	if err != nil {
		return "", err
	}

	var statusStr string
	switch status {
	case service.StatusRunning:
		statusStr = "运行中 (Running)"
	case service.StatusStopped:
		statusStr = "已停止 (Stopped)"
	case service.StatusUnknown:
		statusStr = "未知 (Unknown)"
	default:
		statusStr = fmt.Sprintf("状态: %d", status)
	}

	return statusStr, nil
}

// Run 运行服务（用于 service run 命令）
func (m *ServiceManager) Run() error {
	// 检查是否在服务模式下运行
	interactive := service.Interactive()

	if !interactive {
		// 在服务管理器控制下运行
		return m.service.Run()
	}

	// 交互模式（前台运行）
	log.Printf("✅ 配置加载成功")
	log.Printf("   服务器地址: %s", m.cfg.Server.Endpoint)
	log.Printf("   采集间隔: %v", m.cfg.GetCollectorInterval())
	log.Printf("   心跳间隔: %v", m.cfg.GetHeartbeatInterval())

	// 初始化系统配置（Linux ICMP 权限等）
	configureICMP()

	// 创建 context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 监听系统信号
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	// 启动 Agent
	agent := startAgent(ctx, m.cfg)

	// 等待中断信号
	<-interrupt
	log.Println("📴 收到中断信号，正在关闭...")
	cancel()

	// 等待 Agent 停止
	agent.Stop()
	log.Println("✅ 探针已停止")

	return nil
}
