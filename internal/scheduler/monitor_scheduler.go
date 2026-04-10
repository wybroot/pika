package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/wybroot/sentinel/internal/service"
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

// MonitorTask 调度任务（轻量级，仅存储必要信息）
type MonitorTask struct {
	ID      string       // 监控任务 ID
	EntryID cron.EntryID // cron 任务的 ID
}

// MonitorScheduler 监控任务调度器
type MonitorScheduler struct {
	mu             sync.RWMutex
	cron           *cron.Cron
	tasks          map[string]*MonitorTask // taskID -> MonitorTask
	monitorService *service.MonitorService
	logger         *zap.Logger
	ctx            context.Context
	cancel         context.CancelFunc
}

// NewMonitorScheduler 创建监控任务调度器
func NewMonitorScheduler(monitorService *service.MonitorService, logger *zap.Logger) *MonitorScheduler {
	return &MonitorScheduler{
		cron:           cron.New(cron.WithSeconds()), // 支持秒级调度
		tasks:          make(map[string]*MonitorTask),
		monitorService: monitorService,
		logger:         logger,
	}
}

// Start 启动调度器
func (s *MonitorScheduler) Start(ctx context.Context) {
	s.ctx, s.cancel = context.WithCancel(ctx)

	s.logger.Info("启动监控任务调度器")

	// 首次加载所有启用的任务
	s.LoadTasks()

	// 启动 cron 调度器
	s.cron.Start()
}

// Stop 停止调度器
func (s *MonitorScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}

	// 停止 cron 调度器
	ctx := s.cron.Stop()
	<-ctx.Done()

	s.logger.Info("监控任务调度器已停止")
}

// LoadTasks 加载所有启用的监控任务
func (s *MonitorScheduler) LoadTasks() {
	monitors, err := s.monitorService.FindByEnabled(context.Background(), true)
	if err != nil {
		s.logger.Error("加载监控任务失败", zap.Error(err))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 标记当前存在的任务
	existingTasks := make(map[string]bool)
	for _, monitor := range monitors {
		existingTasks[monitor.ID] = true

		if _, exists := s.tasks[monitor.ID]; !exists {
			// 新任务，添加到调度器
			if err := s.addTaskLocked(monitor.ID, monitor.Interval); err != nil {
				s.logger.Error("添加监控任务失败",
					zap.String("taskID", monitor.ID),
					zap.String("taskName", monitor.Name),
					zap.Error(err))
			}
		}
	}

	// 删除已不存在或已禁用的任务
	for taskID := range s.tasks {
		if !existingTasks[taskID] {
			s.removeTaskLocked(taskID)
		}
	}
}

// AddTask 添加监控任务
func (s *MonitorScheduler) AddTask(monitorID string, interval int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addTaskLocked(monitorID, interval)
}

// addTaskLocked 添加监控任务（需要持有锁）
func (s *MonitorScheduler) addTaskLocked(monitorID string, interval int) error {
	// 如果任务已存在，先删除
	if task, exists := s.tasks[monitorID]; exists {
		s.cron.Remove(task.EntryID)
		delete(s.tasks, monitorID)
	}

	// 确保间隔合法
	if interval <= 0 {
		interval = 60 // 默认 60 秒
	}

	// 构建 cron 表达式: @every Ns
	spec := fmt.Sprintf("@every %ds", interval)

	// 添加到 cron 调度器
	entryID, err := s.cron.AddFunc(spec, func() {
		s.executeTask(monitorID)
	})
	if err != nil {
		return fmt.Errorf("添加 cron 任务失败: %w", err)
	}

	// 保存任务信息
	s.tasks[monitorID] = &MonitorTask{
		ID:      monitorID,
		EntryID: entryID,
	}

	s.logger.Info("添加监控任务",
		zap.String("taskID", monitorID),
		zap.Int("interval", interval))

	return nil
}

// UpdateTask 更新监控任务（先删除再添加）
func (s *MonitorScheduler) UpdateTask(monitorID string, interval int) error {
	// 移除旧监控任务
	s.removeTaskLocked(monitorID)
	// 添加新任务
	return s.addTaskLocked(monitorID, interval)
}

// RemoveTask 删除监控任务
func (s *MonitorScheduler) RemoveTask(monitorID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeTaskLocked(monitorID)
}

// removeTaskLocked 删除监控任务（需要持有锁）
func (s *MonitorScheduler) removeTaskLocked(monitorID string) {
	if task, exists := s.tasks[monitorID]; exists {
		s.cron.Remove(task.EntryID)
		delete(s.tasks, monitorID)
		s.logger.Info("删除监控任务", zap.String("taskID", monitorID))
	}
}

// executeTask 执行任务（从数据库查询最新配置）
func (s *MonitorScheduler) executeTask(monitorID string) {
	// 从数据库查询最新的监控任务配置
	monitor, err := s.monitorService.FindById(s.ctx, monitorID)
	if err != nil {
		s.logger.Error("查询监控任务失败",
			zap.String("taskID", monitorID),
			zap.Error(err))
		return
	}

	// 检查任务是否仍然启用
	if !monitor.Enabled {
		s.logger.Warn("监控任务已禁用，跳过执行",
			zap.String("taskID", monitorID),
			zap.String("taskName", monitor.Name))
		return
	}

	//s.logger.Debug("执行监控任务",
	//	zap.String("taskID", monitorID),
	//	zap.String("taskName", monitor.Name),
	//	zap.Int("interval", monitor.Interval))

	// 发送监控任务到探针
	if err := s.monitorService.SendMonitorTaskToAgents(s.ctx, monitor); err != nil {
		s.logger.Error("发送监控任务失败",
			zap.String("taskID", monitorID),
			zap.String("taskName", monitor.Name),
			zap.Error(err))
	}
}

// GetTaskCount 获取任务数量
func (s *MonitorScheduler) GetTaskCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tasks)
}

// GetTaskStatus 获取任务状态
func (s *MonitorScheduler) GetTaskStatus() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tasks := make([]map[string]interface{}, 0, len(s.tasks))

	// 获取 cron 的所有条目
	entries := s.cron.Entries()
	entryMap := make(map[cron.EntryID]cron.Entry)
	for _, entry := range entries {
		entryMap[entry.ID] = entry
	}

	for _, task := range s.tasks {
		taskInfo := map[string]interface{}{
			"id": task.ID,
		}

		// 从 cron entry 获取下次执行时间
		if entry, exists := entryMap[task.EntryID]; exists {
			taskInfo["nextRunTime"] = entry.Next.Format(time.RFC3339)
		}

		tasks = append(tasks, taskInfo)
	}

	return map[string]interface{}{
		"totalTasks": len(s.tasks),
		"tasks":      tasks,
	}
}
