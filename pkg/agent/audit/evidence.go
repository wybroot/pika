package audit

import (
	"fmt"
	"os"
	"strings"

	"github.com/wybroot/sentinel/internal/protocol"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/process"
)

// EvidenceCollector 证据收集器
type EvidenceCollector struct {
	hashCache *FileHashCache
}

// NewEvidenceCollector 创建证据收集器
func NewEvidenceCollector() *EvidenceCollector {
	return &EvidenceCollector{
		hashCache: NewFileHashCache(),
	}
}

// CollectProcessEvidence 收集进程证据
func (ec *EvidenceCollector) CollectProcessEvidence(p *process.Process, riskLevel string) *protocol.Evidence {
	exe, _ := p.Exe()
	createTime, _ := p.CreateTime()

	var fileHash string
	if exe != "" && !strings.Contains(exe, "deleted") && !strings.Contains(exe, "memfd:") {
		fileHash = ec.hashCache.GetSHA256(exe)
	}

	processTree := ec.buildProcessTree(p)

	return &protocol.Evidence{
		FileHash:    fileHash,
		ProcessTree: processTree,
		FilePath:    exe,
		Timestamp:   createTime,
		RiskLevel:   riskLevel,
	}
}

// CollectFileEvidence 收集文件证据
func (ec *EvidenceCollector) CollectFileEvidence(filePath string, riskLevel string) *protocol.Evidence {
	info, err := os.Stat(filePath)
	if err != nil {
		globalLogger.Debug("无法获取文件信息: %s, err: %v", filePath, err)
		return &protocol.Evidence{
			FilePath:  filePath,
			RiskLevel: riskLevel,
		}
	}

	fileHash := ec.hashCache.GetSHA256(filePath)

	return &protocol.Evidence{
		FilePath:  filePath,
		FileHash:  fileHash,
		Timestamp: info.ModTime().UnixMilli(),
		RiskLevel: riskLevel,
	}
}

// buildProcessTree 构建进程树
func (ec *EvidenceCollector) buildProcessTree(p *process.Process) []string {
	var tree []string
	current := p

	// 向上追溯父进程（最多 5 层）
	for i := 0; i < 5; i++ {
		if current == nil {
			break
		}

		name, _ := current.Name()
		exe, _ := current.Exe()
		cmdline, _ := current.Cmdline()

		info := fmt.Sprintf("PID:%d Name:%s", current.Pid, name)
		if exe != "" && exe != name {
			info += fmt.Sprintf(" Exe:%s", exe)
		}
		if cmdline != "" && len(cmdline) < 100 {
			info += fmt.Sprintf(" Cmd:%s", cmdline)
		}

		tree = append([]string{info}, tree...) // 前置插入

		ppid, err := current.Ppid()
		if err != nil || ppid == 0 {
			break
		}

		parent, err := process.NewProcess(ppid)
		if err != nil {
			break
		}
		current = parent
	}

	return tree
}

// WarningCollector 警告收集器
type WarningCollector struct {
	warnings []string
}

// NewWarningCollector 创建警告收集器
func NewWarningCollector() *WarningCollector {
	return &WarningCollector{
		warnings: []string{},
	}
}

// Add 添加警告
func (wc *WarningCollector) Add(warning string) {
	wc.warnings = append(wc.warnings, warning)
}

// GetAll 获取所有警告
func (wc *WarningCollector) GetAll() []string {
	return wc.warnings
}

// SystemInfoCollector 系统信息收集器
type SystemInfoCollector struct {
	executor *CommandExecutor
}

// NewSystemInfoCollector 创建系统信息收集器
func NewSystemInfoCollector(executor *CommandExecutor) *SystemInfoCollector {
	return &SystemInfoCollector{
		executor: executor,
	}
}

// Collect 收集系统信息
func (sic *SystemInfoCollector) Collect() (*protocol.SystemInfo, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	info, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("获取系统信息失败: %w", err)
	}

	osInfo := fmt.Sprintf("%s %s", info.Platform, info.PlatformVersion)
	if info.PlatformFamily != "" {
		osInfo = fmt.Sprintf("%s (%s)", osInfo, info.PlatformFamily)
	}

	return &protocol.SystemInfo{
		Hostname:      hostname,
		OS:            osInfo,
		KernelVersion: info.KernelVersion,
		Uptime:        info.Uptime,
	}, nil
}
