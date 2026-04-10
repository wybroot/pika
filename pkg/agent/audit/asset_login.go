package audit

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wybroot/sentinel/internal/protocol"
)

// LoginAssetsCollector 登录日志收集器
type LoginAssetsCollector struct {
	config   *Config
	executor *CommandExecutor
}

// NewLoginAssetsCollector 创建登录日志收集器
func NewLoginAssetsCollector(config *Config, executor *CommandExecutor) *LoginAssetsCollector {
	return &LoginAssetsCollector{
		config:   config,
		executor: executor,
	}
}

// Collect 收集登录日志
func (lac *LoginAssetsCollector) Collect() *protocol.LoginAssets {
	assets := &protocol.LoginAssets{}

	// 收集成功登录历史
	assets.SuccessfulLogins = lac.collectSuccessfulLogins()

	// 收集失败登录历史
	assets.FailedLogins = lac.collectFailedLogins()

	// 收集当前登录会话
	assets.CurrentSessions = lac.collectCurrentSessions()

	// 统计信息
	assets.Statistics = lac.calculateStatistics(assets)

	return assets
}

// collectSuccessfulLogins 收集成功登录历史
func (lac *LoginAssetsCollector) collectSuccessfulLogins() []protocol.LoginRecord {
	var records []protocol.LoginRecord

	// 使用 last 命令获取登录历史
	output, err := lac.executor.Execute("last", "-n", "100", "-F", "-w")
	if err != nil {
		globalLogger.Debug("获取登录历史失败: %v", err)
		return records
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和特殊行
		if line == "" || strings.HasPrefix(line, "wtmp") ||
			strings.HasPrefix(line, "reboot") || strings.Contains(line, "system boot") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		username := fields[0]
		terminal := fields[1]
		ip := fields[2]

		// 处理本地登录（没有IP的情况）
		if ip == ":0" || ip == ":0.0" {
			ip = "localhost"
		} else if strings.HasPrefix(ip, ":") {
			ip = "localhost" + ip
		}

		// 解析登录时间
		timestamp := lac.parseLoginTime(fields)

		record := protocol.LoginRecord{
			Username:  username,
			Terminal:  terminal,
			IP:        ip,
			Timestamp: timestamp,
			Status:    "success",
		}

		records = append(records, record)

		// 限制数量
		if len(records) >= 100 {
			break
		}
	}

	return records
}

// parseLoginTime 解析登录时间
func (lac *LoginAssetsCollector) parseLoginTime(fields []string) int64 {
	// last -F 输出格式示例:
	// username pts/0 192.168.1.1 Mon Dec 25 10:30:00 2023 - Mon Dec 25 11:00:00 2023
	// 时间在第4-8个字段

	if len(fields) < 8 {
		return time.Now().UnixMilli()
	}

	// 尝试多种时间格式
	timeFormats := []string{
		"Mon Jan _2 15:04:05 2006", // 标准格式
		"Mon Jan 2 15:04:05 2006",  // 不带下划线
		"2006-01-02 15:04:05",      // ISO格式
	}

	// 从第3个字段开始（索引2），因为前面是 username terminal ip
	timeStr := strings.Join(fields[3:8], " ")

	for _, format := range timeFormats {
		if t, err := time.Parse(format, timeStr); err == nil {
			// 使用本地时区解析时间
			return t.UnixMilli()
		}
	}

	// 如果解析失败，返回当前时间
	globalLogger.Debug("无法解析登录时间: %s", timeStr)
	return time.Now().UnixMilli()
}

// collectFailedLogins 收集失败登录历史
func (lac *LoginAssetsCollector) collectFailedLogins() []protocol.LoginRecord {
	var records []protocol.LoginRecord

	// 使用 lastb 命令获取失败登录历史
	output, err := lac.executor.Execute("lastb", "-n", "100", "-F", "-w")
	if err != nil {
		globalLogger.Debug("获取失败登录历史失败: %v (需要root权限)", err)

		// 尝试从日志文件读取
		records = lac.collectFailedLoginsFromAuthLog()
		return records
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和特殊行
		if line == "" || strings.HasPrefix(line, "btmp") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		username := fields[0]
		terminal := fields[1]
		ip := fields[2]

		// 处理本地登录
		if ip == ":0" || ip == ":0.0" {
			ip = "localhost"
		}

		// 解析登录时间
		timestamp := lac.parseLoginTime(fields)

		record := protocol.LoginRecord{
			Username:  username,
			Terminal:  terminal,
			IP:        ip,
			Timestamp: timestamp,
			Status:    "failed",
		}

		records = append(records, record)

		// 限制数量
		if len(records) >= 100 {
			break
		}
	}

	return records
}

// collectFailedLoginsFromAuthLog 从认证日志读取失败登录
func (lac *LoginAssetsCollector) collectFailedLoginsFromAuthLog() []protocol.LoginRecord {
	var records []protocol.LoginRecord

	// 尝试读取不同的认证日志文件
	authLogPaths := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}

	var authLog string
	for _, path := range authLogPaths {
		if _, err := os.Stat(path); err == nil {
			authLog = path
			break
		}
	}

	if authLog == "" {
		return records
	}

	file, err := os.Open(authLog)
	if err != nil {
		return records
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() && count < 100 {
		line := scanner.Text()

		// 查找失败的SSH登录
		if strings.Contains(line, "Failed password") ||
			strings.Contains(line, "authentication failure") {

			record := lac.parseFailedLoginFromLog(line)
			if record != nil {
				records = append(records, *record)
				count++
			}
		}
	}

	return records
}

// parseFailedLoginFromLog 从日志行解析失败登录
func (lac *LoginAssetsCollector) parseFailedLoginFromLog(line string) *protocol.LoginRecord {
	// 简化解析，提取用户名和IP
	username := "unknown"
	ip := "unknown"

	// 提取用户名
	if idx := strings.Index(line, "user "); idx != -1 {
		rest := line[idx+5:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			username = rest[:spaceIdx]
		}
	} else if idx := strings.Index(line, "for "); idx != -1 {
		rest := line[idx+4:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			username = rest[:spaceIdx]
		}
	}

	// 提取IP地址
	if idx := strings.Index(line, "from "); idx != -1 {
		rest := line[idx+5:]
		if spaceIdx := strings.Index(rest, " "); spaceIdx != -1 {
			ip = rest[:spaceIdx]
		} else {
			ip = rest
		}
	}

	// 尝试解析日志时间
	// syslog 格式: Dec 25 10:30:00
	timestamp := lac.parseSyslogTime(line)

	return &protocol.LoginRecord{
		Username:  username,
		IP:        ip,
		Terminal:  "ssh",
		Timestamp: timestamp,
		Status:    "failed",
	}
}

// parseSyslogTime 解析syslog时间格式
func (lac *LoginAssetsCollector) parseSyslogTime(line string) int64 {
	// syslog 时间格式通常在行首: Dec 25 10:30:00
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return time.Now().UnixMilli()
	}

	// 获取当前年份（syslog不包含年份）
	currentYear := time.Now().Year()

	// 尝试解析: Month Day Time
	timeStr := fmt.Sprintf("%s %s %s %d", fields[0], fields[1], fields[2], currentYear)

	formats := []string{
		"Jan _2 15:04:05 2006",
		"Jan 2 15:04:05 2006",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timeStr); err == nil {
			// 如果解析的时间比当前时间晚，说明是去年的日志
			if t.After(time.Now()) {
				t = t.AddDate(-1, 0, 0)
			}
			return t.UnixMilli()
		}
	}

	return time.Now().UnixMilli()
}

// collectCurrentSessions 收集当前登录会话
func (lac *LoginAssetsCollector) collectCurrentSessions() []protocol.LoginSession {
	var sessions []protocol.LoginSession

	// 使用 w 命令
	output, err := lac.executor.Execute("w", "-h")
	if err != nil {
		globalLogger.Debug("获取当前登录失败: %v", err)
		return sessions
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		username := fields[0]
		terminal := fields[1]
		fromIP := fields[2]

		// 处理本地会话
		if fromIP == "-" || fromIP == "" {
			fromIP = "localhost"
		}

		// 解析空闲时间
		idleStr := fields[3]
		idleSeconds := lac.parseIdleTime(idleStr)

		// 解析登录时间（从空闲时间推算）
		loginTime := time.Now().Add(-time.Duration(idleSeconds) * time.Second).UnixMilli()

		session := protocol.LoginSession{
			Username:  username,
			Terminal:  terminal,
			IP:        fromIP,
			LoginTime: loginTime,
			IdleTime:  idleSeconds,
		}

		sessions = append(sessions, session)
	}

	return sessions
}

// parseIdleTime 解析空闲时间字符串
func (lac *LoginAssetsCollector) parseIdleTime(idleStr string) int {
	if idleStr == "-" || idleStr == "?" {
		return 0
	}

	// 支持格式: "1.00s", "2:30", "1:00m", "3days"
	idleStr = strings.TrimSpace(idleStr)

	// 秒
	if strings.HasSuffix(idleStr, "s") {
		var seconds float64
		if _, err := fmt.Sscanf(idleStr, "%f", &seconds); err == nil {
			return int(seconds)
		}
	}

	// 分:秒 或 时:分
	if strings.Contains(idleStr, ":") {
		parts := strings.Split(idleStr, ":")
		if len(parts) == 2 {
			var hours, minutes int
			if _, err := fmt.Sscanf(idleStr, "%d:%d", &hours, &minutes); err == nil {
				return hours*3600 + minutes*60
			}
		}
	}

	// 天
	if strings.Contains(idleStr, "day") {
		var days int
		if _, err := fmt.Sscanf(idleStr, "%dday", &days); err == nil {
			return days * 86400
		}
	}

	return 0
}

// calculateStatistics 计算统计信息
func (lac *LoginAssetsCollector) calculateStatistics(assets *protocol.LoginAssets) *protocol.LoginStatistics {
	stats := &protocol.LoginStatistics{
		TotalLogins:     len(assets.SuccessfulLogins),
		FailedLogins:    len(assets.FailedLogins),
		CurrentSessions: len(assets.CurrentSessions),
		UniqueIPs:       make(map[string]int),
		UniqueUsers:     make(map[string]int),
	}

	// 统计唯一IP和用户
	for _, login := range assets.SuccessfulLogins {
		stats.UniqueIPs[login.IP]++
		stats.UniqueUsers[login.Username]++
	}

	// 查找高频IP
	for ip, count := range stats.UniqueIPs {
		if count > 10 {
			if stats.HighFrequencyIPs == nil {
				stats.HighFrequencyIPs = make(map[string]int)
			}
			stats.HighFrequencyIPs[ip] = count
		}
	}

	return stats
}
