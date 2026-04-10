package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wybroot/sentinel/internal/models"
	"github.com/wybroot/sentinel/internal/utils"
	"github.com/go-orz/cache"
	"github.com/valyala/fasttemplate"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
)

// AlertTypeMetadata 告警类型元数据
type AlertTypeMetadata struct {
	Name          string // 中文名称
	ThresholdUnit string // 阈值单位
	ValueUnit     string // 当前值单位
}

// 告警类型元数据映射
var alertTypeMetadataMap = map[string]AlertTypeMetadata{
	"cpu": {
		Name:          "CPU告警",
		ThresholdUnit: "%",
		ValueUnit:     "%",
	},
	"memory": {
		Name:          "内存告警",
		ThresholdUnit: "%",
		ValueUnit:     "%",
	},
	"disk": {
		Name:          "磁盘告警",
		ThresholdUnit: "%",
		ValueUnit:     "%",
	},
	"network": {
		Name:          "网络告警",
		ThresholdUnit: "MB/s",
		ValueUnit:     "MB/s",
	},
	"cert": {
		Name:          "证书告警",
		ThresholdUnit: "天",
		ValueUnit:     "天",
	},
	"service": {
		Name:          "服务告警",
		ThresholdUnit: "秒",
		ValueUnit:     "秒",
	},
	"agent_offline": {
		Name:          "探针离线告警",
		ThresholdUnit: "秒",
		ValueUnit:     "秒",
	},
}

// 告警级别图标映射
var levelIconMap = map[string]string{
	"info":     "ℹ️",
	"warning":  "⚠️",
	"critical": "🚨",
}

// Notifier 告警通知服务
type Notifier struct {
	logger *zap.Logger
}

func NewNotifier(logger *zap.Logger) *Notifier {
	return &Notifier{
		logger: logger,
	}
}

// maskIPAddress 打码 IP 地址 (例如: 192.168.1.100 -> 192.168.*.*）
func maskIPAddress(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		// IPv4: 保留前两段，后两段打码
		return parts[0] + "." + parts[1] + ".*.*"
	}
	// IPv6 或其他格式: 保留前半部分，后半部分打码
	if len(ip) > 8 {
		return ip[:len(ip)/2] + "****"
	}
	return "****"
}

// getAlertTypeMetadata 获取告警类型元数据，如果不存在则返回默认值
func getAlertTypeMetadata(alertType string) AlertTypeMetadata {
	if metadata, ok := alertTypeMetadataMap[alertType]; ok {
		return metadata
	}
	// 返回默认值
	return AlertTypeMetadata{
		Name:          "未知告警",
		ThresholdUnit: "",
		ValueUnit:     "",
	}
}

// getLevelIcon 获取告警级别图标，如果不存在则返回默认值
func getLevelIcon(level string) string {
	if icon, ok := levelIconMap[level]; ok {
		return icon
	}
	return "❓" // 未知级别的默认图标
}

// buildMessage 构建告警消息文本
func (n *Notifier) buildMessage(agent *models.Agent, record *models.AlertRecord, maskIP bool) string {
	// 获取告警级别图标
	levelIcon := getLevelIcon(record.Level)

	// 获取告警类型元数据
	metadata := getAlertTypeMetadata(record.AlertType)

	// 处理 IP 地址显示
	displayIP := agent.IP
	if maskIP {
		displayIP = maskIPAddress(agent.IP)
	}

	// 根据状态构建消息
	switch record.Status {
	case "firing":
		return n.buildFiringMessage(agent, record, displayIP, levelIcon, metadata)
	case "resolved":
		return n.buildResolvedMessage(agent, record, displayIP, metadata)
	default:
		// 未知状态，返回基本信息
		return fmt.Sprintf("⚠️ 未知告警状态: %s\n探针: %s (%s)", record.Status, agent.Name, agent.ID)
	}
}

// buildFiringMessage 构建告警触发消息
func (n *Notifier) buildFiringMessage(
	agent *models.Agent,
	record *models.AlertRecord,
	displayIP string,
	levelIcon string,
	metadata AlertTypeMetadata,
) string {
	return fmt.Sprintf(
		"%s %s\n\n"+
			"探针: %s (%s)\n"+
			"主机: %s\n"+
			"IP: %s\n"+
			"告警类型: %s\n"+
			"告警消息: %s\n"+
			"阈值: %.2f%s\n"+
			"当前值: %.2f%s\n"+
			"触发时间: %s",
		levelIcon,
		metadata.Name,
		agent.Name,
		agent.ID,
		agent.Hostname,
		displayIP,
		record.AlertType,
		record.Message,
		record.Threshold,
		metadata.ThresholdUnit,
		record.ActualValue,
		metadata.ValueUnit,
		utils.FormatTimestamp(record.FiredAt),
	)
}

// buildResolvedMessage 构建告警恢复消息
func (n *Notifier) buildResolvedMessage(
	agent *models.Agent,
	record *models.AlertRecord,
	displayIP string,
	metadata AlertTypeMetadata,
) string {
	// 计算持续时间
	var durationStr string
	if record.FiredAt > 0 && record.ResolvedAt > record.FiredAt {
		durationMs := record.ResolvedAt - record.FiredAt
		durationStr = utils.FormatDuration(durationMs)
	}

	return fmt.Sprintf(
		"✅ %s已恢复\n\n"+
			"探针: %s (%s)\n"+
			"主机: %s\n"+
			"IP: %s\n"+
			"告警类型: %s\n"+
			"当前值: %.2f%s\n"+
			"持续时间: %s\n"+
			"恢复时间: %s",
		metadata.Name,
		agent.Name,
		agent.ID,
		agent.Hostname,
		displayIP,
		record.AlertType,
		record.ActualValue,
		metadata.ValueUnit,
		durationStr,
		utils.FormatTimestamp(record.ResolvedAt),
	)
}

// sendDingTalk 发送钉钉通知
func (n *Notifier) sendDingTalk(ctx context.Context, webhook, secret, message string) error {
	// 构造钉钉消息体
	body := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": message,
		},
	}

	// 如果有加签密钥，计算签名
	timestamp := time.Now().UnixMilli()
	if secret != "" {
		sign := n.calculateDingTalkSign(timestamp, secret)
		webhook = fmt.Sprintf("%s&timestamp=%d&sign=%s", webhook, timestamp, sign)
	}
	_, err := n.sendJSONRequest(ctx, webhook, body)
	if err != nil {
		return err
	}
	return nil
}

// calculateDingTalkSign 计算钉钉加签
func (n *Notifier) calculateDingTalkSign(timestamp int64, secret string) string {
	stringToSign := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type WeComResult struct {
	Errcode   int    `json:"errcode"`
	Errmsg    string `json:"errmsg"`
	Type      string `json:"type"`
	MediaId   string `json:"media_id"`
	CreatedAt string `json:"created_at"`
}

// sendWeCom 发送企业微信通知
func (n *Notifier) sendWeCom(ctx context.Context, webhook, message string) error {
	body := map[string]interface{}{
		"msgtype": "text",
		"text": map[string]string{
			"content": message,
		},
	}
	result, err := n.sendJSONRequest(ctx, webhook, body)
	if err != nil {
		return err
	}
	var weComResult WeComResult
	if err := json.Unmarshal(result, &weComResult); err != nil {
		return err
	}
	if weComResult.Errcode != 0 {
		return fmt.Errorf("%s", weComResult.Errmsg)
	}
	return nil
}

var wecomAppAccessTokenCache = cache.New[string, string](time.Minute)
func (n *Notifier) getWecomAppToken(ctx context.Context, origin, corpId, corpSecret string) (string, error) {
	key := fmt.Sprintf("%s#%s", corpId, corpSecret)
	if token, found := wecomAppAccessTokenCache.Get(key); found {
		return token, nil
	}

	accessTokenURL := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s", origin, corpId, corpSecret)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, accessTokenURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ErrCode     int    `json:"errcode"`
		ErrMsg      string `json:"errmsg"`
		ExpiresIn   int64  `json:"expires_in"` //Second
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	if tokenResp.ErrCode != 0 {
		return "", errors.New(tokenResp.ErrMsg)
	}

	// 提前两分钟过期
	token := tokenResp.AccessToken
	expires := time.Duration(tokenResp.ExpiresIn)*time.Second - 2*time.Minute
	wecomAppAccessTokenCache.Set(key, token, expires)
	return token, nil

}

// sendWeComApp 发送企业应用微信通知
func (n *Notifier) sendWeComApp(ctx context.Context, origin, corpId, corpSecret string, agentId int, toUser string, message string) error {
	token, err := n.getWecomAppToken(ctx, origin, corpId, corpSecret)
	if err != nil {
		return fmt.Errorf("获取企业微信应用ACCESS_TOKEN失败：%s", err)
	}

	webhook := fmt.Sprintf("%s/cgi-bin/message/send?access_token=%s", origin, token)

	body := map[string]interface{}{
		"touser":  toUser,
		"msgtype": "text",
		"agentid": agentId,
		"text": map[string]string{
			"content": message,
		},
		"safe": 0,
	}

	result, err := n.sendJSONRequest(ctx, webhook, body)
	if err != nil {
		return err
	}

	var sendRespBody struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}

	if err := json.Unmarshal(result, &sendRespBody); err != nil {
		return err
	}

	if sendRespBody.ErrCode != 0 {
		return fmt.Errorf("%s", sendRespBody.ErrMsg)
	}

	return nil
}

// sendFeishu 发送飞书通知
func (n *Notifier) sendFeishu(ctx context.Context, webhook, message string) error {
	body := map[string]interface{}{
		"msg_type": "text",
		"content": map[string]string{
			"text": message,
		},
	}

	_, err := n.sendJSONRequest(ctx, webhook, body)
	if err != nil {
		return err
	}
	return nil
}

// sendTelegram 发送 Telegram 通知
func (n *Notifier) sendTelegram(ctx context.Context, botToken, chatID, message string) error {
	// 构造 Telegram Bot API URL
	webhookURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	// 构造消息体
	body := map[string]interface{}{
		"chat_id": chatID,
		"text":    message,
		// 可选：使用 Markdown 格式
		// "parse_mode": "Markdown",
	}

	_, err := n.sendJSONRequest(ctx, webhookURL, body)
	if err != nil {
		return err
	}
	return nil
}

// sendEmail 发送邮件通知
func (n *Notifier) sendEmail(ctx context.Context, smtpHost string, smtpPort int, fromEmail, password, toEmail, subject, message string) error {
	// 创建邮件消息
	m := gomail.NewMessage()
	m.SetHeader("From", fromEmail)
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", message)

	// 创建 SMTP 拨号器
	d := gomail.NewDialer(smtpHost, smtpPort, fromEmail, password)

	// 发送邮件
	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("发送邮件失败: %w", err)
	}

	n.logger.Info("邮件发送成功",
		zap.String("from", fromEmail),
		zap.String("to", toEmail),
		zap.String("subject", subject),
	)

	return nil
}

// webhookConfig Webhook 配置
type webhookConfig struct {
	URL          string
	Method       string
	Headers      map[string]string
	BodyTemplate string
	CustomBody   string
}

// parseWebhookConfig 解析 Webhook 配置
func parseWebhookConfig(config map[string]interface{}) (*webhookConfig, error) {
	// 解析 URL
	webhookURL, ok := config["url"].(string)
	if !ok || webhookURL == "" {
		return nil, fmt.Errorf("自定义Webhook配置缺少 url")
	}

	// 获取请求方法，默认 POST
	method := "POST"
	if m, ok := config["method"].(string); ok && m != "" {
		method = strings.ToUpper(m)
	}

	// 获取自定义请求头
	headers := make(map[string]string)
	if h, ok := config["headers"].(map[string]interface{}); ok {
		for k, v := range h {
			if strVal, ok := v.(string); ok {
				headers[k] = strVal
			}
		}
	}

	// 获取请求体模板类型，默认 json
	bodyTemplate := "json"
	if bt, ok := config["bodyTemplate"].(string); ok && bt != "" {
		bodyTemplate = bt
	}

	// 获取自定义请求体
	customBody, _ := config["customBody"].(string)

	return &webhookConfig{
		URL:          webhookURL,
		Method:       method,
		Headers:      headers,
		BodyTemplate: bodyTemplate,
		CustomBody:   customBody,
	}, nil
}

// buildJSONBody 构建 JSON 格式的请求体
func (n *Notifier) buildJSONBody(agent *models.Agent, record *models.AlertRecord, message string) (io.Reader, error) {
	body := map[string]interface{}{
		"msg_type": "text",
		"text": map[string]string{
			"content": message,
		},
		"agent": map[string]interface{}{
			"id":       agent.ID,
			"name":     agent.Name,
			"hostname": agent.Hostname,
			"ip":       agent.IP,
		},
		"alert": map[string]interface{}{
			"type":        record.AlertType,
			"level":       record.Level,
			"status":      record.Status,
			"message":     record.Message,
			"threshold":   record.Threshold,
			"actualValue": record.ActualValue,
			"firedAt":     record.FiredAt,
			"resolvedAt":  record.ResolvedAt,
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化 JSON 失败: %w", err)
	}
	return bytes.NewReader(data), nil
}

// buildFormBody 构建 Form 表单格式的请求体
func (n *Notifier) buildFormBody(agent *models.Agent, record *models.AlertRecord, message string) io.Reader {
	formData := url.Values{}
	formData.Set("message", message)
	formData.Set("agent_id", agent.ID)
	formData.Set("agent_name", agent.Name)
	formData.Set("agent_hostname", agent.Hostname)
	formData.Set("agent_ip", agent.IP)
	formData.Set("alert_type", record.AlertType)
	formData.Set("alert_level", record.Level)
	formData.Set("alert_status", record.Status)
	formData.Set("alert_message", record.Message)
	formData.Set("threshold", fmt.Sprintf("%.2f", record.Threshold))
	formData.Set("actual_value", fmt.Sprintf("%.2f", record.ActualValue))
	formData.Set("fired_at", fmt.Sprintf("%d", record.FiredAt))
	if record.ResolvedAt > 0 {
		formData.Set("resolved_at", fmt.Sprintf("%d", record.ResolvedAt))
	}
	return strings.NewReader(formData.Encode())
}

// buildCustomBody 构建自定义模板格式的请求体
func (n *Notifier) buildCustomBody(agent *models.Agent, record *models.AlertRecord, message, customBody string) (io.Reader, error) {
	if customBody == "" {
		return nil, fmt.Errorf("使用 custom 模板时必须提供 customBody")
	}

	// 使用 fasttemplate 进行变量替换
	t := fasttemplate.New(customBody, "{{", "}}")
	escape := func(s string) string {
		b, _ := json.Marshal(s)
		// json.Marshal 会返回带双引号的字符串，例如 "hello\nworld"
		// 模板中不需要外层双引号，所以去掉
		return string(b[1 : len(b)-1])
	}

	bodyStr := t.ExecuteFuncString(func(w io.Writer, tag string) (int, error) {
		var v string

		switch tag {
		case "message":
			v = message
		case "agent.id":
			v = agent.ID
		case "agent.name":
			v = agent.Name
		case "agent.hostname":
			v = agent.Hostname
		case "agent.ip":
			v = agent.IP
		case "alert.type":
			v = record.AlertType
		case "alert.level":
			v = record.Level
		case "alert.status":
			v = record.Status
		case "alert.message":
			v = record.Message
		case "alert.threshold":
			v = fmt.Sprintf("%.2f", record.Threshold)
		case "alert.actualValue":
			v = fmt.Sprintf("%.2f", record.ActualValue)
		case "alert.firedAt":
			// 格式化的触发时间 (使用系统时区，Docker 中设置为 Asia/Shanghai)
			v = utils.FormatTimestamp(record.FiredAt)
		case "alert.resolvedAt":
			// 格式化的恢复时间 (使用系统时区，Docker 中设置为 Asia/Shanghai)
			v = utils.FormatTimestamp(record.ResolvedAt)
		default:
			return w.Write([]byte("{{" + tag + "}}"))
		}

		// 写入 JSON 安全转义后的值
		return w.Write([]byte(escape(v)))
	})

	n.logger.Sugar().Debugf("自定义Webhook请求体: %s", bodyStr)
	return strings.NewReader(bodyStr), nil
}

// sendHTTPRequest 发送 HTTP 请求
func (n *Notifier) sendHTTPRequest(ctx context.Context, method, webhookURL string, body io.Reader, headers map[string]string, contentType string) error {
	// 创建请求
	req, err := http.NewRequestWithContext(ctx, method, webhookURL, body)
	if err != nil {
		return fmt.Errorf("创建请求失败: %w", err)
	}

	// 设置 Content-Type
	req.Header.Set("Content-Type", contentType)

	// 设置自定义请求头
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// 发送请求
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(respBody))
	}

	n.logger.Info("自定义Webhook发送成功",
		zap.String("url", webhookURL),
		zap.String("method", method),
		zap.String("response", string(respBody)),
	)

	return nil
}

// sendCustomWebhook 发送自定义Webhook
func (n *Notifier) sendCustomWebhook(ctx context.Context, config map[string]interface{}, agent *models.Agent, record *models.AlertRecord, maskIP bool) error {
	// 解析配置
	cfg, err := parseWebhookConfig(config)
	if err != nil {
		return err
	}

	// 构建消息内容
	message := n.buildMessage(agent, record, maskIP)

	// 根据模板类型构建请求体
	var reqBody io.Reader
	var contentType string

	switch cfg.BodyTemplate {
	case "json":
		reqBody, err = n.buildJSONBody(agent, record, message)
		if err != nil {
			return err
		}
		contentType = "application/json"

	case "form":
		reqBody = n.buildFormBody(agent, record, message)
		contentType = "application/x-www-form-urlencoded"

	case "custom":
		reqBody, err = n.buildCustomBody(agent, record, message, cfg.CustomBody)
		if err != nil {
			return err
		}
		contentType = "text/plain"

	default:
		return fmt.Errorf("不支持的 bodyTemplate: %s", cfg.BodyTemplate)
	}

	// 发送 HTTP 请求
	return n.sendHTTPRequest(ctx, cfg.Method, cfg.URL, reqBody, cfg.Headers, contentType)
}

// sendJSONRequest 发送JSON请求
func (n *Notifier) sendJSONRequest(ctx context.Context, url string, body interface{}) ([]byte, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("序列化请求体失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 读取响应
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(respBody))
	}

	n.logger.Info("通知发送成功", zap.String("url", url), zap.String("response", string(respBody)))
	return respBody, nil
}

// sendDingTalkByConfig 根据配置发送钉钉通知
func (n *Notifier) sendDingTalkByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	secretKey, ok := config["secretKey"].(string)
	if !ok || secretKey == "" {
		return fmt.Errorf("钉钉配置缺少 secretKey")
	}

	// 构造 Webhook URL
	webhook := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", secretKey)

	// 检查是否有加签密钥
	signSecret, _ := config["signSecret"].(string)

	return n.sendDingTalk(ctx, webhook, signSecret, message)
}

// sendWeComByConfig 根据配置发送企业微信通知
func (n *Notifier) sendWeComByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	secretKey, ok := config["secretKey"].(string)
	if !ok || secretKey == "" {
		return fmt.Errorf("企业微信配置缺少 secretKey")
	}

	// 构造 Webhook URL
	webhook := fmt.Sprintf("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=%s", secretKey)

	return n.sendWeCom(ctx, webhook, message)
}

// sendWeComAppByConfig 根据配置发送企业微信应用通知
func (n *Notifier) sendWeComAppByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	origin := "https://qyapi.weixin.qq.com"
	if v, ok := config["origin"].(string); ok && v != "" {
		origin = v
	}

	toUser := "@all"
	if v, ok := config["toUser"].(string); ok && v != "" {
		toUser = v
	}

	corpId, ok := config["corpId"].(string)
	if !ok || corpId == "" {
		return fmt.Errorf("企业微信应用配置缺少 corpid")
	}

	corpSecret, ok := config["corpSecret"].(string)
	if !ok || corpSecret == "" {
		return fmt.Errorf("企业微信应用配置缺少 corpsecret")
	}

	agentIdf, ok := config["agentId"].(float64)
	if !ok || agentIdf <= 0 {
		return fmt.Errorf("企业微信应用配置缺少 agentid")
	}

	return n.sendWeComApp(ctx, origin, corpId, corpSecret, int(agentIdf), toUser, message)
}

// sendFeishuByConfig 根据配置发送飞书通知
func (n *Notifier) sendFeishuByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	secretKey, ok := config["secretKey"].(string)
	if !ok || secretKey == "" {
		return fmt.Errorf("飞书配置缺少 secretKey")
	}

	// 构造 Webhook URL
	webhook := fmt.Sprintf("https://open.feishu.cn/open-apis/bot/v2/hook/%s", secretKey)

	return n.sendFeishu(ctx, webhook, message)
}

// sendTelegramByConfig 根据配置发送 Telegram 通知
func (n *Notifier) sendTelegramByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	botToken, ok := config["botToken"].(string)
	if !ok || botToken == "" {
		return fmt.Errorf("Telegram 配置缺少 botToken")
	}

	chatID, ok := config["chatID"].(string)
	if !ok || chatID == "" {
		return fmt.Errorf("Telegram 配置缺少 chatID")
	}

	return n.sendTelegram(ctx, botToken, chatID, message)
}

// sendEmailByConfig 根据配置发送邮件通知
func (n *Notifier) sendEmailByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	smtpHost, ok := config["smtpHost"].(string)
	if !ok || smtpHost == "" {
		return fmt.Errorf("邮件配置缺少 smtpHost")
	}

	// 端口可能是 float64 或 string
	var smtpPort int
	switch v := config["smtpPort"].(type) {
	case float64:
		smtpPort = int(v)
	case string:
		port, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("邮件配置 smtpPort 格式错误: %w", err)
		}
		smtpPort = port
	default:
		return fmt.Errorf("邮件配置缺少 smtpPort")
	}

	fromEmail, ok := config["fromEmail"].(string)
	if !ok || fromEmail == "" {
		return fmt.Errorf("邮件配置缺少 fromEmail")
	}

	password, ok := config["password"].(string)
	if !ok || password == "" {
		return fmt.Errorf("邮件配置缺少 password")
	}

	toEmail, ok := config["toEmail"].(string)
	if !ok || toEmail == "" {
		return fmt.Errorf("邮件配置缺少 toEmail")
	}

	// 邮件主题，默认为"Sentinel 告警通知"
	subject, ok := config["subject"].(string)
	if !ok || subject == "" {
		subject = "Sentinel 告警通知"
	}

	return n.sendEmail(ctx, smtpHost, smtpPort, fromEmail, password, toEmail, subject, message)
}

// sendWebhookByConfig 根据配置发送自定义Webhook
func (n *Notifier) sendWebhookByConfig(ctx context.Context, config map[string]interface{}, agent *models.Agent, record *models.AlertRecord, maskIP bool) error {
	return n.sendCustomWebhook(ctx, config, agent, record, maskIP)
}

// SendNotificationByConfig 根据新的配置结构发送通知
func (n *Notifier) SendNotificationByConfig(ctx context.Context, channelConfig *models.NotificationChannelConfig, record *models.AlertRecord, agent *models.Agent, maskIP bool) error {
	if !channelConfig.Enabled {
		return fmt.Errorf("通知渠道已禁用")
	}

	n.logger.Info("发送通知",
		zap.String("channelType", channelConfig.Type),
	)

	// 构造通知消息内容
	message := n.buildMessage(agent, record, maskIP)

	switch channelConfig.Type {
	case "dingtalk":
		return n.sendDingTalkByConfig(ctx, channelConfig.Config, message)
	case "wecom":
		return n.sendWeComByConfig(ctx, channelConfig.Config, message)
	case "wecomApp":
		return n.sendWeComAppByConfig(ctx, channelConfig.Config, message)
	case "feishu":
		return n.sendFeishuByConfig(ctx, channelConfig.Config, message)
	case "telegram":
		return n.sendTelegramByConfig(ctx, channelConfig.Config, message)
	case "email":
		return n.sendEmailByConfig(ctx, channelConfig.Config, message)
	case "webhook":
		return n.sendWebhookByConfig(ctx, channelConfig.Config, agent, record, maskIP)
	default:
		return fmt.Errorf("不支持的通知渠道类型: %s", channelConfig.Type)
	}
}

// SendNotificationByConfigs 根据新的配置结构向多个渠道发送通知
func (n *Notifier) SendNotificationByConfigs(ctx context.Context, channelConfigs []models.NotificationChannelConfig, record *models.AlertRecord, agent *models.Agent, maskIP bool) error {
	var errs []error

	for _, channelConfig := range channelConfigs {
		if err := n.SendNotificationByConfig(ctx, &channelConfig, record, agent, maskIP); err != nil {
			n.logger.Error("发送通知失败",
				zap.String("channelType", channelConfig.Type),
				zap.Error(err),
			)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("部分通知发送失败: %v", errs)
	}

	return nil
}

// SendDingTalkByConfig 导出方法供外部调用
func (n *Notifier) SendDingTalkByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendDingTalkByConfig(ctx, config, message)
}

// SendWeComByConfig 导出方法供外部调用
func (n *Notifier) SendWeComByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendWeComByConfig(ctx, config, message)
}

// SendWeComAppByConfig 导出方法供外部调用
func (n *Notifier) SendWeComAppByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendWeComAppByConfig(ctx, config, message)
}

// SendFeishuByConfig 导出方法供外部调用
func (n *Notifier) SendFeishuByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendFeishuByConfig(ctx, config, message)
}

// SendTelegramByConfig 导出方法供外部调用
func (n *Notifier) SendTelegramByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendTelegramByConfig(ctx, config, message)
}

// SendEmailByConfig 导出方法供外部调用
func (n *Notifier) SendEmailByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	return n.sendEmailByConfig(ctx, config, message)
}

// SendWebhookByConfig 导出方法供外部调用（测试用）
func (n *Notifier) SendWebhookByConfig(ctx context.Context, config map[string]interface{}, message string) error {
	// 为了测试，创建一个临时的 agent 和 record
	agent := &models.Agent{
		ID:       "test-agent",
		Name:     "测试探针",
		Hostname: "test-host",
		IP:       "127.0.0.1",
	}
	record := &models.AlertRecord{
		AlertType:   "test",
		Level:       "info",
		Status:      "firing",
		Message:     message,
		Threshold:   0,
		ActualValue: 0,
		FiredAt:     time.Now().UnixMilli(),
	}
	return n.sendWebhookByConfig(ctx, config, agent, record, false)
}

// SendTestNotification 发送测试通知（动态匹配通知渠道类型）
func (n *Notifier) SendTestNotification(ctx context.Context, channelType string, config map[string]interface{}, message string) error {
	switch channelType {
	case "dingtalk":
		return n.sendDingTalkByConfig(ctx, config, message)
	case "wecom":
		return n.sendWeComByConfig(ctx, config, message)
	case "wecomApp":
		return n.sendWeComAppByConfig(ctx, config, message)
	case "feishu":
		return n.sendFeishuByConfig(ctx, config, message)
	case "telegram":
		return n.sendTelegramByConfig(ctx, config, message)
	case "email":
		return n.sendEmailByConfig(ctx, config, message)
	case "webhook":
		// Webhook 需要 agent 和 record，创建测试数据
		agent := &models.Agent{
			ID:       "test-agent",
			Name:     "测试探针",
			Hostname: "test-host",
			IP:       "127.0.0.1",
		}
		record := &models.AlertRecord{
			AlertType:   "test",
			Level:       "info",
			Status:      "firing",
			Message:     message,
			Threshold:   0,
			ActualValue: 0,
			FiredAt:     time.Now().UnixMilli(),
		}
		return n.sendWebhookByConfig(ctx, config, agent, record, false)
	default:
		return fmt.Errorf("不支持的通知渠道类型: %s", channelType)
	}
}
