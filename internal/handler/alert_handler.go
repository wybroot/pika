package handler

import (
	"net/http"

	"github.com/wybroot/sentinel/internal/service"
	"github.com/go-orz/orz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type AlertHandler struct {
	logger       *zap.Logger
	alertService *service.AlertService
}

func NewAlertHandler(logger *zap.Logger, alertService *service.AlertService) *AlertHandler {
	return &AlertHandler{
		logger:       logger,
		alertService: alertService,
	}
}

// ListAlertRecords 列出告警记录
func (h *AlertHandler) ListAlertRecords(c echo.Context) error {
	agentID := c.QueryParam("agentId")

	pr := orz.GetPageRequest(c, "createdAt", "firedAt")

	builder := orz.NewPageBuilder(h.alertService.AlertRecordRepo.Repository).
		PageRequest(pr)

	if agentID != "" {
		builder.Equal("agent_id", agentID)
	}

	ctx := c.Request().Context()
	page, err := builder.Execute(ctx)
	if err != nil {
		h.logger.Error("获取告警记录失败", zap.Error(err))
		return err
	}

	return orz.Ok(c, page)
}

// ClearAlertRecords 清空告警记录
func (h *AlertHandler) ClearAlertRecords(c echo.Context) error {
	if err := h.alertService.Clear(c.Request().Context()); err != nil {
		h.logger.Error("清空告警记录失败", zap.Error(err))
		return c.JSON(http.StatusInternalServerError, map[string]string{
			"error": "清空告警记录失败",
		})
	}

	return c.JSON(http.StatusOK, map[string]string{
		"message": "清空成功",
	})
}
