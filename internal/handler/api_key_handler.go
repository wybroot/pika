package handler

import (
	"github.com/wybroot/sentinel/internal/service"
	"github.com/go-orz/orz"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

type ApiKeyHandler struct {
	logger        *zap.Logger
	apiKeyService *service.ApiKeyService
}

func NewApiKeyHandler(logger *zap.Logger, apiKeyService *service.ApiKeyService) *ApiKeyHandler {
	return &ApiKeyHandler{
		logger:        logger,
		apiKeyService: apiKeyService,
	}
}

// GenerateApiKeyRequest 生成API密钥请求
type GenerateApiKeyRequest struct {
	Name string `json:"name" validate:"required"`
}

// UpdateApiKeyNameRequest 更新API密钥名称请求
type UpdateApiKeyNameRequest struct {
	Name string `json:"name" validate:"required"`
}

// Paging API密钥分页查询
func (r ApiKeyHandler) Paging(c echo.Context) error {
	name := c.QueryParam("name")

	pr := orz.GetPageRequest(c, "created_at", "name")

	builder := orz.NewPageBuilder(r.apiKeyService.ApiKeyRepo).
		PageRequest(pr).
		Contains("name", name)

	ctx := c.Request().Context()
	page, err := builder.Execute(ctx)
	if err != nil {
		return err
	}

	// 返回完整密钥,由前端控制显示/隐藏
	return orz.Ok(c, orz.Map{
		"items": page.Items,
		"total": page.Total,
	})
}

// Create 生成API密钥
func (r ApiKeyHandler) Create(c echo.Context) error {
	var req GenerateApiKeyRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	if err := c.Validate(&req); err != nil {
		return err
	}

	// 从上下文获取用户ID
	userID := c.Get("userID").(string)

	ctx := c.Request().Context()
	apiKey, err := r.apiKeyService.GenerateApiKey(ctx, req.Name, userID)
	if err != nil {
		r.logger.Error("failed to generate api key", zap.Error(err))
		return err
	}

	return orz.Ok(c, apiKey)
}

// Get 获取API密钥详情
func (r ApiKeyHandler) Get(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	apiKey, err := r.apiKeyService.GetApiKey(ctx, id)
	if err != nil {
		r.logger.Error("failed to get api key", zap.Error(err))
		return err
	}

	// 返回完整密钥,由前端控制显示/隐藏
	return orz.Ok(c, apiKey)
}

// Update 更新API密钥名称
func (r ApiKeyHandler) Update(c echo.Context) error {
	id := c.Param("id")

	var req UpdateApiKeyNameRequest
	if err := c.Bind(&req); err != nil {
		return err
	}
	if err := c.Validate(&req); err != nil {
		return err
	}

	ctx := c.Request().Context()
	if err := r.apiKeyService.UpdateApiKeyName(ctx, id, req.Name); err != nil {
		r.logger.Error("failed to update api key name", zap.Error(err))
		return err
	}

	return orz.Ok(c, orz.Map{
		"message": "API密钥名称更新成功",
	})
}

// Delete 删除API密钥
func (r ApiKeyHandler) Delete(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	if err := r.apiKeyService.DeleteApiKey(ctx, id); err != nil {
		r.logger.Error("failed to delete api key", zap.Error(err))
		return err
	}

	return orz.Ok(c, orz.Map{
		"message": "API密钥删除成功",
	})
}

// Enable 启用API密钥
func (r ApiKeyHandler) Enable(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	if err := r.apiKeyService.EnableApiKey(ctx, id); err != nil {
		r.logger.Error("failed to enable api key", zap.Error(err))
		return err
	}

	return orz.Ok(c, orz.Map{
		"message": "API密钥启用成功",
	})
}

// Disable 禁用API密钥
func (r ApiKeyHandler) Disable(c echo.Context) error {
	id := c.Param("id")
	ctx := c.Request().Context()

	if err := r.apiKeyService.DisableApiKey(ctx, id); err != nil {
		r.logger.Error("failed to disable api key", zap.Error(err))
		return err
	}

	return orz.Ok(c, orz.Map{
		"message": "API密钥禁用成功",
	})
}
