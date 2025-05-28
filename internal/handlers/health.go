package handlers

import (
	"net/http"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/utils"
	"github.com/gin-gonic/gin"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

func (h *HealthHandler) HealthCheck(c *gin.Context) {
	response := gin.H{
		"status":  "healthy",
		"service": "prism-auth-service",
		"version": "1.0.0",
	}

	utils.SuccessResponse(c, "Service is healthy", response)
}

func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	// TODO: Add actual readiness checks (database connectivity, etc.)
	response := gin.H{
		"status":  "ready",
		"service": "prism-auth-service",
		"version": "1.0.0",
	}

	c.JSON(http.StatusOK, response)
}
