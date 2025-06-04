package handlers

import (
	"net/http"
	// <-- [TAMBAHKAN]
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/services"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger" // <-- [TAMBAHKAN]
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/utils"
	"github.com/gin-gonic/gin"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	// Get tenant ID from header if not provided in request
	if req.TenantID == "" {
		if tenantID, exists := c.Get("tenant_id"); exists {
			req.TenantID = tenantID.(string)
		} else {
			req.TenantID = "default"
		}
	}

	response, err := h.authService.Login(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Login failed", err)
		return
	}

	utils.SuccessResponse(c, "Login successful", response)
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	// Get tenant ID from header if not provided in request
	if req.TenantID == "" {
		if tenantID, exists := c.Get("tenant_id"); exists {
			req.TenantID = tenantID.(string)
		} else {
			req.TenantID = "default"
		}
	}

	response, err := h.authService.Register(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Registration failed", err)
		return
	}

	utils.SuccessResponse(c, "Registration successful", response)
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	response, err := h.authService.RefreshToken(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusUnauthorized, "Token refresh failed", err)
		return
	}

	utils.SuccessResponse(c, "Token refreshed successfully", response)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	// Untuk logout, kita idealnya membutuhkan refresh token untuk dicabut.
	// Refresh token biasanya tidak dikirim di Authorization header.
	// Pilihan:
	// 1. Client mengirim refresh token di body JSON.
	// 2. Client mengirim access token di Auth header, server mencari refresh token terkait (lebih kompleks, perlu mapping).
	// Kita akan pakai opsi 1 untuk kesederhanaan.

	var req models.RefreshTokenRequest // Menggunakan model yang sama karena hanya butuh refresh_token
	if err := c.ShouldBindJSON(&req); err != nil {
		commonLogger.Warnf("Logout: Bad request for logout: %v", err)
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid request payload", err)
		return
	}

	if req.RefreshToken == "" {
		commonLogger.Warn("Logout: Refresh token not provided in request.")
		utils.ErrorResponse(c, http.StatusBadRequest, "Refresh token required", nil)
		return
	}

	err := h.authService.Logout(req.RefreshToken)
	if err != nil {
		// Jangan ekspos error detail ke client untuk logout
		commonLogger.Errorf("Logout: Service error during logout: %v", err)
		utils.ErrorResponse(c, http.StatusInternalServerError, "Logout failed", nil) // Error generik
		return
	}

	utils.SuccessResponse(c, "Logout successful", nil)
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	// Get tenant ID from header if not provided in request
	if req.TenantID == "" {
		if tenantID, exists := c.Get("tenant_id"); exists {
			req.TenantID = tenantID.(string)
		} else {
			req.TenantID = "default"
		}
	}

	err := h.authService.ForgotPassword(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Password reset request failed", err)
		return
	}

	utils.SuccessResponse(c, "Password reset email sent", nil)
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	err := h.authService.ResetPassword(&req)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Password reset failed", err)
		return
	}

	utils.SuccessResponse(c, "Password reset successful", nil)
}
