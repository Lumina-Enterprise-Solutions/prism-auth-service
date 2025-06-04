// File: prism-auth-service/internal/handlers/user.go
package handlers

import (
	"net/http"
	"strconv"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/services"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type UserHandler struct {
	userService *services.UserService
	authService *services.AuthService // Pastikan field ini ada dan digunakan
}

// [MODIFIKASI] Konstruktor sekarang menerima userService dan authService
func NewUserHandler(userService *services.UserService, authService *services.AuthService) *UserHandler {
	return &UserHandler{
		userService: userService,
		authService: authService, // Inisialisasi authService
	}
}

func (h *UserHandler) GetUsers(c *gin.Context) {
	tenantID := h.getTenantID(c)

	// Parse query parameters
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "10"))

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 10
	}

	users, total, err := h.userService.GetUsers(tenantID, page, limit)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get users", err)
		return
	}

	response := gin.H{
		"users": users,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	}

	utils.SuccessResponse(c, "Users retrieved successfully", response)
}

func (h *UserHandler) GetUser(c *gin.Context) {
	tenantID := h.getTenantID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	user, err := h.userService.GetUser(id, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "User not found", err)
		return
	}

	utils.SuccessResponse(c, "User retrieved successfully", user)
}

func (h *UserHandler) UpdateUser(c *gin.Context) {
	tenantID := h.getTenantID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	var req models.UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	user, err := h.userService.UpdateUser(id, &req, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to update user", err)
		return
	}

	utils.SuccessResponse(c, "User updated successfully", user)
}

func (h *UserHandler) DeleteUser(c *gin.Context) {
	tenantID := h.getTenantID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid user ID", err)
		return
	}

	err = h.userService.DeleteUser(id, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to delete user", err)
		return
	}

	utils.SuccessResponse(c, "User deleted successfully", nil)
}

func (h *UserHandler) GetProfile(c *gin.Context) {
	tenantID := h.getTenantID(c)
	userID := h.getUserID(c)

	user, err := h.userService.GetUser(userID, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusNotFound, "Profile not found", err)
		return
	}

	utils.SuccessResponse(c, "Profile retrieved successfully", user)
}

func (h *UserHandler) UpdateProfile(c *gin.Context) {
	tenantID := h.getTenantID(c)
	userID := h.getUserID(c)

	var req models.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	user, err := h.userService.UpdateProfile(userID, &req, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to update profile", err)
		return
	}

	utils.SuccessResponse(c, "Profile updated successfully", user)
}

func (h *UserHandler) ChangePassword(c *gin.Context) {
	tenantID := h.getTenantID(c)
	userID := h.getUserID(c)

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	// Pastikan authService tidak nil sebelum dipanggil
	if h.authService == nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Internal server error: auth service not configured for user handler", nil)
		return
	}
	err := h.authService.ChangePassword(userID, &req, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to change password", err)
		return
	}

	utils.SuccessResponse(c, "Password changed successfully", nil)
}

// Role management handlers
func (h *UserHandler) GetRoles(c *gin.Context) {
	tenantID := h.getTenantID(c)

	roles, err := h.userService.GetRoles(tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusInternalServerError, "Failed to get roles", err)
		return
	}

	utils.SuccessResponse(c, "Roles retrieved successfully", roles)
}

func (h *UserHandler) CreateRole(c *gin.Context) {
	tenantID := h.getTenantID(c)

	var req models.CreateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	role, err := h.userService.CreateRole(&req, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to create role", err)
		return
	}

	utils.SuccessResponse(c, "Role created successfully", role)
}

func (h *UserHandler) UpdateRole(c *gin.Context) {
	tenantID := h.getTenantID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	var req models.UpdateRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		validationErrors := utils.FormatValidationErrors(err)
		utils.ValidationErrorResponse(c, validationErrors)
		return
	}

	role, err := h.userService.UpdateRole(id, &req, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to update role", err)
		return
	}

	utils.SuccessResponse(c, "Role updated successfully", role)
}

func (h *UserHandler) DeleteRole(c *gin.Context) {
	tenantID := h.getTenantID(c)

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Invalid role ID", err)
		return
	}

	err = h.userService.DeleteRole(id, tenantID)
	if err != nil {
		utils.ErrorResponse(c, http.StatusBadRequest, "Failed to delete role", err)
		return
	}

	utils.SuccessResponse(c, "Role deleted successfully", nil)
}

// Helper methods
func (h *UserHandler) getTenantID(c *gin.Context) string {
	if tenantID, exists := c.Get("tenant_id"); exists {
		if tidStr, ok := tenantID.(string); ok {
			return tidStr
		}
	}
	return "default" // Default tenant
}

func (h *UserHandler) getUserID(c *gin.Context) uuid.UUID {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil // Atau handle error jika user_id wajib ada
	}

	userIDStr, ok := userIDVal.(string)
	if !ok {
		return uuid.Nil // Atau handle error
	}

	parsedID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil // Atau handle error
	}
	return parsedID
}
