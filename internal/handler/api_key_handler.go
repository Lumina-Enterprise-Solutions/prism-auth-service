package handler

import (
	"net/http"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonauth "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
	"github.com/gin-gonic/gin"
)

// APIKeyHandler menangani semua permintaan HTTP yang berkaitan dengan manajemen API Key.
type APIKeyHandler struct {
	authService service.AuthService
}

// NewAPIKeyHandler membuat instance baru dari APIKeyHandler.
func NewAPIKeyHandler(authService service.AuthService) *APIKeyHandler {
	return &APIKeyHandler{authService: authService}
}

// CreateAPIKey menangani permintaan POST /auth/keys
// untuk membuat API key baru.
func (h *APIKeyHandler) CreateAPIKey(c *gin.Context) {
	// Ambil userID dari token JWT yang sudah divalidasi oleh middleware
	userID, err := commonauth.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: " + err.Error()})
		return
	}

	var req struct {
		Description string `json:"description" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body: 'description' is required."})
		return
	}

	// Panggil service untuk membuat key.
	// Service akan mengembalikan key asli (plaintext) HANYA SEKALI saat pembuatan.
	apiKeyString, err := h.authService.CreateAPIKey(c.Request.Context(), userID, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create API key", "details": err.Error()})
		return
	}

	// Kirim response yang berisi key asli.
	// Tekankan di dokumentasi API bahwa key ini tidak akan bisa dilihat lagi.
	c.JSON(http.StatusCreated, gin.H{
		"message": "API Key created successfully. Please save this key securely, it will not be shown again.",
		"api_key": apiKeyString,
	})
}

// GetAPIKeys menangani permintaan GET /auth/keys
// untuk mendapatkan daftar metadata API key milik pengguna.
func (h *APIKeyHandler) GetAPIKeys(c *gin.Context) {
	userID, err := commonauth.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: " + err.Error()})
		return
	}

	// Panggil service untuk mendapatkan semua metadata key untuk user ini.
	// Ini tidak akan mengembalikan key rahasianya.
	keys, err := h.authService.GetAPIKeys(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve API keys", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, keys)
}

// RevokeAPIKey menangani permintaan DELETE /auth/keys/:id
// untuk mencabut (menonaktifkan) sebuah API key.
func (h *APIKeyHandler) RevokeAPIKey(c *gin.Context) {
	userID, err := commonauth.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: " + err.Error()})
		return
	}

	// Ambil ID key dari parameter URL
	keyID := c.Param("id")
	if keyID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "API Key ID is required in the URL path."})
		return
	}

	// Panggil service untuk mencabut key.
	// Service akan memastikan bahwa user hanya bisa mencabut key miliknya sendiri.
	err = h.authService.RevokeAPIKey(c.Request.Context(), userID, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke API key", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "API Key has been successfully revoked."})
}
