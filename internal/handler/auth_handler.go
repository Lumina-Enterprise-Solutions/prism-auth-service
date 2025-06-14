package handler

import (
	"net/http"

	"crypto/rand"
	"encoding/hex"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonjwt "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct {
	authService service.AuthService
}

func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
	// TAMBAHKAN field FirstName dan LastName
	type RegisterRequest struct {
		Email     string `json:"email" binding:"required,email"`
		Password  string `json:"password" binding:"required,min=8"`
		FirstName string `json:"first_name" binding:"required"`
		LastName  string `json:"last_name" binding:"required"`
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// UBAH: Buat objek User dari request untuk diteruskan ke service
	user := &model.User{
		Email:     req.Email,
		FirstName: req.FirstName, // Gunakan pointer jika modelnya pointer
		LastName:  req.LastName,
	}

	// UBAH: Panggil service dengan objek user dan password
	userID, err := h.authService.Register(c.Request.Context(), user, req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"userId":  userID,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	type LoginRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil { /* ... */
	}

	// Panggil service yang sekarang mengembalikan response tahap 1
	resp, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// func (h *AuthHandler) Login(c *gin.Context) {
// 	type LoginRequest struct {
// 		Email    string `json:"email" binding:"required,email"`
// 		Password string `json:"password" binding:"required"`
// 	}

// 	var req LoginRequest
// 	if err := c.ShouldBindJSON(&req); err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
// 		return
// 	}

// 	tokens, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)
// 	if err != nil {
// 		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
// 		return
// 	}

// 	// Untuk keamanan, refresh token sebaiknya dikirim via http-only cookie
// 	// Tapi untuk kesederhanaan API, kita kirim di body dulu.
// 	c.JSON(http.StatusOK, tokens)
// }

func (h *AuthHandler) Profile(c *gin.Context) {
	// Get userId from the context set by the JWTMiddleware
	userId, err := commonjwt.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// In a real application, you would fetch user data from DB using this ID.
	c.JSON(http.StatusOK, gin.H{
		"message":             "Welcome to your profile! (Auth Service)",
		"userId_from_context": userId,
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	type RefreshRequest struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		// Jika token tidak valid, kembalikan 401 agar client tahu harus login ulang.
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}
func (h *AuthHandler) Logout(c *gin.Context) {
	// Ambil claims yang sudah divalidasi dan disimpan oleh JWTMiddleware
	claims, exists := c.Get("claims")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Claims not found in context"})
		return
	}

	mapClaims, ok := claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid claims format in context"})
		return
	}

	err := h.authService.Logout(c.Request.Context(), mapClaims)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	// Buat state random untuk proteksi CSRF
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	// Simpan state di cookie yang aman (http-only, samesite)
	// Cookie ini hanya perlu hidup sebentar (misal 10 menit)
	c.SetCookie("oauthstate", state, 600, "/", "localhost", true, true)

	// Buat URL redirect dan arahkan pengguna ke sana
	url := h.authService.GenerateGoogleLoginURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	// 1. Validasi state untuk mencegah CSRF
	oauthState, _ := c.Cookie("oauthstate")
	if c.Query("state") != oauthState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return
	}

	// 2. Proses callback menggunakan kode otorisasi
	code := c.Query("code")
	tokens, err := h.authService.ProcessGoogleCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process Google callback", "details": err.Error()})
		return
	}

	// 3. Kirimkan token internal kita ke pengguna
	c.JSON(http.StatusOK, tokens)
}
func (h *AuthHandler) MicrosoftLogin(c *gin.Context) {
	// Alur membuat state dan cookie SAMA PERSIS dengan GoogleLogin
	stateBytes := make([]byte, 16)
	rand.Read(stateBytes)
	state := hex.EncodeToString(stateBytes)

	c.SetCookie("oauthstate", state, 600, "/", "localhost", true, true)

	url := h.authService.GenerateMicrosoftLoginURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *AuthHandler) MicrosoftCallback(c *gin.Context) {
	// Alur validasi state dan menukar kode SAMA PERSIS dengan GoogleCallback
	oauthState, _ := c.Cookie("oauthstate")
	if c.Query("state") != oauthState {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return
	}

	code := c.Query("code")
	tokens, err := h.authService.ProcessMicrosoftCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process Microsoft callback", "details": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}
func (h *AuthHandler) Setup2FA(c *gin.Context) {
	userID, err := commonjwt.GetUserID(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Kita perlu email user untuk label QR code
	claims, _ := c.Get("claims")
	email := claims.(jwt.MapClaims)["email"].(string)

	setupInfo, err := h.authService.Setup2FA(c.Request.Context(), userID, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to setup 2FA"})
		return
	}

	c.JSON(http.StatusOK, setupInfo)
}

func (h *AuthHandler) Verify2FA(c *gin.Context) {
	type VerifyRequest struct {
		Secret string `json:"secret" binding:"required"`
		Code   string `json:"code" binding:"required"`
	}
	var req VerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID, _ := commonjwt.GetUserID(c)

	err := h.authService.VerifyAndEnable2FA(c.Request.Context(), userID, req.Secret, req.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Mungkin kode salah
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA enabled successfully"})
}

func (h *AuthHandler) LoginWith2FA(c *gin.Context) {
	type Login2FARequest struct {
		Email string `json:"email" binding:"required,email"`
		Code  string `json:"code" binding:"required"`
	}
	var req Login2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.authService.VerifyLogin2FA(c.Request.Context(), req.Email, req.Code)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}
