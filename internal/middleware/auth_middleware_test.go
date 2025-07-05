// File: services/prism-auth-service/internal/middleware/auth_middleware_test.go
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonauth "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9" // <<<<<<<<<<< BARU: Import redismock
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthService adalah mock lengkap untuk service.AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, user *model.User, password string) (string, error) {
	args := m.Called(ctx, user, password)
	return args.String(0), args.Error(1)
}
func (m *MockAuthService) Login(ctx context.Context, email, password string) (*service.LoginStep1Response, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.LoginStep1Response), args.Error(1)
}
func (m *MockAuthService) RefreshToken(ctx context.Context, refreshTokenString string) (*service.AuthTokens, error) {
	args := m.Called(ctx, refreshTokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}
func (m *MockAuthService) Logout(ctx context.Context, claims jwt.MapClaims) error {
	return m.Called(ctx, claims).Error(0)
}
func (m *MockAuthService) GenerateGoogleLoginURL(state string) string {
	return m.Called(state).String(0)
}
func (m *MockAuthService) ProcessGoogleCallback(ctx context.Context, code string) (*service.AuthTokens, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}
func (m *MockAuthService) GenerateMicrosoftLoginURL(state string) string {
	return m.Called(state).String(0)
}
func (m *MockAuthService) ProcessMicrosoftCallback(ctx context.Context, code string) (*service.AuthTokens, error) {
	args := m.Called(ctx, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}
func (m *MockAuthService) Setup2FA(ctx context.Context, userID, email string) (*service.TwoFASetup, error) {
	args := m.Called(ctx, userID, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.TwoFASetup), args.Error(1)
}
func (m *MockAuthService) VerifyAndEnable2FA(ctx context.Context, userID, totpSecret, code string) error {
	return m.Called(ctx, userID, totpSecret, code).Error(0)
}
func (m *MockAuthService) VerifyLogin2FA(ctx context.Context, email, code string) (*service.AuthTokens, error) {
	args := m.Called(ctx, email, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}
func (m *MockAuthService) ForgotPassword(ctx context.Context, email string) error {
	return m.Called(ctx, email).Error(0)
}
func (m *MockAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return m.Called(ctx, token, newPassword).Error(0)
}
func (m *MockAuthService) CreateAPIKey(ctx context.Context, userID, description string) (string, error) {
	args := m.Called(ctx, userID, description)
	return args.String(0), args.Error(1)
}
func (m *MockAuthService) GetAPIKeys(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.APIKeyMetadata), args.Error(1)
}
func (m *MockAuthService) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	return m.Called(ctx, userID, keyID).Error(0)
}
func (m *MockAuthService) ValidateAPIKey(ctx context.Context, apiKeyString string) (*model.User, error) {
	args := m.Called(ctx, apiKeyString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
func (m *MockAuthService) GenerateImpersonationToken(ctx context.Context, targetUser *model.User, actorID string) (string, time.Time, error) {
	args := m.Called(ctx, targetUser, actorID)
	return args.String(0), args.Get(1).(time.Time), args.Error(2)
}
func (m *MockAuthService) RegisterWithInvitation(ctx context.Context, token, firstName, lastName, password string) (*service.AuthTokens, error) {
	args := m.Called(ctx, token, firstName, lastName, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*service.AuthTokens), args.Error(1)
}

// ## PERBAIKAN: Ubah signature fungsi untuk menerima redis mock ##
func setupMiddlewareTest() (*gin.Engine, *MockAuthService, redismock.ClientMock) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockService := new(MockAuthService)
	// Buat redis mock
	redisClient, mockRedis := redismock.NewClientMock()

	// ## PERBAIKAN: Suntikkan redis mock saat memanggil middleware ##
	router.Use(FlexibleAuthMiddleware(mockService, redisClient))

	router.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get(commonauth.UserIDKey)
		c.JSON(http.StatusOK, gin.H{"status": "ok", "user_id": userID})
	})

	return router, mockService, mockRedis
}

func TestFlexibleAuthMiddleware(t *testing.T) {
	t.Setenv("JWT_SECRET_KEY", "test-secret")
	t.Setenv("REDIS_ADDR", "localhost:6379")

	t.Run("Success with API Key", func(t *testing.T) {
		// ## PERBAIKAN: Tangkap mockRedis yang tidak digunakan agar test tidak error.
		router, mockService, _ := setupMiddlewareTest()

		apiKey := "my-secret-api-key"
		user := &model.User{ID: "user-from-apikey", Email: "api@example.com", RoleName: "APIUser"}

		mockService.On("ValidateAPIKey", mock.Anything, apiKey).Return(user, nil).Once()

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", apiKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "user-from-apikey", resp["user_id"])
		mockService.AssertExpectations(t)
	})

	t.Run("Success with Bearer Token", func(t *testing.T) {
		// ## PERBAIKAN: Setup redis mock untuk JWT flow
		router, _, mockRedis := setupMiddlewareTest()

		claims := jwt.MapClaims{
			"sub": "user-from-jwt",
			"jti": "jwt-id-123",
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("test-secret"))
		require.NoError(t, err)

		// Mock ekspektasi Redis: Get akan dipanggil dan harus mengembalikan error 'redis.Nil' (key tidak ditemukan)
		mockRedis.ExpectGet("jwt-id-123").RedisNil()

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp map[string]string
		err = json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err)
		assert.Equal(t, "user-from-jwt", resp["user_id"])
		require.NoError(t, mockRedis.ExpectationsWereMet(), "Ekspektasi Redis tidak terpenuhi")
	})

	t.Run("Failure - No Auth Header", func(t *testing.T) {
		router, _, _ := setupMiddlewareTest()

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Authorization header required")
	})

	t.Run("Failure - Invalid API Key", func(t *testing.T) {
		router, mockService, _ := setupMiddlewareTest()
		apiKey := "invalid-api-key"

		mockService.On("ValidateAPIKey", mock.Anything, apiKey).Return(nil, errors.New("invalid key")).Once()

		req, _ := http.NewRequest(http.MethodGet, "/protected", nil)
		req.Header.Set("X-API-Key", apiKey)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid API Key")
		mockService.AssertExpectations(t)
	})
}
