// File: internal/handler/auth_handler_test.go
package handler

import (
	"bytes"
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
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthService is the single, correct mock for the service.AuthService interface.
// It will be used for all handler tests.
type MockAuthService struct {
	mock.Mock
}

// Implement the service.AuthService interface for the mock
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

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	return router
}

// --- AuthHandler Tests ---

func TestAuthHandler_Login(t *testing.T) {
	// FIX: Berikan nil untuk argumen samlSP saat membuat handler.
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService, nil) // Memberikan nil untuk middleware SAML

	router := setupRouter()
	router.POST("/login", handler.Login)

	t.Run("Success - No 2FA", func(t *testing.T) {
		loginReq := map[string]string{"email": "test@example.com", "password": "password"}
		jsonBody, _ := json.Marshal(loginReq)

		loginResp := &service.LoginStep1Response{
			Is2FARequired: false,
			AuthTokens:    &service.AuthTokens{AccessToken: "access", RefreshToken: "refresh"},
		}

		mockService.On("Login", mock.Anything, loginReq["email"], loginReq["password"]).Return(loginResp, nil).Once()

		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var respBody service.LoginStep1Response
		err := json.Unmarshal(w.Body.Bytes(), &respBody)
		require.NoError(t, err, "Gagal unmarshal response body")
		assert.Equal(t, loginResp.AuthTokens.AccessToken, respBody.AuthTokens.AccessToken)
		mockService.AssertExpectations(t)
	})

	t.Run("Failure - Invalid Credentials", func(t *testing.T) {
		loginReq := map[string]string{"email": "test@example.com", "password": "wrongpassword"}
		jsonBody, _ := json.Marshal(loginReq)

		mockService.On("Login", mock.Anything, loginReq["email"], loginReq["password"]).Return(nil, errors.New("invalid credentials")).Once()

		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Failure - Bad Request", func(t *testing.T) {
		loginReq := map[string]string{"email": "test@example.com"}
		jsonBody, _ := json.Marshal(loginReq)

		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAuthHandler_Register(t *testing.T) {
	mockService := new(MockAuthService)
	// FIX: Berikan nil untuk argumen samlSP saat membuat handler.
	handler := NewAuthHandler(mockService, nil)
	router := setupRouter()
	router.POST("/register", handler.Register)

	t.Run("Success", func(t *testing.T) {
		registerReq := map[string]string{
			"email":      "new@example.com",
			"password":   "password123",
			"first_name": "New",
			"last_name":  "User",
		}
		jsonBody, _ := json.Marshal(registerReq)

		mockService.On("Register", mock.Anything, mock.AnythingOfType("*model.User"), "password123").Return("new-user-id", nil).Once()

		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err, "Gagal unmarshal response body")
		assert.Equal(t, "new-user-id", resp["userId"])
		mockService.AssertExpectations(t)
	})
}

func TestAuthHandler_Logout(t *testing.T) {
	mockService := new(MockAuthService)
	// FIX: Berikan nil untuk argumen samlSP saat membuat handler.
	handler := NewAuthHandler(mockService, nil)
	router := setupRouter()

	router.Use(func(c *gin.Context) {
		c.Set(commonauth.ClaimsKey, jwt.MapClaims{"jti": "jwt-id", "exp": float64(time.Now().Add(1 * time.Hour).Unix())})
		c.Next()
	})
	router.POST("/logout", handler.Logout)

	t.Run("Success", func(t *testing.T) {
		mockService.On("Logout", mock.Anything, mock.AnythingOfType("jwt.MapClaims")).Return(nil).Once()

		req, _ := http.NewRequest(http.MethodPost, "/logout", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})
}

// --- APIKeyHandler Tests (Consolidated) ---

func setupAPIKeyTestRouter(mockService service.AuthService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// FIX: Berikan nil untuk argumen samlSP saat membuat handler.
	// Karena kita hanya menguji APIKeyHandler, ini tidak masalah.
	apiKeyHandler := NewAPIKeyHandler(mockService) // APIKeyHandler tidak berubah

	authMiddleware := func(c *gin.Context) {
		c.Set(commonauth.UserIDKey, "test-user-id")
		c.Next()
	}

	authorized := router.Group("/")
	authorized.Use(authMiddleware)
	{
		authorized.POST("/keys", apiKeyHandler.CreateAPIKey)
		authorized.GET("/keys", apiKeyHandler.GetAPIKeys)
		authorized.DELETE("/keys/:id", apiKeyHandler.RevokeAPIKey)
	}

	return router
}

func TestAPIKeyHandler_CreateAPIKey(t *testing.T) {
	mockService := new(MockAuthService)
	router := setupAPIKeyTestRouter(mockService)

	t.Run("Success", func(t *testing.T) {
		userID := "test-user-id"
		description := "My new test key"
		expectedKey := "zpk_test_abcdef123456"

		reqBody := map[string]string{"description": description}
		jsonBody, _ := json.Marshal(reqBody)

		mockService.On("CreateAPIKey", mock.Anything, userID, description).Return(expectedKey, nil).Once()

		req, _ := http.NewRequest(http.MethodPost, "/keys", bytes.NewBuffer(jsonBody))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var resp map[string]string
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		require.NoError(t, err, "Gagal unmarshal response body")

		assert.Equal(t, expectedKey, resp["api_key"])
		mockService.AssertExpectations(t)
	})

	t.Run("Failure - Service Error", func(t *testing.T) {
		userID := "test-user-id"
		description := "Failing key"
		reqBody := map[string]string{"description": description}
		jsonBody, _ := json.Marshal(reqBody)

		mockService.On("CreateAPIKey", mock.Anything, userID, description).Return("", errors.New("db error")).Once()

		req, _ := http.NewRequest(http.MethodPost, "/keys", bytes.NewBuffer(jsonBody))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Failure - Bad Request", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/keys", bytes.NewBuffer([]byte(`{"desc": "wrong field"}`)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestAPIKeyHandler_RevokeAPIKey(t *testing.T) {
	mockService := new(MockAuthService)
	router := setupAPIKeyTestRouter(mockService)

	t.Run("Success", func(t *testing.T) {
		userID := "test-user-id"
		keyID := "key-to-revoke-123"

		mockService.On("RevokeAPIKey", mock.Anything, userID, keyID).Return(nil).Once()

		req, _ := http.NewRequest(http.MethodDelete, "/keys/"+keyID, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})
}
