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
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require" // <--- TAMBAHKAN require
)

// MockAuthService adalah mock lengkap dan benar dari service.AuthService
type MockAuthService struct {
	mock.Mock
}

// Implementasi Mock yang Sesuai dengan Interface Asli
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
	args := m.Called(ctx, claims)
	return args.Error(0)
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

func TestRegisterHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := gin.Default()
	router.POST("/register", handler.Register)

	t.Run("Success", func(t *testing.T) {
		mockService.On("Register", mock.Anything, mock.AnythingOfType("*model.User"), "password123").Return("new-user-id", nil).Once()
		payload := map[string]string{"email": "test@example.com", "password": "password123", "first_name": "Test", "last_name": "User"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
		var response map[string]interface{}
		// FIX: Always check for unmarshal errors in tests
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Response body should be valid JSON")
		assert.Equal(t, "new-user-id", response["userId"])
	})

	t.Run("Binding Error", func(t *testing.T) {
		payload := map[string]string{"password": "password123"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Service Error", func(t *testing.T) {
		mockService.On("Register", mock.Anything, mock.AnythingOfType("*model.User"), "password123").Return("", errors.New("service failure")).Once()
		payload := map[string]string{"email": "test@example.com", "password": "password123", "first_name": "Test", "last_name": "User"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestLoginHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := gin.Default()
	router.POST("/login", handler.Login)

	t.Run("Success without 2FA", func(t *testing.T) {
		expectedResponse := &service.LoginStep1Response{
			Is2FARequired: false,
			AuthTokens:    &service.AuthTokens{AccessToken: "fake-access-token", RefreshToken: "fake-refresh-token"},
		}
		mockService.On("Login", mock.Anything, "user@example.com", "goodpassword").Return(expectedResponse, nil).Once()
		payload := map[string]string{"email": "user@example.com", "password": "goodpassword"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response service.LoginStep1Response
		// FIX: Always check for unmarshal errors in tests
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Response body should be valid JSON")
		assert.False(t, response.Is2FARequired)
		assert.Equal(t, "fake-access-token", response.AuthTokens.AccessToken)
		mockService.AssertExpectations(t)
	})

	t.Run("Success with 2FA Required", func(t *testing.T) {
		expectedResponse := &service.LoginStep1Response{Is2FARequired: true}
		mockService.On("Login", mock.Anything, "2fa-user@example.com", "goodpassword").Return(expectedResponse, nil).Once()
		payload := map[string]string{"email": "2fa-user@example.com", "password": "goodpassword"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var response service.LoginStep1Response
		// FIX: Always check for unmarshal errors in tests
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err, "Response body should be valid JSON")
		assert.True(t, response.Is2FARequired)
		assert.Nil(t, response.AuthTokens)
		mockService.AssertExpectations(t)
	})

	t.Run("Unauthorized", func(t *testing.T) {
		mockService.On("Login", mock.Anything, "user@example.com", "badpassword").Return(nil, errors.New("invalid credentials")).Once()
		payload := map[string]string{"email": "user@example.com", "password": "badpassword"}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertExpectations(t)
	})
}
