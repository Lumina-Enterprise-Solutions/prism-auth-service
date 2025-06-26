package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Salin MockAuthService yang lengkap
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, user *model.User, password string) (string, error) {
	return "", nil
}
func (m *MockAuthService) Login(ctx context.Context, email, password string) (*service.LoginStep1Response, error) {
	return nil, nil
}
func (m *MockAuthService) RefreshToken(ctx context.Context, refreshTokenString string) (*service.AuthTokens, error) {
	return nil, nil
}
func (m *MockAuthService) Logout(ctx context.Context, claims jwt.MapClaims) error { return nil }
func (m *MockAuthService) GenerateGoogleLoginURL(state string) string             { return "" }
func (m *MockAuthService) ProcessGoogleCallback(ctx context.Context, code string) (*service.AuthTokens, error) {
	return nil, nil
}
func (m *MockAuthService) GenerateMicrosoftLoginURL(state string) string { return "" }
func (m *MockAuthService) ProcessMicrosoftCallback(ctx context.Context, code string) (*service.AuthTokens, error) {
	return nil, nil
}
func (m *MockAuthService) Setup2FA(ctx context.Context, userID, email string) (*service.TwoFASetup, error) {
	return nil, nil
}
func (m *MockAuthService) VerifyAndEnable2FA(ctx context.Context, userID, totpSecret, code string) error {
	return nil
}
func (m *MockAuthService) VerifyLogin2FA(ctx context.Context, email, code string) (*service.AuthTokens, error) {
	return nil, nil
}
func (m *MockAuthService) ForgotPassword(ctx context.Context, email string) error { return nil }
func (m *MockAuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	return nil
}
func (m *MockAuthService) CreateAPIKey(ctx context.Context, userID, description string) (string, error) {
	return "", nil
}
func (m *MockAuthService) GetAPIKeys(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	return nil, nil
}
func (m *MockAuthService) RevokeAPIKey(ctx context.Context, userID, keyID string) error { return nil }
func (m *MockAuthService) GenerateImpersonationToken(ctx context.Context, targetUser *model.User, actorID string) (string, time.Time, error) {
	return "", time.Time{}, nil
}
func (m *MockAuthService) ValidateAPIKey(ctx context.Context, apiKeyString string) (*model.User, error) {
	args := m.Called(ctx, apiKeyString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}

func TestFlexibleAuthMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Setenv("JWT_SECRET_KEY", "test-secret")

	generateDummyJWT := func(jti string, secret string) string {
		claims := jwt.MapClaims{"jti": jti, "sub": "user-123", "exp": time.Now().Add(time.Hour).Unix()}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, _ := token.SignedString([]byte(secret))
		return signedToken
	}

	testCases := []struct {
		name           string
		setupMocks     func(*MockAuthService, redismock.ClientMock)
		setupRequest   func(*http.Request)
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No Auth Header",
			setupMocks:     func(mas *MockAuthService, r redismock.ClientMock) {},
			setupRequest:   func(req *http.Request) {},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"Authorization header required (Bearer Token or X-API-Key)"}`,
		},
		{
			name: "Valid API Key",
			setupMocks: func(mas *MockAuthService, r redismock.ClientMock) {
				user := &model.User{ID: "api-user-1", Email: "api@test.com", RoleName: "api_role"}
				mas.On("ValidateAPIKey", mock.Anything, "valid-api-key").Return(user, nil).Once()
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-API-Key", "valid-api-key")
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name: "Invalid API Key",
			setupMocks: func(mas *MockAuthService, r redismock.ClientMock) {
				mas.On("ValidateAPIKey", mock.Anything, "invalid-api-key").Return(nil, errors.New("invalid key")).Once()
			},
			setupRequest: func(req *http.Request) {
				req.Header.Set("X-API-Key", "invalid-api-key")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"Invalid API Key"}`,
		},
		{
			name: "Valid Bearer Token",
			setupMocks: func(mas *MockAuthService, r redismock.ClientMock) {
				r.ExpectGet("valid-jti").RedisNil()
			},
			setupRequest: func(req *http.Request) {
				token := generateDummyJWT("valid-jti", "test-secret")
				req.Header.Set("Authorization", "Bearer "+token)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			name:       "Invalid Bearer Token Format",
			setupMocks: func(mas *MockAuthService, r redismock.ClientMock) {},
			setupRequest: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer invalidtoken")
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"Invalid token","details":"token is malformed: token contains an invalid number of segments"}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockService := new(MockAuthService)
			redisClient, redisMock := redismock.NewClientMock()
			tc.setupMocks(mockService, redisMock)

			router := gin.New()
			router.Use(FlexibleAuthMiddleware(mockService, redisClient))
			router.GET("/protected", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/protected", nil)
			tc.setupRequest(req)

			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedStatus, w.Code)
			assert.JSONEq(t, tc.expectedBody, w.Body.String())
			mockService.AssertExpectations(t)
			assert.NoError(t, redisMock.ExpectationsWereMet())
		})
	}
}
