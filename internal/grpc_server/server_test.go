package grpc_server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	// --- PERBAIKAN: Hapus "com" yang berlebih ---
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model" // FIX: Removed extra "com"
	authv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/auth/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Salin MockAuthService yang lengkap
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

func TestAuthServer_GenerateImpersonationToken(t *testing.T) {
	ctx := context.Background()

	// Dengan protobuf baru, message request innernya bernama UserInfoForToken
	// bukan ImpersonationUser lagi. Dan di file implementasi (server.go), parameternya
	// TargetUser bukan Target_user.

	targetUser := &model.User{
		ID:       "target-user-id",
		Email:    "target@example.com",
		RoleName: "Admin",
	}

	// Message protobuf yang sesuai dengan file .proto terbaru
	targetUserProto := &authv1.UserInfoForToken{
		Id:       targetUser.ID,
		Email:    targetUser.Email,
		RoleName: targetUser.RoleName,
	}

	t.Run("Success", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		authServer := NewAuthServer(mockService)

		actorID := "actor-user-id"
		expectedToken := "impersonation.token.string"
		expectedExpiry := time.Now().Add(1 * time.Hour)

		// mock service dipanggil dengan tipe model.User
		mockService.On("GenerateImpersonationToken", ctx, targetUser, actorID).Return(expectedToken, expectedExpiry, nil).Once()

		req := &authv1.GenerateImpersonationTokenRequest{
			TargetUser: targetUserProto, // Gunakan proto message yang benar
			ActorId:    actorID,
		}

		// Act
		resp, err := authServer.GenerateImpersonationToken(ctx, req)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, expectedToken, resp.AccessToken)
		assert.InDelta(t, expectedExpiry.Unix(), resp.ExpiresAt.AsTime().Unix(), 1)
		mockService.AssertExpectations(t)
	})

	t.Run("Service Failure", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		authServer := NewAuthServer(mockService)

		mockService.On("GenerateImpersonationToken", mock.Anything, mock.Anything, mock.Anything).Return("", time.Time{}, errors.New("internal service error")).Once()

		req := &authv1.GenerateImpersonationTokenRequest{
			TargetUser: targetUserProto,
			ActorId:    "actor-id",
		}

		// Act
		_, err := authServer.GenerateImpersonationToken(ctx, req)

		// Assert
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.Internal, st.Code())
		mockService.AssertExpectations(t)
	})

	t.Run("Invalid Argument - Nil TargetUser", func(t *testing.T) {
		// Arrange
		mockService := new(MockAuthService)
		authServer := NewAuthServer(mockService)

		req := &authv1.GenerateImpersonationTokenRequest{
			TargetUser: nil,
			ActorId:    "actor-id",
		}

		// Act
		_, err := authServer.GenerateImpersonationToken(ctx, req)

		// Assert
		require.Error(t, err)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
	})
}
