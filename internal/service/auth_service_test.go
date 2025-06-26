package service

import (
	"context"
	"testing"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// --- Mocks untuk semua dependensi ---

type MockUserServiceClient struct {
	mock.Mock
}

func (m *MockUserServiceClient) GetUserAuthDetailsByEmail(ctx context.Context, email string) (*model.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
func (m *MockUserServiceClient) GetUserAuthDetailsByID(ctx context.Context, id string) (*model.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
func (m *MockUserServiceClient) CreateUser(ctx context.Context, req *userv1.CreateUserRequest) (*model.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
func (m *MockUserServiceClient) CreateSocialUser(ctx context.Context, req *userv1.CreateSocialUserRequest) (*model.User, error) {
	return nil, nil
}
func (m *MockUserServiceClient) Enable2FA(ctx context.Context, userID, totpSecret string) error {
	return nil
}
func (m *MockUserServiceClient) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	return nil
}
func (m *MockUserServiceClient) Close() {}

type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}
func (m *MockTokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	return nil, nil
}
func (m *MockTokenRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	return nil
}

type MockAPIKeyRepository struct{ mock.Mock }

func (m *MockAPIKeyRepository) StoreKey(ctx context.Context, userID, keyHash, prefix, description string, expiresAt *time.Time) (string, error) {
	return "", nil
}
func (m *MockAPIKeyRepository) GetUserByKeyPrefix(ctx context.Context, prefix string) (*repository.UserWithKeyHash, error) {
	return nil, nil
}
func (m *MockAPIKeyRepository) GetKeysForUser(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	return nil, nil
}
func (m *MockAPIKeyRepository) RevokeKey(ctx context.Context, userID, keyID string) error { return nil }

type MockPasswordResetRepository struct{ mock.Mock }

func (m *MockPasswordResetRepository) StoreToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	return nil
}
func (m *MockPasswordResetRepository) GetUserIDByToken(ctx context.Context, tokenHash string) (string, error) {
	return "", nil
}
func (m *MockPasswordResetRepository) DeleteToken(ctx context.Context, tokenHash string) error {
	return nil
}

// Test untuk Login
func TestAuthService_Login(t *testing.T) {
	// Set secret key dummy untuk pembuatan token
	t.Setenv("JWT_SECRET_KEY", "my-super-secret-key-for-testing")

	mockUserClient := new(MockUserServiceClient)
	mockTokenRepo := new(MockTokenRepository)
	mockAPIKeyRepo := new(MockAPIKeyRepository)
	mockPassResetRepo := new(MockPasswordResetRepository)

	// Inject mocks ke dalam service
	authSvc := NewAuthService(mockUserClient, mockTokenRepo, mockAPIKeyRepo, mockPassResetRepo)

	ctx := context.Background()

	t.Run("Success Login without 2FA", func(t *testing.T) {
		// Arrange
		email := "test@example.com"
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		mockUser := &model.User{
			ID:           "user-1",
			Email:        email,
			PasswordHash: string(hashedPassword),
			Status:       "active",
			Is2FAEnabled: false,
			RoleName:     "user",
		}

		mockUserClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(mockUser, nil).Once()
		mockTokenRepo.On("StoreRefreshToken", ctx, mockUser.ID, mock.AnythingOfType("string"), mock.AnythingOfType("time.Time")).Return(nil).Once()

		// Act
		response, err := authSvc.Login(ctx, email, password)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, response)
		assert.False(t, response.Is2FARequired)
		assert.NotNil(t, response.AuthTokens)
		assert.NotEmpty(t, response.AuthTokens.AccessToken)
		assert.NotEmpty(t, response.AuthTokens.RefreshToken)

		mockUserClient.AssertExpectations(t)
		mockTokenRepo.AssertExpectations(t)
	})

	t.Run("Login requires 2FA", func(t *testing.T) {
		// Arrange
		email := "2fa_user@example.com"
		password := "password123"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		mockUser := &model.User{
			ID:           "user-2",
			Email:        email,
			PasswordHash: string(hashedPassword),
			Status:       "active",
			Is2FAEnabled: true, // 2FA diaktifkan
		}
		mockUserClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(mockUser, nil).Once()

		// Act
		response, err := authSvc.Login(ctx, email, password)

		// Assert
		require.NoError(t, err)
		assert.NotNil(t, response)
		assert.True(t, response.Is2FARequired)
		assert.Nil(t, response.AuthTokens) // Tidak ada token yang diberikan

		mockUserClient.AssertExpectations(t)
	})

	t.Run("Login failed - invalid password", func(t *testing.T) {
		// Arrange
		email := "test@example.com"
		password := "wrongpassword"
		correctPasswordHashed, _ := bcrypt.GenerateFromPassword([]byte("correctpassword"), bcrypt.DefaultCost)

		mockUser := &model.User{
			ID:           "user-1",
			Email:        email,
			PasswordHash: string(correctPasswordHashed),
			Status:       "active",
		}

		mockUserClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(mockUser, nil).Once()

		// Act
		_, err := authSvc.Login(ctx, email, password)

		// Assert
		require.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())

		mockUserClient.AssertExpectations(t)
	})

	t.Run("Login failed - user not found", func(t *testing.T) {
		// Arrange
		email := "notfound@example.com"
		mockUserClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(nil, client.ErrUserNotFound).Once()

		// Act
		_, err := authSvc.Login(ctx, email, "anypassword")

		// Assert
		require.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
	})
}
