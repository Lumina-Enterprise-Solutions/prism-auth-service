// File: internal/service/auth_service_test.go
package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// --- Mocks for all dependencies ---

type MockUserServiceClient struct{ mock.Mock }

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
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*model.User), args.Error(1)
}
func (m *MockUserServiceClient) Enable2FA(ctx context.Context, userID, totpSecret string) error {
	return m.Called(ctx, userID, totpSecret).Error(0)
}
func (m *MockUserServiceClient) UpdatePassword(ctx context.Context, userID, newPasswordHash string) error {
	return m.Called(ctx, userID, newPasswordHash).Error(0)
}
func (m *MockUserServiceClient) Close() { m.Called() }

type MockTokenRepository struct{ mock.Mock }

func (m *MockTokenRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	return m.Called(ctx, userID, tokenHash, expiresAt).Error(0)
}
func (m *MockTokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.RefreshToken), args.Error(1)
}
func (m *MockTokenRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}

type MockAPIKeyRepository struct{ mock.Mock }

func (m *MockAPIKeyRepository) StoreKey(ctx context.Context, userID, keyHash, prefix, description string, expiresAt *time.Time) (string, error) {
	args := m.Called(ctx, userID, keyHash, prefix, description, expiresAt)
	return args.String(0), args.Error(1)
}
func (m *MockAPIKeyRepository) GetUserByKeyPrefix(ctx context.Context, prefix string) (*repository.UserWithKeyHash, error) {
	args := m.Called(ctx, prefix)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*repository.UserWithKeyHash), args.Error(1)
}
func (m *MockAPIKeyRepository) GetKeysForUser(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]model.APIKeyMetadata), args.Error(1)
}
func (m *MockAPIKeyRepository) RevokeKey(ctx context.Context, userID, keyID string) error {
	return m.Called(ctx, userID, keyID).Error(0)
}

type MockPasswordResetRepository struct{ mock.Mock }

func (m *MockPasswordResetRepository) StoreToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	return m.Called(ctx, tokenHash, userID, expiresAt).Error(0)
}
func (m *MockPasswordResetRepository) GetUserIDByToken(ctx context.Context, tokenHash string) (string, error) {
	args := m.Called(ctx, tokenHash)
	return args.String(0), args.Error(1)
}
func (m *MockPasswordResetRepository) DeleteToken(ctx context.Context, tokenHash string) error {
	return m.Called(ctx, tokenHash).Error(0)
}

type MockNotificationClient struct{ mock.Mock }

func (m *MockNotificationClient) SendWelcomeEmail(ctx context.Context, userID, email, firstName string) {
	m.Called(ctx, userID, email, firstName)
}
func (m *MockNotificationClient) SendPasswordResetEmail(ctx context.Context, userID, email, firstName, resetLink string) {
	m.Called(ctx, userID, email, firstName, resetLink)
}

type MockInvitationClient struct{ mock.Mock }

func (m *MockInvitationClient) ValidateInvitation(ctx context.Context, token string) (*client.InvitationData, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*client.InvitationData), args.Error(1)
}

// --- Test Setup ---

type authServiceMocks struct {
	userClient         *MockUserServiceClient
	tokenRepo          *MockTokenRepository
	apiKeyRepo         *MockAPIKeyRepository
	passwordResetRepo  *MockPasswordResetRepository
	notificationClient *MockNotificationClient
	invitationClient   *MockInvitationClient
}

func setupServiceTest(t *testing.T) (*authService, authServiceMocks) {
	// Set dummy env vars required by the service
	t.Setenv("JWT_SECRET_KEY", "test-secret")
	t.Setenv("GOOGLE_OAUTH_CLIENT_ID", "test-google-id")
	t.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", "test-google-secret")
	t.Setenv("MICROSOFT_OAUTH_CLIENT_ID", "test-ms-id")
	t.Setenv("MICROSOFT_OAUTH_CLIENT_SECRET", "test-ms-secret")

	mocks := authServiceMocks{
		userClient:         new(MockUserServiceClient),
		tokenRepo:          new(MockTokenRepository),
		apiKeyRepo:         new(MockAPIKeyRepository),
		passwordResetRepo:  new(MockPasswordResetRepository),
		notificationClient: new(MockNotificationClient),
		invitationClient:   new(MockInvitationClient),
	}

	// This creates the service with REAL clients initially
	service := NewAuthService(mocks.userClient, mocks.tokenRepo, mocks.apiKeyRepo, mocks.passwordResetRepo).(*authService)
	// Now we OVERWRITE the real clients with our mocks for testing
	service.notificationClient = mocks.notificationClient
	service.invitationClient = mocks.invitationClient

	return service, mocks
}

func TestAuthService_Register(t *testing.T) {
	ctx := context.Background()
	user := &model.User{Email: "test@example.com", FirstName: "Test", LastName: "User"}
	password := "password123"

	t.Run("Success", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		reqMatcher := mock.MatchedBy(func(req *userv1.CreateUserRequest) bool {
			err := bcrypt.CompareHashAndPassword([]byte(req.Password), []byte(password))
			return req.Email == user.Email && err == nil
		})

		createdUser := &model.User{ID: "new-user-id", Email: user.Email, FirstName: user.FirstName}
		mocks.userClient.On("CreateUser", ctx, reqMatcher).Return(createdUser, nil).Once()
		mocks.notificationClient.On("SendWelcomeEmail", ctx, createdUser.ID, user.Email, user.FirstName).Return().Once()

		userID, err := service.Register(ctx, user, password)

		require.NoError(t, err)
		assert.Equal(t, "new-user-id", userID)
		mocks.userClient.AssertExpectations(t)
		mocks.notificationClient.AssertExpectations(t)
	})

	t.Run("User Service Error", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.userClient.On("CreateUser", ctx, mock.Anything).Return(nil, errors.New("gRPC error")).Once()

		_, err := service.Register(ctx, user, password)

		require.Error(t, err)
		assert.Equal(t, "gRPC error", err.Error())
		mocks.userClient.AssertExpectations(t)
	})
}

func TestAuthService_Login(t *testing.T) {
	ctx := context.Background()
	email := "user@example.com"
	password := "goodpassword"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	baseUser := &model.User{
		ID:           "user-123",
		Email:        email,
		PasswordHash: string(hashedPassword),
		RoleName:     "User",
		Status:       "active",
		Is2FAEnabled: false,
	}

	t.Run("Success - No 2FA", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		user := *baseUser // copy
		user.Is2FAEnabled = false

		mocks.userClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(&user, nil).Once()
		mocks.tokenRepo.On("StoreRefreshToken", ctx, user.ID, mock.Anything, mock.Anything).Return(nil).Once()

		resp, err := service.Login(ctx, email, password)

		require.NoError(t, err)
		assert.False(t, resp.Is2FARequired)
		assert.NotNil(t, resp.AuthTokens)
		assert.NotEmpty(t, resp.AuthTokens.AccessToken)
		assert.NotEmpty(t, resp.AuthTokens.RefreshToken)
		mocks.userClient.AssertExpectations(t)
		mocks.tokenRepo.AssertExpectations(t)
	})

	t.Run("Success - 2FA Required", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		user := *baseUser // copy
		user.Is2FAEnabled = true

		mocks.userClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(&user, nil).Once()

		resp, err := service.Login(ctx, email, password)

		require.NoError(t, err)
		assert.True(t, resp.Is2FARequired)
		assert.Nil(t, resp.AuthTokens)
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - Invalid Password", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.userClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(baseUser, nil).Once()

		_, err := service.Login(ctx, email, "wrongpassword")

		require.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - User Not Found", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.userClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(nil, errors.New("not found")).Once()

		_, err := service.Login(ctx, email, password)

		require.Error(t, err)
		assert.Equal(t, "invalid credentials", err.Error())
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - Inactive User", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		user := *baseUser
		user.Status = "suspended"
		mocks.userClient.On("GetUserAuthDetailsByEmail", ctx, email).Return(&user, nil).Once()

		_, err := service.Login(ctx, email, password)

		require.Error(t, err)
		assert.Equal(t, "account is not active (status: suspended)", err.Error())
		mocks.userClient.AssertExpectations(t)
	})
}

func TestAuthService_RefreshToken(t *testing.T) {
	ctx := context.Background()
	refreshTokenString := "valid-refresh-token"
	refreshTokenHash := hashToken(refreshTokenString)
	userID := "user-123"

	storedToken := &repository.RefreshToken{
		UserID:    userID,
		TokenHash: refreshTokenHash,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	user := &model.User{ID: userID, Email: "user@example.com", RoleName: "Admin", Status: "active"}

	t.Run("Success", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.tokenRepo.On("GetRefreshToken", ctx, refreshTokenHash).Return(storedToken, nil).Once()
		mocks.tokenRepo.On("DeleteRefreshToken", ctx, refreshTokenHash).Return(nil).Once()
		mocks.userClient.On("GetUserAuthDetailsByID", ctx, userID).Return(user, nil).Once()
		mocks.tokenRepo.On("StoreRefreshToken", ctx, userID, mock.Anything, mock.Anything).Return(nil).Once()

		tokens, err := service.RefreshToken(ctx, refreshTokenString)

		require.NoError(t, err)
		assert.NotNil(t, tokens)
		assert.NotEmpty(t, tokens.AccessToken)
		assert.NotEmpty(t, tokens.RefreshToken)
		mocks.tokenRepo.AssertExpectations(t)
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - Token Expired", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		expiredStoredToken := &repository.RefreshToken{
			UserID:    userID,
			TokenHash: refreshTokenHash,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
		}
		mocks.tokenRepo.On("GetRefreshToken", ctx, refreshTokenHash).Return(expiredStoredToken, nil).Once()
		mocks.tokenRepo.On("DeleteRefreshToken", ctx, refreshTokenHash).Return(nil).Once()

		_, err := service.RefreshToken(ctx, refreshTokenString)

		require.Error(t, err)
		assert.Equal(t, "refresh token has expired", err.Error())
		mocks.tokenRepo.AssertExpectations(t)
	})
}

func TestAuthService_VerifyAndEnable2FA(t *testing.T) {
	ctx := context.Background()
	userID := "user-123"

	// Generate a real secret and a valid code for it in each test run
	t.Run("Success", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		setupInfo, err := service.Setup2FA(ctx, userID, "test@example.com")
		require.NoError(t, err)
		validCode, err := totp.GenerateCode(setupInfo.Secret, time.Now())
		require.NoError(t, err)

		mocks.userClient.On("Enable2FA", ctx, userID, setupInfo.Secret).Return(nil).Once()

		err = service.VerifyAndEnable2FA(ctx, userID, setupInfo.Secret, validCode)

		require.NoError(t, err)
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - Invalid Code", func(t *testing.T) {
		service, _ := setupServiceTest(t)
		setupInfo, err := service.Setup2FA(ctx, userID, "test@example.com")
		require.NoError(t, err)

		err = service.VerifyAndEnable2FA(ctx, userID, setupInfo.Secret, "123456")

		require.Error(t, err)
		assert.Equal(t, "invalid 2FA code", err.Error())
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	ctx := context.Background()
	token := "valid-reset-token"
	tokenHash := hashToken(token)
	userID := "user-for-reset"
	newPassword := "newSecurePassword123"

	t.Run("Success", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.passwordResetRepo.On("GetUserIDByToken", ctx, tokenHash).Return(userID, nil).Once()

		// Match any hashed password, since we can't predict the salt
		mocks.userClient.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(nil).Once()

		mocks.passwordResetRepo.On("DeleteToken", ctx, tokenHash).Return(nil).Once()

		err := service.ResetPassword(ctx, token, newPassword)

		require.NoError(t, err)
		mocks.passwordResetRepo.AssertExpectations(t)
		mocks.userClient.AssertExpectations(t)
	})

	t.Run("Failure - Invalid Token", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.passwordResetRepo.On("GetUserIDByToken", ctx, tokenHash).Return("", errors.New("not found")).Once()

		err := service.ResetPassword(ctx, token, newPassword)

		require.Error(t, err)
		assert.Equal(t, "invalid or expired token", err.Error())
		mocks.passwordResetRepo.AssertExpectations(t)
	})

	t.Run("Failure - User Service Fails to Update", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.passwordResetRepo.On("GetUserIDByToken", ctx, tokenHash).Return(userID, nil).Once()
		mocks.userClient.On("UpdatePassword", ctx, userID, mock.AnythingOfType("string")).Return(errors.New("db error")).Once()

		// IMPORTANT: DeleteToken should NOT be called if the password update fails.

		err := service.ResetPassword(ctx, token, newPassword)

		require.Error(t, err)
		assert.Equal(t, "db error", err.Error())
		mocks.passwordResetRepo.AssertExpectations(t)
		mocks.userClient.AssertExpectations(t)
		// Verify DeleteToken was not called
		mocks.passwordResetRepo.AssertNotCalled(t, "DeleteToken", mock.Anything, mock.Anything)
	})
}

func TestAuthService_ValidateAPIKey(t *testing.T) {
	ctx := context.Background()
	apiKeyString := "zpk_mysecretkey"
	prefix := "zpk"
	keyHash := hashToken(apiKeyString)

	userWithHash := &repository.UserWithKeyHash{
		User: model.User{
			ID:       "api-user-id",
			Email:    "api@example.com",
			RoleName: "APIUser",
			Status:   "active",
		},
		KeyHash: keyHash,
	}

	t.Run("Success", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.apiKeyRepo.On("GetUserByKeyPrefix", ctx, prefix).Return(userWithHash, nil).Once()

		user, err := service.ValidateAPIKey(ctx, apiKeyString)

		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, userWithHash.ID, user.ID)
		mocks.apiKeyRepo.AssertExpectations(t)
	})

	t.Run("Failure - Invalid Key Format", func(t *testing.T) {
		service, _ := setupServiceTest(t)
		_, err := service.ValidateAPIKey(ctx, "invalidkey")
		require.Error(t, err)
		assert.Equal(t, "invalid api key format", err.Error())
	})

	t.Run("Failure - Key Not Found", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		mocks.apiKeyRepo.On("GetUserByKeyPrefix", ctx, prefix).Return(nil, errors.New("not found")).Once()

		_, err := service.ValidateAPIKey(ctx, apiKeyString)

		require.Error(t, err)
		assert.Equal(t, "api key not found, expired, or revoked", err.Error())
		mocks.apiKeyRepo.AssertExpectations(t)
	})

	t.Run("Failure - Hash Mismatch", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		// Store a different hash to simulate a mismatch
		mismatchedUserWithHash := &repository.UserWithKeyHash{
			User:    model.User{ID: "api-user-id", Status: "active"},
			KeyHash: hashToken("zpk_differentkey"),
		}
		mocks.apiKeyRepo.On("GetUserByKeyPrefix", ctx, prefix).Return(mismatchedUserWithHash, nil).Once()

		_, err := service.ValidateAPIKey(ctx, apiKeyString)

		require.Error(t, err)
		assert.Equal(t, "invalid api key", err.Error())
		mocks.apiKeyRepo.AssertExpectations(t)
	})

	t.Run("Failure - Inactive User", func(t *testing.T) {
		service, mocks := setupServiceTest(t)
		inactiveUserWithHash := &repository.UserWithKeyHash{
			User:    model.User{ID: "api-user-id", Status: "inactive"},
			KeyHash: keyHash,
		}
		mocks.apiKeyRepo.On("GetUserByKeyPrefix", ctx, prefix).Return(inactiveUserWithHash, nil).Once()

		_, err := service.ValidateAPIKey(ctx, apiKeyString)

		require.Error(t, err)
		assert.Equal(t, "user account is inactive", err.Error())
		mocks.apiKeyRepo.AssertExpectations(t)
	})
}

func TestAuthService_GenerateImpersonationToken(t *testing.T) {
	service, _ := setupServiceTest(t)
	ctx := context.Background()

	targetUser := &model.User{ID: "target-user", Email: "target@example.com", RoleName: "Manager"}
	actorID := "admin-user"

	t.Run("Success", func(t *testing.T) {
		tokenString, expiry, err := service.GenerateImpersonationToken(ctx, targetUser, actorID)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)
		assert.WithinDuration(t, time.Now().Add(1*time.Hour), expiry, time.Second)

		// Verify claims
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET_KEY")), nil
		})
		require.NoError(t, err)
		claims := token.Claims.(jwt.MapClaims)
		assert.Equal(t, targetUser.ID, claims["sub"])
		assert.Equal(t, actorID, claims["act"])
		assert.Equal(t, true, claims["impersonated"])
	})

	t.Run("Failure - Nil Target User", func(t *testing.T) {
		_, _, err := service.GenerateImpersonationToken(ctx, nil, actorID)
		require.Error(t, err)
	})

	t.Run("Failure - Empty Actor ID", func(t *testing.T) {
		_, _, err := service.GenerateImpersonationToken(ctx, targetUser, "")
		require.Error(t, err)
	})
}
