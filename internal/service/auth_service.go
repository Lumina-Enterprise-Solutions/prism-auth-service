package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	userv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/user/v1"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	googleoauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

// Definisikan struct baru untuk response 2FA setup
type TwoFASetup struct {
	QRCode       string `json:"qr_code"`
	Secret       string `json:"secret"`
	ProvisionURL string `json:"provision_url"`
}

// Definisikan struct baru untuk response login tahap 1
type LoginStep1Response struct {
	Is2FARequired bool        `json:"is_2fa_required"`
	AuthTokens    *AuthTokens `json:"auth_tokens,omitempty"`
}

type AuthTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthService interface {
	Register(ctx context.Context, user *model.User, password string) (string, error)
	RefreshToken(ctx context.Context, refreshTokenString string) (*AuthTokens, error)
	Logout(ctx context.Context, claims jwt.MapClaims) error
	GenerateGoogleLoginURL(state string) string
	ProcessGoogleCallback(ctx context.Context, code string) (*AuthTokens, error)
	GenerateMicrosoftLoginURL(state string) string
	ProcessMicrosoftCallback(ctx context.Context, code string) (*AuthTokens, error)
	Setup2FA(ctx context.Context, userID, email string) (*TwoFASetup, error)
	VerifyAndEnable2FA(ctx context.Context, userID, totpSecret, code string) error
	Login(ctx context.Context, email, password string) (*LoginStep1Response, error)
	VerifyLogin2FA(ctx context.Context, email, code string) (*AuthTokens, error)
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, newPassword string) error
	CreateAPIKey(ctx context.Context, userID, description string) (string, error)
	GetAPIKeys(ctx context.Context, userID string) ([]model.APIKeyMetadata, error)
	RevokeAPIKey(ctx context.Context, userID, keyID string) error
	ValidateAPIKey(ctx context.Context, apiKeyString string) (*model.User, error)
	GenerateImpersonationToken(ctx context.Context, targetUser *model.User, actorID string) (string, time.Time, error)
}

type authService struct {
	userServiceClient    client.UserServiceClient
	tokenRepo            repository.TokenRepository
	apiKeyRepo           repository.APIKeyRepository
	passwordResetRepo    repository.PasswordResetRepository
	notificationClient   client.NotificationClient
	googleOAuthConfig    *oauth2.Config
	microsoftOAuthConfig *oauth2.Config
}

// Constructor has changed to accept the new dependencies
func NewAuthService(userClient client.UserServiceClient, tokenRepo repository.TokenRepository, apiKeyRepo repository.APIKeyRepository, passwordResetRepo repository.PasswordResetRepository) AuthService {
	googleOAuthConfig := &oauth2.Config{
		RedirectURL:  "http://localhost:8000/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	microsoftOAuthConfig := &oauth2.Config{
		RedirectURL:  "http://localhost:8000/auth/microsoft/callback",
		ClientID:     os.Getenv("MICROSOFT_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("MICROSOFT_OAUTH_CLIENT_SECRET"),
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"User.Read",
		},
		Endpoint: microsoft.AzureADEndpoint("common"),
	}

	// NewNotificationClient sekarang mengembalikan struct, bukan pointer.
	// Jika tetap pointer, baris `notificationClient: client.NewNotificationClient()` juga valid
	return &authService{
		userServiceClient:    userClient,
		tokenRepo:            tokenRepo,
		apiKeyRepo:           apiKeyRepo,
		passwordResetRepo:    passwordResetRepo,
		notificationClient:   *client.NewNotificationClient(), // * di sini jika New... mengembalikan pointer
		googleOAuthConfig:    googleOAuthConfig,
		microsoftOAuthConfig: microsoftOAuthConfig,
	}
}

func (s *authService) Register(ctx context.Context, user *model.User, password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Create user via gRPC call to user-service
	req := &userv1.CreateUserRequest{
		Email:     user.Email,
		Password:  string(hashedPassword),
		FirstName: user.FirstName,
		LastName:  user.LastName,
	}
	createdUser, err := s.userServiceClient.CreateUser(ctx, req)
	if err != nil {
		return "", err
	}

	// Panggil dengan argumen yang benar: userID, email, firstName
	s.notificationClient.SendWelcomeEmail(ctx, createdUser.ID, user.Email, user.FirstName)

	return createdUser.ID, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (*LoginStep1Response, error) {
	// Get user via gRPC
	user, err := s.userServiceClient.GetUserAuthDetailsByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if user.Status != "active" {
		return nil, fmt.Errorf("account is not active (status: %s)", user.Status)
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if user.Is2FAEnabled {
		return &LoginStep1Response{Is2FARequired: true}, nil
	}

	tokens, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, err
	}
	return &LoginStep1Response{
		Is2FARequired: false,
		AuthTokens:    tokens,
	}, nil
}

func (s *authService) processSocialCallback(ctx context.Context, code string, config *oauth2.Config, provider string) (*AuthTokens, error) {
	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("gagal menukar kode %s: %w", provider, err)
	}

	oauthClient := config.Client(ctx, token)
	oauthService, err := googleoauth.NewService(ctx, option.WithHTTPClient(oauthClient))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat service oauth untuk %s: %w", provider, err)
	}

	userInfo, err := oauthService.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil info user dari %s: %w", provider, err)
	}

	// For social login, we can use a dedicated gRPC method that handles "get or create" logic
	req := &userv1.CreateSocialUserRequest{
		Email:     userInfo.Email,
		FirstName: userInfo.GivenName,
		LastName:  userInfo.FamilyName,
	}
	user, err := s.userServiceClient.CreateSocialUser(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gagal memproses user sosial: %w", err)
	}

	return s.generateTokenPair(ctx, user)
}

func (s *authService) GenerateGoogleLoginURL(state string) string {
	return s.googleOAuthConfig.AuthCodeURL(state)
}

func (s *authService) ProcessGoogleCallback(ctx context.Context, code string) (*AuthTokens, error) {
	return s.processSocialCallback(ctx, code, s.googleOAuthConfig, "google")
}

func (s *authService) GenerateMicrosoftLoginURL(state string) string {
	return s.microsoftOAuthConfig.AuthCodeURL(state)
}

func (s *authService) ProcessMicrosoftCallback(ctx context.Context, code string) (*AuthTokens, error) {
	return s.processSocialCallback(ctx, code, s.microsoftOAuthConfig, "microsoft")
}

func (s *authService) RefreshToken(ctx context.Context, refreshTokenString string) (*AuthTokens, error) {
	refreshTokenHash := hashToken(refreshTokenString)

	storedToken, err := s.tokenRepo.GetRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	if err := s.tokenRepo.DeleteRefreshToken(ctx, refreshTokenHash); err != nil {
		log.Printf("ERROR: Failed to delete old refresh token: %v", err)
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("refresh token has expired")
	}

	user, err := s.userServiceClient.GetUserAuthDetailsByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("could not find user for token: %w", err)
	}

	tokens, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("could not generate new token pair: %w", err)
	}

	return tokens, nil
}

func (s *authService) generateTokenPair(ctx context.Context, user *model.User) (*AuthTokens, error) {
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshTokenHash, expiresAt, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	if err := s.tokenRepo.StoreRefreshToken(ctx, user.ID, refreshTokenHash, expiresAt); err != nil {
		return nil, err
	}

	return &AuthTokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) generateAccessToken(user *model.User) (string, error) {
	expirationMinutes, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_MINUTES"))
	if expirationMinutes == 0 {
		expirationMinutes = 15
	}
	secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))

	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.RoleName, // Using RoleName from the model
		"iss":   "prism-app-issuer",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Minute * time.Duration(expirationMinutes)).Unix(),
		"jti":   uuid.NewString(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func (s *authService) generateRefreshToken() (string, string, time.Time, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", time.Time{}, err
	}

	refreshTokenString := base64.URLEncoding.EncodeToString(randomBytes)
	refreshTokenHash := hashToken(refreshTokenString)

	expirationDays, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION_DAYS"))
	if expirationDays == 0 {
		expirationDays = 7
	}
	expiresAt := time.Now().Add(time.Hour * 24 * time.Duration(expirationDays))

	return refreshTokenString, refreshTokenHash, expiresAt, nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (s *authService) Logout(ctx context.Context, claims jwt.MapClaims) error {
	jti, ok := claims["jti"].(string)
	if !ok {
		return errors.New("invalid token: missing jti")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("invalid token: missing exp")
	}
	expTime := time.Unix(int64(expFloat), 0)

	ttl := time.Until(expTime) + 1*time.Second
	if ttl <= 0 {
		return nil
	}

	return redis.AddToDenylist(ctx, jti, ttl)
}

func (s *authService) Setup2FA(ctx context.Context, userID, email string) (*TwoFASetup, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Prism ERP",
		AccountName: email,
	})
	if err != nil {
		return nil, fmt.Errorf("gagal generate TOTP key: %w", err)
	}

	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("gagal generate QR code image: %w", err)
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("gagal encode QR code ke PNG: %w", err)
	}

	return &TwoFASetup{
		QRCode:       base64.StdEncoding.EncodeToString(buf.Bytes()),
		Secret:       key.Secret(),
		ProvisionURL: key.String(),
	}, nil
}

func (s *authService) VerifyAndEnable2FA(ctx context.Context, userID, totpSecret, code string) error {
	isValid := totp.Validate(code, totpSecret)
	if !isValid {
		return errors.New("invalid 2FA code")
	}

	// PERBAIKAN: Ganti TODO dengan panggilan gRPC yang sebenarnya.
	return s.userServiceClient.Enable2FA(ctx, userID, totpSecret)
}

func (s *authService) VerifyLogin2FA(ctx context.Context, email, code string) (*AuthTokens, error) {
	user, err := s.userServiceClient.GetUserAuthDetailsByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("user not found")
	}

	isValid := totp.Validate(code, user.TOTPSecret)
	if !isValid {
		return nil, errors.New("invalid 2FA code")
	}

	return s.generateTokenPair(ctx, user)
}
func (s *authService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userServiceClient.GetUserAuthDetailsByEmail(ctx, email)
	if err != nil {
		log.Printf("Password reset requested for non-existent email: %s", email)
		return nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	token := hex.EncodeToString(tokenBytes)

	tokenHash := hashToken(token) // Gunakan fungsi hash yang sama dengan refresh token
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := s.passwordResetRepo.StoreToken(ctx, tokenHash, user.ID, expiresAt); err != nil {
		return err
	}

	// Kirim email (secara asinkron)
	resetLink := fmt.Sprintf("https://app.prismerp.com/reset-password?token=%s", token)
	s.notificationClient.SendPasswordResetEmail(ctx, user.ID, user.Email, user.FirstName, resetLink)

	return nil
}

func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	tokenHash := hashToken(token)
	userID, err := s.passwordResetRepo.GetUserIDByToken(ctx, tokenHash)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	newPasswordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update the user's password first.
	if err := s.userServiceClient.UpdatePassword(ctx, userID, string(newPasswordHash)); err != nil {
		return err // If password update fails, do NOT delete the token.
	}

	// SECURITY FIX: Only delete the token AFTER the password has been successfully updated.
	// This makes the operation transactional and prevents the token from being burned on a failed attempt.
	if err := s.passwordResetRepo.DeleteToken(ctx, tokenHash); err != nil {
		// Log this error but don't fail the whole operation, as the user's password is now reset.
		log.Printf("WARN: Failed to delete used password reset token, but password was reset. TokenHash: %s. Error: %v", tokenHash, err)
	}

	return nil
}
func (s *authService) CreateAPIKey(ctx context.Context, userID, description string) (string, error) {
	// Format: [Prefix]_[Secret]
	// Prefix akan disimpan di DB, Secret hanya ada di string lengkapnya.
	prefix := "zpk" // Zetta Prism Key

	// Buat bagian rahasia yang panjang
	secretBytes := make([]byte, 32) // 32 bytes -> ~43 karakter base64
	if _, err := rand.Read(secretBytes); err != nil {
		return "", err
	}
	secretPart := base64.RawURLEncoding.EncodeToString(secretBytes)

	apiKeyString := prefix + "_" + secretPart
	keyHash := hashToken(apiKeyString)

	// Simpan hash dan prefix ke database
	_, err := s.apiKeyRepo.StoreKey(ctx, userID, keyHash, prefix, description, nil)
	if err != nil {
		return "", err
	}

	return apiKeyString, nil
}

// GetAPIKeys mengambil metadata semua key milik seorang user.
func (s *authService) GetAPIKeys(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	return s.apiKeyRepo.GetKeysForUser(ctx, userID)
}

// RevokeAPIKey menonaktifkan sebuah API key.
func (s *authService) RevokeAPIKey(ctx context.Context, userID, keyID string) error {
	return s.apiKeyRepo.RevokeKey(ctx, userID, keyID)
}

func (s *authService) ValidateAPIKey(ctx context.Context, apiKeyString string) (*model.User, error) {
	parts := strings.Split(apiKeyString, "_")
	// Key harus memiliki setidaknya 2 bagian: prefix dan secret
	if len(parts) < 2 {
		return nil, errors.New("invalid api key format")
	}
	prefix := parts[0]

	// Cari user dan hash key yang cocok berdasarkan prefix
	userWithHash, err := s.apiKeyRepo.GetUserByKeyPrefix(ctx, prefix)
	if err != nil {
		return nil, errors.New("api key not found, expired, or revoked")
	}

	// Lakukan perbandingan hash dengan waktu konstan untuk keamanan
	requestKeyHash := hashToken(apiKeyString)
	if subtle.ConstantTimeCompare([]byte(requestKeyHash), []byte(userWithHash.KeyHash)) != 1 {
		return nil, errors.New("invalid api key")
	}

	if userWithHash.Status != "active" {
		return nil, fmt.Errorf("user account is %s", userWithHash.Status)
	}

	// TODO: Update last_used_at secara asinkron

	return &userWithHash.User, nil
}
func (s *authService) GenerateImpersonationToken(ctx context.Context, targetUser *model.User, actorID string) (string, time.Time, error) {
	if targetUser == nil || targetUser.ID == "" {
		return "", time.Time{}, errors.New("target user for impersonation cannot be nil or have an empty ID")
	}
	if actorID == "" {
		return "", time.Time{}, errors.New("actor ID for impersonation cannot be empty")
	}

	expirationTime := time.Now().Add(1 * time.Hour) // Sesi impersonasi singkat
	secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))

	claims := jwt.MapClaims{
		"sub":          targetUser.ID,
		"email":        targetUser.Email,
		"role":         targetUser.RoleName,
		"iss":          "prism-app-issuer",
		"iat":          time.Now().Unix(),
		"exp":          expirationTime.Unix(),
		"jti":          uuid.NewString(),
		"act":          actorID, // Klaim 'actor' standar JWT
		"impersonated": true,    // Klaim kustom untuk menandai token ini
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", time.Time{}, err
	}

	return signedToken, expirationTime, nil
}
