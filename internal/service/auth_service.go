package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"image/png"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	authredis "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	googleoauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option" // <-- TAMBAHKAN IMPORT BARU
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
}

type authService struct {
	userRepo             repository.UserRepository
	notificationClient   *client.NotificationClient
	googleOAuthConfig    *oauth2.Config
	microsoftOAuthConfig *oauth2.Config
}

func NewAuthService(userRepo repository.UserRepository) AuthService {
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

	return &authService{
		userRepo:             userRepo,
		notificationClient:   client.NewNotificationClient(),
		googleOAuthConfig:    googleOAuthConfig,
		microsoftOAuthConfig: microsoftOAuthConfig,
	}
}

func (s *authService) GenerateMicrosoftLoginURL(state string) string {
	return s.microsoftOAuthConfig.AuthCodeURL(state)
}

func (s *authService) ProcessMicrosoftCallback(ctx context.Context, code string) (*AuthTokens, error) {
	microsoftToken, err := s.microsoftOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("gagal menukar kode microsoft: %w", err)
	}

	_, ok := microsoftToken.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token tidak ditemukan di response Microsoft")
	}

	oauthClient := s.microsoftOAuthConfig.Client(ctx, microsoftToken)
	// PERBAIKAN: Gunakan NewService() yang direkomendasikan
	oauthService, err := googleoauth.NewService(ctx, option.WithHTTPClient(oauthClient))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat service oauth untuk microsoft: %w", err)
	}

	userInfo, err := oauthService.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil info user dari microsoft: %w", err)
	}

	user, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			newUser := &model.User{
				Email:        userInfo.Email,
				FirstName:    userInfo.GivenName,
				LastName:     userInfo.FamilyName,
				PasswordHash: "social-login",
			}
			userID, err := s.userRepo.CreateUser(ctx, newUser)
			if err != nil {
				return nil, fmt.Errorf("gagal membuat user baru dari social login: %w", err)
			}
			user, err = s.userRepo.GetUserByID(ctx, userID)
			if err != nil {
				return nil, fmt.Errorf("gagal mengambil user yang baru dibuat: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error saat mencari user: %w", err)
		}
	}

	return s.generateTokenPair(ctx, user)
}

func (s *authService) GenerateGoogleLoginURL(state string) string {
	return s.googleOAuthConfig.AuthCodeURL(state)
}

func (s *authService) ProcessGoogleCallback(ctx context.Context, code string) (*AuthTokens, error) {
	googleToken, err := s.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("gagal menukar kode: %w", err)
	}

	oauthClient := s.googleOAuthConfig.Client(ctx, googleToken)
	// PERBAIKAN: Gunakan NewService() yang direkomendasikan
	oauthService, err := googleoauth.NewService(ctx, option.WithHTTPClient(oauthClient))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat service oauth: %w", err)
	}

	userInfo, err := oauthService.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil info user: %w", err)
	}

	user, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			newUser := &model.User{
				Email:        userInfo.Email,
				FirstName:    userInfo.GivenName,
				LastName:     userInfo.FamilyName,
				PasswordHash: "social-login",
			}
			userID, err := s.userRepo.CreateUser(ctx, newUser)
			if err != nil {
				return nil, fmt.Errorf("gagal membuat user baru dari social login: %w", err)
			}
			user, err = s.userRepo.GetUserByID(ctx, userID)
			if err != nil {
				return nil, fmt.Errorf("gagal mengambil user yang baru dibuat: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error saat mencari user: %w", err)
		}
	}

	return s.generateTokenPair(ctx, user)
}

func (s *authService) Register(ctx context.Context, user *model.User, password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	user.PasswordHash = string(hashedPassword)

	userID, err := s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return "", err
	}

	s.notificationClient.SendWelcomeEmail(ctx, user.Email, user.FirstName)

	return userID, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (*LoginStep1Response, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
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

// PERBAIKAN: Fungsi generateJWT yang tidak digunakan telah dihapus.

func (s *authService) RefreshToken(ctx context.Context, refreshTokenString string) (*AuthTokens, error) {
	refreshTokenHash := hashToken(refreshTokenString)

	storedToken, err := s.userRepo.GetRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	if err := s.userRepo.DeleteRefreshToken(ctx, refreshTokenHash); err != nil {
		log.Printf("ERROR: Failed to delete old refresh token: %v", err)
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("refresh token has expired")
	}

	user, err := s.userRepo.GetUserByID(ctx, storedToken.UserID)
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

	if err := s.userRepo.StoreRefreshToken(ctx, user.ID, refreshTokenHash, expiresAt); err != nil {
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
		"role":  user.Role,
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

	return authredis.AddToDenylist(ctx, jti, ttl)
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

	return s.userRepo.Enable2FA(ctx, userID, totpSecret)
}

func (s *authService) VerifyLogin2FA(ctx context.Context, email, code string) (*AuthTokens, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("user not found")
	}

	isValid := totp.Validate(code, user.TOTPSecret)
	if !isValid {
		return nil, errors.New("invalid 2FA code")
	}

	return s.generateTokenPair(ctx, user)
}
