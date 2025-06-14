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
	"github.com/golang-jwt/jwt/v5" // Pastikan ada
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
	googleoauth "google.golang.org/api/oauth2/v2"
)

// Definisikan struct baru untuk response 2FA setup
type TwoFASetup struct {
	QRCode       string `json:"qr_code"`       // Base64 encoded PNG image
	Secret       string `json:"secret"`        // Secret key untuk user yang ingin copy-paste manual
	ProvisionURL string `json:"provision_url"` // otpauth://... URL
}

// Definisikan struct baru untuk response login tahap 1
type LoginStep1Response struct {
	Is2FARequired bool        `json:"is_2fa_required"`
	AuthTokens    *AuthTokens `json:"auth_tokens,omitempty"` // Hanya diisi jika 2FA tidak diperlukan
}

type AuthTokens struct { // <-- TAMBAHKAN STRUCT INI
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AuthService interface {
	Register(ctx context.Context, user *model.User, password string) (string, error)
	// UBAH: Login sekarang mengembalikan struct AuthTokens
	// Login(ctx context.Context, email, password string) (*AuthTokens, error)
	// TAMBAHKAN: Method baru untuk me-refresh token
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
			"openid",    // Diperlukan untuk OIDC
			"profile",   // Info dasar profil
			"email",     // Alamat email
			"User.Read", // Diperlukan untuk membaca profil pengguna
		},
		Endpoint: microsoft.AzureADEndpoint("common"), // Endpoint "common" untuk multitenant & personal
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
	// Alurnya SAMA PERSIS dengan Google, hanya menggunakan config yang berbeda.
	// 1. Tukar kode dengan token dari Microsoft
	microsoftToken, err := s.microsoftOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("gagal menukar kode microsoft: %w", err)
	}

	// 2. Ambil id_token dari response. Microsoft menyimpannya di "extra"
	_, ok := microsoftToken.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token tidak ditemukan di response Microsoft")
	}

	// 3. Parse dan verifikasi id_token untuk mendapatkan info user
	// Untuk OIDC, kita bisa parse JWT ini. Tapi untuk simplicity, kita gunakan endpoint userinfo.
	oauthClient := s.microsoftOAuthConfig.Client(ctx, microsoftToken)
	oauthService, err := googleoauth.New(oauthClient) // Kita bisa pakai ulang library google untuk ini!
	if err != nil {
		return nil, fmt.Errorf("gagal membuat service oauth untuk microsoft: %w", err)
	}

	// Microsoft OIDC UserInfo endpoint adalah standar
	userInfo, err := oauthService.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil info user dari microsoft: %w", err)
	}

	// Alur selanjutnya sama persis dengan Google
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
	// 1. Tukar authorization code dengan token dari Google
	googleToken, err := s.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("gagal menukar kode: %w", err)
	}

	// 2. Gunakan token untuk membuat klien yang bisa mengambil info user
	oauthClient := s.googleOAuthConfig.Client(ctx, googleToken)
	oauthService, err := googleoauth.New(oauthClient)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat service oauth: %w", err)
	}

	// 3. Ambil info profil user dari Google
	userInfo, err := oauthService.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("gagal mengambil info user: %w", err)
	}

	// 4. Cari user di DB kita berdasarkan email
	user, err := s.userRepo.GetUserByEmail(ctx, userInfo.Email)
	if err != nil {
		// Jika user tidak ditemukan, buat user baru
		if errors.Is(err, pgx.ErrNoRows) { // Anda perlu import "github.com/jackc/pgx/v5"
			newUser := &model.User{
				Email:     userInfo.Email,
				FirstName: userInfo.GivenName,
				LastName:  userInfo.FamilyName,
				// PasswordHash bisa dikosongkan atau diisi nilai random karena tidak akan digunakan
				PasswordHash: "social-login",
			}
			userID, err := s.userRepo.CreateUser(ctx, newUser)
			if err != nil {
				return nil, fmt.Errorf("gagal membuat user baru dari social login: %w", err)
			}
			// Ambil kembali data user yang baru dibuat untuk mendapatkan ID-nya
			user, err = s.userRepo.GetUserByID(ctx, userID)
			if err != nil {
				return nil, fmt.Errorf("gagal mengambil user yang baru dibuat: %w", err)
			}
		} else {
			// Error database lain
			return nil, fmt.Errorf("error saat mencari user: %w", err)
		}
	}

	// 5. Buat token internal kita untuk user tersebut
	return s.generateTokenPair(ctx, user)
}

func (s *authService) Register(ctx context.Context, user *model.User, password string) (string, error) {
	// Logika bisnis: Hashing password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	// Set password yang sudah di-hash ke objek user
	user.PasswordHash = string(hashedPassword)

	// Memanggil lapisan repository untuk menyimpan data user lengkap
	userID, err := s.userRepo.CreateUser(ctx, user)
	if err != nil {
		return "", err // Gagal membuat user, jangan kirim notifikasi
	}

	// Panggil klien notifikasi SETELAH user berhasil dibuat
	s.notificationClient.SendWelcomeEmail(ctx, user.Email, user.FirstName)

	return userID, nil // Kembalikan userID seperti biasa
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

	// Cek apakah 2FA aktif untuk user ini
	if user.Is2FAEnabled {
		return &LoginStep1Response{Is2FARequired: true}, nil
	}

	// Jika 2FA tidak aktif, langsung berikan token
	tokens, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, err
	}
	return &LoginStep1Response{
		Is2FARequired: false,
		AuthTokens:    tokens,
	}, nil
}

// func (s *authService) Login(ctx context.Context, email, password string) (*AuthTokens, error) {
// 	user, err := s.userRepo.GetUserByEmail(ctx, email)
// 	if err != nil {
// 		return nil, errors.New("invalid credentials")
// 	}

// 	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
// 	if err != nil {
// 		return nil, errors.New("invalid credentials")
// 	}

// 	// Buat access token dan refresh token
// 	tokens, err := s.generateTokenPair(ctx, user)
// 	if err != nil {
// 		return nil, fmt.Errorf("could not generate tokens: %w", err)
// 	}

// 	return tokens, nil
// }

func (s *authService) generateJWT(user *model.User) (string, error) {
	expirationHours, _ := strconv.Atoi(os.Getenv("JWT_EXPIRATION_HOURS"))
	secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))

	claims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"role":  user.Role, // <-- TAMBAHKAN KLAIM PERAN (ROLE)
		"iss":   "prism-app-issuer",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour * time.Duration(expirationHours)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}
func (s *authService) RefreshToken(ctx context.Context, refreshTokenString string) (*AuthTokens, error) {
	// 1. Hash refresh token yang masuk agar bisa dicocokkan dengan yang di DB
	refreshTokenHash := hashToken(refreshTokenString)

	// 2. Dapatkan token dari DB
	storedToken, err := s.userRepo.GetRefreshToken(ctx, refreshTokenHash)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// 3. Hapus token lama dari DB (PENTING untuk keamanan)
	if err := s.userRepo.DeleteRefreshToken(ctx, refreshTokenHash); err != nil {
		// Log error ini tapi tetap lanjutkan agar user tidak stuck
		log.Printf("ERROR: Failed to delete old refresh token: %v", err)
	}

	// 4. Cek apakah token sudah kedaluwarsa
	if time.Now().After(storedToken.ExpiresAt) {
		return nil, errors.New("refresh token has expired")
	}

	// 5. Dapatkan data user yang terkait dengan token ini
	//    Di sini kita perlu menambahkan method GetUserByID ke repository
	//    (Kita akan melakukannya di langkah berikutnya)
	user, err := s.userRepo.GetUserByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("could not find user for token: %w", err)
	}

	// 6. Buat pasangan token baru
	tokens, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("could not generate new token pair: %w", err)
	}

	return tokens, nil
}
func (s *authService) generateTokenPair(ctx context.Context, user *model.User) (*AuthTokens, error) {
	// Buat Access Token
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	// Buat Refresh Token
	refreshToken, refreshTokenHash, expiresAt, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Simpan hash dari refresh token ke DB
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
		"jti":   uuid.NewString(), // <-- TAMBAHKAN JTI (JWT ID) UNIK
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}
func (s *authService) generateRefreshToken() (string, string, time.Time, error) {
	// Buat 32 byte random
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", time.Time{}, err
	}

	// Encode menjadi string yang aman untuk URL
	refreshTokenString := base64.URLEncoding.EncodeToString(randomBytes)

	// Hash token untuk disimpan di DB
	refreshTokenHash := hashToken(refreshTokenString)

	// Tentukan masa berlaku refresh token
	expirationDays, _ := strconv.Atoi(os.Getenv("REFRESH_TOKEN_EXPIRATION_DAYS"))
	if expirationDays == 0 {
		expirationDays = 7 // Default 7 hari
	}
	expiresAt := time.Now().Add(time.Hour * 24 * time.Duration(expirationDays))

	return refreshTokenString, refreshTokenHash, expiresAt, nil
}

// TAMBAHKAN: Helper untuk hashing token
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}
func (s *authService) Logout(ctx context.Context, claims jwt.MapClaims) error {
	jti, ok := claims["jti"].(string)
	if !ok {
		return errors.New("invalid token: missing jti")
	}

	// Ambil waktu kedaluwarsa token (exp)
	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("invalid token: missing exp")
	}
	expTime := time.Unix(int64(expFloat), 0)

	// Hitung sisa masa berlaku token (TTL)
	// Tambahkan sedikit buffer (misal 1 detik) untuk memastikan TTL positif
	ttl := time.Until(expTime) + 1*time.Second
	if ttl <= 0 {
		// Token sudah kedaluwarsa, tidak perlu di-blacklist.
		return nil
	}

	// Gunakan client Redis yang sudah kita buat
	// Karena client Redis di service auth-service, kita perlu buat package terpisah
	// Mari kita refactor ke `internal/redis`

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

	// Generate QR code sebagai gambar PNG
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return nil, fmt.Errorf("gagal generate QR code image: %w", err)
	}
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("gagal encode QR code ke PNG: %w", err)
	}

	// TODO: Enkripsi secret sebelum disimpan ke DB (untuk production)
	// Untuk sekarang, kita simpan plain text.
	// Di sini kita TIDAK menyimpan ke DB dulu, hanya mengembalikan ke user.
	// Kita simpan setelah user berhasil memverifikasi.

	return &TwoFASetup{
		QRCode:       base64.StdEncoding.EncodeToString(buf.Bytes()),
		Secret:       key.Secret(),
		ProvisionURL: key.String(),
	}, nil
}

func (s *authService) VerifyAndEnable2FA(ctx context.Context, userID, totpSecret, code string) error {
	// Verifikasi kode yang diberikan user terhadap secret yang baru dibuat
	isValid := totp.Validate(code, totpSecret)
	if !isValid {
		return errors.New("invalid 2FA code")
	}

	// Jika valid, simpan secret (terenkripsi) dan aktifkan 2FA di DB
	// TODO: Enkripsi totpSecret sebelum menyimpan
	return s.userRepo.Enable2FA(ctx, userID, totpSecret)
}

func (s *authService) VerifyLogin2FA(ctx context.Context, email, code string) (*AuthTokens, error) {
	user, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// TODO: Dekripsi user.TOTPSecret sebelum validasi
	isValid := totp.Validate(code, user.TOTPSecret)
	if !isValid {
		return nil, errors.New("invalid 2FA code")
	}

	// Jika kode valid, buatkan token
	return s.generateTokenPair(ctx, user)
}
