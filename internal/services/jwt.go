// File: prism-auth-service/internal/services/jwt.go
package services

import (
	"context" // <-- [TAMBAHKAN]
	"fmt"     // <-- [TAMBAHKAN]
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/cache" // <-- [TAMBAHKAN]
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid" // <-- [TAMBAHKAN]
)

const (
	refreshTokenType = "refresh_token"
	// refreshTokenTTL adalah durasi refresh token disimpan di Redis, harus sama dengan expiry di claims
	refreshTokenStoreTTL = 24 * 7 * time.Hour // 7 hari
)

type JWTService struct {
	config      config.JWTConfig
	redisClient *cache.RedisClient // <-- [TAMBAHKAN]
}

// [MODIFIKASI] Konstruktor untuk menerima RedisClient
func NewJWTService(config config.JWTConfig, redisClient *cache.RedisClient) *JWTService {
	return &JWTService{
		config:      config,
		redisClient: redisClient,
	}
}

// Helper function untuk membuat key Redis untuk refresh token
func (s *JWTService) getRefreshTokenRedisKey(jti string) string {
	return fmt.Sprintf("refresh_token_jti:%s", jti)
}

func (s *JWTService) GenerateTokens(userID, email, tenantID string, roles []string) (string, string, time.Time, error) {
	// Access token (short-lived)
	accessTokenExpiresAt := time.Now().Add(time.Duration(s.config.ExpirationTime) * time.Second)
	accessTokenClaims := &models.Claims{
		UserID:   userID,
		Email:    email,
		TenantID: tenantID,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(), // JTI untuk Access Token (opsional, tapi baik)
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Refresh token (long-lived)
	refreshTokenJTI := uuid.NewString() // JTI unik untuk refresh token ini
	refreshTokenExpiresAt := time.Now().Add(refreshTokenStoreTTL)

	refreshClaims := &models.Claims{
		UserID:   userID,
		Email:    email,    // Bisa dihilangkan dari refresh token jika tidak perlu
		TenantID: tenantID, // Bisa dihilangkan dari refresh token jika tidak perlu
		// Roles tidak perlu di refresh token, karena akan diambil dari DB saat refresh
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ID:        refreshTokenJTI, // Simpan JTI di dalam claims
			Subject:   userID,          // Subject adalah user ID
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// [TAMBAHKAN] Simpan JTI refresh token ke Redis
	// Nilai yang disimpan bisa sederhana (misalnya "true" atau user ID)
	// Kuncinya adalah JTI, masa berlakunya sama dengan token.
	err = s.redisClient.Set(context.Background(), s.getRefreshTokenRedisKey(refreshTokenJTI), userID, refreshTokenStoreTTL)
	if err != nil {
		// Jika gagal menyimpan ke Redis, token tidak boleh diterbitkan karena tidak bisa direvoke/dirotasi
		return "", "", time.Time{}, fmt.Errorf("could not store refresh token JTI: %w", err)
	}

	return accessToken, refreshTokenString, accessTokenExpiresAt, nil
}

func (s *JWTService) ValidateToken(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid // Atau error yang lebih spesifik
	}

	// [TAMBAHKAN] Untuk refresh token, periksa apakah JTI-nya ada di Redis (valid)
	// Kita bisa bedakan jenis token dengan field tambahan di claims atau dari konteks penggunaan.
	// Untuk sekarang, kita asumsikan ValidateToken ini bisa dipanggil untuk access atau refresh.
	// Saat digunakan untuk refresh, kita akan melakukan pengecekan JTI.
	// Pengecekan JTI lebih baik dilakukan di service yang menggunakan refresh token (AuthService).

	return claims, nil
}

// [TAMBAHKAN] Fungsi untuk memvalidasi refresh token JTI secara eksplisit
func (s *JWTService) ValidateRefreshTokenJTI(jti string) (string, bool, error) {
	var userID string
	err := s.redisClient.Get(context.Background(), s.getRefreshTokenRedisKey(jti), &userID)
	if err == cache.ErrNil { // cache.ErrNil jika Redis mengembalikan nil (key tidak ada)
		return "", false, nil // JTI tidak ditemukan, token tidak valid
	}
	if err != nil {
		return "", false, fmt.Errorf("error checking refresh token JTI from redis: %w", err)
	}
	return userID, true, nil // JTI ditemukan, token valid
}

// [TAMBAHKAN] Fungsi untuk mencabut (revoke) refresh token JTI
func (s *JWTService) RevokeRefreshTokenJTI(jti string) error {
	err := s.redisClient.Delete(context.Background(), s.getRefreshTokenRedisKey(jti))
	if err != nil && err != cache.ErrNil { // cache.ErrNil jika key sudah tidak ada, itu bukan error
		return fmt.Errorf("error revoking refresh token JTI from redis: %w", err)
	}
	return nil
}

// [TAMBAHKAN] Helper untuk mengekstrak JTI dari token string
func (s *JWTService) ExtractJTI(tokenString string) (string, error) {
	claims, err := s.ValidateToken(tokenString) // Validasi dulu, termasuk expiry
	if err != nil {
		return "", fmt.Errorf("cannot extract JTI from invalid token: %w", err)
	}
	if claims.ID == "" {
		return "", fmt.Errorf("token does not contain JTI (ID claim)")
	}
	return claims.ID, nil
}
