package services

import (
	"context"
	"fmt"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/cache"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	// refreshTokenTTL adalah durasi refresh token disimpan di Redis, harus sama dengan expiry di claims
	refreshTokenStoreTTL = 24 * 7 * time.Hour // 7 hari
)

type JWTService struct {
	config      config.JWTConfig
	redisClient *cache.RedisClient
}

func NewJWTService(config config.JWTConfig, redisClient *cache.RedisClient) *JWTService {
	return &JWTService{
		config:      config,
		redisClient: redisClient,
	}
}

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
			ID:        uuid.NewString(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Refresh token (long-lived)
	refreshTokenJTI := uuid.NewString()
	refreshTokenExpiresAt := time.Now().Add(refreshTokenStoreTTL)

	refreshClaims := &models.Claims{
		UserID:   userID,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        refreshTokenJTI, // Simpan JTI di dalam claims
			Subject:   userID,
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// [MODIFIKASI] Simpan JTI refresh token ke Redis
	err = s.redisClient.Set(context.Background(), s.getRefreshTokenRedisKey(refreshTokenJTI), userID, refreshTokenStoreTTL)
	if err != nil {
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
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

// [BARU] Fungsi untuk memvalidasi refresh token JTI secara eksplisit
func (s *JWTService) ValidateRefreshTokenJTI(jti string) (userID string, isValid bool, err error) {
	redisKey := s.getRefreshTokenRedisKey(jti)
	err = s.redisClient.Get(context.Background(), redisKey, &userID)
	if err != nil {
		if err == cache.ErrNil {
			return "", false, nil // JTI tidak ditemukan, token tidak valid, bukan error aplikasi
		}
		// Error redis lainnya
		return "", false, fmt.Errorf("error checking refresh token JTI from redis: %w", err)
	}
	return userID, true, nil // JTI ditemukan, token valid
}

// [BARU] Fungsi untuk mencabut (revoke) refresh token JTI
func (s *JWTService) RevokeRefreshTokenJTI(jti string) error {
	redisKey := s.getRefreshTokenRedisKey(jti)
	err := s.redisClient.Delete(context.Background(), redisKey)
	if err != nil {
		// Jika key sudah tidak ada, redis.Del tidak error. Jadi kita hanya cek error koneksi dll.
		commonLogger.Errorf("Error revoking refresh token JTI from redis: %v", err)
		return err
	}
	return nil
}
