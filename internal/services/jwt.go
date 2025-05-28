package services

import (
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	"github.com/golang-jwt/jwt/v4"
)

type JWTService struct {
	config config.JWTConfig
}

func NewJWTService(config config.JWTConfig) *JWTService {
	return &JWTService{config: config}
}

func (s *JWTService) GenerateTokens(userID, email, tenantID string, roles []string) (string, string, time.Time, error) {
	// Access token (short-lived)
	expiresAt := time.Now().Add(time.Duration(s.config.ExpirationTime) * time.Second)

	claims := &models.Claims{
		UserID:   userID,
		Email:    email,
		TenantID: tenantID,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	// Refresh token (long-lived)
	refreshClaims := &models.Claims{
		UserID:   userID,
		Email:    email,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * 7 * time.Hour)), // 7 days
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.Secret))
	if err != nil {
		return "", "", time.Time{}, err
	}

	return accessToken, refreshTokenString, expiresAt, nil
}

func (s *JWTService) ValidateToken(tokenString string) (*models.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.config.Secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*models.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, jwt.ErrSignatureInvalid
}
