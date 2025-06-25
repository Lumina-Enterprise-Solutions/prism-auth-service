// services/prism-auth-service/internal/middleware/auth_middleware.go
package middleware

import (
	"net/http"
	"strings"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonauth "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// FlexibleAuthMiddleware akan mencoba otentikasi via JWT, lalu fallback ke API Key.
func FlexibleAuthMiddleware(authSvc service.AuthService, redisClient *redis.Client) gin.HandlerFunc {
	jwtMiddleware := commonauth.JWTMiddleware(redisClient)

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		apiKeyHeader := c.GetHeader("X-API-Key")

		if strings.HasPrefix(authHeader, "Bearer ") {
			jwtMiddleware(c) // Gunakan middleware JWT yang sudah ada
			return
		}

		if apiKeyHeader != "" {
			user, err := authSvc.ValidateAPIKey(c.Request.Context(), apiKeyHeader)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid API Key"})
				return
			}

			c.Set("user_id", user.ID)
			c.Set("claims", jwt.MapClaims{"sub": user.ID, "email": user.Email, "role": user.RoleName})
			c.Next()
			return
		}

		// Jika tidak ada header sama sekali
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required (Bearer Token or X-API-Key)"})
	}
}
