package middleware

import (
	"net/http"
	"strings"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	// Impor RoleRepository atau interface yang akan digunakannya

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models" // Untuk commonModels.PermissionMap

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// Interface untuk dependency RBAC check, agar bisa di-mock atau diganti implementasinya
type RBACPermissionChecker interface {
	GetUserPermissions(tenantID string, roleNames []string) (commonModels.PermissionMap, error)
}

// RequireAuth middleware for this specific service
func RequireAuth(jwtConfig config.JWTConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

		token, err := jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				commonLogger.Error(c, "Unexpected signing method in JWT", "method", token.Header["alg"])
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(jwtConfig.Secret), nil
		})

		if err != nil || !token.Valid {
			validationErr, ok := err.(*jwt.ValidationError)
			if ok {
				if validationErr.Errors&jwt.ValidationErrorMalformed != 0 {
					commonLogger.Warn(c, "Malformed JWT token received.")
				} else if validationErr.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
					commonLogger.Info(c, "Expired or not yet valid JWT token received.")
				} else {
					commonLogger.Warn(c, "Invalid JWT token.", "error", err)
				}
			} else {
				commonLogger.Warn(c, "Invalid JWT token.", "error", err)
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*models.Claims); ok {
			c.Set("user_id", claims.UserID)
			c.Set("tenant_id", claims.TenantID)
			c.Set("user_email", claims.Email)
			c.Set("user_roles", claims.Roles) // claims.Roles adalah []string berisi nama role
		} else {
			commonLogger.Error(c, "Failed to parse JWT claims.")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// RequirePermission sekarang menerima RBACPermissionChecker
// `requiredPermission` formatnya: "resource:action", contoh: "users:create"
func RequirePermission(permissionChecker RBACPermissionChecker, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Dapatkan roles user dari context (diset oleh RequireAuth)
		userRolesVal, exists := c.Get("user_roles")
		if !exists {
			commonLogger.Warn(c, "RBAC: user_roles not found in context. Ensure RequireAuth runs first.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. User roles not available."})
			c.Abort()
			return
		}

		userRoleNames, ok := userRolesVal.([]string)
		if !ok {
			commonLogger.Error(c, "RBAC: user_roles in context is not []string.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Invalid role format in token."})
			c.Abort()
			return
		}

		if len(userRoleNames) == 0 {
			commonLogger.Info(c, "RBAC: User has no roles.", "required_permission", requiredPermission)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. No roles assigned to user."})
			c.Abort()
			return
		}

		tenantIDVal, _ := c.Get("tenant_id")
		tenantID, ok := tenantIDVal.(string)
		if !ok || tenantID == "" {
			commonLogger.Warn(c, "RBAC: tenant_id not found or invalid in context.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Tenant information missing."})
			c.Abort()
			return
		}

		// 2. Dapatkan semua permission gabungan untuk user berdasarkan role-rolenya
		// Ini akan memanggil metode dari permissionChecker yang disuntikkan
		userPermissions, err := permissionChecker.GetUserPermissions(tenantID, userRoleNames)
		if err != nil {
			commonLogger.Error(c, "RBAC: Error fetching user permissions.", "error", err, "roles", userRoleNames)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error processing permissions."})
			c.Abort()
			return
		}

		// 3. Cek apakah requiredPermission ada di userPermissions
		hasPermission := false
		parts := strings.Split(requiredPermission, ":")
		if len(parts) == 2 {
			resource, action := parts[0], parts[1]

			// Cek permission spesifik: resource:action
			if actions, ok := userPermissions[resource]; ok {
				for _, act := range actions {
					if act == action || act == "*" { // "*" adalah wildcard untuk action
						hasPermission = true
						break
					}
				}
			}

			// Jika tidak ada permission spesifik, cek wildcard resource: resource:*
			if !hasPermission {
				if actions, ok := userPermissions[resource]; ok {
					for _, act := range actions {
						if act == "*" {
							hasPermission = true
							break
						}
					}
				}
			}

			// Jika masih tidak ada, cek wildcard umum: "*:action" (kurang umum tapi bisa)
			if !hasPermission {
				if actions, ok := userPermissions["*"]; ok { // "*" adalah wildcard untuk resource
					for _, act := range actions {
						if act == action || act == "*" {
							hasPermission = true
							break
						}
					}
				}
			}

			// Cek wildcard paling umum: "*:*"
			if !hasPermission {
				if actions, ok := userPermissions["*"]; ok {
					for _, act := range actions {
						if act == "*" {
							hasPermission = true
							break
						}
					}
				}
			}

		} else {
			commonLogger.Warn(c, "RBAC: Invalid requiredPermission format.", "format", requiredPermission)
		}

		if !hasPermission {
			commonLogger.Warn(c, "RBAC: Permission denied.",
				"user_roles", strings.Join(userRoleNames, ","),
				"required_permission", requiredPermission,
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Insufficient permissions."})
			c.Abort()
			return
		}

		commonLogger.Info(c, "RBAC: Permission granted.",
			"user_roles", strings.Join(userRoleNames, ","),
			"required_permission", requiredPermission,
		)
		c.Next()
	}
}
