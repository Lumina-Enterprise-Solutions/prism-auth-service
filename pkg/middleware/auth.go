package middleware

import (
	"net/http"
	"strings"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/models"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

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
			return []byte(jwtConfig.Secret), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*models.Claims); ok {
			c.Set("user_id", claims.UserID)
			c.Set("tenant_id", claims.TenantID)
			c.Set("user_email", claims.Email)
			c.Set("user_roles", claims.Roles)
		}

		c.Next()
	}
}

// RequirePermission adalah middleware untuk memeriksa apakah user memiliki permission tertentu.
// `requiredPermission` formatnya: "resource:action", contoh: "users:create"
func RequirePermission(requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// 1. Dapatkan roles user dari context (diset oleh RequireAuth)
		userRolesVal, exists := c.Get("user_roles")
		if !exists {
			commonLogger.Warn(c, "RBAC: user_roles not found in context. Ensure RequireAuth runs first.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Not authenticated properly."})
			c.Abort()
			return
		}

		userRoles, ok := userRolesVal.([]string)
		if !ok {
			commonLogger.Error(c, "RBAC: user_roles in context is not []string.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Invalid role format."})
			c.Abort()
			return
		}

		if len(userRoles) == 0 {
			commonLogger.Info(c, "RBAC: User has no roles.", "required_permission", requiredPermission)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. No roles assigned."})
			c.Abort()
			return
		}

		// Untuk implementasi RBAC yang sebenarnya, Anda perlu:
		// A. Mengambil detail permission untuk setiap `userRoles` dari database (atau cache).
		//    Ini karena `claims.Roles` di JWT hanya berisi nama role, bukan daftar permission lengkap.
		//    Ini adalah bagian yang belum kita implementasikan sepenuhnya di service layer untuk middleware.
		//
		// B. Setelah mendapatkan semua permission dari semua role user, gabungkan dan cek.
		//
		// PENDEKATAN SEMENTARA (Sederhana, hanya jika permission ada di JWT, TIDAK DIREKOMENDASIKAN UNTUK PRODUKSI):
		// Jika Anda memutuskan untuk memasukkan permission langsung ke JWT (bisa membuat JWT besar),
		// maka `claims.Permissions` (misalnya `map[string][]string`) bisa dicek di sini.
		// Namun, ini tidak fleksibel karena perubahan permission memerlukan penerbitan ulang JWT.

		// PENDEKATAN YANG LEBIH BAIK (Membutuhkan pemanggilan service/repo):
		// Di sini kita akan membuat placeholder. Idealnya, middleware ini akan memanggil
		// sebuah service (misalnya `RBACService`) yang akan:
		//  1. Mendapatkan `userID` dan `tenantID` dari context.
		//  2. Mengambil semua role user dari `userRepo.GetUserRoles(userID, tenantID)`.
		//  3. Untuk setiap role, mengambil `role.Permissions`.
		//  4. Menggabungkan semua permission.
		//  5. Mengecek apakah `requiredPermission` ada di permission gabungan.

		// Untuk contoh ini, kita akan mensimulasikan bahwa kita sudah mendapatkan permission gabungan.
		// Misalkan kita punya fungsi `checkUserPermission(userID, tenantID, requiredPermission) bool`
		// yang melakukan langkah B di atas.

		// Placeholder logic:
		// Anda perlu mengganti ini dengan logika RBAC yang sesungguhnya.
		// Untuk sekarang, kita bisa log dan mengizinkan jika ada role "admin" sebagai contoh.
		// Ini TIDAK aman dan hanya untuk ilustrasi.

		//userID, _ := c.Get("user_id") // Anda bisa ambil userID jika perlu
		//tenantID, _ := c.Get("tenant_id") // Anda bisa ambil tenantID jika perlu

		hasPermission := false
		// Simulasi: Jika salah satu role adalah "admin", anggap punya semua permission.
		// Atau jika JWT Anda *memang* menyertakan permissions (TIDAK DIREKOMENDASIKAN):
		// userPermissionsVal, _ := c.Get("user_permissions_map") // Jika Anda set ini di RequireAuth
		// userPermissions, _ := userPermissionsVal.(map[string][]string)
		// if parts := strings.Split(requiredPermission, ":"); len(parts) == 2 {
		//     resource, action := parts[0], parts[1]
		//     if actions, ok := userPermissions[resource]; ok {
		//         for _, act := range actions {
		//             if act == action || act == "*" { // "*" untuk wildcard action
		//                 hasPermission = true
		//                 break
		//             }
		//         }
		//     }
		//     // Cek juga untuk resource wildcard, misal "admin:*"
		//     if !hasPermission {
		//        if actions, ok := userPermissions["*"]; ok { // "*" untuk wildcard resource
		//             for _, act := range actions {
		//                 if act == action || act == "*" {
		//                     hasPermission = true
		//                     break
		//                 }
		//             }
		//        }
		//     }
		// }

		// Logika RBAC yang lebih nyata (ini masih perlu service untuk fetch permissions):
		// Di sini kita perlu service untuk mengambil permissions dari role names.
		// Misal, ada `rbacService.UserHasPermission(userRoles, requiredPermission, tenantID)`
		// Untuk sementara, jika user memiliki role "admin", kita izinkan. Ini harus diganti!
		for _, roleName := range userRoles {
			if roleName == "admin" { // CONTOH SANGAT SEDERHANA, HARUS DIGANTI
				hasPermission = true
				break
			}
		}
		// Jika Anda ingin lebih detail, Anda bisa mengambil objek Role lengkap di middleware
		// (misalnya dengan memanggil roleRepo atau service), lalu cek permissionsnya.
		// Ini akan menambah overhead DB call per request yang diproteksi.
		// Alternatif: cache permissions role.

		if !hasPermission {
			commonLogger.Warn(c, "RBAC: Permission denied.",
				"user_roles", strings.Join(userRoles, ","),
				"required_permission", requiredPermission,
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied. Insufficient permissions."})
			c.Abort()
			return
		}

		commonLogger.Info(c, "RBAC: Permission granted.",
			"user_roles", strings.Join(userRoles, ","),
			"required_permission", requiredPermission,
		)
		c.Next()
	}
}
