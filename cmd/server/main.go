// File: prism-auth-service/cmd/server/main.go
package main

import (
	"context"
	"fmt"
	stdlog "log" // Menggunakan alias agar tidak bentrok dengan commonLogger jika ada
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handlers"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/services"

	commonCache "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/cache" // <-- [TAMBAHKAN]
	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonDb "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/discovery"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	commonMiddleware "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/middleware"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := commonConfig.Load()
	if err != nil {
		stdlog.Fatalf("FATAL: Failed to load application configuration: %v", err)
	}
	commonLogger.Info("Application configuration loaded successfully.")

	db, err := commonDb.NewPostgresConnection(&cfg.Database)
	if err != nil {
		commonLogger.Fatal("Failed to connect to database", "error", err)
	}
	commonLogger.Info("Database connection established.")

	// [TAMBAHKAN] Inisialisasi Redis Client
	redisClient := commonCache.NewRedisClient(cfg.Redis) // cfg.Redis diisi oleh commonConfig.Load()
	// Ping untuk memastikan koneksi (opsional tapi bagus untuk startup check)
	if _, err := redisClient.Exists(context.Background(), "startup_ping"); err != nil { // Menggunakan Exists sebagai ping sederhana
		commonLogger.Warn("Could not connect to Redis or Redis is not ready", "error", err)
		// Anda mungkin ingin menggagalkan startup jika Redis krusial:
		// commonLogger.Fatal("Failed to connect to Redis", "error", err)
	} else {
		commonLogger.Info("Redis connection established.")
	}

	consulDiscoveryClient, err := discovery.NewConsulClient(cfg)
	if err != nil {
		commonLogger.Fatal("Failed to create Consul discovery client", "error", err)
	}
	commonLogger.Info("Consul discovery client initialized.", "consul_address", cfg.Consul.Address)

	if cfg.ServiceName == "" {
		commonLogger.Fatal("Service name is not configured (expected from Vault via commonConfig.Load).")
	}
	if cfg.Server.Port == 0 {
		commonLogger.Fatal("Server port is not configured (expected from Vault via commonConfig.Load).")
	}

	serviceID := fmt.Sprintf("%s-%s", cfg.ServiceName, uuid.New().String())
	serviceHostForRegistration := "auth-service"
	commonLogger.Info("Attempting to register service with Consul...",
		"service_id", serviceID,
		"service_name", cfg.ServiceName,
		"register_as_host", serviceHostForRegistration,
		"port", cfg.Server.Port,
	)
	err = consulDiscoveryClient.RegisterService(
		serviceID,
		cfg.ServiceName,
		serviceHostForRegistration,
		cfg.Server.Port,
	)
	if err != nil {
		commonLogger.Fatal("Failed to register service with Consul", "error", err)
	}
	commonLogger.Info("Service registered with Consul successfully.")

	userRepo := repository.NewUserRepository(db)
	tenantRepo := repository.NewTenantRepository(db)
	roleRepo := repository.NewRoleRepository(db) // <-- [TAMBAHKAN]

	tenant, err := tenantRepo.GetBySlug("default")
	if err != nil {
		commonLogger.Fatal("Failed to query for default tenant", "error", err)
	}
	if tenant == nil {
		commonLogger.Info("Default tenant not found, creating one...")
		defaultTenant := &commonModels.Tenant{
			Name:   "Default Tenant",
			Slug:   "default",
			Status: "active",
		}
		if err := tenantRepo.Create(defaultTenant); err != nil {
			commonLogger.Fatal("Failed to create default tenant", "error", err)
		}
		commonLogger.Info("Default tenant created.")
	} else {
		commonLogger.Info("Default tenant found.")
	}

	// [MODIFIKASI] Teruskan redisClient ke JWTService
	jwtService := services.NewJWTService(cfg.JWT, redisClient)
	// [MODIFIKASI] Teruskan redisClient ke AuthService jika AuthService perlu revoke token langsung
	authAppService := services.NewAuthService(userRepo, jwtService, redisClient)
	// [MODIFIKASI] Teruskan roleRepo ke NewUserService
	userAppService := services.NewUserService(userRepo, tenantRepo, roleRepo)
	commonLogger.Info("Application services initialized.")

	authHandler := handlers.NewAuthHandler(authAppService)
	userHandler := handlers.NewUserHandler(userAppService, authAppService)
	healthHandler := handlers.NewHealthHandler()
	commonLogger.Info("HTTP handlers initialized.")

	router := setupRouter(cfg, authHandler, userHandler, healthHandler)
	commonLogger.Info("HTTP router configured.")

	serverAddr := fmt.Sprintf(":%d", cfg.Server.Port)
	commonLogger.Info("Starting HTTP server...", "address", serverAddr, "read_timeout", cfg.Server.ReadTimeout, "write_timeout", cfg.Server.WriteTimeout)

	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			commonLogger.Fatal("HTTP server ListenAndServe error", "error", err)
		}
	}()

	quitChannel := make(chan os.Signal, 1)
	signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)
	receivedSignal := <-quitChannel
	commonLogger.Info("Received shutdown signal", "signal", receivedSignal.String())

	commonLogger.Info("Attempting to deregister service from Consul...", "service_id", serviceID)
	if err := consulDiscoveryClient.DeregisterService(serviceID); err != nil {
		commonLogger.Error("Failed to deregister service from Consul", "service_id", serviceID, "error", err)
	} else {
		commonLogger.Info("Service deregistered from Consul successfully.")
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelShutdown()

	commonLogger.Info("Attempting graceful shutdown of HTTP server...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		commonLogger.Fatal("HTTP server graceful shutdown failed", "error", err)
	}

	commonLogger.Info("HTTP server shutdown complete. Application exiting.")
}

func setupRouter(
	cfg *commonConfig.Config,
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler, // UserHandler sekarang menangani endpoint roles juga
	healthHandler *handlers.HealthHandler,
) *gin.Engine {
	ginMode := os.Getenv("GIN_MODE")
	if ginMode == "" {
		ginMode = gin.DebugMode // Default
	}
	if ginMode == gin.ReleaseMode {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
	commonLogger.Info("GIN mode set.", "mode", gin.Mode())
	router := gin.New()
	if commonLogger.Log != nil {
		router.Use(commonLogger.GinLogger(commonLogger.Log), commonLogger.GinRecovery(commonLogger.Log, true))
	} else {
		router.Use(gin.Logger(), gin.Recovery())
	}
	router.Use(commonMiddleware.CORS())
	router.Use(commonMiddleware.RequestID())
	router.Use(commonMiddleware.TenantMiddleware())
	router.GET("/health", healthHandler.HealthCheck)
	router.GET("/ready", healthHandler.ReadinessCheck)
	v1 := router.Group("/api/v1")
	{
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/refresh", authHandler.RefreshToken)
			// [TAMBAHKAN] Logout endpoint baru
			authGroup.POST("/logout", commonMiddleware.RequireAuth(cfg.JWT), authHandler.Logout) // Logout perlu diautentikasi untuk tahu token mana yang direvoke
			authGroup.POST("/forgot-password", authHandler.ForgotPassword)
			authGroup.POST("/reset-password", authHandler.ResetPassword)
		}
		protected := v1.Group("/")
		protected.Use(commonMiddleware.RequireAuth(cfg.JWT)) // Middleware JWT untuk semua di 'protected'
		// Tambahkan middleware RBAC di sini jika sudah siap
		{
			usersGroup := protected.Group("/users")
			{
				usersGroup.GET("/", userHandler.GetUsers)         // Membutuhkan: "users:read"
				usersGroup.GET("/:id", userHandler.GetUser)       // Membutuhkan: "users:read"
				usersGroup.PUT("/:id", userHandler.UpdateUser)    // Membutuhkan: "users:update"
				usersGroup.DELETE("/:id", userHandler.DeleteUser) // Membutuhkan: "users:delete"
				// Endpoint Create User mungkin lebih cocok di luar user specific /:id
				// usersGroup.POST("/", userHandler.CreateUser) // Ini mungkin perlu di admin/users, bukan /users

				usersGroup.GET("/profile", userHandler.GetProfile)              // User bisa lihat profil sendiri
				usersGroup.PUT("/profile", userHandler.UpdateProfile)           // User bisa update profil sendiri
				usersGroup.POST("/change-password", userHandler.ChangePassword) // User bisa ganti password sendiri

				// User-Role specific endpoints
				usersGroup.POST("/assign-role", userHandler.AssignRoleToUser)   // Membutuhkan: "users:manage_roles" atau "roles:assign"
				usersGroup.POST("/revoke-role", userHandler.RevokeRoleFromUser) // Membutuhkan: "users:manage_roles" atau "roles:revoke"
				usersGroup.GET("/:user_id/roles", userHandler.GetUserRoles)     // Membutuhkan: "users:read_roles"
			}

			// Endpoint untuk manajemen roles itu sendiri
			rolesGroup := protected.Group("/roles")
			{
				rolesGroup.GET("/", userHandler.GetRoles)              // Membutuhkan: "roles:read"
				rolesGroup.POST("/", userHandler.CreateRole)           // Membutuhkan: "roles:create"
				rolesGroup.GET("/:role_id", userHandler.GetRoleByID)   // Membutuhkan: "roles:read"
				rolesGroup.PUT("/:role_id", userHandler.UpdateRole)    // Membutuhkan: "roles:update"
				rolesGroup.DELETE("/:role_id", userHandler.DeleteRole) // Membutuhkan: "roles:delete"
			}
		}
	}
	return router
}
