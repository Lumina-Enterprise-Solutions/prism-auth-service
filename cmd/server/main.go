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

	// authConfigModule "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/config" // Tidak lagi dibutuhkan jika commonConfig.Load() cukup
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handlers"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/services"

	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	commonDb "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/database"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/discovery"
	commonLogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/logger"
	commonMiddleware "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/middleware"
	commonModels "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/models"

	"github.com/gin-gonic/gin"
)

func main() {
	// Langkah 1: Muat konfigurasi dari Vault (atau sumber lain yang dikelola commonConfig.Load)
	// commonConfig.Load() diharapkan membaca VAULT_ADDR, VAULT_TOKEN, VAULT_CONFIG_PATH dari env.
	cfg, err := commonConfig.Load()
	if err != nil {
		// Gunakan logger standar Go karena commonLogger mungkin belum terkonfigurasi
		stdlog.Fatalf("FATAL: Failed to load application configuration: %v", err)
	}

	// (Opsional) Konfigurasi commonLogger berdasarkan nilai dari cfg
	// Misalnya, jika cfg memiliki field Log.Level:
	// if level, err := commonLogger.ParseLevel(cfg.Log.Level); err == nil {
	//     commonLogger.SetLevel(level)
	// }
	commonLogger.Info("Application configuration loaded successfully.")

	// Langkah 2: Inisialisasi Koneksi Database
	db, err := commonDb.NewPostgresConnection(&cfg.Database) // cfg.Database diisi oleh commonConfig.Load()
	if err != nil {
		commonLogger.Fatal("Failed to connect to database", "error", err)
	}
	commonLogger.Info("Database connection established.")

	// Langkah 3: Inisialisasi Klien Consul untuk Service Discovery
	// cfg.Consul.Address diisi oleh commonConfig.Load() dari Vault (key: "consul_address")
	consulDiscoveryClient, err := discovery.NewConsulClient(cfg) // cfg adalah *commonConfig.Config
	if err != nil {
		commonLogger.Fatal("Failed to create Consul discovery client", "error", err)
	}
	commonLogger.Info("Consul discovery client initialized.", "consul_address", cfg.Consul.Address)

	// Langkah 4: Persiapan Detail untuk Registrasi Service
	// Asumsi cfg.ServiceName dan cfg.Server.Port diisi oleh commonConfig.Load() dari Vault
	if cfg.ServiceName == "" {
		commonLogger.Fatal("Service name is not configured (expected from Vault via commonConfig.Load).")
	}
	if cfg.Server.Port == 0 {
		commonLogger.Fatal("Server port is not configured (expected from Vault via commonConfig.Load).")
	}

	serviceID := fmt.Sprintf("%s-%s", cfg.ServiceName, uuid.New().String())

	// serviceHostForRegistration adalah nama service ini di Docker Compose,
	// yang dapat di-resolve di dalam network bersama (prism_global_network).
	// Ini harus sesuai dengan nama service di prism-auth-service/docker-compose.yml
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
		serviceHostForRegistration, // Alamat yang akan digunakan Consul untuk health check & ditemukan service lain
		cfg.Server.Port,
	)
	if err != nil {
		commonLogger.Fatal("Failed to register service with Consul", "error", err)
	}
	commonLogger.Info("Service registered with Consul successfully.")

	// Langkah 5: Inisialisasi Repositories
	userRepo := repository.NewUserRepository(db)
	tenantRepo := repository.NewTenantRepository(db)

	// Pastikan tenant default ada
	tenant, err := tenantRepo.GetBySlug("default")
	if err != nil {
		commonLogger.Fatal("Failed to query for default tenant", "error", err)
	}
	if tenant == nil {
		commonLogger.Info("Default tenant not found, creating one...")
		defaultTenant := &commonModels.Tenant{
			Name:   "Default Tenant", // Bisa juga dari config jika perlu
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

	// Langkah 6: Inisialisasi Application Services
	jwtService := services.NewJWTService(cfg.JWT) // cfg.JWT diisi oleh commonConfig.Load()
	authAppService := services.NewAuthService(userRepo, jwtService)
	userAppService := services.NewUserService(userRepo, tenantRepo)
	commonLogger.Info("Application services initialized.")

	// Langkah 7: Inisialisasi HTTP Handlers
	authHandler := handlers.NewAuthHandler(authAppService)
	userHandler := handlers.NewUserHandler(userAppService)
	healthHandler := handlers.NewHealthHandler() // Jika butuh DB: handlers.NewHealthHandler(db)
	commonLogger.Info("HTTP handlers initialized.")

	// Langkah 8: Setup Router
	router := setupRouter(cfg, authHandler, userHandler, healthHandler)
	commonLogger.Info("HTTP router configured.")

	// Langkah 9: Konfigurasi dan Jalankan HTTP Server
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

	// Langkah 10: Implementasi Graceful Shutdown
	quitChannel := make(chan os.Signal, 1)
	signal.Notify(quitChannel, syscall.SIGINT, syscall.SIGTERM)
	receivedSignal := <-quitChannel
	commonLogger.Info("Received shutdown signal", "signal", receivedSignal.String())

	// Deregister dari Consul
	commonLogger.Info("Attempting to deregister service from Consul...", "service_id", serviceID)
	if err := consulDiscoveryClient.DeregisterService(serviceID); err != nil {
		commonLogger.Error("Failed to deregister service from Consul", "service_id", serviceID, "error", err)
	} else {
		commonLogger.Info("Service deregistered from Consul successfully.")
	}

	// Shutdown HTTP server
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 30*time.Second) // Timeout bisa dari cfg
	defer cancelShutdown()

	commonLogger.Info("Attempting graceful shutdown of HTTP server...")
	if err := srv.Shutdown(shutdownCtx); err != nil {
		commonLogger.Fatal("HTTP server graceful shutdown failed", "error", err)
	}

	commonLogger.Info("HTTP server shutdown complete. Application exiting.")
}

// setupRouter sekarang menerima *commonConfig.Config
func setupRouter(
	cfg *commonConfig.Config,
	authHandler *handlers.AuthHandler,
	userHandler *handlers.UserHandler,
	healthHandler *handlers.HealthHandler,
) *gin.Engine {

	// Ambil gin_mode dari konfigurasi yang dimuat (misal dari Vault)
	// Asumsi ada helper atau cara untuk mendapatkan "gin_mode" dari cfg.
	// Jika tidak, Anda bisa hardcode atau ambil dari env var lain yang tidak dari Vault.
	// Untuk contoh ini, kita asumsikan cfg bisa menyediakan string "gin_mode".
	// Jika cfg tidak memiliki metode GetStringFromMap, dan sudah menjadi struct:
	// Anda perlu memastikan 'gin_mode' adalah field di struct cfg atau sub-structnya.
	// Misal: cfg.Server.GinMode
	// Untuk kesederhanaan, kita pakai env var biasa untuk GIN_MODE saat ini.
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

	// Gunakan logger dan recovery kustom dari common-libs jika tersedia dan diinginkan
	// Sesuaikan dengan implementasi di commonLogger Anda
	if commonLogger.Log != nil { // Periksa apakah logger sudah diinisialisasi
		router.Use(commonLogger.GinLogger(commonLogger.Log), commonLogger.GinRecovery(commonLogger.Log, true))
	} else { // Fallback ke logger Gin standar
		router.Use(gin.Logger(), gin.Recovery())
	}

	router.Use(commonMiddleware.CORS())
	router.Use(commonMiddleware.RequestID())
	router.Use(commonMiddleware.TenantMiddleware())

	// Health check endpoints
	router.GET("/health", healthHandler.HealthCheck)
	router.GET("/ready", healthHandler.ReadinessCheck) // Pastikan ReadinessCheck diimplementasikan

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		authGroup := v1.Group("/auth")
		{
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/refresh", authHandler.RefreshToken)
			authGroup.POST("/logout", authHandler.Logout)
			authGroup.POST("/forgot-password", authHandler.ForgotPassword)
			authGroup.POST("/reset-password", authHandler.ResetPassword)
		}

		// Protected routes
		// cfg.JWT adalah *commonConfig.JWTConfig yang diisi oleh commonConfig.Load()
		protected := v1.Group("/")
		protected.Use(commonMiddleware.RequireAuth(cfg.JWT))
		{
			users := protected.Group("/users")
			{
				users.GET("/", userHandler.GetUsers)
				users.GET("/:id", userHandler.GetUser)
				users.PUT("/:id", userHandler.UpdateUser)
				users.DELETE("/:id", userHandler.DeleteUser)
				users.GET("/profile", userHandler.GetProfile)
				users.PUT("/profile", userHandler.UpdateProfile)
				users.POST("/change-password", userHandler.ChangePassword)
			}
			roles := protected.Group("/roles")
			{
				roles.GET("/", userHandler.GetRoles)
				roles.POST("/", userHandler.CreateRole)
				roles.PUT("/:id", userHandler.UpdateRole)
				roles.DELETE("/:id", userHandler.DeleteRole)
			}
		}
	}
	return router
}
