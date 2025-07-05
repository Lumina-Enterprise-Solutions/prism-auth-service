package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	authconfig "github.com/Lumina-Enterprise-Solutions/prism-auth-service/config"
	authclient "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/grpc_server"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handler"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/middleware"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonclient "github.com/Lumina-Enterprise-Solutions/prism-common-libs/client"
	enhancedlogger "github.com/Lumina-Enterprise-Solutions/prism-common-libs/enhanced_logger"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/telemetry"
	authv1 "github.com/Lumina-Enterprise-Solutions/prism-protobufs/gen/go/prism/auth/v1"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	redis_client "github.com/redis/go-redis/v9"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"google.golang.org/grpc"
)

// setupDependencies menginisialisasi semua dependensi yang diperlukan aplikasi
// seperti Vault client, database connection pool, dan secret loading
func setupDependencies(cfg *authconfig.Config) (*pgxpool.Pool, error) {
	// Membuat logger khusus untuk setup dependencies dengan context yang jelas
	setupLogger := enhancedlogger.WithService("prism-auth-service")

	// Log dimulainya proses setup dependencies
	setupLogger.Info().Msg("Starting dependencies setup")

	// 1. Inisialisasi VaultClient menggunakan konfigurasi yang disuntikkan
	setupLogger.Debug().
		Str("vault_addr", cfg.VaultAddr).
		Msg("Initializing Vault client")

	vaultClient, err := commonclient.NewVaultClient(cfg.VaultAddr, cfg.VaultToken)
	if err != nil {
		// Log error dengan detail yang cukup untuk debugging
		setupLogger.Error().
			Err(err).
			Str("vault_addr", cfg.VaultAddr).
			Msg("Failed to create Vault client")
		return nil, fmt.Errorf("gagal membuat klien Vault: %w", err)
	}

	// Log sukses membuat Vault client
	setupLogger.Info().
		Str("vault_addr", cfg.VaultAddr).
		Msg("Vault client initialized successfully")

	// 2. Muat rahasia dari Vault ke environment variables
	secretPath := "secret/data/prism"
	requiredSecrets := []string{
		"database_url",
		"jwt_secret_key",
		"google_oauth_client_id",
		"google_oauth_client_secret",
		"microsoft_oauth_client_id",
		"microsoft_oauth_client_secret",
	}

	// Log proses loading secrets dengan detail path dan required secrets
	setupLogger.Debug().
		Str("secret_path", secretPath).
		Strs("required_secrets", requiredSecrets).
		Msg("Loading secrets from Vault")

	if err := vaultClient.LoadSecretsToEnv(secretPath, requiredSecrets...); err != nil {
		// Log error dengan detail secret path yang gagal dimuat
		setupLogger.Error().
			Err(err).
			Str("secret_path", secretPath).
			Strs("required_secrets", requiredSecrets).
			Msg("Failed to load secrets from Vault")
		return nil, fmt.Errorf("gagal memuat rahasia-rahasia penting dari Vault: %w", err)
	}

	// Log sukses loading secrets
	setupLogger.Info().
		Str("secret_path", secretPath).
		Int("secrets_count", len(requiredSecrets)).
		Msg("Secrets loaded successfully from Vault")

	// 3. Inisialisasi koneksi Database
	// Ambil database URL dari environment variable yang sudah dimuat dari Vault
	databaseURL := os.Getenv("DATABASE_URL")

	// Log proses inisialisasi database connection pool
	setupLogger.Debug().
		Str("database_url_prefix", databaseURL[:20]+"..."). // Hanya tampilkan prefix untuk keamanan
		Msg("Initializing database connection pool")

	dbpool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		// Log error dengan detail yang membantu debugging tanpa expose sensitive info
		setupLogger.Error().
			Err(err).
			Msg("Failed to create database connection pool")
		return nil, fmt.Errorf("gagal membuat connection pool: %w", err)
	}

	// Log sukses membuat database connection pool
	setupLogger.Info().Msg("Database connection pool initialized successfully")

	// Log completion dari setup dependencies
	setupLogger.Info().Msg("Dependencies setup completed successfully")

	return dbpool, nil
}

func main() {
	// === Tahap 1: Setup Konfigurasi & Dependensi ===

	// Inisialisasi enhanced logger sebagai langkah pertama
	enhancedlogger.Init()

	// Membuat service logger dengan nama service yang konsisten
	serviceLogger := enhancedlogger.WithService("prism-auth-service")

	// Log startup message
	serviceLogger.Info().Msg("Starting prism-auth-service application")

	// Load konfigurasi dari environment variables atau config files
	cfg := authconfig.Load()

	// Log konfigurasi yang berhasil dimuat dengan detail penting
	serviceLogger.Info().
		Str("service", cfg.ServiceName).
		Int("port", cfg.Port).
		Str("jaeger_endpoint", cfg.JaegerEndpoint).
		Str("vault_addr", cfg.VaultAddr).
		Msg("Configuration loaded successfully")

	// Setup Redis address dengan fallback ke default value
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "cache-redis:6379" // Default Redis address untuk Docker environment
		serviceLogger.Debug().
			Str("redis_addr", redisAddr).
			Msg("Using default Redis address")
	} else {
		serviceLogger.Debug().
			Str("redis_addr", redisAddr).
			Msg("Using Redis address from environment")
	}

	// Log startup information dengan semua konfigurasi penting
	enhancedlogger.LogStartup(cfg.ServiceName, cfg.Port, map[string]interface{}{
		"jaeger_endpoint": cfg.JaegerEndpoint,
		"vault_addr":      cfg.VaultAddr,
		"redis_addr":      redisAddr,
		"grpc_port":       9002, // Port gRPC internal auth-service
	})

	// Inisialisasi OpenTelemetry tracer provider untuk distributed tracing
	serviceLogger.Debug().
		Str("service_name", cfg.ServiceName).
		Str("jaeger_endpoint", cfg.JaegerEndpoint).
		Msg("Initializing OpenTelemetry tracer provider")

	tp, err := telemetry.InitTracerProvider(cfg.ServiceName, cfg.JaegerEndpoint)
	if err != nil {
		// Log fatal error jika tracer provider gagal diinisialisasi
		serviceLogger.Fatal().
			Err(err).
			Str("jaeger_endpoint", cfg.JaegerEndpoint).
			Msg("Failed to initialize OpenTelemetry tracer provider")
	}

	// Setup defer function untuk graceful shutdown tracer provider
	defer func() {
		// Shutdown tracer provider dengan context yang sesuai
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := tp.Shutdown(shutdownCtx); err != nil {
			serviceLogger.Error().
				Err(err).
				Msg("Error shutting down tracer provider")
		} else {
			serviceLogger.Debug().Msg("Tracer provider shutdown successfully")
		}
	}()

	// Log sukses inisialisasi tracer provider
	serviceLogger.Info().
		Str("jaeger_endpoint", cfg.JaegerEndpoint).
		Msg("OpenTelemetry tracer provider initialized successfully")

	// Setup dependencies (Vault, Database, Secrets)
	serviceLogger.Debug().Msg("Setting up application dependencies")
	dbpool, err := setupDependencies(cfg)
	if err != nil {
		// Log fatal error jika dependencies gagal disetup
		serviceLogger.Fatal().
			Err(err).
			Msg("Failed to initialize dependencies")
	}

	// Setup defer untuk graceful close database connection pool
	defer func() {
		serviceLogger.Debug().Msg("Closing database connection pool")
		dbpool.Close()
		serviceLogger.Debug().Msg("Database connection pool closed")
	}()

	// Inisialisasi Redis client dengan konfigurasi yang sudah ditentukan
	serviceLogger.Debug().
		Str("redis_addr", redisAddr).
		Msg("Initializing Redis client")

	redisClient := redis_client.NewClient(&redis_client.Options{Addr: redisAddr})

	// Setup defer untuk graceful close Redis client
	defer func() {
		serviceLogger.Debug().Msg("Closing Redis client")
		if err := redisClient.Close(); err != nil {
			serviceLogger.Error().
				Err(err).
				Msg("Error closing Redis client")
		} else {
			serviceLogger.Debug().Msg("Redis client closed successfully")
		}
	}()

	// Inisialisasi global Redis client untuk digunakan di package lain
	redis.InitRedisClient(redisClient)

	serviceLogger.Info().
		Str("redis_addr", redisAddr).
		Msg("Redis client initialized successfully")

	// === Tahap 2: Inisialisasi Klien, Repositori, Service, dan Handler ===

	// Log dimulainya proses inisialisasi komponen aplikasi
	serviceLogger.Info().Msg("Initializing application components")

	// Klien - Inisialisasi client untuk komunikasi dengan user-service
	serviceLogger.Debug().
		Str("user_service_addr", "user-service:9001").
		Msg("Creating user service client")

	userServiceClient, err := authclient.NewUserServiceClient("user-service:9001")
	if err != nil {
		// Log fatal error jika user service client gagal dibuat
		serviceLogger.Fatal().
			Err(err).
			Str("user_service_addr", "user-service:9001").
			Msg("Failed to create user service client")
	}

	// Setup defer untuk graceful close user service client
	defer func() {
		serviceLogger.Debug().Msg("Closing user service client")
		userServiceClient.Close()
		serviceLogger.Debug().Msg("User service client closed successfully")
	}()

	serviceLogger.Info().
		Str("user_service_addr", "user-service:9001").
		Msg("User service client created successfully")

	// Repositori - Inisialisasi semua repository yang diperlukan
	serviceLogger.Debug().Msg("Initializing repositories")

	tokenRepo := repository.NewPostgresTokenRepository(dbpool)
	apiKeyRepo := repository.NewAPIKeyRepository(dbpool)
	passwordResetRepo := repository.NewPostgresPasswordResetRepository(dbpool)

	serviceLogger.Info().Msg("Repositories initialized successfully")

	// Service - Inisialisasi business logic service
	serviceLogger.Debug().Msg("Initializing auth service")

	authSvc := service.NewAuthService(userServiceClient, tokenRepo, apiKeyRepo, passwordResetRepo)

	serviceLogger.Info().Msg("Auth service initialized successfully")

	// Handler - Inisialisasi HTTP handlers
	serviceLogger.Debug().Msg("Initializing HTTP handlers")

	// Inisialisasi SAML Service Provider
	samlSP, err := service.NewSAMLServiceProvider(cfg.SAML)
	if err != nil {
		// Log error tapi jangan hentikan aplikasi jika SAML gagal (mungkin opsional)
		serviceLogger.Error().Err(err).Msg("Gagal menginisialisasi SAML Service Provider, SSO akan dinonaktifkan.")
	} else if samlSP != nil {
		serviceLogger.Info().Msg("SAML Service Provider berhasil diinisialisasi.")
	}

	// Inisialisasi handler
	authHandler := handler.NewAuthHandler(authSvc, samlSP) // Handler sekarang menerima samlSP
	apiKeyHandler := handler.NewAPIKeyHandler(authSvc)

	serviceLogger.Info().Msg("HTTP handlers initialized successfully")

	// === Tahap 3: Setup Router dan Middleware ===

	serviceLogger.Debug().Msg("Setting up HTTP router and middleware")

	// Convert port dari integer ke string untuk digunakan dalam server
	portStr := strconv.Itoa(cfg.Port)

	// Inisialisasi Gin router dengan default middleware
	router := gin.Default()

	// Tambahkan OpenTelemetry middleware untuk tracing HTTP requests
	router.Use(otelgin.Middleware(cfg.ServiceName))

	serviceLogger.Debug().
		Str("service_name", cfg.ServiceName).
		Msg("OpenTelemetry middleware added to router")

	// Setup Prometheus metrics untuk monitoring
	p := ginprometheus.NewPrometheus("gin")
	p.Use(router)

	serviceLogger.Debug().Msg("Prometheus metrics middleware added to router")

	// Setup pprof untuk profiling (berguna untuk debugging performance)
	pprof.Register(router)

	serviceLogger.Debug().Msg("pprof profiling endpoints registered")

	// Middleware otentikasi yang fleksibel (mendukung JWT dan API Key)
	authMiddleware := middleware.FlexibleAuthMiddleware(authSvc, redisClient)

	serviceLogger.Debug().Msg("Flexible auth middleware initialized")

	// --- Definisi Rute ---
	serviceLogger.Debug().Msg("Setting up HTTP routes")

	authRoutes := router.Group("/auth") // Group semua auth-related routes
	{

		// Rute Publik - tidak memerlukan autentikasi
		authRoutes.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "healthy"})
		})
		authRoutes.POST("/register/invite", authHandler.RegisterWithInvitation)
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/login/2fa", authHandler.LoginWith2FA)
		authRoutes.POST("/refresh", authHandler.Refresh)
		authRoutes.POST("/forgot-password", authHandler.ForgotPassword)
		authRoutes.POST("/reset-password", authHandler.ResetPassword)

		// OAuth routes untuk Google dan Microsoft
		authRoutes.GET("/google/login", authHandler.GoogleLogin)
		authRoutes.GET("/google/callback", authHandler.GoogleCallback)
		authRoutes.GET("/microsoft/login", authHandler.MicrosoftLogin)
		authRoutes.GET("/microsoft/callback", authHandler.MicrosoftCallback)

		// Rute Terproteksi - memerlukan autentikasi (JWT atau API Key)
		protected := authRoutes.Group("/")
		protected.Use(authMiddleware) // Apply auth middleware
		{
			protected.POST("/logout", authHandler.Logout)
			protected.GET("/profile", authHandler.Profile)

			// Grup untuk manajemen 2FA
			twoFactorRoutes := protected.Group("/2fa")
			{
				twoFactorRoutes.POST("/setup", authHandler.Setup2FA)
				twoFactorRoutes.POST("/verify", authHandler.Verify2FA)
			}

			// Grup untuk manajemen API Key
			keysRoutes := protected.Group("/keys")
			{
				keysRoutes.POST("/", apiKeyHandler.CreateAPIKey)
				keysRoutes.GET("/", apiKeyHandler.GetAPIKeys)
				keysRoutes.DELETE("/:id", apiKeyHandler.RevokeAPIKey)
			}
		}
		if samlSP != nil {
			samlRoutes := authRoutes.Group("/saml")
			{
				// FIX: Handler untuk metadata dan ACS (Assertion Consumer Service)
				// ditangani langsung oleh middleware `samlsp`.
				samlRoutes.GET("/metadata", gin.WrapF(samlSP.ServeMetadata))
				samlRoutes.POST("/acs", gin.WrapF(samlSP.ServeACS))

				// Endpoint yang kita buat untuk memulai alur login/logout.
				samlRoutes.GET("/login", authHandler.SAMLLogin)
				samlRoutes.POST("/logout", authHandler.SAMLLogout)
			}
		}
	}

	serviceLogger.Info().Msg("HTTP routes configured successfully")

	// === Setup gRPC Server ===

	grpcPort := 9002 // Port internal untuk gRPC auth-service

	serviceLogger.Debug().
		Int("grpc_port", grpcPort).
		Msg("Setting up gRPC server")

	// Create TCP listener untuk gRPC server
	lis, err := net.Listen("tcp", ":"+strconv.Itoa(grpcPort))
	if err != nil {
		serviceLogger.Fatal().
			Err(err).
			Int("grpc_port", grpcPort).
			Msg("Failed to listen on gRPC port")
	}

	// Create gRPC server instance
	s := grpc.NewServer()
	authServer := grpc_server.NewAuthServer(authSvc)
	authv1.RegisterAuthServiceServer(s, authServer)

	serviceLogger.Info().
		Int("grpc_port", grpcPort).
		Msg("gRPC server configured successfully")

	// Start gRPC server dalam goroutine terpisah
	go func() {
		grpcLogger := enhancedlogger.WithService("prism-auth-service")

		grpcLogger.Info().
			Int("port", grpcPort).
			Msg("Starting gRPC server")

		if err := s.Serve(lis); err != nil {
			grpcLogger.Fatal().
				Err(err).
				Int("port", grpcPort).
				Msg("gRPC server failed to serve")
		}
	}()

	// === Tahap 4: Jalankan Server & Tangani Graceful Shutdown ===

	// Setup HTTP server dengan konfigurasi yang sesuai
	srv := &http.Server{
		Addr:    ":" + portStr,
		Handler: router,
	}

	// Start HTTP server dalam goroutine terpisah
	go func() {
		httpLogger := enhancedlogger.WithService("prism-auth-service")

		httpLogger.Info().
			Str("service", cfg.ServiceName).
			Str("addr", srv.Addr).
			Msg("Starting HTTP server")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			httpLogger.Fatal().
				Err(err).
				Str("addr", srv.Addr).
				Msg("HTTP server ListenAndServe error")
		}
	}()

	// Setup graceful shutdown handling
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM) // Listen untuk SIGINT dan SIGTERM

	// Block sampai menerima shutdown signal
	<-quit

	// Log dimulainya proses graceful shutdown
	serviceLogger.Info().Msg("Shutdown signal received, starting graceful shutdown")

	// Create context dengan timeout untuk graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown HTTP server dengan graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		serviceLogger.Fatal().
			Err(err).
			Dur("timeout", 10*time.Second).
			Msg("Server forced to shutdown due to timeout")
	}

	// Stop gRPC server gracefully
	serviceLogger.Debug().Msg("Stopping gRPC server")
	s.GracefulStop()
	serviceLogger.Debug().Msg("gRPC server stopped")

	// Log sukses graceful shutdown
	enhancedlogger.LogShutdown(cfg.ServiceName)
	serviceLogger.Info().Msg("Server exited gracefully")
}
