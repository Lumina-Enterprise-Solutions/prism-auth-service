package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	authconfig "github.com/Lumina-Enterprise-Solutions/prism-auth-service/config"
	authclient "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handler"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/middleware"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/client"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/logger"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/telemetry"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	redis_client "github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

func setupDependencies(cfg *authconfig.Config) (*pgxpool.Pool, error) {
	// 1. Inisialisasi VaultClient menggunakan konfigurasi yang disuntikkan
	vaultClient, err := client.NewVaultClient(cfg.VaultAddr, cfg.VaultToken)
	if err != nil {
		return nil, fmt.Errorf("gagal membuat klien Vault: %w", err)
	}

	// 2. Muat rahasia dari Vault ke environment variables (logika ini tetap sama)
	secretPath := "secret/data/prism"
	requiredSecrets := []string{
		"database_url",
		"jwt_secret_key",
		"google_oauth_client_id",
		"google_oauth_client_secret",
		"microsoft_oauth_client_id",
		"microsoft_oauth_client_secret",
	}

	if err := vaultClient.LoadSecretsToEnv(secretPath, requiredSecrets...); err != nil {
		return nil, fmt.Errorf("gagal memuat rahasia-rahasia penting dari Vault: %w", err)
	}

	// 3. Inisialisasi koneksi Database
	dbpool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat connection pool: %w", err)
	}
	return dbpool, nil
}

func main() {
	// === Tahap 1: Setup Konfigurasi & Dependensi ===
	logger.Init()
	cfg := authconfig.Load()
	log.Info().
		Str("service", cfg.ServiceName).
		Int("port", cfg.Port).
		Str("jaeger_endpoint", cfg.JaegerEndpoint).
		Msg("Configuration loaded")

	tp, err := telemetry.InitTracerProvider(cfg.ServiceName, cfg.JaegerEndpoint)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize OTel tracer provider")
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("Error shutting down tracer provider")
		}
	}()

	dbpool, err := setupDependencies(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize dependencies")
	}
	defer dbpool.Close()

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "cache-redis:6379"
	}
	redisClient := redis_client.NewClient(&redis_client.Options{Addr: redisAddr})
	defer redisClient.Close()
	redis.InitRedisClient(redisClient)

	// === Tahap 2: Inisialisasi Klien, Repositori, Service, dan Handler ===

	// Klien
	userServiceClient, err := authclient.NewUserServiceClient("user-service:9001")
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create user service client")
	}
	defer userServiceClient.Close()

	// Repositori
	tokenRepo := repository.NewPostgresTokenRepository(dbpool)
	apiKeyRepo := repository.NewAPIKeyRepository(dbpool) // <-- Inisialisasi repo baru

	// Service
	authSvc := service.NewAuthService(userServiceClient, tokenRepo, apiKeyRepo) // <-- Inject repo baru

	// Handler
	authHandler := handler.NewAuthHandler(authSvc)
	apiKeyHandler := handler.NewAPIKeyHandler(authSvc) // <-- Inisialisasi handler baru

	// === Tahap 3: Setup Router dan Middleware ===

	portStr := strconv.Itoa(cfg.Port)
	router := gin.Default()
	router.Use(otelgin.Middleware(cfg.ServiceName))

	p := ginprometheus.NewPrometheus("gin")
	p.Use(router)

	pprof.Register(router)

	// Middleware otentikasi yang fleksibel
	authMiddleware := middleware.FlexibleAuthMiddleware(authSvc, redisClient)

	// --- Definisi Rute ---
	authRoutes := router.Group("/auth")
	{
		// Rute Publik
		authRoutes.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "healthy"}) })
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/login/2fa", authHandler.LoginWith2FA)
		authRoutes.POST("/refresh", authHandler.Refresh)
		authRoutes.POST("/forgot-password", authHandler.ForgotPassword)
		authRoutes.POST("/reset-password", authHandler.ResetPassword)
		authRoutes.GET("/google/login", authHandler.GoogleLogin)
		authRoutes.GET("/google/callback", authHandler.GoogleCallback)
		authRoutes.GET("/microsoft/login", authHandler.MicrosoftLogin)
		authRoutes.GET("/microsoft/callback", authHandler.MicrosoftCallback)

		// Rute Terproteksi (bisa via JWT atau API Key)
		protected := authRoutes.Group("/")
		protected.Use(authMiddleware)
		{
			protected.POST("/logout", authHandler.Logout)
			protected.GET("/profile", authHandler.Profile) // Endpoint ini sekarang juga bisa diakses dengan API Key

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
	}

	// === Tahap 4: Jalankan Server & Tangani Graceful Shutdown ===
	srv := &http.Server{
		Addr:    ":" + portStr,
		Handler: router,
	}

	go func() {
		log.Info().Str("service", cfg.ServiceName).Msgf("HTTP server listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP server ListenAndServe error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("Shutdown signal received, starting graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exiting gracefully.")
}
