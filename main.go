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
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonauth "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
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
			log.Error().Err(err).Msg("Error saat mematikan tracer provider")
		}
	}()

	dbpool, err := setupDependencies(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Gagal menginisialisasi dependensi")
	}
	defer dbpool.Close()

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "cache-redis:6379"
	}
	redisClient := redis_client.NewClient(&redis_client.Options{Addr: redisAddr})
	defer redisClient.Close()

	redis.InitRedisClient(redisClient)

	userServiceClient, err := authclient.NewUserServiceClient("user-service:9001") // Target: nama service & port gRPC
	if err != nil {
		log.Fatal().Err(err).Msg("Gagal membuat user service client")
	}

	// PENTING: Defer penutupan koneksi gRPC
	defer userServiceClient.Close()

	tokenRepo := repository.NewPostgresTokenRepository(dbpool)
	authSvc := service.NewAuthService(userServiceClient, tokenRepo)
	authHandler := handler.NewAuthHandler(authSvc)

	portStr := strconv.Itoa(cfg.Port)
	router := gin.Default()
	router.Use(otelgin.Middleware(cfg.ServiceName))
	p := ginprometheus.NewPrometheus("gin")
	p.Use(router)
	pprof.Register(router)

	authRoutes := router.Group("/auth")
	{
		authRoutes.GET("/health", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "healthy"}) })
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.Refresh)
		authRoutes.GET("/google/login", authHandler.GoogleLogin)
		authRoutes.GET("/google/callback", authHandler.GoogleCallback)
		authRoutes.GET("/microsoft/login", authHandler.MicrosoftLogin)
		authRoutes.GET("/microsoft/callback", authHandler.MicrosoftCallback)
		authRoutes.POST("/login/2fa", authHandler.LoginWith2FA)

		protected := authRoutes.Group("/")
		protected.Use(commonauth.JWTMiddleware(redisClient))
		{
			protected.GET("/profile", authHandler.Profile)
			protected.POST("/logout", authHandler.Logout)
			protected.POST("/2fa/setup", authHandler.Setup2FA)
			protected.POST("/2fa/verify", authHandler.Verify2FA)
		}
	}

	consulClient, err := client.RegisterService(client.ServiceRegistrationInfo{
		ServiceName:    cfg.ServiceName,
		ServiceID:      fmt.Sprintf("%s-%s", cfg.ServiceName, portStr),
		Port:           cfg.Port,
		HealthCheckURL: fmt.Sprintf("http://prism-auth-service:%s/auth/health", portStr),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Gagal mendaftarkan service ke Consul: %v")
	}
	defer client.DeregisterService(consulClient, fmt.Sprintf("%s-%s", cfg.ServiceName, portStr))

	log.Info().
		Str("service", cfg.ServiceName).
		Str("port", portStr).
		Msg("Memulai service")

	if err := router.Run(":" + portStr); err != nil {
		log.Fatal().Err(err).Msg("Gagal menjalankan server: %v")
	}
	// === Tahap 2: Jalankan Server & Tangani Shutdown ===
	srv := &http.Server{
		Addr:    ":" + portStr,
		Handler: router,
	}

	// Jalankan server HTTP di goroutine
	go func() {
		log.Info().Str("service", cfg.ServiceName).Msgf("HTTP server listening on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("HTTP server ListenAndServe error")
		}
	}()

	// Tunggu sinyal shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("Shutdown signal received, starting graceful shutdown...")

	// Buat context dengan timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Shutdown server HTTP
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	log.Info().Msg("Server exiting gracefully.")
}
