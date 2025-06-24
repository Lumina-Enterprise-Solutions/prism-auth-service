package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	authconfig "github.com/Lumina-Enterprise-Solutions/prism-auth-service/config"
	authclient "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/client"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handler"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonauth "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/client"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/telemetry"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	redis_client "github.com/redis/go-redis/v9"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

// setupDependencies sekarang hanya menginisialisasi DB untuk refresh token.
func setupDependencies() (*pgxpool.Pool, error) {
	// 1. Muat rahasia dari Vault ke environment variables
	vaultClient, err := client.NewVaultClient()
	if err != nil {
		return nil, fmt.Errorf("gagal membuat klien Vault: %w", err)
	}

	secretPath := "secret/data/prism"
	// Rahasia yang dibutuhkan auth-service kini lebih sedikit
	requiredSecrets := []string{
		"database_url", // Masih butuh DB untuk refresh_tokens
		"jwt_secret_key",
		"google_oauth_client_id",
		"google_oauth_client_secret",
		"microsoft_oauth_client_id",
		"microsoft_oauth_client_secret",
	}

	if err := vaultClient.LoadSecretsToEnv(secretPath, requiredSecrets...); err != nil {
		return nil, fmt.Errorf("gagal memuat rahasia-rahasia penting dari Vault: %w", err)
	}

	// 2. Inisialisasi koneksi Database untuk token
	dbpool, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, fmt.Errorf("gagal membuat connection pool: %w", err)
	}
	return dbpool, nil
}

func main() {
	cfg := authconfig.Load()
	log.Printf("Konfigurasi dimuat: ServiceName=%s, Port=%d, Jaeger=%s", cfg.ServiceName, cfg.Port, cfg.JaegerEndpoint)

	tp, err := telemetry.InitTracerProvider(cfg.ServiceName, cfg.JaegerEndpoint)
	if err != nil {
		log.Fatalf("Gagal menginisialisasi OTel tracer provider: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error saat mematikan tracer provider: %v", err)
		}
	}()

	dbpool, err := setupDependencies()
	if err != nil {
		log.Fatalf("Gagal menginisialisasi dependensi DB: %v", err)
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
		log.Fatalf("Gagal membuat user service client: %v", err)
	}

	defer userServiceClient.Close()


	tokenRepo := repository.NewPostgresTokenRepository(dbpool)
	authSvc := service.NewAuthService(userServiceClient, tokenRepo) // Service diinisialisasi dengan client, bukan repo user
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
		log.Fatalf("Gagal mendaftarkan service ke Consul: %v", err)
	}
	defer client.DeregisterService(consulClient, fmt.Sprintf("%s-%s", cfg.ServiceName, portStr))

	log.Printf("Memulai %s di port %s", cfg.ServiceName, portStr)
	if err := router.Run(":" + portStr); err != nil {
		log.Fatalf("Gagal menjalankan server: %v", err)
	}
}
