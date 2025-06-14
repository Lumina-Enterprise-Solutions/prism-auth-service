package main

import (
	"context"
	"log"
	"os"
	"strconv"

	authconfig "github.com/Lumina-Enterprise-Solutions/prism-auth-service/config"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/handler"
	authredis "github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/redis"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/repository"
	"github.com/Lumina-Enterprise-Solutions/prism-auth-service/internal/service"
	commonjwt "github.com/Lumina-Enterprise-Solutions/prism-common-libs/auth" // <-- Import with alias
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/client"         // <-- TAMBAHKAN
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/ginutil"
	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/telemetry"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	ginprometheus "github.com/zsais/go-gin-prometheus"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

// Fungsi helper untuk mengambil rahasia dari Vault dan set sebagai env var
func loadSecretsFromVault() {
	client, err := client.NewVaultClient()
	if err != nil {
		log.Fatalf("Gagal membuat klien Vault: %v", err)
	}

	// Path rahasia di Vault. Kita akan menggunakan 'secret/data/prism'
	secretPath := "secret/data/prism"

	googleClientID, err := client.ReadSecret(secretPath, "google_oauth_client_id")
	if err != nil {
		log.Fatalf("Gagal membaca google_oauth_client_id dari Vault: %v", err)
	}
	googleClientSecret, err := client.ReadSecret(secretPath, "google_oauth_client_secret")
	if err != nil {
		log.Fatalf("Gagal membaca google_oauth_client_secret dari Vault: %v", err)
	}
	os.Setenv("GOOGLE_OAUTH_CLIENT_ID", googleClientID)
	os.Setenv("GOOGLE_OAUTH_CLIENT_SECRET", googleClientSecret)
	log.Println("Berhasil memuat kredensial Google OAuth dari Vault.")

	microsoftClientID, err := client.ReadSecret(secretPath, "microsoft_oauth_client_id")
	if err != nil {
		log.Fatalf("Gagal membaca microsoft_oauth_client_id dari Vault: %v", err)
	}
	microsoftClientSecret, err := client.ReadSecret(secretPath, "microsoft_oauth_client_secret")
	if err != nil {
		log.Fatalf("Gagal membaca microsoft_oauth_client_secret dari Vault: %v", err)
	}
	os.Setenv("MICROSOFT_OAUTH_CLIENT_ID", microsoftClientID)
	os.Setenv("MICROSOFT_OAUTH_CLIENT_SECRET", microsoftClientSecret)
	log.Println("Berhasil memuat kredensial Microsoft OAuth dari Vault.")

	// Baca 'jwt_secret' dari path di atas
	jwtSecret, err := client.ReadSecret(secretPath, "jwt_secret")
	if err != nil {
		log.Fatalf("Gagal membaca jwt_secret dari Vault: %v. Pastikan rahasia sudah dimasukkan.", err)
	}

	// Set sebagai environment variable agar kode yang ada tidak perlu diubah
	os.Setenv("JWT_SECRET_KEY", jwtSecret)
	log.Println("Berhasil memuat JWT_SECRET_KEY dari Vault.")
}

func main() {
	log.Println("Starting Prism Auth Service...")

	loadSecretsFromVault()
	authredis.InitRedisClient()

	cfg := authconfig.Load()
	log.Printf("Konfigurasi dimuat: Port=%d, Jaeger=%s", cfg.Port, cfg.JaegerEndpoint)

	serviceName := "prism-auth-service"
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		jaegerEndpoint = "jaeger:4317"
	}
	tp, err := telemetry.InitTracerProvider(cfg.ServiceName, cfg.JaegerEndpoint)
	if err != nil {
		log.Fatalf("Failed to initialize OTel tracer provider: %v", err)
	}
	defer func() {
		if err := tp.Shutdown(context.Background()); err != nil {
			log.Printf("Error shutting down tracer provider: %v", err)
		}
	}()
	databaseUrl := os.Getenv("DATABASE_URL")
	if databaseUrl == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}
	dbpool, err := pgxpool.New(context.Background(), databaseUrl)
	if err != nil {
		log.Fatalf("Unable to create connection pool: %v\n", err)
	}
	defer dbpool.Close()
	userRepo := repository.NewPostgresUserRepository(dbpool)
	authSvc := service.NewAuthService(userRepo)
	authHandler := handler.NewAuthHandler(authSvc)
	portStr := strconv.Itoa(cfg.Port)
	// port, _ := strconv.Atoi(portStr)
	// consul.RegisterAuthService(port)
	log.Printf("Service configured to run on port %s", portStr)

	// Initialize Gin Router
	router := gin.Default()
	router.Use(otelgin.Middleware(serviceName))
	p := ginprometheus.NewPrometheus("gin")
	p.Use(router)
	pprof.Register(router)

	// --- Group routes ---
	authRoutes := router.Group("/auth")
	{
		// Public routes
		authRoutes.POST("/register", authHandler.Register)
		authRoutes.POST("/login", authHandler.Login)
		authRoutes.POST("/refresh", authHandler.Refresh)
		authRoutes.GET("/google/login", authHandler.GoogleLogin)
		authRoutes.GET("/google/callback", authHandler.GoogleCallback)
		authRoutes.GET("/microsoft/login", authHandler.MicrosoftLogin)
		authRoutes.GET("/microsoft/callback", authHandler.MicrosoftCallback)
		authRoutes.POST("/login/2fa", authHandler.LoginWith2FA) // Rute publik untuk login tahap 2

		// Protected routes group
		protected := authRoutes.Group("/")
		protected.Use(commonjwt.JWTMiddleware())
		{
			protected.GET("/profile", authHandler.Profile)
			protected.POST("/logout", authHandler.Logout)
			protected.POST("/2fa/setup", authHandler.Setup2FA)
			protected.POST("/2fa/verify", authHandler.Verify2FA)
		}
	}

	// Option 1: Health routes within the auth group only (/auth/health)
	ginutil.SetupHealthRoutesForGroup(authRoutes, "prism-auth-service", "1.0.0")

	// Option 2: Health routes at both root and group level (/health and /auth/health)
	// handlers.SetupBothHealthRoutes(router, authRoutes, "prism-auth-service", "1.0.0")

	// Option 3: Only root level health routes (/health)
	// handlers.SetupHealthRoutes(router, "prism-auth-service", "1.0.0")

	log.Printf("Starting %s on port %s", cfg.ServiceName, portStr)
	if err := router.Run(":" + portStr); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
