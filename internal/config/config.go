package config

import (
	"log"

	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
	"github.com/joho/godotenv"
)

type Config struct {
	*commonConfig.Config
	ServiceName string
	Version     string
}

func Load() (*Config, error) {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	baseConfig, err := commonConfig.Load()
	if err != nil {
		return nil, err
	}

	return &Config{
		Config:      baseConfig,
		ServiceName: "prism-auth-service",
		Version:     "1.0.0",
	}, nil
}
