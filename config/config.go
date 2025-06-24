// file: services/prism-auth-service/config/config.go
package config

import (
	"fmt"
	"os"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/config"
)

type Config struct {
	Port           int
	ServiceName    string
	JaegerEndpoint string
	VaultAddr      string
	VaultToken     string
}

func Load() *Config {
	loader, err := config.NewLoader()
	if err != nil {
		panic(fmt.Sprintf("gagal membuat config loader: %v", err))
	}

	serviceName := "prism-auth-service"

	return &Config{
		Port:           loader.GetInt(fmt.Sprintf("config/%s/port", serviceName), 8080),
		ServiceName:    serviceName,
		JaegerEndpoint: loader.Get("config/global/jaeger_endpoint", "jaeger:4317"),
		// BARU: Muat konfigurasi Vault. Gunakan env var sebagai sumber utama.
		VaultAddr:  os.Getenv("VAULT_ADDR"), // Env var masih cara terbaik untuk info infra
		VaultToken: os.Getenv("VAULT_TOKEN"),
	}
}
