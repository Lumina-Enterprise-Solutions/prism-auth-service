// file: services/prism-auth-service/config/config.go
package config

import (
	"fmt"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/config"
)

type Config struct {
	Port           int
	ServiceName    string
	JaegerEndpoint string
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
	}
}
