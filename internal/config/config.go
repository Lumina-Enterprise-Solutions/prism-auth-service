package config

import (
	commonConfig "github.com/Lumina-Enterprise-Solutions/prism-common-libs/pkg/config"
)

type Config struct {
	*commonConfig.Config
	ServiceName string
	Version     string
}

func Load() (*Config, error) {
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
