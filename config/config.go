package config

import (
	"fmt"
	"os"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/config"
)

// BARU: Menambahkan struct untuk konfigurasi SAML.
type SAMLConfig struct {
	IDPMetadataURL string
	SPCertificate  string
	SPPrivateKey   string
	SPEntityID     string
	SPACSURL       string
}

type Config struct {
	Port           int
	ServiceName    string
	JaegerEndpoint string
	VaultAddr      string
	VaultToken     string
	// BARU: Menambahkan konfigurasi SAML ke struct utama.
	SAML SAMLConfig
}

func Load() *Config {
	loader, err := config.NewLoader()
	if err != nil {
		panic(fmt.Sprintf("gagal membuat config loader: %v", err))
	}

	serviceName := "prism-auth-service"
	pathPrefix := fmt.Sprintf("config/%s", serviceName)

	return &Config{
		Port:           loader.GetInt(fmt.Sprintf("%s/port", pathPrefix), 8080),
		ServiceName:    serviceName,
		JaegerEndpoint: loader.Get("config/global/jaeger_endpoint", "jaeger:4317"),
		VaultAddr:      os.Getenv("VAULT_ADDR"),
		VaultToken:     os.Getenv("VAULT_TOKEN"),
		// BARU: Memuat konfigurasi SAML dari Vault melalui environment variables.
		SAML: SAMLConfig{
			IDPMetadataURL: os.Getenv("SAML_IDP_METADATA_URL"),
			SPCertificate:  os.Getenv("SAML_SP_CERT"),
			SPPrivateKey:   os.Getenv("SAML_SP_KEY"),
			SPEntityID:     os.Getenv("SAML_SP_ENTITY_ID"),
			SPACSURL:       os.Getenv("SAML_SP_ACS_URL"),
		},
	}
}
