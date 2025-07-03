// File: services/prism-auth-service/internal/repository/main_test.go
package repository

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

var (
	testDBPool *pgxpool.Pool
)

// Definisikan semua skema yang dibutuhkan oleh auth-service.
const schemaSQL = `
DROP TABLE IF EXISTS api_keys, password_reset_tokens, refresh_tokens, users, roles CASCADE;

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role_id UUID REFERENCES roles(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    is_2fa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    totp_secret TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prefix VARCHAR(50) NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    description TEXT,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`

// TestMain adalah setup global untuk semua tes di paket ini.
func TestMain(m *testing.M) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		log.Println("Skipping repository integration tests (RUN_INTEGRATION_TESTS not set to 'true').")
		os.Exit(0)
	}

	log.Println("Setting up for auth-service repository integration tests...")

	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_PORT"),
		os.Getenv("POSTGRES_DB"),
	)

	var err error
	var attempts = 5
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		testDBPool, err = pgxpool.New(ctx, databaseURL)
		if err == nil {
			if err = testDBPool.Ping(ctx); err == nil {
				log.Println("✅ SUCCESS: Database connection verified.")
				break
			}
		}
		if i == attempts-1 {
			log.Fatalf("❌ FATAL: Could not connect to database after %d attempts: %v", attempts, err)
		}
		time.Sleep(2 * time.Second)
	}

	log.Println("Applying database schema for auth-service tests...")
	_, err = testDBPool.Exec(context.Background(), schemaSQL)
	if err != nil {
		log.Fatalf("FATAL: Could not apply database schema: %v", err)
	}

	exitCode := m.Run()

	log.Println("Tearing down repository integration tests...")
	if testDBPool != nil {
		testDBPool.Close()
	}
	os.Exit(exitCode)
}

func truncateTables(ctx context.Context, t *testing.T, tables ...string) {
	t.Helper()
	require.NotNil(t, testDBPool)
	for _, table := range tables {
		query := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)
		_, err := testDBPool.Exec(ctx, query)
		require.NoError(t, err, "Failed to truncate table %s", table)
	}
}

func seedUser(ctx context.Context, t *testing.T) (string, string) {
	t.Helper()
	require.NotNil(t, testDBPool)
	var roleID string
	roleQuery := `INSERT INTO roles (name, description) VALUES ('Test Role', 'A role for testing') RETURNING id`
	err := testDBPool.QueryRow(ctx, roleQuery).Scan(&roleID)
	require.NoError(t, err)

	var userID string
	userQuery := `INSERT INTO users (email, password_hash, role_id) VALUES ('test@example.com', 'hashed_password', $1) RETURNING id`
	err = testDBPool.QueryRow(ctx, userQuery, roleID).Scan(&userID)
	require.NoError(t, err)

	return userID, roleID
}
