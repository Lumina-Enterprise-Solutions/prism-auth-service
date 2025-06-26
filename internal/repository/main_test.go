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

// FIX: Define the required database schema as a string.
// This will be executed to ensure the database is ready for tests.
const schemaSQL = `
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
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
    expires_at TIMESTAMPTZ NOT NULL
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
);`

// TestMain is the global setup for integration testing the repository package.
func TestMain(m *testing.M) {
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		log.Println("Skipping repository integration tests (RUN_INTEGRATION_TESTS not set to 'true').")
		os.Exit(0)
	}

	log.Println("Setting up for repository integration tests...")

	dbUser := os.Getenv("POSTGRES_USER")
	if dbUser == "" {
		dbUser = "prismuser"
	}
	dbPassword := os.Getenv("POSTGRES_PASSWORD")
	if dbPassword == "" {
		dbPassword = "prismpassword"
	}
	dbHost := os.Getenv("POSTGRES_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}
	dbPort := os.Getenv("POSTGRES_PORT")
	if dbPort == "" {
		dbPort = "5432"
	}
	dbName := os.Getenv("POSTGRES_DB")
	if dbName == "" {
		dbName = "prism_erp"
	}

	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	var attempts = 10
	for i := 0; i < attempts; i++ {
		log.Printf("Connecting to test database (attempt %d/%d)...", i+1, attempts)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

		testDBPool, err = pgxpool.New(ctx, databaseURL)
		if err == nil {
			if err = testDBPool.Ping(ctx); err == nil {
				cancel()
				log.Println("SUCCESS: Database connection pool created and verified.")
				break
			}
			testDBPool.Close()
			testDBPool = nil
		}
		cancel()

		if i == attempts-1 {
			log.Fatalf("FATAL: Could not connect to database after %d attempts: %v", attempts, err)
		}
		log.Printf("WARN: Database not ready, retrying in 2 seconds... (error: %v)", err)
		time.Sleep(2 * time.Second)
	}

	if testDBPool == nil {
		log.Fatal("FATAL: testDBPool is nil after setup.")
	}

	// FIX: Apply the schema to the test database
	log.Println("Applying database schema for tests...")
	_, err = testDBPool.Exec(context.Background(), schemaSQL)
	if err != nil {
		log.Fatalf("FATAL: Could not apply database schema: %v", err)
	}
	log.Println("SUCCESS: Database schema applied.")

	log.Printf("Successfully connected to database: %s", dbName)

	// Run all tests in this package
	exitCode := m.Run()

	log.Println("Tearing down repository integration tests...")
	if testDBPool != nil {
		testDBPool.Close()
	}

	os.Exit(exitCode)
}

// truncateTables cleans data from specified tables to ensure a clean state for each test.
func truncateTables(ctx context.Context, t *testing.T, tables ...string) {
	t.Helper()
	require.NotNil(t, testDBPool, "cannot truncate tables: testDBPool is nil")

	for _, table := range tables {
		// FIX: Use CASCADE to handle foreign key relationships correctly during truncation
		query := fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)
		_, err := testDBPool.Exec(ctx, query)
		require.NoError(t, err, "Failed to truncate table %s", table)
	}
}

// seedUser creates a dummy user and role for tests that need foreign key dependencies.
func seedUser(ctx context.Context, t *testing.T) (string, string) {
	t.Helper()
	require.NotNil(t, testDBPool, "cannot seed user: testDBPool is nil")

	var roleID string
	roleQuery := `
		INSERT INTO roles (name, description)
		VALUES ('Test Role', 'A role for testing')
		ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
		RETURNING id`
	err := testDBPool.QueryRow(ctx, roleQuery).Scan(&roleID)
	require.NoError(t, err, "failed to seed role")

	var userID string
	userQuery := `
		INSERT INTO users (email, first_name, last_name, password_hash, role_id, status)
		VALUES ('test@example.com', 'Test', 'User', 'hashedpassword', $1, 'active')
		RETURNING id`
	err = testDBPool.QueryRow(ctx, userQuery, roleID).Scan(&userID)
	require.NoError(t, err, "failed to seed user")

	return userID, roleID
}
