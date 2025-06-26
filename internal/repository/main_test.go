// File: internal/repository/main_test.go
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

// TestMain is the global setup for integration testing the repository package.
// It runs once before all tests in this package.
func TestMain(m *testing.M) {
	// FIX: This is the definitive fix for the 'panic: testing: Short called before Parse'.
	// We rely ONLY on the environment variable, which is explicitly set by our integration
	// test script (`scripts/test-integration.sh`).
	// When running `make test` (which executes `go test -short`), this variable is NOT set,
	// so we correctly skip the database setup and avoid the panic.
	if os.Getenv("RUN_INTEGRATION_TESTS") != "true" {
		log.Println("Skipping repository integration tests (RUN_INTEGRATION_TESTS not set to 'true'). This is expected for 'make test'.")
		// Exit immediately. No need to run the tests in this package as they all require a database.
		os.Exit(0)
	}

	log.Println("Setting up for repository integration tests...")

	// Get database configuration from environment variables
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

	// Construct the connection string for PostgreSQL
	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	var err error
	var attempts = 10 // Try to connect up to 10 times

	// ================== RETRY LOOP FOR DATABASE CONNECTION ==================
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
		log.Fatal("FATAL: testDBPool is nil after setup. This should not happen.")
	}

	log.Printf("Successfully connected to database: %s", dbName)

	// Run all tests in this package
	exitCode := m.Run()

	// ================== CLEANUP AFTER ALL TESTS ARE DONE ==================
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
