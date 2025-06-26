#!/bin/bash

# --- Test Integration Script for prism-auth-service ---
#
# Script ini menjalankan integration tests dengan setup environment yang tepat
# Hentikan eksekusi jika ada perintah yang gagal (sangat penting untuk debugging)
set -e

echo "▶️ Setting up environment for integration tests..."

# ================== ENVIRONMENT VARIABLES SETUP ==================
# Ekspor semua variabel yang dibutuhkan untuk integration testing
# Dengan 'export', variabel ini akan tersedia untuk semua sub-proses (termasuk go test)

# FIX: Export an explicit environment variable to signal that integration tests should run.
# This avoids the 'panic: testing: Short called before Parse' issue.
export RUN_INTEGRATION_TESTS="true"

export POSTGRES_USER="prismuser"
export POSTGRES_PASSWORD="prismpassword"
export POSTGRES_HOST="localhost"
export POSTGRES_PORT="5432"

export POSTGRES_DB="prism_erp"

# Redis configuration untuk test yang membutuhkan cache
export REDIS_ADDR="localhost:6379"

# JWT secret key untuk test authentication
export JWT_SECRET_KEY="dummy-secret-for-integration-tests"

# Optional: set Go test timeout untuk test yang berjalan lama
export GO_TEST_TIMEOUT="5m"

echo "Environment variables set:"
echo "  RUN_INTEGRATION_TESTS: $RUN_INTEGRATION_TESTS"
echo "  POSTGRES_USER: $POSTGRES_USER"
echo "  POSTGRES_HOST: $POSTGRES_HOST:$POSTGRES_PORT"
echo "  POSTGRES_DB: $POSTGRES_DB"
echo "  REDIS_ADDR: $REDIS_ADDR"

echo "✅ Environment set. Running tests..."

# ================== RUN INTEGRATION TESTS ==================
# Penjelasan flags yang digunakan:
# -v                : verbose output, tampilkan detail setiap test
# -race             : enable race detector untuk mendeteksi race conditions
# -count=1          : disable test result caching, selalu run fresh tests
# -timeout          : set maximum time untuk semua tests
# ./...             : run tests di semua subdirectories

echo "Running integration tests with race detection..."
go test -v -race -count=1 -timeout="$GO_TEST_TIMEOUT" ./...

# Capture exit code dari go test
TEST_EXIT_CODE=$?

if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Integration tests finished successfully."
else
    echo "❌ Integration tests failed with exit code: $TEST_EXIT_CODE"
    echo "Check the output above for detailed error information."
fi

echo "Integration test run completed."

# Exit dengan code yang sama seperti hasil go test
exit $TEST_EXIT_CODE
