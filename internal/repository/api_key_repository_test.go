package repository

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid" // <-- ADD THIS IMPORT
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hashTokenTest creates a SHA256 hash of the token for testing purposes
// This simulates how API keys are hashed before storing in database
func hashTokenTest(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func TestAPIKeyRepository(t *testing.T) {
	// Ensure testDBPool is available from TestMain setup
	require.NotNil(t, testDBPool, "testDBPool is nil. TestMain setup may have failed.")

	// Create context for database operations
	ctx := context.Background()

	// Initialize the repository with the test database pool
	repo := NewAPIKeyRepository(testDBPool)

	// Setup: clean up tables and create a test user
	truncateTables(ctx, t, "api_keys", "users", "roles")
	userID, _ := seedUser(ctx, t)

	t.Run("Store_and_Get_User_By_Key_Prefix_Success", func(t *testing.T) {
		// Arrange
		rawKey := "zpk_test_secret_123456789"
		keyHash := hashTokenTest(rawKey)
		prefix := "zpk"
		description := "My Test API Key"

		// Act
		storedKeyID, err := repo.StoreKey(ctx, userID, keyHash, prefix, description, nil)

		// Assert
		require.NoError(t, err, "Should successfully store API key")
		assert.NotEmpty(t, storedKeyID, "Stored key ID should not be empty")

		userWithHash, err := repo.GetUserByKeyPrefix(ctx, prefix)
		require.NoError(t, err, "Should successfully get user by key prefix")
		assert.NotNil(t, userWithHash, "Retrieved user should not be nil")
		assert.Equal(t, userID, userWithHash.ID, "User ID should match")
		assert.Equal(t, "test@example.com", userWithHash.Email, "Email should match seeded user")
		assert.Equal(t, "Test Role", userWithHash.RoleName, "Role name should match seeded role")
		assert.Equal(t, keyHash, userWithHash.KeyHash, "Key hash should match stored hash")
	})

	t.Run("Get_User_By_Key_Prefix_With_Expired_Key", func(t *testing.T) {
		truncateTables(ctx, t, "api_keys")
		expiresAt := time.Now().Add(-1 * time.Hour)
		expiredKeyHash := hashTokenTest("expired_key_12345")
		expiredPrefix := "zpk_expired"
		_, err := repo.StoreKey(ctx, userID, expiredKeyHash, expiredPrefix, "Expired Key", &expiresAt)
		require.NoError(t, err, "Should successfully store expired key")

		_, err = repo.GetUserByKeyPrefix(ctx, expiredPrefix)
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for expired key")
	})

	t.Run("Get_User_By_Nonexistent_Key_Prefix", func(t *testing.T) {
		_, err := repo.GetUserByKeyPrefix(ctx, "nonexistent_prefix")
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for non-existent key prefix")
	})

	t.Run("Revoke_Key_and_Verify_Changes", func(t *testing.T) {
		truncateTables(ctx, t, "api_keys")
		keyHash1 := hashTokenTest("key1_secret")
		keyHash2 := hashTokenTest("key2_secret")
		keyID1, err := repo.StoreKey(ctx, userID, keyHash1, "prefix1", "Key One", nil)
		require.NoError(t, err)
		keyID2, err := repo.StoreKey(ctx, userID, keyHash2, "prefix2", "Key Two", nil)
		require.NoError(t, err)

		keys, err := repo.GetKeysForUser(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, keys, 2)
		for _, key := range keys {
			assert.Nil(t, key.RevokedAt)
		}

		err = repo.RevokeKey(ctx, userID, keyID1)
		require.NoError(t, err)

		err = repo.RevokeKey(ctx, userID, keyID1)
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows when trying to revoke already revoked key")

		_, err = repo.GetUserByKeyPrefix(ctx, "prefix1")
		assert.ErrorIs(t, err, pgx.ErrNoRows)

		userWithHash, err := repo.GetUserByKeyPrefix(ctx, "prefix2")
		require.NoError(t, err)
		assert.Equal(t, userID, userWithHash.ID)

		keys, err = repo.GetKeysForUser(ctx, userID)
		require.NoError(t, err)
		assert.Len(t, keys, 2)
		for _, key := range keys {
			switch key.ID {
			case keyID1:
				assert.NotNil(t, key.RevokedAt, "Key 1 should be revoked")
			case keyID2:
				assert.Nil(t, key.RevokedAt, "Key 2 should not be revoked")
			default:
				t.Fatalf("Found an unexpected key ID: %s", key.ID)
			}
		}
	})

	t.Run("Store_Key_With_Expiration", func(t *testing.T) {
		truncateTables(ctx, t, "api_keys")
		futureExpiry := time.Now().Add(24 * time.Hour)
		keyHash := hashTokenTest("expiring_key_123")
		prefix := "zpk_exp"
		keyID, err := repo.StoreKey(ctx, userID, keyHash, prefix, "Expiring Key", &futureExpiry)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)

		userWithHash, err := repo.GetUserByKeyPrefix(ctx, prefix)
		require.NoError(t, err)
		assert.Equal(t, userID, userWithHash.ID)
	})

	t.Run("Get_Keys_For_User_Empty_Result", func(t *testing.T) {
		truncateTables(ctx, t, "api_keys")
		keys, err := repo.GetKeysForUser(ctx, userID)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("Revoke_Nonexistent_Key", func(t *testing.T) {
		// FIX: Instead of an invalid string, generate a valid, random UUID
		// that is guaranteed not to be in the database.
		nonExistentUUID := uuid.NewString()

		// Act: try to revoke the key using the valid (but non-existent) UUID
		err := repo.RevokeKey(ctx, userID, nonExistentUUID)

		// Assert: should return "no rows" error because the UUID doesn't match any key
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for non-existent key")
	})
}
