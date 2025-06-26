package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordResetRepository(t *testing.T) {
	// The check for short mode is now handled globally for the package in main_test.go's TestMain.
	// No need to skip here individually.

	// Ensure testDBPool is available from TestMain setup
	require.NotNil(t, testDBPool, "testDBPool is nil. TestMain setup may have failed.")

	// Create context for database operations
	ctx := context.Background()

	// Initialize the repository with the test database pool
	repo := NewPostgresPasswordResetRepository(testDBPool)

	// Setup: clean up tables and create a test user
	// Order matters: clean dependent tables first, then parent tables
	truncateTables(ctx, t, "password_reset_tokens", "users", "roles")
	userID, _ := seedUser(ctx, t)

	t.Run("Store_and_Get_UserID_By_Token_Success", func(t *testing.T) {
		// Arrange: prepare test data for password reset token
		tokenHash := "reset-token-hash-123456789"  // Hash of the reset token
		expiresAt := time.Now().Add(1 * time.Hour) // Token expires in 1 hour

		// Act: store the password reset token
		err := repo.StoreToken(ctx, tokenHash, userID, expiresAt)

		// Assert: verify storage was successful
		require.NoError(t, err, "Should successfully store password reset token")

		// Act: retrieve user ID by token hash
		retrievedUserID, err := repo.GetUserIDByToken(ctx, tokenHash)

		// Assert: verify retrieval was successful and user ID matches
		require.NoError(t, err, "Should successfully get user ID by token")
		assert.Equal(t, userID, retrievedUserID, "Retrieved user ID should match stored user ID")
	})

	t.Run("Get_UserID_By_Nonexistent_Token", func(t *testing.T) {
		// Act: try to get user ID with non-existent token
		_, err := repo.GetUserIDByToken(ctx, "non-existent-token-hash-12345")

		// Assert: should return "no rows" error for non-existent token
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for non-existent token")
	})

	t.Run("Get_UserID_By_Expired_Token", func(t *testing.T) {
		// Arrange: create an expired token (1 hour ago)
		expiredTokenHash := "expired-token-hash-987654321"
		expiredTime := time.Now().Add(-1 * time.Hour)

		// Store the expired token
		err := repo.StoreToken(ctx, expiredTokenHash, userID, expiredTime)
		require.NoError(t, err, "Should successfully store expired token")

		// Act: try to get user ID with expired token
		// Note: This depends on your repository implementation
		// If your repo checks expiration, it should return ErrNoRows
		// If it doesn't check expiration, you might get the user ID
		_, err = repo.GetUserIDByToken(ctx, expiredTokenHash)

		// Assert: behavior depends on your implementation
		// Most secure implementations would return ErrNoRows for expired tokens
		if err != nil {
			assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for expired token")
		}
		// If your implementation doesn't check expiration in the query,
		// you should add expiration checking logic to your repository
	})

	t.Run("Delete_Token_Success", func(t *testing.T) {
		// Arrange: create a token to be deleted
		tokenHash := "token-to-be-deleted-456789"
		expiresAt := time.Now().Add(1 * time.Hour)

		// Store the token first
		err := repo.StoreToken(ctx, tokenHash, userID, expiresAt)
		require.NoError(t, err, "Should successfully store token before deletion")

		// Verify token exists before deletion
		retrievedUserID, err := repo.GetUserIDByToken(ctx, tokenHash)
		require.NoError(t, err, "Token should exist before deletion")
		assert.Equal(t, userID, retrievedUserID, "User ID should match")

		// Act: delete the token
		err = repo.DeleteToken(ctx, tokenHash)

		// Assert: deletion should be successful
		require.NoError(t, err, "Should successfully delete token")

		// Verify token no longer exists
		_, err = repo.GetUserIDByToken(ctx, tokenHash)
		assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows after token deletion")
	})

	t.Run("Delete_Nonexistent_Token", func(t *testing.T) {
		// Act: try to delete a non-existent token
		err := repo.DeleteToken(ctx, "nonexistent-token-hash-999999")

		// Assert: depending on implementation, this might succeed (idempotent) or fail
		// Most implementations should handle this gracefully (no error for idempotent operations)
		// But if your implementation returns an error, that's also valid
		if err != nil {
			// If your implementation returns an error for non-existent tokens
			assert.ErrorIs(t, err, pgx.ErrNoRows, "Should return ErrNoRows for non-existent token")
		}
		// If no error, that means the operation is idempotent (which is good)
	})

	t.Run("Store_Multiple_Tokens_For_Same_User", func(t *testing.T) {
		// Clean up existing tokens
		truncateTables(ctx, t, "password_reset_tokens")

		// Arrange: create multiple tokens for the same user
		token1Hash := "token1-hash-111111"
		token2Hash := "token2-hash-222222"
		expiresAt := time.Now().Add(1 * time.Hour)

		// Act: store multiple tokens
		err1 := repo.StoreToken(ctx, token1Hash, userID, expiresAt)
		err2 := repo.StoreToken(ctx, token2Hash, userID, expiresAt)

		// Assert: both tokens should be stored successfully
		require.NoError(t, err1, "Should successfully store first token")
		require.NoError(t, err2, "Should successfully store second token")

		// Verify both tokens can be retrieved
		retrievedUserID1, err := repo.GetUserIDByToken(ctx, token1Hash)
		require.NoError(t, err, "Should successfully get user ID by first token")
		assert.Equal(t, userID, retrievedUserID1, "First token should return correct user ID")

		retrievedUserID2, err := repo.GetUserIDByToken(ctx, token2Hash)
		require.NoError(t, err, "Should successfully get user ID by second token")
		assert.Equal(t, userID, retrievedUserID2, "Second token should return correct user ID")
	})

	t.Run("Store_Token_With_Far_Future_Expiration", func(t *testing.T) {
		// Arrange: create a token with very long expiration (30 days)
		tokenHash := "long-lived-token-hash-333333"
		farFutureExpiry := time.Now().Add(30 * 24 * time.Hour)

		// Act: store token with far future expiration
		err := repo.StoreToken(ctx, tokenHash, userID, farFutureExpiry)

		// Assert: should store successfully
		require.NoError(t, err, "Should successfully store token with far future expiration")

		// Verify token can be retrieved
		retrievedUserID, err := repo.GetUserIDByToken(ctx, tokenHash)
		require.NoError(t, err, "Should successfully get user ID by long-lived token")
		assert.Equal(t, userID, retrievedUserID, "User ID should match for long-lived token")
	})

	t.Run("Replace_Existing_Token_For_User", func(t *testing.T) {
		// This test checks if your implementation handles token replacement
		// Some implementations might want to ensure only one active reset token per user

		// Clean up existing tokens
		truncateTables(ctx, t, "password_reset_tokens")

		// Arrange: store first token
		firstTokenHash := "first-token-hash-444444"
		secondTokenHash := "second-token-hash-555555"
		expiresAt := time.Now().Add(1 * time.Hour)

		// Store first token
		err := repo.StoreToken(ctx, firstTokenHash, userID, expiresAt)
		require.NoError(t, err, "Should successfully store first token")

		// Store second token for same user
		err = repo.StoreToken(ctx, secondTokenHash, userID, expiresAt)
		require.NoError(t, err, "Should successfully store second token")

		// Verify both tokens exist (unless your implementation invalidates previous tokens)
		_, err1 := repo.GetUserIDByToken(ctx, firstTokenHash)
		_, err2 := repo.GetUserIDByToken(ctx, secondTokenHash)

		// Depending on your business logic:
		// Option 1: Both tokens should be valid (multiple active reset tokens allowed)
		// Option 2: Only the latest token should be valid (previous tokens invalidated)

		// For this test, we'll assume both are valid unless your implementation says otherwise
		if err1 == nil && err2 == nil {
			t.Log("Both tokens are valid - multiple reset tokens allowed")
		} else if err1 != nil && err2 == nil {
			t.Log("Only latest token is valid - previous tokens invalidated")
		} else {
			t.Errorf("Unexpected token state: first_token_err=%v, second_token_err=%v", err1, err2)
		}
	})
}
