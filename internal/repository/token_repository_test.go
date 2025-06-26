package repository

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRepository(t *testing.T) {
	// The check for short mode is now handled globally for the package in main_test.go's TestMain.
	// No need to skip here individually.

	require.NotNil(t, testDBPool, "testDBPool is nil. TestMain setup may have failed.")

	ctx := context.Background()
	repo := NewPostgresTokenRepository(testDBPool)

	truncateTables(ctx, t, "users", "refresh_tokens", "roles")
	userID, _ := seedUser(ctx, t)

	t.Run("Store and Get Refresh Token", func(t *testing.T) {
		tokenHash := "refresh-token-hash-456"
		expiresAt := time.Now().Add(24 * time.Hour)

		err := repo.StoreRefreshToken(ctx, userID, tokenHash, expiresAt)
		require.NoError(t, err)

		refreshToken, err := repo.GetRefreshToken(ctx, tokenHash)

		require.NoError(t, err)
		assert.NotNil(t, refreshToken)
		assert.Equal(t, userID, refreshToken.UserID)
		assert.Equal(t, tokenHash, refreshToken.TokenHash)
		assert.WithinDuration(t, expiresAt, refreshToken.ExpiresAt, time.Second)
	})

	t.Run("Get Non-existent Refresh Token", func(t *testing.T) {
		_, err := repo.GetRefreshToken(ctx, "non-existent-refresh-hash")
		assert.ErrorIs(t, err, pgx.ErrNoRows)
	})

	t.Run("Delete Refresh Token", func(t *testing.T) {
		tokenHash := "rt-to-be-deleted"
		expiresAt := time.Now().Add(1 * time.Hour)
		err := repo.StoreRefreshToken(ctx, userID, tokenHash, expiresAt)
		require.NoError(t, err)

		err = repo.DeleteRefreshToken(ctx, tokenHash)
		require.NoError(t, err)

		_, err = repo.GetRefreshToken(ctx, tokenHash)
		assert.ErrorIs(t, err, pgx.ErrNoRows)
	})
}
