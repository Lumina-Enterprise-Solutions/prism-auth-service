// services/prism-auth-service/internal/repository/api_key_repository.go
package repository

import (
	"context"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UserWithKeyHash adalah struct internal untuk mengambil data gabungan.
type UserWithKeyHash struct {
	model.User
	KeyHash string
}

type APIKeyRepository interface {
	StoreKey(ctx context.Context, userID, keyHash, prefix, description string, expiresAt *time.Time) (string, error)
	GetUserByKeyPrefix(ctx context.Context, prefix string) (*UserWithKeyHash, error)
	GetKeysForUser(ctx context.Context, userID string) ([]model.APIKeyMetadata, error)
	RevokeKey(ctx context.Context, userID, keyID string) error
}

type postgresAPIKeyRepository struct {
	db *pgxpool.Pool
}

func NewAPIKeyRepository(db *pgxpool.Pool) APIKeyRepository {
	return &postgresAPIKeyRepository{db: db}
}

func (r *postgresAPIKeyRepository) StoreKey(ctx context.Context, userID, keyHash, prefix, description string, expiresAt *time.Time) (string, error) {
	var id string
	sql := `INSERT INTO api_keys (user_id, key_hash, prefix, description, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id;`
	err := r.db.QueryRow(ctx, sql, userID, keyHash, prefix, description, expiresAt).Scan(&id)
	return id, err
}

// Mengambil data user lengkap berdasarkan prefix key.
func (r *postgresAPIKeyRepository) GetUserByKeyPrefix(ctx context.Context, prefix string) (*UserWithKeyHash, error) {
	var result UserWithKeyHash
	// Query ini menggabungkan tabel users dan api_keys
	sql := `
        SELECT
            u.id, u.email, r.name as role_name, u.status,
            k.key_hash
        FROM api_keys k
        JOIN users u ON k.user_id = u.id
        JOIN roles r ON u.role_id = r.id
        WHERE k.prefix = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW())`

	err := r.db.QueryRow(ctx, sql, prefix).Scan(
		&result.ID, &result.Email, &result.RoleName, &result.Status,
		&result.KeyHash,
	)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *postgresAPIKeyRepository) GetKeysForUser(ctx context.Context, userID string) ([]model.APIKeyMetadata, error) {
	sql := `SELECT id, user_id, prefix, description, expires_at, last_used_at, created_at, revoked_at FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC;`
	rows, err := r.db.Query(ctx, sql, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToStructByName[model.APIKeyMetadata])
}

func (r *postgresAPIKeyRepository) RevokeKey(ctx context.Context, userID, keyID string) error {
	sql := `UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;`
	commandTag, err := r.db.Exec(ctx, sql, keyID, userID)
	if err != nil {
		return err
	}
	if commandTag.RowsAffected() == 0 {
		return pgx.ErrNoRows // Tidak ada key yang cocok atau sudah di-revoke
	}
	return nil
}
