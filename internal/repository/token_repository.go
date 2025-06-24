package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshToken adalah model data untuk refresh token yang disimpan di database.
// Model ini bersifat internal untuk auth-service.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
}

// TokenRepository mendefinisikan operasi DB yang dibutuhkan oleh auth-service untuk mengelola token.
type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
}

type postgresTokenRepository struct {
	db *pgxpool.Pool
}

func NewPostgresTokenRepository(db *pgxpool.Pool) TokenRepository {
	return &postgresTokenRepository{db: db}
}

func (r *postgresTokenRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	sql := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3);`
	_, err := r.db.Exec(ctx, sql, userID, tokenHash, expiresAt)
	return err
}

func (r *postgresTokenRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	sql := `SELECT id, user_id, token_hash, expires_at FROM refresh_tokens WHERE token_hash = $1;`
	err := r.db.QueryRow(ctx, sql, tokenHash).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *postgresTokenRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	sql := `DELETE FROM refresh_tokens WHERE token_hash = $1;`
	_, err := r.db.Exec(ctx, sql, tokenHash)
	return err
}
