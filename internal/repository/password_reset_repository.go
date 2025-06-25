package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PasswordResetRepository interface {
	StoreToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error
	GetUserIDByToken(ctx context.Context, tokenHash string) (string, error)
	DeleteToken(ctx context.Context, tokenHash string) error
}

type postgresPasswordResetRepository struct {
	db *pgxpool.Pool
}

func NewPostgresPasswordResetRepository(db *pgxpool.Pool) PasswordResetRepository {
	return &postgresPasswordResetRepository{db: db}
}

func (r *postgresPasswordResetRepository) StoreToken(ctx context.Context, tokenHash, userID string, expiresAt time.Time) error {
	sql := `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3);`
	_, err := r.db.Exec(ctx, sql, userID, tokenHash, expiresAt)
	return err
}

func (r *postgresPasswordResetRepository) GetUserIDByToken(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	sql := `SELECT user_id FROM password_reset_tokens WHERE token_hash = $1;`
	err := r.db.QueryRow(ctx, sql, tokenHash).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (r *postgresPasswordResetRepository) DeleteToken(ctx context.Context, tokenHash string) error {
	sql := `DELETE FROM password_reset_tokens WHERE token_hash = $1;`
	_, err := r.db.Exec(ctx, sql, tokenHash)
	return err
}
