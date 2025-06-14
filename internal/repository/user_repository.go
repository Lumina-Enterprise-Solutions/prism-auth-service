package repository

import (
	"context"
	"time"

	"github.com/Lumina-Enterprise-Solutions/prism-common-libs/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RefreshToken struct { // <-- TAMBAHKAN STRUCT BARU INI
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
}

type UserRepository interface {
	// UBAH: Parameter diubah menjadi objek User
	CreateUser(ctx context.Context, user *model.User) (string, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	Enable2FA(ctx context.Context, userID, totpSecret string) error
}

type postgresUserRepository struct {
	db *pgxpool.Pool
}

func NewPostgresUserRepository(db *pgxpool.Pool) UserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) CreateUser(ctx context.Context, user *model.User) (string, error) {
	// UBAH: SQL Query untuk memasukkan field baru
	sql := `INSERT INTO users (email, password_hash, first_name, last_name)
            VALUES ($1, $2, $3, $4)
            RETURNING id;`
	var userID string
	// UBAH: Tambahkan parameter baru ke QueryRow
	err := r.db.QueryRow(ctx, sql, user.Email, user.PasswordHash, user.FirstName, user.LastName).Scan(&userID)
	if err != nil {
		return "", err
	}
	return userID, nil
}

func (r *postgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var user model.User

	sql := `SELECT id, email, password_hash, first_name, last_name, role, is_2fa_enabled, totp_secret, status, created_at, updated_at
            FROM users
            WHERE email = $1;`
	err := r.db.QueryRow(ctx, sql, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Role,
		&user.Is2FAEnabled, &user.TOTPSecret, &user.Status, // <-- Tambahkan &user.Status
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

//	func (r *postgresUserRepository) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
//		var user model.User
//		sql := `SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
//	            FROM users
//	            WHERE email = $1;`
//		err := r.db.QueryRow(ctx, sql, email).Scan(
//			&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Role, &user.CreatedAt, &user.UpdatedAt,
//		)
//		if err != nil {
//			return nil, err // pgx.ErrNoRows akan di-handle di service
//		}
//		return &user, nil
//	}
func (r *postgresUserRepository) StoreRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	sql := `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3);`
	_, err := r.db.Exec(ctx, sql, userID, tokenHash, expiresAt)
	return err
}

func (r *postgresUserRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var rt RefreshToken
	sql := `SELECT id, user_id, token_hash, expires_at FROM refresh_tokens WHERE token_hash = $1;`
	err := r.db.QueryRow(ctx, sql, tokenHash).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &rt, nil
}

func (r *postgresUserRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	sql := `DELETE FROM refresh_tokens WHERE token_hash = $1;`
	_, err := r.db.Exec(ctx, sql, tokenHash)
	return err
}

func (r *postgresUserRepository) GetUserByID(ctx context.Context, id string) (*model.User, error) {
	var user model.User
	sql := `SELECT id, email, password_hash, first_name, last_name, role, is_2fa_enabled, totp_secret, created_at, updated_at
            FROM users
            WHERE id = $1;`
	err := r.db.QueryRow(ctx, sql, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Role,
		&user.Is2FAEnabled, &user.TOTPSecret, // <-- Tambahan di sini
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

//	func (r *postgresUserRepository) GetUserByID(ctx context.Context, id string) (*model.User, error) {
//		var user model.User
//		sql := `SELECT id, email, password_hash, first_name, last_name, role, created_at, updated_at
//	            FROM users
//	            WHERE id = $1;`
//		err := r.db.QueryRow(ctx, sql, id).Scan(
//			&user.ID, &user.Email, &user.PasswordHash, &user.FirstName, &user.LastName, &user.Role, &user.CreatedAt, &user.UpdatedAt,
//		)
//		if err != nil {
//			return nil, err
//		}
//		return &user, nil
//	}
func (r *postgresUserRepository) Enable2FA(ctx context.Context, userID, totpSecret string) error {
	sql := `UPDATE users SET is_2fa_enabled = TRUE, totp_secret = $1, updated_at = NOW() WHERE id = $2;`
	_, err := r.db.Exec(ctx, sql, totpSecret, userID)
	return err
}
