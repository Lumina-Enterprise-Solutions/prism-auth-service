package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// Kita akan menggunakan singleton pattern sederhana untuk klien Redis
	redisClient *redis.Client
)

// InitRedisClient menginisialisasi koneksi ke Redis.
func InitRedisClient(client *redis.Client) {
	redisClient = client
}

// AddToDenylist menambahkan JTI token ke daftar hitam dengan TTL.
func AddToDenylist(ctx context.Context, jti string, ttl time.Duration) error {
	return redisClient.Set(ctx, jti, "revoked", ttl).Err()
}

// IsInDenylist memeriksa apakah sebuah JTI ada di daftar hitam.
func IsInDenylist(ctx context.Context, jti string) (bool, error) {
	err := redisClient.Get(ctx, jti).Err()
	if err == redis.Nil {
		// JTI tidak ditemukan, berarti token valid (tidak di-blacklist)
		return false, nil
	}
	if err != nil {
		// Error Redis lainnya
		return false, err
	}
	// JTI ditemukan, berarti token telah dicabut
	return true, nil
}
