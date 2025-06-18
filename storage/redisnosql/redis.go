package redisnosql

import (
	"auth/config"
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

func ConnectRDB() *redis.Client {
	conf := config.Load()
	rdb := redis.NewClient(&redis.Options{
		Addr:     conf.Redis.RDB_ADDRESS,
		Password: conf.Redis.RDB_PASSWORD,
		DB:       0,
	})
	return rdb
}

type RedisRepository struct {
	Rdb *redis.Client
}

func NewRedisRepository(rdb *redis.Client) *RedisRepository {
	return &RedisRepository{Rdb: rdb}
}

func (s RedisRepository) StoreCodes(ctx context.Context, code, email string) error {
	err := s.Rdb.Set(ctx, email, code, 10*time.Minute).Err()
	if err != nil {
		return errors.Wrap(err, "failed to set code in Redis")
	}

	return nil
}

func (s RedisRepository) GetCodes(ctx context.Context, email string) (string, error) {
	code, err := s.Rdb.Get(ctx, email).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("no code found for email: %s", email)
		}
		return "", errors.Wrap(err, "failed to get code from Redis")
	}
	return code, nil
}
