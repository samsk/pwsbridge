package store

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisLimiter shares rate limits across processes via Valkey/Redis.
type RedisLimiter struct {
	Client *redis.Client
}

// NewRedisLimiter connects to addr.
func NewRedisLimiter(addr string) *RedisLimiter {
	return &RedisLimiter{Client: redis.NewClient(&redis.Options{Addr: addr})}
}

// Allow uses SET NX with TTL as a simple rate window.
func (l *RedisLimiter) Allow(ctx context.Context, key string, every time.Duration) (bool, error) {
	if every <= 0 {
		return true, nil
	}
	ok, err := l.Client.SetNX(ctx, "pwsbridge:limit:"+key, "1", every).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

// Close closes the redis client.
func (l *RedisLimiter) Close() error {
	return l.Client.Close()
}
