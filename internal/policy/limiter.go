package policy

import (
	"context"
	"sync"
	"time"
)

const memoryLimiterMaxKeys = 4096

// Limiter reports whether a key may pass. Backends: memory, sqlite, redis.
type Limiter interface {
	Allow(ctx context.Context, key string, every time.Duration) (bool, error)
}

// MemoryLimiter is an in-process rate limiter with a capped key map.
type MemoryLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// NewMemoryLimiter creates an empty memory limiter.
func NewMemoryLimiter() *MemoryLimiter {
	return &MemoryLimiter{last: make(map[string]time.Time)}
}

// Allow returns false when key is inside the every window.
func (l *MemoryLimiter) Allow(_ context.Context, key string, every time.Duration) (bool, error) {
	if every <= 0 {
		return true, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if t, ok := l.last[key]; ok && now.Sub(t) < every {
		return false, nil
	}
	if len(l.last) >= memoryLimiterMaxKeys {
		l.evictOlderThan(now, every)
	}
	if len(l.last) >= memoryLimiterMaxKeys {
		for k := range l.last {
			delete(l.last, k)
			break
		}
	}
	l.last[key] = now
	return true, nil
}

func (l *MemoryLimiter) evictOlderThan(now time.Time, every time.Duration) {
	for k, t := range l.last {
		if now.Sub(t) >= every {
			delete(l.last, k)
		}
	}
}

// Len returns tracked keys for tests.
func (l *MemoryLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.last)
}
