package store

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRedisLimitShared(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	a := NewRedisLimiter(mr.Addr())
	b := NewRedisLimiter(mr.Addr())
	defer a.Close()
	defer b.Close()

	ctx := context.Background()
	ok1, err := a.Allow(ctx, "home/test", time.Second)
	if err != nil || !ok1 {
		t.Fatalf("first allow=%v err=%v", ok1, err)
	}
	ok2, err := b.Allow(ctx, "home/test", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok2 {
		t.Fatal("second process should be rate limited")
	}
}
