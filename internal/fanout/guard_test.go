package fanout

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/ingress"
)

type stubFanout struct {
	name  string
	res   Result
	n     atomic.Int32
	block chan struct{}
}

func (s *stubFanout) Name() string { return s.name }
func (s *stubFanout) Forward(ctx context.Context, _ ingress.RawUpload) Result {
	s.n.Add(1)
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return TransportResult(ctx.Err())
		}
	}
	return s.res
}

func TestGuardBackoffSkipsUntilDelay(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	inner := &stubFanout{name: "wu", res: RefusalResult(401, "nope")}
	g := NewGuard(inner, nil, nil)
	g.SetNowForTest(func() time.Time { return now })

	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	if g.StateForTest("t", "s").State != "paused" {
		t.Fatalf("state=%+v", g.StateForTest("t", "s"))
	}
	if inner.n.Load() != 1 {
		t.Fatalf("n=%d", inner.n.Load())
	}
	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	if inner.n.Load() != 1 {
		t.Fatal("should skip while paused")
	}
	now = now.Add(time.Minute)
	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	if inner.n.Load() != 2 {
		t.Fatalf("probe n=%d", inner.n.Load())
	}
}

func TestGuardDisablesAfter24h(t *testing.T) {
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	inner := &stubFanout{name: "wu", res: RefusalResult(401, "nope")}
	g := NewGuard(inner, nil, nil)
	g.SetNowForTest(func() time.Time { return now })

	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	now = now.Add(24 * time.Hour)
	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	st := g.StateForTest("t", "s")
	if st.State != "disabled" {
		t.Fatalf("state=%+v", st)
	}
	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	if inner.n.Load() != 2 {
		t.Fatalf("disabled should not call again, n=%d", inner.n.Load())
	}
}

func TestGuardNetworkErrorDoesNotPause(t *testing.T) {
	inner := &stubFanout{name: "wu", res: TransportResult(context.DeadlineExceeded)}
	g := NewGuard(inner, nil, nil)
	g.Try("t", "s", ingress.RawUpload{})
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
	if g.StateForTest("t", "s").State != "ok" {
		t.Fatalf("state=%+v", g.StateForTest("t", "s"))
	}
}

func TestGuardTryDoesNotBlock(t *testing.T) {
	block := make(chan struct{})
	inner := &stubFanout{name: "wu", res: OKResult(), block: block}
	g := NewGuard(inner, nil, nil)
	started := time.Now()
	g.Try("t", "s", ingress.RawUpload{})
	if time.Since(started) > 50*time.Millisecond {
		t.Fatal("Try blocked on Forward")
	}
	close(block)
	if !g.WaitIdleForTest(time.Second) {
		t.Fatal("busy")
	}
}
