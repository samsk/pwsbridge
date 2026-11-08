package fanout

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/samsk/pwsbridge/internal/ingress"
)

var backoffSteps = []time.Duration{
	time.Minute,
	5 * time.Minute,
	15 * time.Minute,
	time.Hour,
	4 * time.Hour,
}

const (
	disableAfter   = 24 * time.Hour
	maxPerTenant   = 2
)

// FanoutState is the client-visible forward status.
type FanoutState struct {
	State   string    `json:"state"` // ok, paused, disabled
	Reason  string    `json:"reason,omitempty"`
	RetryAt time.Time `json:"retry_at,omitempty"`
}

// Notifier reports fanout state transitions to the operator.
type Notifier interface {
	NotifyFanout(tenant, station, fanoutName string, st FanoutState)
}

// Guard wraps a Fanout with per-station refusal backoff.
type Guard struct {
	Inner    Fanout
	Notifier Notifier
	Logger   *slog.Logger
	Now      func() time.Time

	mu       sync.Mutex
	slots    map[string]*stationSlot
	tenantN  map[string]int
}

type stationSlot struct {
	state      string
	reason     string
	retryAt    time.Time
	firstRef   time.Time
	step       int
	inFlight   bool
	lastNotify FanoutState
}

// NewGuard creates a refusal guard around inner.
func NewGuard(inner Fanout, n Notifier, log *slog.Logger) *Guard {
	return &Guard{
		Inner:    inner,
		Notifier: n,
		Logger:   log,
		Now:      time.Now,
		slots:    make(map[string]*stationSlot),
		tenantN:  make(map[string]int),
	}
}

// Name returns the inner fanout name.
func (g *Guard) Name() string {
	if g.Inner == nil {
		return ""
	}
	return g.Inner.Name()
}

// Try schedules a non-blocking forward for tenant/station.
func (g *Guard) Try(tenant, station string, raw ingress.RawUpload) {
	key := tenant + "/" + station
	g.mu.Lock()
	slot := g.slots[key]
	if slot == nil {
		slot = &stationSlot{state: "ok"}
		g.slots[key] = slot
	}
	now := g.now()
	if slot.state == "disabled" {
		g.mu.Unlock()
		return
	}
	if slot.state == "paused" && now.Before(slot.retryAt) {
		g.mu.Unlock()
		return
	}
	if slot.inFlight || g.tenantN[tenant] >= maxPerTenant {
		g.mu.Unlock()
		return
	}
	slot.inFlight = true
	g.tenantN[tenant]++
	g.mu.Unlock()

	go g.run(key, tenant, station, raw)
}

func (g *Guard) run(key, tenant, station string, raw ingress.RawUpload) {
	defer func() {
		if rec := recover(); rec != nil && g.Logger != nil {
			g.Logger.Error("fanout panic", "tenant", tenant, "station", station, "panic", rec)
		}
		g.mu.Lock()
		if s := g.slots[key]; s != nil {
			s.inFlight = false
		}
		if g.tenantN[tenant] > 0 {
			g.tenantN[tenant]--
		}
		g.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := g.Inner.Forward(ctx, raw)
	g.applyResult(key, tenant, station, res)
}

func (g *Guard) applyResult(key, tenant, station string, res Result) {
	g.mu.Lock()
	defer g.mu.Unlock()
	slot := g.slots[key]
	if slot == nil {
		slot = &stationSlot{state: "ok"}
		g.slots[key] = slot
	}
	now := g.now()
	switch res.Kind {
	case KindOK:
		slot.state = "ok"
		slot.reason = ""
		slot.retryAt = time.Time{}
		slot.firstRef = time.Time{}
		slot.step = 0
		g.emitLocked(tenant, station, slot)
	case KindRefusal:
		if slot.firstRef.IsZero() {
			slot.firstRef = now
		}
		slot.reason = res.Reason
		if now.Sub(slot.firstRef) >= disableAfter {
			slot.state = "disabled"
			slot.retryAt = time.Time{}
			g.emitLocked(tenant, station, slot)
			if g.Logger != nil {
				g.Logger.Error("fanout disabled after refusals",
					"fanout", g.Name(), "tenant", tenant, "station", station, "reason", slot.reason)
			}
			return
		}
		slot.state = "paused"
		if slot.step >= len(backoffSteps) {
			slot.step = len(backoffSteps) - 1
		}
		slot.retryAt = now.Add(backoffSteps[slot.step])
		slot.step++
		g.emitLocked(tenant, station, slot)
		if g.Logger != nil {
			g.Logger.Warn("fanout paused after refusal",
				"fanout", g.Name(), "tenant", tenant, "station", station,
				"reason", slot.reason, "retry_at", slot.retryAt)
		}
	case KindTransport:
		// leave pause/disable clocks unchanged
	}
}

func (g *Guard) emitLocked(tenant, station string, slot *stationSlot) {
	st := FanoutState{State: slot.state, Reason: slot.reason, RetryAt: slot.retryAt}
	if st.State == slot.lastNotify.State && st.Reason == slot.lastNotify.Reason &&
		st.RetryAt.Equal(slot.lastNotify.RetryAt) {
		return
	}
	slot.lastNotify = st
	if g.Notifier != nil {
		n := g.Notifier
		name := g.Name()
		go n.NotifyFanout(tenant, station, name, st)
	}
}

func (g *Guard) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

// StateForTest returns the slot state for tests.
func (g *Guard) StateForTest(tenant, station string) FanoutState {
	g.mu.Lock()
	defer g.mu.Unlock()
	slot := g.slots[tenant+"/"+station]
	if slot == nil {
		return FanoutState{State: "ok"}
	}
	return FanoutState{State: slot.state, Reason: slot.reason, RetryAt: slot.retryAt}
}

// SetNowForTest injects a clock.
func (g *Guard) SetNowForTest(now func() time.Time) {
	g.Now = now
}

// WaitIdleForTest waits until no in-flight work remains.
func (g *Guard) WaitIdleForTest(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		g.mu.Lock()
		busy := false
		for _, s := range g.slots {
			if s.inFlight {
				busy = true
				break
			}
		}
		g.mu.Unlock()
		if !busy {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
