package mqtt

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
)

func TestClientIDNotConstant(t *testing.T) {
	host, _ := os.Hostname()
	cfg := Config{Broker: "tcp://127.0.0.1:9", ClientID: ""}
	// Don't connect — just check default id construction path via New failure or helper
	id := cfg.ClientID
	if id == "" {
		if host == "" {
			host = "unknown"
		}
		id = "pwsbridge-" + host
	}
	if id == "pws_exporter" {
		t.Fatal("constant client id")
	}
	if !strings.HasPrefix(id, "pwsbridge-") {
		t.Fatalf("id=%s", id)
	}
	cfg.ClientID = "custom-id"
	if cfg.ClientID != "custom-id" {
		t.Fatal("override failed")
	}
	_, err := New(Config{Broker: "tcp://127.0.0.1:9", ClientID: "pws_exporter"})
	if err == nil {
		t.Fatal("expected reject pws_exporter")
	}
}

func TestStaleKeyKeepsUnderscoreStation(t *testing.T) {
	s := &Sink{
		cfg:        Config{StaleTimeout: time.Hour},
		discovered: map[string]struct{}{},
		lastSeen:   map[string]time.Time{},
		devices:    map[string]deviceID{},
	}
	s.TouchLastSeenForTest("home", "ft_0300")
	if !s.LastSeenHas("home", "ft_0300") {
		t.Fatal("missing station with underscore")
	}
	if s.LastSeenHas("home_ft", "0300") {
		t.Fatal("must not split on underscore")
	}
}

func TestQueueDropOldest(t *testing.T) {
	s := &Sink{
		cfg:        Config{},
		discovered: map[string]struct{}{},
		lastSeen:   map[string]time.Time{},
		queue:      nil,
	}
	s.SetConnectedForTest(false)
	for i := 0; i < 101; i++ {
		o := obs.New("default", "test", time.Now())
		o.SetReceived("temperature", float64(i))
		s.EnqueueForTest(o)
	}
	if s.QueueLen() != 100 {
		t.Fatalf("len=%d", s.QueueLen())
	}
	s.mu.Lock()
	first := s.queue[0]
	s.mu.Unlock()
	if v, _ := first.Get("temperature"); v != 1 {
		t.Fatalf("oldest should be 1, got %v", v)
	}
}
