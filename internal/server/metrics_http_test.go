package server_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/server"
	"github.com/samsk/pwsbridge/internal/sink"
	"github.com/samsk/pwsbridge/internal/sink/prom"
	"log/slog"
)

func TestStationMetricsAuthAndFilter(t *testing.T) {
	capA := &captureSink{name: "a"}
	capB := &captureSink{name: "b"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{
				{ID: "ta", Stations: []config.Station{{ID: "A", Password: "pa"}}, Sinks: []string{"a", "prom"}},
				{ID: "tb", Stations: []config.Station{{ID: "B", Password: "pb"}}, Sinks: []string{"b", "prom"}},
			},
		},
		Sinks: map[string]sink.Sink{
			"a": capA, "b": capB, "prom": &prom.Sink{M: m},
		},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	_ = doGET(t, srv.Handler(), "ID=A&PASSWORD=pa&action=updateraw&tempf=70")
	waitObs(t, capA)
	_ = doGET(t, srv.Handler(), "ID=B&PASSWORD=pb&action=updateraw&tempf=60")
	waitObs(t, capB)
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/metrics/station/A", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("unauth status=%d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/metrics/station/A", nil)
	req.SetBasicAuth("A", "pa")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `station="A"`) {
		t.Fatalf("missing A: %s", body)
	}
	if strings.Contains(body, `station="B"`) {
		t.Fatalf("leaked B: %s", body)
	}
	if strings.Contains(body, "http_requests_total") {
		t.Fatal("service metrics must not appear on station endpoint")
	}
}

func TestServiceMetricsToken(t *testing.T) {
	m := metrics.New()
	m.HTTPRequests.WithLabelValues("200").Inc()
	h := server.ServiceMetricsHandler(m, "secret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("status=%d", rr.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "pwsbridge_http_requests_total") {
		t.Fatalf("body=%s", body)
	}
	if strings.Contains(string(body), "temperature_celsius") {
		t.Fatal("weather metrics must not appear on service endpoint")
	}
}

func TestOpenMetricsNoAuth(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "open",
			Tenants: []config.Tenant{{
				ID: "default", Stations: []config.Station{{ID: "test", Password: "x"}},
				Sinks: []string{"ha", "prom"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap, "prom": &prom.Sink{M: m}},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	_ = doGET(t, srv.Handler(), "ID=test&PASSWORD=x&action=updateraw&tempf=70")
	waitObs(t, cap)
	time.Sleep(50 * time.Millisecond)
	req := httptest.NewRequest(http.MethodGet, "/metrics/station/test", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("open mode status=%d", rr.Code)
	}
}
