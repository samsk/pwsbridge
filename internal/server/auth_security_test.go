package server_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/ingress/ecowitt"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/server"
	"github.com/samsk/pwsbridge/internal/sink"
	"github.com/samsk/pwsbridge/internal/sink/prom"
)

func TestEcowittUsesWUPasswordByDefault(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{{
				ID: "default",
				Stations: []config.Station{{
					ID: "FT0300", Password: "wu-secret", Protocols: []string{"ecowitt"},
				}},
				Sinks: []string{"ha"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	form := url.Values{"PASSKEY": {"wu-secret"}, "tempf": {"70"}, "dateutc": {"now"}}
	req := httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	o := waitObs(t, cap)
	if o.StationID != "FT0300" {
		t.Fatalf("station=%s", o.StationID)
	}
}

func TestEcowittPasskeyOverride(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{{
				ID: "default",
				Stations: []config.Station{{
					ID: "FT0300", Password: "wu-secret", Passkey: "eco-only",
					Protocols: []string{"ecowitt"},
				}},
				Sinks: []string{"ha"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	form := url.Values{"PASSKEY": {"wu-secret"}, "tempf": {"70"}, "dateutc": {"now"}}
	req := httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("wu password alone status=%d", rr.Code)
	}
	form.Set("PASSKEY", "eco-only")
	req = httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("override status=%d", rr.Code)
	}
	_ = waitObs(t, cap)
}

func TestEcowittRejectsStationIDWithoutPassword(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{{
				ID: "default",
				Stations: []config.Station{{
					ID: "FT0300", Password: "real-secret", Protocols: []string{"ecowitt"},
				}},
				Sinks: []string{"ha"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	form := url.Values{
		"PASSKEY": {"FT0300"},
		"tempf":   {"70"},
		"dateutc": {"now"},
	}
	req := httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 401 {
		t.Fatalf("status=%d", rr.Code)
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 0 {
		t.Fatal("sink must not publish")
	}
}

func TestOpenModeRejectsUnknownStation(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "open",
			Tenants: []config.Tenant{{
				ID: "default",
				Stations: []config.Station{{ID: "known", Password: "x"}},
				Sinks:    []string{"ha"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	res := doGET(t, srv.Handler(), "ID=unknown&PASSWORD=x&action=updateraw&tempf=70")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 401 || string(body) != "INVALIDPASSWORDID" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 0 {
		t.Fatal("sink must not publish")
	}
}

func TestStationMetricsHidesOtherTenant(t *testing.T) {
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
	req.SetBasicAuth("A", "pa")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `tenant="ta"`) {
		t.Fatalf("missing tenant ta: %s", body)
	}
	if strings.Contains(body, `tenant="tb"`) || strings.Contains(body, `station="B"`) {
		t.Fatalf("leaked other tenant: %s", body)
	}
}
