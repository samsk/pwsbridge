package server_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/ingress/ecowitt"
	"github.com/samsk/pwsbridge/internal/ingress/wu"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/server"
	"github.com/samsk/pwsbridge/internal/sink"
)

// FuzzWUHandler checks accepted WU uploads keep safe ids and field keys.
func FuzzWUHandler(f *testing.F) {
	seeds := []string{
		"ID=test&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=a/b&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=a+b&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=a#b&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=test&PASSWORD=testtest&action=updateraw&dateutc=now&bad/key=1",
		"ID=test&PASSWORD=testtest&action=updateraw&dateutc=now&ok_key=1",
		"ID=&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=" + strings.Repeat("A", 65) + "&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
		"ID=../x&PASSWORD=testtest&action=updateraw&dateutc=now&tempf=70",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, rawQuery string) {
		cap := &captureSink{name: "ha"}
		m := metrics.New()
		srv := &server.Server{
			Cfg: config.Config{
				AuthMode:  "open",
				RateLimit: time.Millisecond,
				Tenants: []config.Tenant{{
					ID: "default", Sinks: []string{"ha"},
					Stations: []config.Station{{ID: "test", Password: "testtest"}},
				}},
			},
			Sinks:   map[string]sink.Sink{"ha": cap},
			Limiter: policy.NewMemoryLimiter(),
			Metrics: m,
			Logger:  slog.Default(),
		}
		q := parseFuzzForm(rawQuery)
		req := httptest.NewRequest(http.MethodGet, wu.SubmissionPath+"?"+q.Encode(), nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		assertSafeAccepted(t, rr, cap)
	})
}

// FuzzEcowittHandler checks accepted Ecowitt uploads keep safe ids and keys.
func FuzzEcowittHandler(f *testing.F) {
	seeds := []string{
		"PASSKEY=AABBCCDDEEFF00112233445566778899&tempf=70&dateutc=now",
		"PASSKEY=a/b&tempf=70&dateutc=now",
		"PASSKEY=a+b&tempf=70&dateutc=now",
		"PASSKEY=a#b&tempf=70&dateutc=now",
		"PASSKEY=AABBCCDDEEFF00112233445566778899&bad/key=1&dateutc=now",
		"PASSKEY=AABBCCDDEEFF00112233445566778899&ok_key=1&dateutc=now",
		"PASSKEY=&tempf=70&dateutc=now",
		"PASSKEY=" + strings.Repeat("A", 65) + "&tempf=70&dateutc=now",
		"PASSKEY=../x&tempf=70&dateutc=now",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		cap := &captureSink{name: "ha"}
		m := metrics.New()
		srv := &server.Server{
			Cfg: config.Config{
				AuthMode:  "open",
				RateLimit: time.Millisecond,
				Tenants: []config.Tenant{{
					ID: "default", Sinks: []string{"ha"},
					Stations: []config.Station{{
						ID: "AABBCCDDEEFF00112233445566778899", Password: "x",
					}},
				}},
			},
			Sinks:   map[string]sink.Sink{"ha": cap},
			Limiter: policy.NewMemoryLimiter(),
			Metrics: m,
			Logger:  slog.Default(),
		}
		form := parseFuzzForm(body)
		req := httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		assertSafeAccepted(t, rr, cap)
	})
}

// parseFuzzForm turns "k=v&k2=v2" fuzz input into encoded form values.
func parseFuzzForm(raw string) url.Values {
	form := url.Values{}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			form.Set(part, "")
			continue
		}
		form.Set(k, v)
	}
	return form
}

// assertSafeAccepted checks 2xx uploads yield safe station ids and field keys.
func assertSafeAccepted(t *testing.T, rr *httptest.ResponseRecorder, cap *captureSink) {
	t.Helper()
	if rr.Code != http.StatusOK {
		return
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if cap.count() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	o, ok := cap.last()
	if !ok {
		return
	}
	if !policy.ValidStationID(o.StationID) {
		t.Fatalf("accepted unsafe station %q", o.StationID)
	}
	for k := range o.Fields {
		if !obs.ValidKey(k) {
			t.Fatalf("accepted unsafe field %q", k)
		}
	}
}
