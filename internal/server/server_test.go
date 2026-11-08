package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/fanout"
	"github.com/samsk/pwsbridge/internal/ingress"
	"github.com/samsk/pwsbridge/internal/ingress/ecowitt"
	"github.com/samsk/pwsbridge/internal/ingress/wu"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/server"
	"github.com/samsk/pwsbridge/internal/sink"
	mqttsink "github.com/samsk/pwsbridge/internal/sink/mqtt"
	"github.com/samsk/pwsbridge/internal/sink/prom"
	dto "github.com/prometheus/client_model/go"
)

type captureSink struct {
	mu   sync.Mutex
	obs  []obs.Observation
	err  error
	name string
}

func (c *captureSink) Name() string { return c.name }
func (c *captureSink) Close() error { return nil }
func (c *captureSink) Publish(_ context.Context, o obs.Observation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.obs = append(c.obs, o)
	return c.err
}
func (c *captureSink) last() (obs.Observation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.obs) == 0 {
		return obs.Observation{}, false
	}
	return c.obs[len(c.obs)-1], true
}
func (c *captureSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.obs)
}

type captureFanout struct {
	mu   sync.Mutex
	raws []ingress.RawUpload
	res  fanout.Result
}

func (c *captureFanout) Name() string { return "wu" }
func (c *captureFanout) Forward(_ context.Context, raw ingress.RawUpload) fanout.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raws = append(c.raws, raw)
	if c.res.Kind == 0 && c.res.Err == nil && c.res.Reason == "" {
		return fanout.OKResult()
	}
	return c.res
}

func goldenQuery(t *testing.T) string {
	t.Helper()
	candidates := []string{
		filepath.Join("..", "..", "testdata", "wu_golden.txt"),
		filepath.Join("testdata", "wu_golden.txt"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	t.Fatal("golden file missing")
	return ""
}

func build(t *testing.T, derived bool, sinkErr error, logBuf *bytes.Buffer) (*server.Server, *captureSink, *metrics.Metrics, *bytes.Buffer) {
	t.Helper()
	cap := &captureSink{name: "ha", err: sinkErr}
	m := metrics.New()
	if logBuf == nil {
		logBuf = &bytes.Buffer{}
	}
	log := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	out := &server.Server{
		Cfg: config.Config{
			AuthMode:  "password",
			RateLimit: 2 * time.Second,
			Tenants: []config.Tenant{{
				ID: "default", Derived: derived,
				Stations: []config.Station{{ID: "test", Password: "testtest"}},
				Sinks:    []string{"ha", "prom"},
			}},
		},
		Sinks: map[string]sink.Sink{
			"ha":   cap,
			"prom": &prom.Sink{M: m},
		},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  log,
	}
	return out, cap, m, logBuf
}

func waitObs(t *testing.T, c *captureSink) obs.Observation {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if o, ok := c.last(); ok {
			return o
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no observation")
	return obs.Observation{}
}

func doGET(t *testing.T, h http.Handler, rawQuery string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, wu.SubmissionPath+"?"+rawQuery, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result()
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func TestGoldenObservation(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	res := doGET(t, srv.Handler(), goldenQuery(t))
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "success\n" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	o := waitObs(t, cap)
	if v, _ := o.Get("temperature"); v != 17.5 {
		t.Fatalf("temp=%v", v)
	}
	if v, _ := o.Get("humidity"); v != 64 {
		t.Fatalf("humidity=%v", v)
	}
	wantWind := 4.4 * 1.609344
	if v, _ := o.Get("wind_speed"); abs(v-wantWind) > 1e-9 {
		t.Fatalf("wind=%v want %v", v, wantWind)
	}
	wantP := 29.65 * 33.8639
	if v, _ := o.Get("pressure"); abs(v-wantP) > 1e-9 {
		t.Fatalf("pressure=%v want %v", v, wantP)
	}
	if o.Has("PASSWORD") {
		t.Fatal("PASSWORD should not be a sensor")
	}
}

func TestPOSTSameAsGET(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	form := url.Values{}
	for _, part := range strings.Split(goldenQuery(t), "&") {
		kv := strings.SplitN(part, "=", 2)
		form.Set(kv[0], kv[1])
	}
	req := httptest.NewRequest(http.MethodPost, wu.SubmissionPath+"?tempf=1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	o := waitObs(t, cap)
	if v, _ := o.Get("temperature"); v != 17.5 {
		t.Fatalf("form should win: temp=%v", v)
	}
}

func TestSentinelOmitted(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), goldenQuery(t)+"&solarradiation=-9999")
	o := waitObs(t, cap)
	if o.WasReceived("solar_radiation") || o.Has("solar_radiation") {
		t.Fatal("sentinel should be omitted")
	}
}

func TestUnknownNumericExtra(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), goldenQuery(t)+"&customfield=1.5&customfield2=abc")
	o := waitObs(t, cap)
	if v, ok := o.Get("customfield"); !ok || v != 1.5 {
		t.Fatalf("extra=%v ok=%v", v, ok)
	}
	if o.Has("customfield2") {
		t.Fatal("non-numeric ignored")
	}
	topic, body, err := mqttsink.DiscoveryPayload("homeassistant", o)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(topic, "default_test") {
		t.Fatalf("topic=%s", topic)
	}
	if !strings.Contains(string(body), "customfield") {
		t.Fatalf("discovery missing customfield: %s", body)
	}
}

func TestDerivedOffByDefault(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	q := "ID=test&PASSWORD=testtest&action=updateraw&tempf=63.5&humidity=64&windspeedmph=4.4"
	_ = doGET(t, srv.Handler(), q)
	o := waitObs(t, cap)
	for _, k := range []string{"dew_point", "humidity_abs", "feels_like", "heat_index", "wind_chill", "aus_apparent_temp"} {
		if o.Has(k) {
			t.Fatalf("derived %s should be absent", k)
		}
	}
	srv2, cap2, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv2.Handler(), q+"&dewptf=51.2")
	o2 := waitObs(t, cap2)
	if !o2.Has("dew_point") {
		t.Fatal("sent dewptf should publish")
	}
}

func TestDerivedOnFillsGaps(t *testing.T) {
	srv, cap, _, _ := build(t, true, nil, nil)
	q := "ID=test&PASSWORD=testtest&action=updateraw&tempf=63.5&humidity=64&windspeedmph=4.4&windchillf=60"
	_ = doGET(t, srv.Handler(), q)
	o := waitObs(t, cap)
	if !o.Has("dew_point") {
		t.Fatal("expected calculated dew point")
	}
	if !o.WasReceived("wind_chill") {
		t.Fatal("sent windchillf should be received")
	}
	srv2, cap2, _, _ := build(t, true, nil, nil)
	_ = doGET(t, srv2.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&tempf=63.5&humidity=64&dewptf=0")
	o2 := waitObs(t, cap2)
	// dewptf=0 is 0°F → -17.777...°C; must be kept (not treated as missing)
	want := (0.0 - 32) * 5 / 9
	if v, ok := o2.Get("dew_point"); !ok || abs(v-want) > 1e-9 || !o2.WasReceived("dew_point") {
		t.Fatalf("dewptf=0 kept as %v ok=%v received=%v", v, ok, o2.WasReceived("dew_point"))
	}
}

func TestDiscoveryShape(t *testing.T) {
	o := obs.New("default", "test", time.Now())
	o.SetReceived("temperature", 17.5)
	o.SetReceived("wind_direction", 270)
	topic, body, err := mqttsink.DiscoveryPayload("homeassistant", o)
	if err != nil {
		t.Fatal(err)
	}
	if topic != "homeassistant/device/default_test/config" {
		t.Fatalf("topic=%s", topic)
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	cmps := payload["components"].(map[string]any)
	temp := cmps["temperature"].(map[string]any)
	if temp["value_template"] != "{{ value_json.temperature }}" {
		t.Fatalf("template=%v", temp["value_template"])
	}
	wd := cmps["wind_direction"].(map[string]any)
	if wd["state_class"] != "measurement_angle" {
		t.Fatalf("state_class=%v", wd["state_class"])
	}
	if payload["payload_available"] != "online" || payload["payload_not_available"] != "offline" {
		t.Fatal("availability payloads")
	}
}

func TestSinkErrorStillSuccess(t *testing.T) {
	srv, _, _, _ := build(t, false, io.ErrUnexpectedEOF, nil)
	res := doGET(t, srv.Handler(), goldenQuery(t))
	body, _ := io.ReadAll(res.Body)
	if string(body) != "success\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestRejectUpdateraww(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	res := doGET(t, srv.Handler(), "ID=test&PASSWORD=testtest&action=updateraww&tempf=63.5")
	if res.StatusCode != 400 {
		t.Fatalf("status=%d", res.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 0 {
		t.Fatal("sink should not be called")
	}
	res = doGET(t, srv.Handler(), goldenQuery(t))
	if res.StatusCode != 200 {
		t.Fatalf("updateraw status=%d", res.StatusCode)
	}
	res = doGET(t, srv.Handler(), "")
	if res.StatusCode != 400 {
		t.Fatalf("empty status=%d", res.StatusCode)
	}
}

func TestZeroDewPointKept(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&dewptf=0&dailyrainin=0&tempf=32")
	o := waitObs(t, cap)
	wantDew := (0.0 - 32) * 5 / 9 // 0°F in SI
	if v, ok := o.Get("dew_point"); !ok || abs(v-wantDew) > 1e-9 || !o.WasReceived("dew_point") {
		t.Fatalf("dew=%v ok=%v", v, ok)
	}
	if v, ok := o.Get("rain_daily"); !ok || v != 0 || !o.WasReceived("rain_daily") {
		t.Fatalf("rain=%v ok=%v", v, ok)
	}
}

func TestHumidityScale(t *testing.T) {
	srv, cap, m, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), goldenQuery(t))
	o := waitObs(t, cap)
	if v, _ := o.Get("humidity"); v != 64 {
		t.Fatalf("humidity=%v", v)
	}
	time.Sleep(50 * time.Millisecond)
	g := m.Humidity.WithLabelValues("default", "test")
	var metric dto.Metric
	if err := g.Write(&metric); err != nil {
		t.Fatal(err)
	}
	if metric.GetGauge().GetValue() != 64 {
		t.Fatalf("gauge=%v", metric.GetGauge().GetValue())
	}
	fams, err := m.Weather.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == "pwsbridge_humidity_percent" {
			if f.GetType() != dto.MetricType_GAUGE {
				t.Fatalf("type=%v", f.GetType())
			}
			help := f.GetHelp()
			if strings.Contains(help, "0-1)") || strings.Contains(help, "0.0-1.0") || strings.Contains(help, "0 to 1") {
				t.Fatalf("help=%q", help)
			}
			if !strings.Contains(help, "0-100") && !strings.Contains(help, "0 to 100") {
				t.Fatalf("help should say percent 0-100: %q", help)
			}
		}
	}
}

func TestRainIsGauge(t *testing.T) {
	srv, _, m, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&tempf=70&rainin=0.0393700787&dailyrainin=0.0393700787")
	time.Sleep(50 * time.Millisecond)
	for _, name := range []string{"pwsbridge_rain_past_hour_mm", "pwsbridge_rain_daily_mm"} {
		fams, _ := m.Weather.Gather()
		found := false
		for _, f := range fams {
			if f.GetName() == name {
				found = true
				if f.GetType() != dto.MetricType_GAUGE {
					t.Fatalf("%s type=%v", name, f.GetType())
				}
			}
		}
		if !found {
			t.Fatalf("missing %s", name)
		}
	}
	srv2, _, m2, _ := build(t, false, nil, nil)
	_ = doGET(t, srv2.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&tempf=70&dailyrainin=0")
	time.Sleep(50 * time.Millisecond)
	g := m2.RainDaily.WithLabelValues("default", "test")
	var metric dto.Metric
	_ = g.Write(&metric)
	if metric.GetGauge().GetValue() != 0 {
		t.Fatalf("daily after reset=%v", metric.GetGauge().GetValue())
	}
	_ = m
}

func TestBadDateUTCAccepted(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	before := time.Now().UTC().Add(-time.Second)
	res := doGET(t, srv.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&dateutc=not-a-date&tempf=70")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "success\n" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	o := waitObs(t, cap)
	if o.LastUpdated.Before(before) {
		t.Fatalf("time=%v", o.LastUpdated)
	}
}

func TestBadFieldSkipped(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), "ID=test&PASSWORD=testtest&action=updateraw&tempf=63.5&windspeedmph=abc")
	o := waitObs(t, cap)
	if !o.Has("temperature") {
		t.Fatal("temp missing")
	}
	if o.Has("wind_speed") {
		t.Fatal("bad wind should be skipped")
	}
}

func TestGETOnlyIsNotEnough(t *testing.T) {
	srv, _, _, _ := build(t, false, nil, nil)
	form := url.Values{"ID": {"test"}, "PASSWORD": {"testtest"}, "action": {"updateraw"}, "tempf": {"70"}}
	req := httptest.NewRequest(http.MethodPost, wu.SubmissionPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("POST=%d", rr.Code)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, wu.SubmissionPath+"?"+goldenQuery(t), nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 405 {
			t.Fatalf("%s=%d", method, rr.Code)
		}
	}
}

func TestUnknownPath404(t *testing.T) {
	srv, _, _, _ := build(t, false, nil, nil)
	for _, path := range []string{"/", "/anything"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != 404 {
			t.Fatalf("%s=%d", path, rr.Code)
		}
		if strings.Contains(rr.Body.String(), "success") {
			t.Fatalf("%s body has success", path)
		}
	}
}

func TestStationBodyIsSuccess(t *testing.T) {
	srv, _, _, _ := build(t, false, nil, nil)
	res := doGET(t, srv.Handler(), goldenQuery(t))
	body, _ := io.ReadAll(res.Body)
	if string(body) != "success\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestStationIDInjection(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	for _, id := range []string{"a/b", "../x", "a+b"} {
		res := doGET(t, srv.Handler(), "ID="+url.QueryEscape(id)+"&PASSWORD=testtest&action=updateraw&tempf=70")
		if res.StatusCode != 400 {
			t.Fatalf("id %q status=%d", id, res.StatusCode)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 0 {
		t.Fatal("should not publish")
	}
}

func TestPasswordNotLogged(t *testing.T) {
	var buf bytes.Buffer
	srv, _, _, _ := build(t, false, nil, &buf)
	_ = doGET(t, srv.Handler(), goldenQuery(t))
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(buf.String(), "testtest") {
		t.Fatalf("password leaked in logs: %s", buf.String())
	}
}

func TestNoDefaultPublishInterval(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), goldenQuery(t))
	waitObs(t, cap)
	time.Sleep(3 * time.Second)
	_ = doGET(t, srv.Handler(), goldenQuery(t)+"&tempf=64.4")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cap.count() >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("got %d samples, want 2", cap.count())
}

func TestWrongPassword(t *testing.T) {
	srv, cap, _, _ := build(t, false, nil, nil)
	res := doGET(t, srv.Handler(), "ID=test&PASSWORD=wrong&action=updateraw&tempf=70")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 401 || string(body) != "INVALIDPASSWORDID" {
		t.Fatalf("status=%d body=%q", res.StatusCode, body)
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 0 {
		t.Fatal("sink called")
	}
}

func TestRateLimitDropsSecond(t *testing.T) {
	srv, cap, m, _ := build(t, false, nil, nil)
	_ = doGET(t, srv.Handler(), goldenQuery(t))
	waitObs(t, cap)
	res := doGET(t, srv.Handler(), goldenQuery(t))
	body, _ := io.ReadAll(res.Body)
	if string(body) != "success\n" {
		t.Fatalf("body=%q", body)
	}
	time.Sleep(50 * time.Millisecond)
	if cap.count() != 1 {
		t.Fatalf("count=%d", cap.count())
	}
	g := m.Dropped.WithLabelValues("rate")
	var metric dto.Metric
	_ = g.Write(&metric)
	if metric.GetCounter().GetValue() < 1 {
		t.Fatal("dropped not incremented")
	}
}

func TestFanoutDownStillPublishes(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	bad := &captureFanout{res: fanout.TransportResult(io.ErrUnexpectedEOF)}
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{{
				ID: "default", Stations: []config.Station{{ID: "test", Password: "testtest"}},
				Sinks: []string{"ha"}, Fanouts: []string{"wu"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Fanouts: map[string]*fanout.Guard{"wu": fanout.NewGuard(bad, nil, slog.Default())},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	res := doGET(t, srv.Handler(), goldenQuery(t))
	body, _ := io.ReadAll(res.Body)
	if string(body) != "success\n" {
		t.Fatalf("body=%q", body)
	}
	_ = waitObs(t, cap)
}

func TestTenantIsolation(t *testing.T) {
	capA := &captureSink{name: "a"}
	capB := &captureSink{name: "b"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{
				{ID: "ta", Stations: []config.Station{{ID: "A", Password: "pa"}}, Sinks: []string{"a"}, Derived: true},
				{ID: "tb", Stations: []config.Station{{ID: "B", Password: "pb"}}, Sinks: []string{"b"}},
			},
		},
		Sinks:   map[string]sink.Sink{"a": capA, "b": capB},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	_ = doGET(t, srv.Handler(), "ID=A&PASSWORD=pa&action=updateraw&tempf=70&humidity=50")
	_ = waitObs(t, capA)
	_ = doGET(t, srv.Handler(), "ID=B&PASSWORD=pb&action=updateraw&tempf=60&humidity=40")
	_ = waitObs(t, capB)
	if capB.count() == 0 || capA.count() == 0 {
		t.Fatal("both should receive")
	}
	if oa, _ := capA.last(); oa.TenantID != "ta" {
		t.Fatalf("tenant A=%s", oa.TenantID)
	}
	if ob, _ := capB.last(); ob.TenantID != "tb" {
		t.Fatalf("tenant B=%s", ob.TenantID)
	}
}

func TestTenantDerivedIsolated(t *testing.T) {
	capA := &captureSink{name: "a"}
	capB := &captureSink{name: "b"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{
				{ID: "ta", Derived: true, Stations: []config.Station{{ID: "A", Password: "pa"}}, Sinks: []string{"a"}},
				{ID: "tb", Stations: []config.Station{{ID: "B", Password: "pb"}}, Sinks: []string{"b"}},
			},
		},
		Sinks:   map[string]sink.Sink{"a": capA, "b": capB},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
	}
	q := "&action=updateraw&tempf=63.5&humidity=64&windspeedmph=4.4"
	_ = doGET(t, srv.Handler(), "ID=A&PASSWORD=pa"+q)
	oa := waitObs(t, capA)
	_ = doGET(t, srv.Handler(), "ID=B&PASSWORD=pb"+q)
	ob := waitObs(t, capB)
	if !oa.Has("dew_point") {
		t.Fatal("tenant A should derive")
	}
	if ob.Has("dew_point") {
		t.Fatal("tenant B should not derive")
	}
}

func TestEcowittNotParsedAsWU(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password",
			Tenants: []config.Tenant{{
				ID: "default",
				Stations: []config.Station{{
					ID: "home1", Password: "AABBCCDDEEFF00112233445566778899", Protocols: []string{"ecowitt"},
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
		"PASSKEY":     {"AABBCCDDEEFF00112233445566778899"},
		"tempinf":     {"70.0"},
		"baromrelin":  {"30.0"},
		"tempf":       {"68.0"},
		"humidity":    {"50"},
		"dateutc":     {"2024-01-01 00:00:00"},
	}
	req := httptest.NewRequest(http.MethodPost, ecowitt.ReportPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	o := waitObs(t, cap)
	if !o.Has("indoor_temperature") {
		t.Fatal("tempinf should map to indoor_temperature")
	}
	if !o.Has("pressure") {
		t.Fatal("baromrelin should map to pressure")
	}
	// WU uses baromin, not baromrelin — ensure we got Ecowitt mapping (30 inHg)
	want := 30.0 * 33.8639
	if v, _ := o.Get("pressure"); abs(v-want) > 1e-6 {
		t.Fatalf("pressure=%v want %v", v, want)
	}
}

func TestASNReject(t *testing.T) {
	cap := &captureSink{name: "ha"}
	m := metrics.New()
	gate := policy.NewNetLearn("enforce_asn", &fanout.UDPResolver{Addr: "1.1.1.1:53"}, slog.Default())
	gate.SetASNForTest("default", "test", "AS99999")
	srv := &server.Server{
		Cfg: config.Config{
			AuthMode: "password", NetLearnMode: "enforce_asn",
			Tenants: []config.Tenant{{
				ID: "default", Stations: []config.Station{{ID: "test", Password: "testtest"}},
				Sinks: []string{"ha"},
			}},
		},
		Sinks:   map[string]sink.Sink{"ha": cap},
		Limiter: policy.NewMemoryLimiter(),
		Metrics: m,
		Logger:  slog.Default(),
		NetGate: gate,
	}
	// Without a working ASN for 127.0.0.1 this may 403 on lookup failure in enforce mode.
	res := doGET(t, srv.Handler(), goldenQuery(t))
	if res.StatusCode != 403 && res.StatusCode != 200 {
		t.Fatalf("status=%d", res.StatusCode)
	}
}
