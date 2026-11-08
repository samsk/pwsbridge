package server

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/samsk/pwsbridge/internal/calc"
	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/fanout"
	"github.com/samsk/pwsbridge/internal/ingress"
	"github.com/samsk/pwsbridge/internal/ingress/ecowitt"
	"github.com/samsk/pwsbridge/internal/ingress/wu"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/sink"
)

const (
	maxSinkWorkers   = 32
	maxSinkPerTenant = 4
	preAuthEvery     = time.Minute
	preAuthLimit     = 20
)

// unknownPasswordStandIn keeps WU auth timing similar for unknown ids.
const unknownPasswordStandIn = "\x00pwsbridge-unknown-station-secret\x00"

// Server serves WU/Ecowitt ingest and station-scoped metrics.
type Server struct {
	Cfg         config.Config
	Sinks       map[string]sink.Sink
	Fanouts     map[string]*fanout.Guard
	Limiter     policy.Limiter
	PreAuth     policy.Limiter
	Metrics     *metrics.Metrics
	Logger      *slog.Logger
	NetGate     *policy.NetLearn
	HTTP        *http.Server
	MetricsHTTP *http.Server

	sinkSem       chan struct{}
	tenantSinkSem sync.Map // tenant -> chan struct{}
}

// Handler returns the HTTP mux for ingest and tenant weather metrics.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wu.SubmissionPath, s.handleWU)
	mux.HandleFunc(ecowitt.ReportPath, s.handleEcowitt)
	mux.HandleFunc(ecowitt.ReportPath+"/", s.handleEcowitt)
	if s.Metrics != nil {
		mux.HandleFunc("/metrics/station/", s.handleStationMetrics)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// ListenAndServe starts the ingest HTTP server with plan timeouts.
func (s *Server) ListenAndServe() error {
	s.ensureWorkers()
	if s.PreAuth == nil {
		s.PreAuth = policy.NewMemoryLimiter()
	}
	s.HTTP = &http.Server{
		Addr:              s.Cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	s.Logger.Info("listening", "addr", s.Cfg.Listen)
	return s.HTTP.ListenAndServe()
}

// ListenAndServeMetrics starts the optional service-metrics server.
func (s *Server) ListenAndServeMetrics() error {
	if s.Cfg.MetricsListen == "" || s.Metrics == nil {
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", ServiceMetricsHandler(s.Metrics, s.Cfg.MetricsToken))
	s.MetricsHTTP = &http.Server{
		Addr:              s.Cfg.MetricsListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	s.Logger.Info("service metrics listening", "addr", s.Cfg.MetricsListen)
	return s.MetricsHTTP.ListenAndServe()
}

// Shutdown stops ingest and metrics HTTP servers.
func (s *Server) Shutdown(ctx context.Context) error {
	var first error
	if s.HTTP != nil {
		if err := s.HTTP.Shutdown(ctx); err != nil {
			first = err
		}
	}
	if s.MetricsHTTP != nil {
		if err := s.MetricsHTTP.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Server) ensureWorkers() {
	if s.sinkSem == nil {
		s.sinkSem = make(chan struct{}, maxSinkWorkers)
	}
}

func (s *Server) handleWU(w http.ResponseWriter, r *http.Request) {
	s.ensureWorkers()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !s.allowPreAuth(r) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		s.incHTTP(429)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		s.incHTTP(405)
		return
	}
	params, err := collectParams(r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		s.incHTTP(400)
		return
	}
	if len(params) > 128 {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		s.incHTTP(400)
		return
	}
	if params["action"] != "updateraw" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		s.incHTTP(400)
		return
	}
	stationID := params["ID"]
	if !policy.ValidStationID(stationID) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		s.incHTTP(400)
		return
	}

	tenant, station, ok := s.Cfg.FindStation(stationID)
	switch policy.AuthMode(s.Cfg.AuthMode) {
	case policy.AuthOpen:
		if !ok {
			s.writeInvalidPassword(w)
			return
		}
	default:
		want := unknownPasswordStandIn
		if ok {
			want = station.Password
		}
		passOK := policy.CheckPassword(want, params["PASSWORD"])
		if !ok || !passOK {
			s.writeInvalidPassword(w)
			return
		}
	}
	if !policy.StationAllowsProtocol(station.Protocols, "wu") {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		s.incHTTP(403)
		return
	}

	remoteIP := clientIP(r)
	if s.NetGate != nil {
		if err := s.NetGate.Check(r.Context(), tenant.ID, stationID, remoteIP); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			s.incHTTP(403)
			return
		}
	}

	limitKey := tenant.ID + "/" + stationID
	allowed, err := s.Limiter.Allow(r.Context(), limitKey, s.Cfg.RateLimit)
	if err != nil {
		s.Logger.Error("limiter", "err", err)
	}
	if !allowed {
		if s.Metrics != nil {
			s.Metrics.Dropped.WithLabelValues("rate").Inc()
		}
		s.writeSuccess(w)
		s.incHTTP(200)
		return
	}

	at := parseDateUTC(params["dateutc"], s.Logger)
	o := obs.New(tenant.ID, stationID, at)
	wu.ApplyParams(params, &o)
	if tenant.Derived {
		calc.Apply(&o)
	}

	raw := ingress.RawUpload{
		Method:   r.Method,
		Path:     r.URL.Path,
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
		Host:     r.Host,
	}

	s.Logger.Info("received wu upload",
		"station_id", stationID,
		"tenant", tenant.ID,
		"remote", remoteIP,
		"proto", r.Proto,
	)

	s.writeSuccess(w)
	s.incHTTP(200)
	s.schedulePublish(tenant, o, raw)
}
