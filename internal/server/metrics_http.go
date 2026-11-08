package server

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// handleStationMetrics serves weather metrics for one authorized station.
// Auth: HTTP Basic where username is station_id and password is the station secret,
// or Authorization: Bearer <station_password>.
func (s *Server) handleStationMetrics(w http.ResponseWriter, r *http.Request) {
	stationID := strings.TrimPrefix(r.URL.Path, "/metrics/station/")
	stationID = strings.Trim(stationID, "/")
	if stationID == "" || strings.Contains(stationID, "/") {
		http.NotFound(w, r)
		return
	}
	if !policy.ValidStationID(stationID) {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	tenant, station, ok := s.Cfg.FindStation(stationID)
	if !ok {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if policy.AuthMode(s.Cfg.AuthMode) != policy.AuthOpen {
		if !s.authorizeStation(r, station.ID, station.Password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="pwsbridge-station-metrics"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
	}
	if s.Metrics == nil {
		http.NotFound(w, r)
		return
	}
	g := metrics.StationGatherer{Inner: s.Metrics.Weather, Tenant: tenant.ID, Station: stationID}
	promhttp.HandlerFor(g, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

func (s *Server) authorizeStation(r *http.Request, stationID, password string) bool {
	if user, pass, ok := r.BasicAuth(); ok {
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(stationID)) == 1
		return userOK && policy.CheckPassword(password, pass)
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		return policy.CheckPassword(password, token)
	}
	return false
}

// ServiceMetricsHandler serves process metrics, optionally bearer-protected.
func ServiceMetricsHandler(m *metrics.Metrics, token string) http.Handler {
	inner := promhttp.HandlerFor(m.Service, promhttp.HandlerOpts{})
	if token == "" {
		return inner
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		got := []byte(strings.TrimSpace(auth[7:]))
		if subtle.ConstantTimeCompare(want, got) != 1 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
