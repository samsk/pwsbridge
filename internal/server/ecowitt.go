package server

import (
	"net/http"

	"github.com/samsk/pwsbridge/internal/calc"
	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/ingress"
	"github.com/samsk/pwsbridge/internal/ingress/ecowitt"
	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/policy"
)

func (s *Server) handleEcowitt(w http.ResponseWriter, r *http.Request) {
	s.ensureWorkers()
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if !s.allowPreAuth(r) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		s.incHTTP(429)
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
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
	passkey := params["PASSKEY"]
	if passkey == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		s.incHTTP(400)
		return
	}

	tenant, station, ok := s.resolveEcowitt(passkey)
	if !ok {
		s.writeInvalidPassword(w)
		return
	}
	if !policy.StationAllowsProtocol(station.Protocols, "ecowitt") {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		s.incHTTP(403)
		return
	}

	stationID := station.ID
	remoteIP := clientIP(r)
	if s.NetGate != nil {
		if err := s.NetGate.Check(r.Context(), tenant.ID, stationID, remoteIP); err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			s.incHTTP(403)
			return
		}
	}

	limitKey := tenant.ID + "/" + stationID
	allowed, _ := s.Limiter.Allow(r.Context(), limitKey, s.Cfg.RateLimit)
	if !allowed {
		if s.Metrics != nil {
			s.Metrics.Dropped.WithLabelValues("rate").Inc()
		}
		s.writeSuccess(w)
		s.incHTTP(200)
		return
	}

	o := obs.New(tenant.ID, stationID, ecowitt.ParseDateUTC(params["dateutc"]))
	ecowitt.ApplyParams(params, &o)
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
	s.writeSuccess(w)
	s.incHTTP(200)
	s.schedulePublish(tenant, o, raw)
}

// resolveEcowitt maps PASSKEY to a configured station.
// Password mode matches PASSKEY to passkey override or WU password; open mode uses station id.
func (s *Server) resolveEcowitt(passkey string) (config.Tenant, config.Station, bool) {
	switch policy.AuthMode(s.Cfg.AuthMode) {
	case policy.AuthOpen:
		if !policy.ValidStationID(passkey) {
			return config.Tenant{}, config.Station{}, false
		}
		return s.Cfg.FindStation(passkey)
	default:
		return s.Cfg.FindStationByEcowittSecret(passkey)
	}
}
