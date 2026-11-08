package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) writeInvalidPassword(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, "INVALIDPASSWORDID")
	s.incHTTP(401)
}

func (s *Server) writeSuccess(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "success\n")
}

func (s *Server) incHTTP(code int) {
	if s.Metrics != nil {
		s.Metrics.HTTPRequests.WithLabelValues(strconv.Itoa(code)).Inc()
	}
}

func (s *Server) allowPreAuth(r *http.Request) bool {
	if s.PreAuth == nil {
		return true
	}
	key := "ip:" + clientIP(r)
	every := preAuthEvery / time.Duration(preAuthLimit)
	if every <= 0 {
		every = time.Second
	}
	ok, _ := s.PreAuth.Allow(r.Context(), key, every)
	return ok
}

func collectParams(r *http.Request) (map[string]string, error) {
	params := make(map[string]string)
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			params[k] = vs[0]
		}
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		for k, vs := range r.PostForm {
			if len(vs) > 0 {
				params[k] = vs[0]
			}
		}
	}
	return params, nil
}

func parseDateUTC(v string, log *slog.Logger) time.Time {
	if v == "" || v == "now" {
		return time.Now().UTC()
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", v, time.UTC)
	if err != nil {
		log.Warn("bad dateutc, using now", "err", err)
		return time.Now().UTC()
	}
	return t
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SanitizeLogURL redacts secrets from a raw query for tests.
func SanitizeLogURL(q string) string {
	parts := strings.Split(q, "&")
	for i, p := range parts {
		if strings.HasPrefix(strings.ToUpper(p), "PASSWORD=") ||
			strings.HasPrefix(p, "PASSKEY=") ||
			strings.HasPrefix(p, "key=") {
			parts[i] = strings.SplitN(p, "=", 2)[0] + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}
