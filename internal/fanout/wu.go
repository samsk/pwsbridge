package fanout

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/samsk/pwsbridge/internal/ingress"
	"github.com/samsk/pwsbridge/internal/metrics"
)

const (
	primaryHost  = "rtupdate.wunderground.com"
	fallbackHost = "weatherstation.wunderground.com"
	wuPath       = "/weatherstation/updateweatherstation.php"
	dnsCacheTTL  = 6 * time.Hour
)

// WU forwards uploads to Weather Underground via public DNS.
type WU struct {
	Resolver Resolver
	Client   *http.Client
	Metrics  *metrics.Metrics
	Logger   *slog.Logger

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips []net.IP
	at  time.Time
}

// Name returns the fanout name.
func (w *WU) Name() string { return "wu" }

// Forward sends the original RawQuery to WU with Host and TLS ServerName set.
func (w *WU) Forward(ctx context.Context, raw ingress.RawUpload) Result {
	host := primaryHost
	ips, err := w.lookup(ctx, host)
	if err != nil || len(ips) == 0 {
		host = fallbackHost
		ips, err = w.lookup(ctx, host)
		if err != nil {
			w.inc(host, "error")
			return TransportResult(err)
		}
	}
	return w.send(ctx, host, ips[0], raw.RawQuery)
}

func (w *WU) send(ctx context.Context, host string, ip net.IP, rawQuery string) Result {
	client := w.Client
	if client == nil {
		client = w.defaultClient(host)
	}
	url := fmt.Sprintf("https://%s%s", ip.String(), wuPath)
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return TransportResult(err)
	}
	req.Host = host
	req.Header.Set("Host", host)

	resp, err := client.Do(req)
	if err != nil {
		w.mu.Lock()
		delete(w.cache, host)
		w.mu.Unlock()
		w.inc(host, "error")
		return TransportResult(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	res := ClassifyHTTP(resp.StatusCode, string(body))
	switch res.Kind {
	case KindOK:
		w.inc(host, "ok")
	case KindRefusal:
		if w.Logger != nil {
			w.Logger.Warn("wu forward refused", "host", host, "status", resp.StatusCode, "reason", res.Reason)
		}
		w.inc(host, "refused")
	default:
		if w.Logger != nil {
			w.Logger.Warn("wu forward transport", "host", host, "status", resp.StatusCode)
		}
		w.inc(host, "error")
	}
	return res
}

func (w *WU) defaultClient(host string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		DialContext:         (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
		TLSHandshakeTimeout: 2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (w *WU) lookup(ctx context.Context, host string) ([]net.IP, error) {
	w.mu.Lock()
	if w.cache == nil {
		w.cache = make(map[string]cacheEntry)
	}
	if e, ok := w.cache[host]; ok && time.Since(e.at) < dnsCacheTTL {
		ips := e.ips
		w.mu.Unlock()
		return ips, nil
	}
	w.mu.Unlock()

	ips, err := w.Resolver.LookupA(ctx, host)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.cache[host] = cacheEntry{ips: ips, at: time.Now()}
	w.mu.Unlock()
	return ips, nil
}

func (w *WU) inc(host, result string) {
	if w.Metrics != nil {
		w.Metrics.Fanout.WithLabelValues(host, result).Inc()
	}
}

// BuildRequestURL exposes the outbound URL shape for tests.
func BuildRequestURL(ip net.IP, rawQuery string) string {
	u := fmt.Sprintf("https://%s%s", ip.String(), wuPath)
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	return u
}
