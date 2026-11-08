package fanout

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/samsk/pwsbridge/internal/ingress"
)

type fakeResolver struct {
	ips map[string][]net.IP
}

func (f *fakeResolver) LookupA(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := f.ips[host]
	if !ok {
		return nil, net.UnknownNetworkError("unexpected " + host)
	}
	return ips, nil
}

func TestFanoutKeepsRawQuery(t *testing.T) {
	var gotURL string
	var gotHost string
	var gotServerName string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.RawQuery
		gotHost = r.Host
		w.Write([]byte("success"))
	}))
	defer ts.Close()

	ip := net.ParseIP("127.0.0.1")
	u := ts.URL
	hostPort := strings.TrimPrefix(u, "https://")
	_, port, _ := net.SplitHostPort(hostPort)

	rawQuery := "dateutc=2000-01-01+10%3A32%3A35&ID=x&PASSWORD=y&action=updateraw"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         primaryHost,
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				gotServerName = primaryHost
				return net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	w := &WU{
		Resolver: &fakeResolver{ips: map[string][]net.IP{primaryHost: {ip}}},
		Client:   client,
	}
	res := w.Forward(context.Background(), ingress.RawUpload{
		RawQuery: rawQuery,
		Host:     "weather-01.home",
	})
	if res.Kind != KindOK {
		t.Fatalf("kind=%v err=%v", res.Kind, res.Err)
	}
	if gotURL != rawQuery {
		t.Fatalf("query=%q want %q", gotURL, rawQuery)
	}
	if gotHost != primaryHost {
		t.Fatalf("host=%q", gotHost)
	}
	if gotServerName != primaryHost {
		t.Fatalf("serverName=%q", gotServerName)
	}
	_ = io.EOF
}

func TestFanoutHostHeader(t *testing.T) {
	var gotHost string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		w.Write([]byte("success"))
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: primaryHost},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
	prod := (&WU{}).defaultClient(primaryHost)
	tr := prod.Transport.(*http.Transport)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify should be false")
	}
	if tr.TLSClientConfig.ServerName != primaryHost {
		t.Fatal("ServerName")
	}
	if prod.CheckRedirect == nil {
		t.Fatal("CheckRedirect required")
	}

	w := &WU{
		Resolver: &fakeResolver{ips: map[string][]net.IP{primaryHost: {net.ParseIP("127.0.0.1")}}},
		Client:   client,
	}
	_ = w.Forward(context.Background(), ingress.RawUpload{RawQuery: "a=1", Host: "weather-01.home"})
	if gotHost != primaryHost {
		t.Fatalf("host=%q", gotHost)
	}
}

func TestFanoutOneHost(t *testing.T) {
	var hosts []string
	r := &fakeResolver{ips: map[string][]net.IP{
		primaryHost: {net.ParseIP("1.2.3.4")},
	}}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				hosts = append(hosts, addr)
				return nil, net.UnknownNetworkError("stop")
			},
		},
	}
	w := &WU{Resolver: r, Client: client}
	res := w.Forward(context.Background(), ingress.RawUpload{RawQuery: "x=1"})
	if res.Kind != KindTransport {
		t.Fatalf("kind=%v", res.Kind)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts=%v", hosts)
	}
	if !strings.HasPrefix(hosts[0], "1.2.3.4:") {
		t.Fatalf("addr=%s", hosts[0])
	}
}

func TestFanoutIgnoresSystemResolver(t *testing.T) {
	r := &fakeResolver{ips: map[string][]net.IP{}}
	w := &WU{Resolver: r, Client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.Fatal("should not dial when resolver empty")
			return nil, nil
		},
	}}}
	res := w.Forward(context.Background(), ingress.RawUpload{RawQuery: "x=1"})
	if res.Kind != KindTransport {
		t.Fatal("expected resolver error")
	}
}

func TestBuildRequestURL(t *testing.T) {
	u := BuildRequestURL(net.ParseIP("9.9.9.9"), "a=1&b=2")
	if u != "https://9.9.9.9/weatherstation/updateweatherstation.php?a=1&b=2" {
		t.Fatalf("u=%s", u)
	}
}

func TestWURefusalReturnsReason(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("INVALIDPASSWORDID"))
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: primaryHost},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
	w := &WU{
		Resolver: &fakeResolver{ips: map[string][]net.IP{primaryHost: {net.ParseIP("127.0.0.1")}}},
		Client:   client,
	}
	res := w.Forward(context.Background(), ingress.RawUpload{RawQuery: "x=1"})
	if res.Kind != KindRefusal {
		t.Fatalf("kind=%v", res.Kind)
	}
	if res.Reason != "INVALIDPASSWORDID" {
		t.Fatalf("reason=%q", res.Reason)
	}
}

func TestWUServerErrorIsTransport(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(ts.URL, "https://"))
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: primaryHost},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
			},
		},
	}
	w := &WU{
		Resolver: &fakeResolver{ips: map[string][]net.IP{primaryHost: {net.ParseIP("127.0.0.1")}}},
		Client:   client,
	}
	res := w.Forward(context.Background(), ingress.RawUpload{RawQuery: "x=1"})
	if res.Kind != KindTransport {
		t.Fatalf("kind=%v", res.Kind)
	}
}

func TestNewResolverRequiresIP(t *testing.T) {
	if _, err := NewResolver("cloudflare-dns.com:53"); err == nil {
		t.Fatal("expected error for hostname resolver")
	}
	if _, err := NewResolver("1.1.1.1:53"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewResolver("https://cloudflare-dns.com/dns-query"); err == nil {
		t.Fatal("expected error for DoH hostname")
	}
}
