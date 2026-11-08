package fanout

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver looks up A records without using the system resolver.
type Resolver interface {
	LookupA(ctx context.Context, host string) ([]net.IP, error)
}

// UDPResolver uses miekg/dns against a public UDP resolver.
type UDPResolver struct {
	Addr   string
	Client *dns.Client
}

// LookupA resolves host via UDP DNS.
func (r *UDPResolver) LookupA(ctx context.Context, host string) ([]net.IP, error) {
	if r.Client == nil {
		r.Client = &dns.Client{Timeout: 5 * time.Second}
	}
	addr := r.Addr
	if addr == "" {
		addr = "1.1.1.1:53"
	}
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	resp, _, err := r.Client.ExchangeContext(ctx, m, addr)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records for %s", host)
	}
	return ips, nil
}

// DoHResolver uses DNS-over-HTTPS against an IP-literal URL.
type DoHResolver struct {
	URL    string
	Client *http.Client
}

// LookupA resolves host via DoH POST.
func (r *DoHResolver) LookupA(ctx context.Context, host string) ([]net.IP, error) {
	client := r.Client
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
				// Dial by URL host which must be an IP; no system DNS for the resolver itself.
			},
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return nil, err
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, ans := range out.Answer {
		if a, ok := ans.(*dns.A); ok {
			ips = append(ips, a.A)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no A records for %s", host)
	}
	return ips, nil
}

// NewResolver picks UDP or DoH from an address string. Host must be an IP literal.
func NewResolver(addr string) (Resolver, error) {
	if err := validateResolverAddr(addr); err != nil {
		return nil, err
	}
	if strings.HasPrefix(addr, "https://") {
		return &DoHResolver{URL: addr}, nil
	}
	return &UDPResolver{Addr: addr}, nil
}

func validateResolverAddr(addr string) error {
	if addr == "" {
		return fmt.Errorf("resolver address required")
	}
	if strings.HasPrefix(addr, "https://") {
		u, err := url.Parse(addr)
		if err != nil {
			return fmt.Errorf("resolver: %w", err)
		}
		host := u.Hostname()
		if net.ParseIP(host) == nil {
			return fmt.Errorf("resolver host must be an IP literal, got %q", host)
		}
		return nil
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	} else if strings.Contains(addr, ":") && net.ParseIP(addr) == nil {
		return fmt.Errorf("resolver address must be host:port with IP host")
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("resolver host must be an IP literal, got %q", host)
	}
	return nil
}

// MustResolver is NewResolver that panics — used only in tests.
func MustResolver(addr string) Resolver {
	r, err := NewResolver(addr)
	if err != nil {
		panic(err)
	}
	return r
}
