package policy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"

	"github.com/samsk/pwsbridge/internal/fanout"
	"github.com/miekg/dns"
)

// NetLearnMode controls ASN/subnet learning.
type NetLearnMode string

const (
	NetOff        NetLearnMode = "off"
	NetModeLearn  NetLearnMode = "learn"
	NetEnforceASN NetLearnMode = "enforce_asn"
)

// NetLearn records and optionally enforces source ASN after password auth.
type NetLearn struct {
	Mode     NetLearnMode
	Resolver fanout.Resolver
	Logger   *slog.Logger

	mu    sync.Mutex
	asns  map[string]string // tenant/station -> ASN
}

// NewNetLearn creates a gate with the given mode.
func NewNetLearn(mode string, r fanout.Resolver, log *slog.Logger) *NetLearn {
	return &NetLearn{
		Mode:     NetLearnMode(mode),
		Resolver: r,
		Logger:   log,
		asns:     make(map[string]string),
	}
}

// Check learns or enforces ASN for a station key.
func (n *NetLearn) Check(ctx context.Context, tenant, station, ip string) error {
	if n == nil || n.Mode == NetOff || n.Mode == "" {
		return nil
	}
	asn, err := n.lookupASN(ctx, ip)
	if err != nil {
		if n.Logger != nil {
			n.Logger.Warn("asn lookup", "ip", ip, "err", err)
		}
		if n.Mode == NetEnforceASN {
			return fmt.Errorf("asn lookup failed")
		}
		return nil
	}
	key := tenant + "/" + station
	n.mu.Lock()
	defer n.mu.Unlock()
	known, ok := n.asns[key]
	if !ok {
		n.asns[key] = asn
		return nil
	}
	if n.Mode == NetEnforceASN && known != asn {
		return fmt.Errorf("asn mismatch")
	}
	return nil
}

// SetASNForTest seeds a learned ASN.
func (n *NetLearn) SetASNForTest(tenant, station, asn string) {
	n.mu.Lock()
	n.asns[tenant+"/"+station] = asn
	n.mu.Unlock()
}

func (n *NetLearn) lookupASN(ctx context.Context, ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("bad ip")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("ipv6 asn not implemented")
	}
	// Team Cymru: reversed-ip.origin.asn.cymru.com TXT
	rev := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", ip4[3], ip4[2], ip4[1], ip4[0])
	if n.Resolver == nil {
		return "", fmt.Errorf("no resolver")
	}
	// Use DNS TXT via UDP resolver internals
	ur, ok := n.Resolver.(*fanout.UDPResolver)
	if !ok {
		// fallback: try A lookup just to exercise resolver; ASN needs TXT
		ur = &fanout.UDPResolver{Addr: "1.1.1.1:53"}
	}
	client := ur.Client
	if client == nil {
		client = &dns.Client{}
	}
	addr := ur.Addr
	if addr == "" {
		addr = "1.1.1.1:53"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(rev), dns.TypeTXT)
	resp, _, err := client.ExchangeContext(ctx, m, addr)
	if err != nil {
		return "", err
	}
	for _, ans := range resp.Answer {
		if t, ok := ans.(*dns.TXT); ok && len(t.Txt) > 0 {
			// format: "AS | IP | BGP Prefix | CC | Registry | Allocated"
			parts := strings.Split(t.Txt[0], "|")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0]), nil
			}
		}
	}
	return "", fmt.Errorf("no txt")
}
