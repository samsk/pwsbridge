package config

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/samsk/pwsbridge/internal/policy"
)

// Validate checks config consistency for single and multi-tenant modes.
func (c Config) Validate() error {
	if err := c.validateMetricsBind(); err != nil {
		return err
	}
	if err := c.validateTenants(); err != nil {
		return err
	}
	multi := len(c.Tenants) > 1
	if multi {
		if policy.AuthMode(c.AuthMode) != policy.AuthPassword {
			return fmt.Errorf("multi-tenant requires auth_mode=password")
		}
	}
	if err := c.validateSinkOwnership(multi); err != nil {
		return err
	}
	if err := c.validateSQLitePaths(); err != nil {
		return err
	}
	if multi {
		if err := c.validatePublicSinkDial(); err != nil {
			return err
		}
	}
	return nil
}

func (c Config) validateMetricsBind() error {
	if c.MetricsListen == "" {
		return nil
	}
	if c.MetricsToken != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(c.MetricsListen)
	if err != nil {
		// ":9091" style
		if strings.HasPrefix(c.MetricsListen, ":") {
			return fmt.Errorf("metrics_listen %q requires metrics_token when not loopback", c.MetricsListen)
		}
		return fmt.Errorf("metrics_listen: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("metrics_listen %q requires metrics_token when not loopback", c.MetricsListen)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics_listen %q requires metrics_token when not loopback", c.MetricsListen)
	}
	return nil
}

func (c Config) validateTenants() error {
	stationIDs := map[string]string{}
	passwords := map[string]string{}
	ecowittSecrets := map[string]string{}
	for _, t := range c.Tenants {
		if !policy.ValidTenantID(t.ID) {
			return fmt.Errorf("invalid tenant id %q", t.ID)
		}
		for _, s := range t.Stations {
			if !policy.ValidStationID(s.ID) {
				return fmt.Errorf("invalid station id %q", s.ID)
			}
			if prev, ok := stationIDs[s.ID]; ok {
				return fmt.Errorf("duplicate station id %q (tenants %s and %s)", s.ID, prev, t.ID)
			}
			stationIDs[s.ID] = t.ID
			if s.Password != "" {
				if prev, ok := passwords[s.Password]; ok {
					return fmt.Errorf("duplicate station password (stations %s and %s)", prev, s.ID)
				}
				passwords[s.Password] = s.ID
			}
			if secret := s.EcowittSecret(); secret != "" {
				if prev, ok := ecowittSecrets[secret]; ok {
					return fmt.Errorf("duplicate ecowitt secret (stations %s and %s)", prev, s.ID)
				}
				ecowittSecrets[secret] = s.ID
			}
		}
	}
	return nil
}

func (c Config) validateSinkOwnership(multi bool) error {
	if !multi {
		return nil
	}
	owner := map[string]string{}
	for _, t := range c.Tenants {
		for _, name := range t.Sinks {
			sc, ok := c.Sinks[name]
			if !ok {
				return fmt.Errorf("tenant %s references unknown sink %q", t.ID, name)
			}
			switch sc.Type {
			case "mqtt", "sqlite", "influx":
				if prev, ok := owner[name]; ok && prev != t.ID {
					return fmt.Errorf("sink %q shared by tenants %s and %s", name, prev, t.ID)
				}
				owner[name] = t.ID
			}
		}
	}
	return nil
}

func (c Config) validateSQLitePaths() error {
	dataDir := c.DataDir
	if dataDir == "" {
		dataDir = "/data"
	}
	seen := map[string]string{}
	for name, sc := range c.Sinks {
		if sc.Type != "sqlite" {
			continue
		}
		path := sc.Path
		if path == "" {
			path = c.SQLitePath
		}
		if path == "" {
			return fmt.Errorf("sqlite sink %q missing path", name)
		}
		clean := filepath.Clean(path)
		if !filepath.IsAbs(clean) {
			return fmt.Errorf("sqlite sink %q path must be absolute", name)
		}
		rel, err := filepath.Rel(filepath.Clean(dataDir), clean)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("sqlite sink %q path must be under %s", name, dataDir)
		}
		if prev, ok := seen[clean]; ok {
			return fmt.Errorf("sqlite path %s used by sinks %s and %s", clean, prev, name)
		}
		seen[clean] = name
	}
	return nil
}

func (c Config) validatePublicSinkDial() error {
	for name, sc := range c.Sinks {
		switch sc.Type {
		case "mqtt":
			if err := rejectPrivateBroker(sc.Broker); err != nil {
				return fmt.Errorf("sink %s: %w", name, err)
			}
		case "influx":
			if err := rejectPrivateURL(sc.URL); err != nil {
				return fmt.Errorf("sink %s: %w", name, err)
			}
		}
	}
	return nil
}

func rejectPrivateBroker(broker string) error {
	u, err := url.Parse(broker)
	if err != nil {
		return fmt.Errorf("broker: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("broker missing host")
	}
	return rejectPrivateHost(host)
}

func rejectPrivateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url missing host")
	}
	return rejectPrivateHost(host)
}

// rejectPrivateHost refuses loopback, link-local, multicast, and private hosts.
func rejectPrivateHost(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return fmt.Errorf("host %s is not a public address", host)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("resolve %s: no addresses", host)
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("host %s resolves to non-public address", host)
		}
	}
	return nil
}

func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	// IPv6 ULA fc00::/7
	return len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc
}

// FindStationByEcowittSecret returns the station whose Ecowitt secret matches PASSKEY.
func (c Config) FindStationByEcowittSecret(passkey string) (Tenant, Station, bool) {
	var found Tenant
	var st Station
	n := 0
	for _, t := range c.Tenants {
		for _, s := range t.Stations {
			if policy.CheckPassword(s.EcowittSecret(), passkey) {
				found = t
				st = s
				n++
			}
		}
	}
	if n != 1 {
		return Tenant{}, Station{}, false
	}
	return found, st, true
}
