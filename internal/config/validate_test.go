package config

import (
	"strings"
	"testing"
)

func TestMetricsRejectsPublicBindWithoutToken(t *testing.T) {
	cfg := Config{
		AuthMode:      "password",
		MetricsListen: "0.0.0.0:9091",
		Tenants: []Tenant{{
			ID: "default",
			Stations: []Station{{ID: "test", Password: "secret"}},
		}},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "metrics_token") {
		t.Fatalf("err=%v", err)
	}
	cfg.MetricsToken = "tok"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateStationRejected(t *testing.T) {
	cfg := Config{
		AuthMode: "password",
		Tenants: []Tenant{
			{ID: "a", Stations: []Station{{ID: "same", Password: "p1"}}},
			{ID: "b", Stations: []Station{{ID: "same", Password: "p2"}}},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate station") {
		t.Fatalf("err=%v", err)
	}
}

func TestMultiTenantRejectsOpenAuth(t *testing.T) {
	cfg := Config{
		AuthMode: "open",
		Tenants: []Tenant{
			{ID: "a", Stations: []Station{{ID: "s1", Password: "p1"}}, Sinks: []string{"ha"}},
			{ID: "b", Stations: []Station{{ID: "s2", Password: "p2"}}, Sinks: []string{"hb"}},
		},
		Sinks: map[string]SinkCfg{
			"ha": {Type: "mqtt", Broker: "tcp://203.0.113.1:1883"},
			"hb": {Type: "mqtt", Broker: "tcp://203.0.113.2:1883"},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "auth_mode=password") {
		t.Fatalf("err=%v", err)
	}
}

func TestMultiTenantRejectsSharedSink(t *testing.T) {
	cfg := Config{
		AuthMode: "password",
		Tenants: []Tenant{
			{ID: "a", Stations: []Station{{ID: "s1", Password: "p1"}}, Sinks: []string{"shared"}},
			{ID: "b", Stations: []Station{{ID: "s2", Password: "p2"}}, Sinks: []string{"shared"}},
		},
		Sinks: map[string]SinkCfg{
			"shared": {Type: "mqtt", Broker: "tcp://203.0.113.1:1883"},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "shared") {
		t.Fatalf("err=%v", err)
	}
}

func TestMultiTenantRejectsPrivateBroker(t *testing.T) {
	cfg := Config{
		AuthMode: "password",
		Tenants: []Tenant{
			{ID: "a", Stations: []Station{{ID: "s1", Password: "p1"}}, Sinks: []string{"ha"}},
			{ID: "b", Stations: []Station{{ID: "s2", Password: "p2"}}, Sinks: []string{"hb"}},
		},
		Sinks: map[string]SinkCfg{
			"ha": {Type: "mqtt", Broker: "tcp://192.168.1.10:1883"},
			"hb": {Type: "mqtt", Broker: "tcp://203.0.113.2:1883"},
		},
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "public") {
		t.Fatalf("err=%v", err)
	}
}
