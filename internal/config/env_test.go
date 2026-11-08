package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadEnvNames(t *testing.T) {
	names := RequireEnvNames()
	for _, n := range names {
		if !strings.HasPrefix(n, "PWSBRIDGE_") {
			t.Fatalf("env name %q missing PWSBRIDGE_ prefix", n)
		}
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("PWSBRIDGE_LISTEN", ":9090")
	t.Setenv("PWSBRIDGE_STATION_ID", "FT0300")
	t.Setenv("PWSBRIDGE_STATION_PASSWORD", "secret")
	t.Setenv("PWSBRIDGE_MQTT_BROKER", "tcp://mosquitto:1883")
	t.Setenv("PWSBRIDGE_PROMETHEUS", "true")
	t.Setenv("PWSBRIDGE_DERIVED", "false")
	os.Unsetenv("PWSBRIDGE_CONFIG")

	cfg, e, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if e.Listen != ":9090" {
		t.Fatalf("listen=%q", e.Listen)
	}
	if cfg.Listen != ":9090" {
		t.Fatalf("cfg.listen=%q", cfg.Listen)
	}
	if len(cfg.Tenants) != 1 || cfg.Tenants[0].ID != "default" {
		t.Fatalf("tenant=%+v", cfg.Tenants)
	}
	if cfg.Tenants[0].Derived {
		t.Fatal("derived should default false")
	}
	if _, ok := cfg.Sinks["ha"]; !ok {
		t.Fatal("expected ha sink")
	}
}

func TestEnvNotFlagsOnly(t *testing.T) {
	// Ensures required docker-style names are documented and loadable.
	for _, name := range RequireEnvNames() {
		if strings.Contains(name, "--") {
			t.Fatalf("flag-style name %q", name)
		}
	}
}
