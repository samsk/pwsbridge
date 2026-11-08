package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wx.yaml")
	content := `
auth_mode: password
tenants:
  - id: home
    derived: true
    stations:
      - id: FT0300
        password: secret
        protocols: [wu]
    sinks: [ha]
sinks:
  ha:
    type: mqtt
    broker: tcp://mosquitto:1883
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PWSBRIDGE_CONFIG", path)
	t.Setenv("PWSBRIDGE_LISTEN", ":9099")
	t.Setenv("PWSBRIDGE_RATE_LIMIT", "5s")
	cfg, _, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9099" {
		t.Fatalf("listen=%s", cfg.Listen)
	}
	if !cfg.Tenants[0].Derived {
		t.Fatal("derived")
	}
	if cfg.RateLimit.Seconds() != 5 {
		t.Fatalf("rate=%v", cfg.RateLimit)
	}
}
