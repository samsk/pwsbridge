package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runtime directory of tenants, sinks, and fanouts.
type Config struct {
	Listen        string             `yaml:"listen"`
	MetricsListen string             `yaml:"metrics_listen"`
	MetricsToken  string             `yaml:"metrics_token"`
	AuthMode      string             `yaml:"auth_mode"`
	RateLimit     time.Duration      `yaml:"rate_limit"`
	StaleTimeout  time.Duration      `yaml:"stale_timeout"`
	LogLevel      string             `yaml:"log_level"`
	Tenants       []Tenant           `yaml:"tenants"`
	Sinks         map[string]SinkCfg `yaml:"sinks"`
	Fanouts       map[string]FanCfg  `yaml:"fanouts"`
	NetLearnMode  string             `yaml:"net_learn"`
	LimitBackend  string             `yaml:"limit_backend"`
	RedisAddr     string             `yaml:"redis_addr"`
	SQLitePath    string             `yaml:"sqlite_path"`
	DataDir       string             `yaml:"data_dir"`
}

// Tenant is one multi-station logical customer.
type Tenant struct {
	ID       string    `yaml:"id"`
	Derived  bool      `yaml:"derived"`
	Stations []Station `yaml:"stations"`
	Sinks    []string  `yaml:"sinks"`
	Fanouts  []string  `yaml:"fanouts"`
}

// Station is a weather station credential and protocol set.
type Station struct {
	ID        string   `yaml:"id"`
	Password  string   `yaml:"password"`
	Passkey   string   `yaml:"passkey"` // optional Ecowitt PASSKEY; defaults to Password
	Protocols []string `yaml:"protocols"`
}

// EcowittSecret is the value matched to Ecowitt PASSKEY.
// Uses Passkey when set, otherwise the WU Password.
func (s Station) EcowittSecret() string {
	if s.Passkey != "" {
		return s.Passkey
	}
	return s.Password
}

// SinkCfg describes a named sink.
type SinkCfg struct {
	Type            string `yaml:"type"`
	Broker          string `yaml:"broker"`
	Username        string `yaml:"username"`
	Password        string `yaml:"password"`
	DiscoveryPrefix string `yaml:"discovery_prefix"`
	ClientID        string `yaml:"client_id"`
	Path            string `yaml:"path"`
	URL             string `yaml:"url"`
	Token           string `yaml:"token"`
	Org             string `yaml:"org"`
	Bucket          string `yaml:"bucket"`
}

// FanCfg describes a named fanout target.
type FanCfg struct {
	Type         string `yaml:"type"`
	URLHost      string `yaml:"url_host"`
	Resolver     string `yaml:"resolver"`
	ResolverAddr string `yaml:"resolver_addr"`
}

// Load builds Config from env, or YAML when PWSBRIDGE_CONFIG is set.
func Load() (Config, Env, error) {
	e, err := LoadEnv()
	if err != nil {
		return Config{}, Env{}, err
	}
	var cfg Config
	if e.HasConfigFile() {
		cfg, err = loadYAML(e)
		if err != nil {
			return Config{}, e, err
		}
	} else {
		cfg = fromEnv(e)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = e.DataDir
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "/data"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, e, err
	}
	return cfg, e, nil
}

func fromEnv(e Env) Config {
	tenant := Tenant{
		ID:      "default",
		Derived: e.Derived,
		Stations: []Station{{
			ID:        e.StationID,
			Password:  e.StationPassword,
			Passkey:   e.StationPasskey,
			Protocols: []string{"wu", "ecowitt"},
		}},
	}
	sinks := map[string]SinkCfg{}
	var sinkNames []string
	if e.MQTTBroker != "" {
		sinks["ha"] = SinkCfg{
			Type:            "mqtt",
			Broker:          e.MQTTBroker,
			Username:        e.MQTTUsername,
			Password:        e.MQTTPassword,
			DiscoveryPrefix: e.MQTTDiscoveryPrefix,
			ClientID:        e.MQTTClientID,
		}
		sinkNames = append(sinkNames, "ha")
	}
	if e.Prometheus {
		sinks["prom"] = SinkCfg{Type: "prometheus"}
		sinkNames = append(sinkNames, "prom")
	}
	if e.SQLitePath != "" {
		sinks["sql"] = SinkCfg{Type: "sqlite", Path: e.SQLitePath}
		sinkNames = append(sinkNames, "sql")
	}
	if e.InfluxURL != "" {
		sinks["influx"] = SinkCfg{
			Type:   "influx",
			URL:    e.InfluxURL,
			Token:  e.InfluxToken,
			Org:    e.InfluxOrg,
			Bucket: e.InfluxBucket,
		}
		sinkNames = append(sinkNames, "influx")
	}
	tenant.Sinks = sinkNames

	fanouts := map[string]FanCfg{}
	var fanNames []string
	if e.ForwardWU {
		fanouts["wu"] = FanCfg{
			Type:         "http",
			URLHost:      "rtupdate.wunderground.com",
			Resolver:     resolverKind(e.ForwardResolver),
			ResolverAddr: e.ForwardResolver,
		}
		fanNames = append(fanNames, "wu")
	}
	tenant.Fanouts = fanNames

	metricsListen := e.MetricsListen
	if metricsListen == "" && e.Prometheus {
		metricsListen = "127.0.0.1:9091"
	}
	return Config{
		Listen:        e.Listen,
		MetricsListen: metricsListen,
		MetricsToken:  e.MetricsToken,
		AuthMode:      e.AuthMode,
		RateLimit:     e.RateLimit,
		StaleTimeout:  e.StaleTimeout,
		LogLevel:      e.LogLevel,
		Tenants:       []Tenant{tenant},
		Sinks:         sinks,
		Fanouts:       fanouts,
		NetLearnMode:  e.NetLearnMode,
		LimitBackend:  e.LimitBackend,
		RedisAddr:     e.RedisAddr,
		SQLitePath:    e.SQLitePath,
	}
}

func loadYAML(e Env) (Config, error) {
	b, err := os.ReadFile(e.ConfigPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return Config{}, fmt.Errorf("yaml: %w", err)
	}
	if e.Listen != "" {
		cfg.Listen = e.Listen
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}
	if e.MetricsListen != "" {
		cfg.MetricsListen = e.MetricsListen
	}
	if e.MetricsToken != "" {
		cfg.MetricsToken = e.MetricsToken
	}
	if e.LogLevel != "" {
		cfg.LogLevel = e.LogLevel
	}
	if e.RateLimit > 0 {
		cfg.RateLimit = e.RateLimit
	}
	if e.StaleTimeout > 0 {
		cfg.StaleTimeout = e.StaleTimeout
	}
	if cfg.AuthMode == "" {
		cfg.AuthMode = e.AuthMode
	}
	if cfg.NetLearnMode == "" {
		cfg.NetLearnMode = e.NetLearnMode
	}
	if cfg.LimitBackend == "" {
		cfg.LimitBackend = e.LimitBackend
	}
	if cfg.RedisAddr == "" {
		cfg.RedisAddr = e.RedisAddr
	}
	return cfg, nil
}

func resolverKind(addr string) string {
	if len(addr) >= 8 && addr[:8] == "https://" {
		return "doh"
	}
	return "dot"
}

// FindStation returns tenant and station for a WU or Ecowitt id.
func (c Config) FindStation(stationID string) (Tenant, Station, bool) {
	for _, t := range c.Tenants {
		for _, s := range t.Stations {
			if s.ID == stationID {
				return t, s, true
			}
		}
	}
	return Tenant{}, Station{}, false
}
