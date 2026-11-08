package config

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v11"
)

// Env holds process configuration from PWSBRIDGE_* variables.
type Env struct {
	Listen              string        `env:"PWSBRIDGE_LISTEN" envDefault:":8080"`
	LogLevel            string        `env:"PWSBRIDGE_LOG_LEVEL" envDefault:"info"`
	AuthMode            string        `env:"PWSBRIDGE_AUTH_MODE" envDefault:"password"`
	StationID           string        `env:"PWSBRIDGE_STATION_ID"`
	StationPassword     string        `env:"PWSBRIDGE_STATION_PASSWORD"`
	StationPasskey      string        `env:"PWSBRIDGE_STATION_PASSKEY"`
	MQTTBroker          string        `env:"PWSBRIDGE_MQTT_BROKER"`
	MQTTUsername        string        `env:"PWSBRIDGE_MQTT_USERNAME"`
	MQTTPassword        string        `env:"PWSBRIDGE_MQTT_PASSWORD"`
	MQTTDiscoveryPrefix string        `env:"PWSBRIDGE_MQTT_DISCOVERY_PREFIX" envDefault:"homeassistant"`
	MQTTClientID        string        `env:"PWSBRIDGE_MQTT_CLIENT_ID"`
	Prometheus          bool          `env:"PWSBRIDGE_PROMETHEUS" envDefault:"true"`
	MetricsListen       string        `env:"PWSBRIDGE_METRICS_LISTEN"`
	MetricsToken        string        `env:"PWSBRIDGE_METRICS_TOKEN"`
	ForwardWU           bool          `env:"PWSBRIDGE_FORWARD_WU" envDefault:"false"`
	ForwardResolver     string        `env:"PWSBRIDGE_FORWARD_RESOLVER" envDefault:"1.1.1.1:53"`
	RateLimit           time.Duration `env:"PWSBRIDGE_RATE_LIMIT" envDefault:"2s"`
	StaleTimeout        time.Duration `env:"PWSBRIDGE_STALE_TIMEOUT" envDefault:"300s"`
	Derived             bool          `env:"PWSBRIDGE_DERIVED" envDefault:"false"`
	ConfigPath          string        `env:"PWSBRIDGE_CONFIG"`
	SQLitePath          string        `env:"PWSBRIDGE_SQLITE_PATH"`
	LimitBackend        string        `env:"PWSBRIDGE_LIMIT_BACKEND" envDefault:"memory"`
	RedisAddr           string        `env:"PWSBRIDGE_REDIS_ADDR"`
	NetLearnMode        string        `env:"PWSBRIDGE_NET_LEARN" envDefault:"off"`
	InfluxURL           string        `env:"PWSBRIDGE_INFLUX_URL"`
	InfluxToken         string        `env:"PWSBRIDGE_INFLUX_TOKEN"`
	InfluxOrg           string        `env:"PWSBRIDGE_INFLUX_ORG"`
	InfluxBucket        string        `env:"PWSBRIDGE_INFLUX_BUCKET"`
	DataDir             string        `env:"PWSBRIDGE_DATA_DIR" envDefault:"/data"`
}

// LoadEnv parses PWSBRIDGE_* environment variables.
func LoadEnv() (Env, error) {
	var e Env
	if err := env.Parse(&e); err != nil {
		return Env{}, fmt.Errorf("parse env: %w", err)
	}
	return e, nil
}

// HasConfigFile reports whether YAML multi-tenant config is set.
func (e Env) HasConfigFile() bool {
	return e.ConfigPath != ""
}

// RequireEnvNames documents required env names for docker-style config.
func RequireEnvNames() []string {
	return []string{
		"PWSBRIDGE_LISTEN",
		"PWSBRIDGE_LOG_LEVEL",
		"PWSBRIDGE_AUTH_MODE",
		"PWSBRIDGE_STATION_ID",
		"PWSBRIDGE_STATION_PASSWORD",
		"PWSBRIDGE_MQTT_BROKER",
		"PWSBRIDGE_MQTT_USERNAME",
		"PWSBRIDGE_MQTT_PASSWORD",
		"PWSBRIDGE_MQTT_DISCOVERY_PREFIX",
		"PWSBRIDGE_MQTT_CLIENT_ID",
		"PWSBRIDGE_PROMETHEUS",
		"PWSBRIDGE_METRICS_LISTEN",
		"PWSBRIDGE_METRICS_TOKEN",
		"PWSBRIDGE_FORWARD_WU",
		"PWSBRIDGE_FORWARD_RESOLVER",
		"PWSBRIDGE_RATE_LIMIT",
		"PWSBRIDGE_STALE_TIMEOUT",
		"PWSBRIDGE_DERIVED",
		"PWSBRIDGE_CONFIG",
	}
}

// Hostname returns the host name for default client ids.
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}
