package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds separate weather and service Prometheus registries.
type Metrics struct {
	Weather *prometheus.Registry
	Service *prometheus.Registry

	HTTPRequests *prometheus.CounterVec
	Dropped      *prometheus.CounterVec
	Fanout       *prometheus.CounterVec
	MQTTQueue    prometheus.Gauge

	Temperature prometheus.GaugeVec
	Humidity    prometheus.GaugeVec
	Pressure    prometheus.GaugeVec
	WindSpeed   prometheus.GaugeVec
	RainHour    prometheus.GaugeVec
	RainDaily   prometheus.GaugeVec
	DewPoint    prometheus.GaugeVec
}

// New creates weather and service registries with pwsbridge metrics.
func New() *Metrics {
	weather := prometheus.NewRegistry()
	service := prometheus.NewRegistry()
	m := &Metrics{Weather: weather, Service: service}

	m.HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pwsbridge",
		Name:      "http_requests_total",
		Help:      "HTTP requests by status code",
	}, []string{"code"})
	m.Dropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pwsbridge",
		Name:      "dropped_total",
		Help:      "Dropped samples by reason",
	}, []string{"reason"})
	m.Fanout = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "pwsbridge",
		Name:      "fanout_total",
		Help:      "Fanout attempts by host and result",
	}, []string{"host", "result"})
	m.MQTTQueue = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "mqtt_queue_depth",
		Help:      "Pending MQTT messages",
	})

	labels := []string{"tenant", "station"}
	m.Temperature = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "temperature_celsius",
		Help:      "Temperature in Celsius",
	}, labels)
	m.Humidity = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "humidity_percent",
		Help:      "Relative humidity percentage 0-100",
	}, labels)
	m.Pressure = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "barometric_pressure_hpa",
		Help:      "Barometric pressure in hectopascals",
	}, labels)
	m.WindSpeed = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "wind_speed_kph",
		Help:      "Wind speed in KM/h",
	}, labels)
	m.RainHour = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "rain_past_hour_mm",
		Help:      "Rain over the past hour in millimeters",
	}, labels)
	m.RainDaily = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "rain_daily_mm",
		Help:      "Daily rain in millimeters",
	}, labels)
	m.DewPoint = *prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "pwsbridge",
		Name:      "dew_point_celsius",
		Help:      "Dew point in Celsius",
	}, labels)

	service.MustRegister(m.HTTPRequests, m.Dropped, m.Fanout, m.MQTTQueue)
	weather.MustRegister(
		&m.Temperature, &m.Humidity, &m.Pressure, &m.WindSpeed,
		&m.RainHour, &m.RainDaily, &m.DewPoint,
	)
	return m
}

// SetWeather updates weather gauges from an observation field map.
func (m *Metrics) SetWeather(tenant, station string, fields map[string]float64) {
	set := func(g *prometheus.GaugeVec, key string) {
		if v, ok := fields[key]; ok {
			g.WithLabelValues(tenant, station).Set(v)
		}
	}
	set(&m.Temperature, "temperature")
	set(&m.Humidity, "humidity")
	set(&m.Pressure, "pressure")
	set(&m.WindSpeed, "wind_speed")
	set(&m.RainHour, "rain_past_hour")
	set(&m.RainDaily, "rain_daily")
	set(&m.DewPoint, "dew_point")
}
