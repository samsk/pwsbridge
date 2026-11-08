package prom

import (
	"context"

	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/obs"
)

// Sink publishes weather gauges to Prometheus.
type Sink struct {
	M *metrics.Metrics
}

// Name returns the sink name.
func (s *Sink) Name() string { return "prometheus" }

// Publish updates weather gauges from an observation.
func (s *Sink) Publish(_ context.Context, o obs.Observation) error {
	if s.M == nil {
		return nil
	}
	s.M.SetWeather(o.TenantID, o.StationID, o.Fields)
	return nil
}

// Close is a no-op.
func (s *Sink) Close() error { return nil }
