package influx

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
)

// Config configures the InfluxDB v2 sink.
type Config struct {
	URL    string
	Token  string
	Org    string
	Bucket string
}

// Sink writes line protocol points to InfluxDB.
type Sink struct {
	client   influxdb2.Client
	writeAPI api.WriteAPIBlocking
	org      string
	bucket   string
}

// New creates an Influx sink with a reused write API.
func New(cfg Config) (*Sink, error) {
	if cfg.URL == "" || cfg.Token == "" || cfg.Org == "" || cfg.Bucket == "" {
		return nil, fmt.Errorf("influx url, token, org, bucket required")
	}
	client := influxdb2.NewClient(cfg.URL, cfg.Token)
	return &Sink{
		client:   client,
		writeAPI: client.WriteAPIBlocking(cfg.Org, cfg.Bucket),
		org:      cfg.Org,
		bucket:   cfg.Bucket,
	}, nil
}

// Name returns the sink name.
func (s *Sink) Name() string { return "influx" }

// Publish writes one observation as a point.
func (s *Sink) Publish(ctx context.Context, o obs.Observation) error {
	p := influxdb2.NewPointWithMeasurement("weather").
		AddTag("tenant", o.TenantID).
		AddTag("station", o.StationID).
		SetTime(o.LastUpdated)
	for k, v := range o.Fields {
		p = p.AddField(sanitize(k), v)
	}
	if err := s.writeAPI.WritePoint(ctx, p); err != nil {
		return err
	}
	return nil
}

func sanitize(k string) string {
	return strings.ReplaceAll(k, ".", "_")
}

// Close flushes and closes the client.
func (s *Sink) Close() error {
	s.client.Close()
	return nil
}

// IdleTimeout documents the write timeout used by the client.
func IdleTimeout() time.Duration { return 10 * time.Second }
