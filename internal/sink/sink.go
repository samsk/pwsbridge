package sink

import (
	"context"

	"github.com/samsk/pwsbridge/internal/obs"
)

// Sink publishes one observation. Must not block the HTTP handler for long.
type Sink interface {
	Name() string
	Publish(ctx context.Context, o obs.Observation) error
	Close() error
}
