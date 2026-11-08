package fanout

import (
	"context"

	"github.com/samsk/pwsbridge/internal/ingress"
)

// Fanout replays the original upload. Resolver is injected; never the system DNS resolver.
type Fanout interface {
	Name() string
	Forward(ctx context.Context, raw ingress.RawUpload) Result
}
