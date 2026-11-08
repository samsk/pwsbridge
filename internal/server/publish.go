package server

import (
	"context"
	"sync"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/ingress"
	"github.com/samsk/pwsbridge/internal/obs"
)

func (s *Server) schedulePublish(tenant config.Tenant, o obs.Observation, raw ingress.RawUpload) {
	s.ensureWorkers()
	select {
	case s.sinkSem <- struct{}{}:
		go func() {
			defer func() { <-s.sinkSem }()
			s.publishSinks(tenant, o)
		}()
	default:
		if s.Metrics != nil {
			s.Metrics.Dropped.WithLabelValues("busy").Inc()
		}
		s.Logger.Warn("sink workers full", "tenant", tenant.ID, "station", o.StationID)
	}
	for _, name := range tenant.Fanouts {
		g, ok := s.Fanouts[name]
		if !ok {
			continue
		}
		g.Try(tenant.ID, o.StationID, raw)
	}
}

func (s *Server) publishSinks(tenant config.Tenant, o obs.Observation) {
	defer func() {
		if rec := recover(); rec != nil {
			s.Logger.Error("sink panic", "tenant", tenant.ID, "panic", rec)
			if s.Metrics != nil {
				s.Metrics.Dropped.WithLabelValues("panic").Inc()
			}
		}
	}()
	sem := s.tenantSem(&s.tenantSinkSem, tenant.ID, maxSinkPerTenant)
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	default:
		if s.Metrics != nil {
			s.Metrics.Dropped.WithLabelValues("tenant_busy").Inc()
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 10*time.Second)
	defer cancel()
	for _, name := range tenant.Sinks {
		sk, ok := s.Sinks[name]
		if !ok {
			continue
		}
		if err := sk.Publish(ctx, o); err != nil {
			s.Logger.Error("sink publish", "sink", name, "err", err)
			if s.Metrics != nil {
				s.Metrics.Dropped.WithLabelValues("sink").Inc()
			}
		}
	}
}

func (s *Server) tenantSem(m *sync.Map, tenant string, n int) chan struct{} {
	if v, ok := m.Load(tenant); ok {
		return v.(chan struct{})
	}
	ch := make(chan struct{}, n)
	actual, _ := m.LoadOrStore(tenant, ch)
	return actual.(chan struct{})
}
