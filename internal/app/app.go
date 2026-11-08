package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/samsk/pwsbridge/internal/config"
	"github.com/samsk/pwsbridge/internal/fanout"
	"github.com/samsk/pwsbridge/internal/metrics"
	"github.com/samsk/pwsbridge/internal/policy"
	"github.com/samsk/pwsbridge/internal/server"
	"github.com/samsk/pwsbridge/internal/sink"
	"github.com/samsk/pwsbridge/internal/sink/influx"
	"github.com/samsk/pwsbridge/internal/sink/mqtt"
	"github.com/samsk/pwsbridge/internal/sink/prom"
	"github.com/samsk/pwsbridge/internal/sink/sqljson"
	"github.com/samsk/pwsbridge/internal/store"
	"golang.org/x/sync/errgroup"
)

// Run loads config, wires sinks, and serves until signal.
func Run() error {
	cfg, env, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	m := metrics.New()

	limiter, closer, err := buildLimiter(cfg)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer()
	}

	sinks, err := buildSinks(cfg, env, m, log)
	if err != nil {
		return err
	}
	defer closeSinks(sinks)

	var notifier fanout.Notifier
	for _, sk := range sinks {
		if n, ok := sk.(fanout.Notifier); ok {
			notifier = n
			break
		}
	}

	fanouts, err := buildFanouts(cfg, m, log, notifier)
	if err != nil {
		return err
	}

	resolver, err := fanout.NewResolver(env.ForwardResolver)
	if err != nil {
		return fmt.Errorf("forward resolver: %w", err)
	}
	netGate := policy.NewNetLearn(cfg.NetLearnMode, resolver, log)

	srv := &server.Server{
		Cfg:     cfg,
		Sinks:   sinks,
		Fanouts: fanouts,
		Limiter: limiter,
		Metrics: m,
		Logger:  log,
		NetGate: netGate,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		if err := srv.ListenAndServe(); err != nil && err != context.Canceled {
			if strings.Contains(err.Error(), "Server closed") {
				return nil
			}
			return err
		}
		return nil
	})
	if cfg.MetricsListen != "" {
		g.Go(func() error {
			if err := srv.ListenAndServeMetrics(); err != nil && err != context.Canceled {
				if strings.Contains(err.Error(), "Server closed") {
					return nil
				}
				return err
			}
			return nil
		})
	}
	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	})
	return g.Wait()
}

func buildLimiter(cfg config.Config) (policy.Limiter, func(), error) {
	switch cfg.LimitBackend {
	case "redis":
		if cfg.RedisAddr == "" {
			return nil, nil, fmt.Errorf("PWSBRIDGE_REDIS_ADDR required for redis limiter")
		}
		l := store.NewRedisLimiter(cfg.RedisAddr)
		return l, func() { _ = l.Close() }, nil
	default:
		return policy.NewMemoryLimiter(), nil, nil
	}
}

func buildSinks(cfg config.Config, env config.Env, m *metrics.Metrics, log *slog.Logger) (map[string]sink.Sink, error) {
	out := map[string]sink.Sink{}
	for name, sc := range cfg.Sinks {
		switch sc.Type {
		case "mqtt":
			clientID := sc.ClientID
			if clientID == "" {
				clientID = env.MQTTClientID
			}
			ms, err := mqtt.New(mqtt.Config{
				Broker:          sc.Broker,
				Username:        sc.Username,
				Password:        sc.Password,
				DiscoveryPrefix: sc.DiscoveryPrefix,
				ClientID:        clientID,
				StaleTimeout:    cfg.StaleTimeout,
				QueueDepthGauge: func(v float64) { m.MQTTQueue.Set(v) },
				Logger:          log,
			})
			if err != nil {
				return nil, fmt.Errorf("mqtt sink %s: %w", name, err)
			}
			out[name] = ms
		case "prometheus":
			out[name] = &prom.Sink{M: m}
		case "sqlite":
			path := sc.Path
			if path == "" {
				path = cfg.SQLitePath
			}
			ss, err := sqljson.New(path)
			if err != nil {
				return nil, err
			}
			out[name] = ss
		case "influx":
			is, err := influx.New(influx.Config{
				URL: sc.URL, Token: sc.Token, Org: sc.Org, Bucket: sc.Bucket,
			})
			if err != nil {
				return nil, err
			}
			out[name] = is
		default:
			return nil, fmt.Errorf("unknown sink type %q", sc.Type)
		}
	}
	return out, nil
}

func buildFanouts(cfg config.Config, m *metrics.Metrics, log *slog.Logger, n fanout.Notifier) (map[string]*fanout.Guard, error) {
	out := map[string]*fanout.Guard{}
	for name, fc := range cfg.Fanouts {
		addr := fc.ResolverAddr
		if addr == "" {
			addr = "1.1.1.1:53"
		}
		res, err := fanout.NewResolver(addr)
		if err != nil {
			return nil, fmt.Errorf("fanout %s resolver: %w", name, err)
		}
		inner := &fanout.WU{
			Resolver: res,
			Metrics:  m,
			Logger:   log,
		}
		out[name] = fanout.NewGuard(inner, n, log)
	}
	return out, nil
}

func closeSinks(sinks map[string]sink.Sink) {
	for _, s := range sinks {
		_ = s.Close()
	}
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}
