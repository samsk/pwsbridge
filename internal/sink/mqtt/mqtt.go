package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	pahomqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/samsk/pwsbridge/internal/obs"
)

const maxQueue = 100

// deviceID identifies a station device without joining on underscore.
type deviceID struct {
	Tenant  string
	Station string
}

func (d deviceID) key() string { return d.Tenant + "\x00" + d.Station }

// Config configures the HA MQTT sink.
type Config struct {
	Broker          string
	Username        string
	Password        string
	DiscoveryPrefix string
	ClientID        string
	StaleTimeout    time.Duration
	QueueDepthGauge func(float64)
	Logger          *slog.Logger
}

// Sink publishes HA device discovery and state.
type Sink struct {
	cfg          Config
	client       pahomqtt.Client
	mu           sync.Mutex
	discovered   map[string]struct{}
	lastSeen     map[string]time.Time
	devices      map[string]deviceID
	queue        []obs.Observation
	connected    bool
	shuttingDown bool
	stopStale    chan struct{}
	pubCtx       context.Context
}

// New creates an MQTT sink and connects.
func New(cfg Config) (*Sink, error) {
	if cfg.DiscoveryPrefix == "" {
		cfg.DiscoveryPrefix = "homeassistant"
	}
	if cfg.ClientID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		cfg.ClientID = "pwsbridge-" + host
	}
	if cfg.StaleTimeout == 0 {
		cfg.StaleTimeout = 300 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if strings.EqualFold(cfg.ClientID, "pws_exporter") {
		return nil, fmt.Errorf("client id must not be pws_exporter")
	}
	s := &Sink{
		cfg:        cfg,
		discovered: make(map[string]struct{}),
		lastSeen:   make(map[string]time.Time),
		devices:    make(map[string]deviceID),
		stopStale:  make(chan struct{}),
		pubCtx:     context.Background(),
	}
	opts := pahomqtt.NewClientOptions().AddBroker(cfg.Broker)
	opts.SetUsername(cfg.Username)
	opts.SetPassword(cfg.Password)
	opts.SetClientID(cfg.ClientID)
	opts.SetAutoReconnect(true)
	opts.SetOnConnectHandler(func(_ pahomqtt.Client) {
		s.mu.Lock()
		s.connected = true
		clear(s.discovered)
		s.mu.Unlock()
		cfg.Logger.Info("mqtt connected", "broker", cfg.Broker, "client_id", cfg.ClientID)
		s.drainQueue()
	})
	opts.SetConnectionLostHandler(func(_ pahomqtt.Client, err error) {
		s.mu.Lock()
		s.connected = false
		s.mu.Unlock()
		cfg.Logger.Warn("mqtt lost", "err", err)
	})
	s.client = pahomqtt.NewClient(opts)
	token := s.client.Connect()
	token.Wait()
	if err := token.Error(); err != nil {
		return nil, fmt.Errorf("mqtt connect: %w", err)
	}
	go s.staleLoop()
	return s, nil
}

// Name returns the sink name.
func (s *Sink) Name() string { return "mqtt" }

// ClientID returns the MQTT client id for tests.
func (s *Sink) ClientID() string { return s.cfg.ClientID }

// Publish queues or sends an observation to MQTT.
func (s *Sink) Publish(ctx context.Context, o obs.Observation) error {
	s.mu.Lock()
	s.pubCtx = ctx
	if !s.connected {
		s.enqueue(o)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if err := s.doPublish(ctx, o); err != nil {
		s.mu.Lock()
		s.enqueue(o)
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Sink) enqueue(o obs.Observation) {
	if len(s.queue) >= maxQueue {
		s.queue = s.queue[1:]
	}
	s.queue = append(s.queue, o)
	if s.cfg.QueueDepthGauge != nil {
		s.cfg.QueueDepthGauge(float64(len(s.queue)))
	}
}

func (s *Sink) drainQueue() {
	for {
		s.mu.Lock()
		if len(s.queue) == 0 || !s.connected {
			s.mu.Unlock()
			return
		}
		head := s.queue[0]
		ctx := s.pubCtx
		if ctx == nil {
			ctx = context.Background()
		}
		s.mu.Unlock()
		if err := s.doPublish(ctx, head); err != nil {
			return
		}
		s.mu.Lock()
		if len(s.queue) > 0 {
			s.queue = s.queue[1:]
		}
		if s.cfg.QueueDepthGauge != nil {
			s.cfg.QueueDepthGauge(float64(len(s.queue)))
		}
		s.mu.Unlock()
	}
}

func (s *Sink) doPublish(ctx context.Context, o obs.Observation) error {
	id := deviceID{Tenant: o.TenantID, Station: o.StationID}
	k := id.key()
	deviceKey := o.TenantID + "_" + o.StationID
	s.mu.Lock()
	_, known := s.discovered[k]
	s.lastSeen[k] = time.Now()
	s.devices[k] = id
	s.mu.Unlock()

	availTopic := fmt.Sprintf("pwsbridge/%s/%s/availability", o.TenantID, o.StationID)
	if err := s.waitPublish(ctx, availTopic, true, []byte("online")); err != nil {
		return err
	}
	if !known {
		if err := s.publishDiscovery(ctx, o); err != nil {
			return err
		}
		s.mu.Lock()
		s.discovered[k] = struct{}{}
		s.mu.Unlock()
	}
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	stateTopic := fmt.Sprintf("pwsbridge/%s/%s/state", o.TenantID, o.StationID)
	_ = deviceKey
	return s.waitPublish(ctx, stateTopic, true, body)
}

func (s *Sink) waitPublish(ctx context.Context, topic string, retained bool, payload []byte) error {
	token := s.client.Publish(topic, 0, retained, payload)
	done := make(chan struct{})
	go func() {
		token.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return token.Error()
	}
}

func (s *Sink) publishDiscovery(ctx context.Context, o obs.Observation) error {
	deviceKey := o.TenantID + "_" + o.StationID
	cmps := map[string]any{}
	for field := range o.Fields {
		c := componentFor(field)
		cmp := map[string]any{
			"p":                  "sensor",
			"name":               c.Name,
			"unique_id":          deviceKey + "_" + c.ID,
			"state_class":        c.StateClass,
			"value_template":     "{{ value_json." + c.ID + " }}",
			"enabled_by_default": true,
		}
		if c.DeviceClass != "" {
			cmp["device_class"] = c.DeviceClass
		}
		if c.Unit != "" {
			cmp["unit_of_measurement"] = c.Unit
		}
		if c.Icon != "" {
			cmp["icon"] = c.Icon
		}
		cmps[c.ID] = cmp
	}
	payload := map[string]any{
		"device": map[string]any{
			"ids":  deviceKey,
			"name": fmt.Sprintf("Weather Station (%s)", strings.ToUpper(o.StationID)),
		},
		"origin": map[string]any{
			"name": "pwsbridge",
		},
		"components":            cmps,
		"state_topic":           fmt.Sprintf("pwsbridge/%s/%s/state", o.TenantID, o.StationID),
		"availability_topic":    fmt.Sprintf("pwsbridge/%s/%s/availability", o.TenantID, o.StationID),
		"payload_available":     "online",
		"payload_not_available": "offline",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	topic := fmt.Sprintf("%s/device/%s/config", s.cfg.DiscoveryPrefix, deviceKey)
	return s.waitPublish(ctx, topic, true, body)
}

func (s *Sink) staleLoop() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.stopStale:
			return
		case <-t.C:
			s.checkStale()
		}
	}
}

func (s *Sink) checkStale() {
	s.mu.Lock()
	if !s.connected || s.shuttingDown {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	stale := make([]deviceID, 0)
	staleKeys := make([]string, 0)
	for k, last := range s.lastSeen {
		if now.Sub(last) > s.cfg.StaleTimeout {
			if id, ok := s.devices[k]; ok {
				stale = append(stale, id)
				staleKeys = append(staleKeys, k)
			}
		}
	}
	s.mu.Unlock()

	for i, id := range stale {
		topic := fmt.Sprintf("pwsbridge/%s/%s/availability", id.Tenant, id.Station)
		_ = s.client.Publish(topic, 0, true, "offline").Wait()
		key := staleKeys[i]
		s.mu.Lock()
		if last, ok := s.lastSeen[key]; ok && time.Since(last) <= s.cfg.StaleTimeout {
			s.mu.Unlock()
			continue
		}
		delete(s.lastSeen, key)
		delete(s.discovered, key)
		delete(s.devices, key)
		s.mu.Unlock()
	}
}

// Close publishes offline and disconnects.
func (s *Sink) Close() error {
	s.mu.Lock()
	s.shuttingDown = true
	ids := make([]deviceID, 0, len(s.devices))
	for _, id := range s.devices {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	close(s.stopStale)
	for _, id := range ids {
		topic := fmt.Sprintf("pwsbridge/%s/%s/availability", id.Tenant, id.Station)
		_ = s.client.Publish(topic, 0, true, "offline").Wait()
	}
	s.client.Disconnect(250)
	return nil
}

// QueueLen returns pending queue length for tests.
func (s *Sink) QueueLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.queue)
}

// EnqueueForTest adds to the queue without publishing.
func (s *Sink) EnqueueForTest(o obs.Observation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enqueue(o)
}

// SetConnectedForTest toggles connected state.
func (s *Sink) SetConnectedForTest(v bool) {
	s.mu.Lock()
	s.connected = v
	s.mu.Unlock()
}

// TouchLastSeenForTest updates last-seen during stale publish race tests.
func (s *Sink) TouchLastSeenForTest(tenant, station string) {
	id := deviceID{Tenant: tenant, Station: station}
	k := id.key()
	s.mu.Lock()
	s.lastSeen[k] = time.Now()
	s.devices[k] = id
	s.mu.Unlock()
}

// LastSeenHas reports whether tenant/station is still tracked.
func (s *Sink) LastSeenHas(tenant, station string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.lastSeen[deviceID{Tenant: tenant, Station: station}.key()]
	return ok
}

// DeviceKeyForTest returns the discovery device key.
func DeviceKeyForTest(tenant, station string) string {
	return tenant + "_" + station
}

// DiscoveryPayload builds discovery JSON for tests without MQTT.
func DiscoveryPayload(prefix string, o obs.Observation) (topic string, body []byte, err error) {
	deviceKey := o.TenantID + "_" + o.StationID
	cmps := map[string]any{}
	for field := range o.Fields {
		c := componentFor(field)
		cmp := map[string]any{
			"p":              "sensor",
			"name":           c.Name,
			"unique_id":      deviceKey + "_" + c.ID,
			"state_class":    c.StateClass,
			"value_template": "{{ value_json." + c.ID + " }}",
		}
		if c.DeviceClass != "" {
			cmp["device_class"] = c.DeviceClass
		}
		if c.Unit != "" {
			cmp["unit_of_measurement"] = c.Unit
		}
		cmps[c.ID] = cmp
	}
	payload := map[string]any{
		"components":            cmps,
		"state_topic":           fmt.Sprintf("pwsbridge/%s/%s/state", o.TenantID, o.StationID),
		"availability_topic":    fmt.Sprintf("pwsbridge/%s/%s/availability", o.TenantID, o.StationID),
		"payload_available":     "online",
		"payload_not_available": "offline",
		"device": map[string]any{
			"ids":  deviceKey,
			"name": fmt.Sprintf("Weather Station (%s)", strings.ToUpper(o.StationID)),
		},
		"origin": map[string]any{"name": "pwsbridge"},
	}
	body, err = json.Marshal(payload)
	topic = fmt.Sprintf("%s/device/%s/config", prefix, deviceKey)
	return topic, body, err
}
