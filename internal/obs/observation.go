package obs

import (
	"encoding/json"
	"math"
	"regexp"
	"time"
)

// fieldKeyRE matches MQTT/Influx-safe observation field names.
var fieldKeyRE = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// ValidKey reports whether key is safe for MQTT topics and Influx fields.
func ValidKey(key string) bool {
	return fieldKeyRE.MatchString(key)
}

// Observation is one SI weather sample from a station.
type Observation struct {
	TenantID    string              `json:"-"`
	StationID   string              `json:"-"`
	LastUpdated time.Time           `json:"last_updated"`
	Fields      map[string]float64  `json:"-"`
	Received    map[string]struct{} `json:"-"`
}

// New creates an empty observation for a tenant and station.
func New(tenantID, stationID string, at time.Time) Observation {
	return Observation{
		TenantID:    tenantID,
		StationID:   stationID,
		LastUpdated: at,
		Fields:      make(map[string]float64),
		Received:    make(map[string]struct{}),
	}
}

// SetReceived stores a station-provided finite SI field.
func (o *Observation) SetReceived(key string, value float64) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	o.Fields[key] = value
	o.Received[key] = struct{}{}
}

// SetDerived stores a calculated field when the key was not received.
func (o *Observation) SetDerived(key string, value float64) {
	if _, ok := o.Received[key]; ok {
		return
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return
	}
	o.Fields[key] = value
}

// Has reports whether a field is present.
func (o Observation) Has(key string) bool {
	_, ok := o.Fields[key]
	return ok
}

// Get returns a field value and whether it exists.
func (o Observation) Get(key string) (float64, bool) {
	v, ok := o.Fields[key]
	return v, ok
}

// WasReceived reports if the station sent the key.
func (o Observation) WasReceived(key string) bool {
	_, ok := o.Received[key]
	return ok
}

// MarshalJSON encodes present fields and last_updated.
func (o Observation) MarshalJSON() ([]byte, error) {
	out := make(map[string]any, len(o.Fields)+1)
	out["last_updated"] = o.LastUpdated.UTC().Format(time.RFC3339)
	for k, v := range o.Fields {
		out[k] = v
	}
	return json.Marshal(out)
}
