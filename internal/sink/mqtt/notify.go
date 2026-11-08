package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samsk/pwsbridge/internal/fanout"
)

// NotifyFanout publishes retained fanout state and a diagnostic sensor.
func (s *Sink) NotifyFanout(tenant, station, fanoutName string, st fanout.FanoutState) {
	if s.client == nil {
		return
	}
	body, err := json.Marshal(st)
	if err != nil {
		return
	}
	topic := fmt.Sprintf("pwsbridge/%s/%s/fanout/%s", tenant, station, fanoutName)
	_ = s.waitPublish(context.Background(), topic, true, body)

	deviceKey := tenant + "_" + station
	cmpID := "fanout_" + fanoutName
	payload := map[string]any{
		"device": map[string]any{
			"ids":  deviceKey,
			"name": fmt.Sprintf("Weather Station (%s)", strings.ToUpper(station)),
		},
		"origin": map[string]any{"name": "pwsbridge"},
		"components": map[string]any{
			cmpID: map[string]any{
				"p":                     "sensor",
				"name":                  "Fanout " + fanoutName,
				"unique_id":             deviceKey + "_" + cmpID,
				"state_topic":           topic,
				"value_template":        "{{ value_json.state }}",
				"json_attributes_topic": topic,
				"entity_category":       "diagnostic",
				"enabled_by_default":    true,
				"icon":                  "mdi:cloud-upload",
			},
		},
		"availability_topic":    fmt.Sprintf("pwsbridge/%s/%s/availability", tenant, station),
		"payload_available":     "online",
		"payload_not_available": "offline",
	}
	disc, err := json.Marshal(payload)
	if err != nil {
		return
	}
	discTopic := fmt.Sprintf("%s/device/%s_%s/config", s.cfg.DiscoveryPrefix, deviceKey, cmpID)
	_ = s.waitPublish(context.Background(), discTopic, true, disc)
}
