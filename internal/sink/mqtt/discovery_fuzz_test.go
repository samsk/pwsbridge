package mqtt

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/policy"
)

// FuzzDiscoveryPayload checks MQTT topics and templates stay safe.
func FuzzDiscoveryPayload(f *testing.F) {
	f.Add("station_1", "temperature")
	f.Add("a/b", "temp")
	f.Add("a+b", "hum")
	f.Add("a#b", "press")
	f.Add("ok", "bad/key")
	f.Add("ok", "a+b")
	f.Add("ok", `quote"`)
	f.Add("ok", "}}evil")
	f.Add(strings.Repeat("A", 65), "temperature")
	f.Add("", "temperature")
	f.Add("ok", "")

	f.Fuzz(func(t *testing.T, stationID, field string) {
		if !policy.ValidStationID(stationID) || !obs.ValidKey(field) {
			return
		}
		o := obs.New("tenant", stationID, time.Now().UTC())
		o.SetReceived(field, 1)
		topic, body, err := DiscoveryPayload("homeassistant", o)
		if err != nil {
			t.Fatalf("discovery: %v", err)
		}
		for _, bad := range []string{" ", "+", "#"} {
			if strings.Contains(topic, bad) {
				t.Fatalf("unsafe topic %q contains %q", topic, bad)
			}
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("json: %v body=%s", err, body)
		}
		cmps, _ := payload["components"].(map[string]any)
		cmp, _ := cmps[field].(map[string]any)
		if cmp == nil {
			t.Fatalf("missing component for %q", field)
		}
		tmpl, _ := cmp["value_template"].(string)
		want := "{{ value_json." + field + " }}"
		if tmpl != want {
			t.Fatalf("template=%q want=%q", tmpl, want)
		}
	})
}
