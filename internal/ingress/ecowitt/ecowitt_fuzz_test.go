package ecowitt

import (
	"strings"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
)

// FuzzEcowittApplyParams checks field keys stay MQTT/Influx-safe.
func FuzzEcowittApplyParams(f *testing.F) {
	seeds := []string{
		"tempf=70",
		"bad/key=1",
		"a+b=2",
		"a#b=3",
		`quote"=4`,
		"}}evil=5",
		"../x=6",
		"ok_key=7",
		"empty=",
		"neg=-9999",
		"PASSKEY=AABB",
		strings.Repeat("A", 65) + "=1",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		params := splitParams(raw)
		o := obs.New("t", "s", time.Now().UTC())
		ApplyParams(params, &o)
		for k := range o.Fields {
			if !obs.ValidKey(k) {
				t.Fatalf("unsafe field key %q from %q", k, raw)
			}
		}
	})
}

// FuzzParseDateUTC checks the date parser never panics.
func FuzzParseDateUTC(f *testing.F) {
	seeds := []string{"", "now", "2024-01-01 00:00:00", "2024-01-01+00:00:00", "bad", "-9999"}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := ParseDateUTC(v)
		if got.IsZero() {
			t.Fatalf("zero time for %q", v)
		}
	})
}

// splitParams turns "k=v&k2=v2" style fuzz input into a param map.
func splitParams(raw string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			out[part] = ""
			continue
		}
		out[k] = v
	}
	return out
}
