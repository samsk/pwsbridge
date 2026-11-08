package policy

import (
	"strings"
	"testing"
	"unicode"
)

// FuzzValidStationID checks accepted ids stay MQTT-safe.
func FuzzValidStationID(f *testing.F) {
	seeds := []string{
		"", "+", "#", "a/b", "a+b", "a#b", "../x",
		strings.Repeat("A", 65), "station_1", "ABC-123",
		"AABBCCDDEEFF00112233445566778899", " ", "\n", "\x00",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if !ValidStationID(id) {
			return
		}
		if len(id) < 1 || len(id) > 64 {
			t.Fatalf("accepted bad length: %q", id)
		}
		for _, r := range id {
			if r == '/' || r == '+' || r == '#' || unicode.IsControl(r) {
				t.Fatalf("accepted unsafe char in %q", id)
			}
		}
	})
}
