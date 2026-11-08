package fanout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFanoutSourceNoSystemDNS(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") {
				continue
			}
			if strings.Contains(line, "net.DefaultResolver") {
				t.Fatalf("%s uses net.DefaultResolver", e.Name())
			}
			if strings.Contains(line, "net.LookupIP") {
				t.Fatalf("%s uses net.LookupIP", e.Name())
			}
		}
	}
}
