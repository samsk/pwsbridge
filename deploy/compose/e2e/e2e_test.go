package e2e_test

import (
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestE2EUpload(t *testing.T) {
	base := os.Getenv("PWSBRIDGE_E2E_URL")
	if base == "" {
		t.Skip("PWSBRIDGE_E2E_URL not set")
	}
	q := "ID=test&PASSWORD=testtest&action=updateraw&tempf=63.5&humidity=64&dateutc=now"
	var last error
	for i := 0; i < 30; i++ {
		res, err := http.Get(base + "/weatherstation/updateweatherstation.php?" + q)
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == 200 && string(body) == "success\n" {
			return
		}
		last = err
		time.Sleep(time.Second)
	}
	t.Fatalf("e2e failed: %v", last)
}
