package sqljson

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
)

func TestPublishJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wx.db")
	s, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	o := obs.New("default", "test", time.Now().UTC())
	o.SetReceived("temperature", 17.5)
	if err := s.Publish(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	n, err := s.Count(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
