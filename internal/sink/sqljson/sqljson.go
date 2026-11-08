package sqljson

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
	_ "modernc.org/sqlite"
)

// Sink stores observations as JSON rows in SQLite.
type Sink struct {
	db *sql.DB
}

// New opens or creates a SQLite database at path with mode 0600.
func New(path string) (*Sink, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		_ = f.Close()
	} else {
		_ = os.Chmod(path, 0o600)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant TEXT NOT NULL,
  station TEXT NOT NULL,
  ts TEXT NOT NULL,
  payload TEXT NOT NULL
);`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &Sink{db: db}, nil
}

// Name returns the sink name.
func (s *Sink) Name() string { return "sqlite" }

// Publish inserts one JSON observation row.
func (s *Sink) Publish(ctx context.Context, o obs.Observation) error {
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO observations(tenant, station, ts, payload) VALUES(?,?,?,?)`,
		o.TenantID, o.StationID, o.LastUpdated.UTC().Format(time.RFC3339), string(body),
	)
	if err != nil {
		return fmt.Errorf("sqlite insert: %w", err)
	}
	return nil
}

// Count returns stored rows for tests.
func (s *Sink) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations`).Scan(&n)
	return n, err
}

// Close closes the database.
func (s *Sink) Close() error { return s.db.Close() }
