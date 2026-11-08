package fanout

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

// Kind classifies a fanout attempt outcome.
type Kind int

const (
	// KindOK means the site accepted the upload.
	KindOK Kind = iota
	// KindRefusal means the site answered and rejected the data.
	KindRefusal
	// KindTransport means network, timeout, or server error.
	KindTransport
)

// Result is the outcome of one Forward call.
type Result struct {
	Kind   Kind
	Reason string
	Err    error
}

// OKResult marks a successful ingest.
func OKResult() Result { return Result{Kind: KindOK} }

// TransportResult marks a network or 5xx failure.
func TransportResult(err error) Result {
	return Result{Kind: KindTransport, Err: err}
}

// RefusalResult marks a site rejection with a sanitized reason.
func RefusalResult(status int, body string) Result {
	return Result{Kind: KindRefusal, Reason: sanitizeReason(status, body)}
}

func sanitizeReason(status int, body string) string {
	line := strings.TrimSpace(body)
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, line)
	upper := strings.ToUpper(line)
	if strings.Contains(upper, "PASSWORD=") || strings.Contains(upper, "PASSKEY=") {
		line = ""
	}
	if len(line) > 120 {
		line = line[:120]
	}
	if line == "" {
		return fmt.Sprintf("http %d", status)
	}
	return line
}

// ClassifyHTTP maps status and body to a Result for WU-style endpoints.
func ClassifyHTTP(status int, body string) Result {
	if status >= 500 {
		return TransportResult(fmt.Errorf("http %d", status))
	}
	lower := strings.ToLower(body)
	if status == http.StatusOK && strings.Contains(lower, "success") {
		return OKResult()
	}
	if status >= 400 && status < 500 {
		return RefusalResult(status, body)
	}
	if status == http.StatusOK {
		return RefusalResult(status, body)
	}
	return TransportResult(fmt.Errorf("http %d", status))
}
